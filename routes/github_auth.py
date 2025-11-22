# routes/github_auth.py
import logging
import secrets
from urllib.parse import urlencode

import requests
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, logout_user, login_required

from models import db, User
from config import config
from utils.email_sender import email_sender

logger = logging.getLogger("github_auth")

github_auth_bp = Blueprint('auth', __name__)

# GitHub OAuth endpoints
GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USER_URL = 'https://api.github.com/user'
GITHUB_EMAIL_URL = 'https://api.github.com/user/emails'

# Request timeout
REQUEST_TIMEOUT = 15


@github_auth_bp.route('/auth/github')
def github_login():
    """Redirect user to GitHub for authorization"""
    if not config.GITHUB_CLIENT_ID or not config.GITHUB_CLIENT_SECRET:
        flash('GitHub OAuth is not configured.', 'error')
        return redirect(url_for('main.login'))
    
    if current_user.is_authenticated and not request.args.get('link'):
        return redirect(url_for('main.dashboard'))
    
    # Generate secure state token
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['oauth_action'] = 'link' if request.args.get('link') else 'login'
    
    params = {
        'client_id': config.GITHUB_CLIENT_ID,
        'redirect_uri': config.GITHUB_REDIRECT_URI,
        'scope': 'user:email read:user',
        'state': state,
        'allow_signup': 'true'
    }
    
    auth_url = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
    logger.info(f"Redirecting to GitHub OAuth")
    
    return redirect(auth_url)


@github_auth_bp.route('/auth/github/callback')
def github_callback():
    """Handle GitHub OAuth callback"""
    return _handle_github_callback()


@github_auth_bp.route('/callback/github')
def github_callback_alternate():
    """Handle GitHub OAuth callback - alternate route"""
    return _handle_github_callback()


def _handle_github_callback():
    """Common handler for GitHub OAuth callback"""
    logger.info("GitHub callback received")
    
    # Check for errors from GitHub
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        logger.error(f"GitHub OAuth error: {error} - {error_description}")
        flash(f'GitHub authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state parameter (CSRF protection)
    state = request.args.get('state')
    stored_state = session.pop('oauth_state', None)
    oauth_action = session.pop('oauth_action', 'login')
    
    if not state or not stored_state or not secrets.compare_digest(state, stored_state):
        logger.warning("State mismatch - possible CSRF attack")
        flash('Security verification failed. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
    code = request.args.get('code')
    if not code:
        logger.error("No authorization code received")
        flash('Authorization failed: No code received', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Exchange code for access token
        token_data = {
            'client_id': config.GITHUB_CLIENT_ID,
            'client_secret': config.GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': config.GITHUB_REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        
        token_response = requests.post(
            GITHUB_TOKEN_URL, 
            data=token_data, 
            headers=headers, 
            timeout=REQUEST_TIMEOUT
        )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code}")
            flash('Failed to authenticate with GitHub', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        if not access_token:
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        # Get user info from GitHub
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        user_response = requests.get(GITHUB_USER_URL, headers=user_headers, timeout=REQUEST_TIMEOUT)
        
        if user_response.status_code != 200:
            flash('Failed to get user information from GitHub', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        logger.info(f"User data received for: {user_data.get('login')}")
        
        # Get user email
        email = user_data.get('email')
        if not email:
            email_response = requests.get(GITHUB_EMAIL_URL, headers=user_headers, timeout=REQUEST_TIMEOUT)
            if email_response.status_code == 200:
                emails = email_response.json()
                for email_data in emails:
                    if email_data.get('primary') and email_data.get('verified'):
                        email = email_data.get('email')
                        break
                if not email:
                    for email_data in emails:
                        if email_data.get('verified'):
                            email = email_data.get('email')
                            break
        
        github_id = str(user_data['id'])
        
        # Handle linking to existing account
        if oauth_action == 'link' and current_user.is_authenticated:
            return _handle_link_github(github_id, access_token, user_data)
        
        # Find or create user
        user = User.query.filter_by(github_id=github_id).first()
        is_new_user = user is None
        
        if is_new_user:
            user = _create_github_user(user_data, github_id, access_token, email)
        else:
            _update_github_user(user, access_token, user_data, email)
        
        # Log the user in
        login_user(user, remember=True)
        logger.info(f"User {user.username} logged in successfully")
        flash(f'Welcome back, {user.username}!', 'success')
        
        # Send appropriate email
        if user.email:
            user_lang = user.language or 'en'
            if is_new_user:
                email_sender.send_welcome_email(user.email, user.username, user_lang)
            elif user.email_on_login:
                email_sender.send_login_email(user.email, user.username, user_lang)
        
        return redirect(url_for('main.dashboard'))
        
    except requests.exceptions.Timeout:
        logger.error("Request timeout during GitHub authentication")
        flash('Connection timeout. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error: {str(e)}")
        flash('Network error. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except Exception as e:
        logger.exception(f"Unexpected error during GitHub auth: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('main.login'))


def _handle_link_github(github_id: str, access_token: str, user_data: dict):
    """Handle linking GitHub to existing account"""
    if current_user.github_id:
        flash('Your account is already linked to GitHub', 'warning')
        return redirect(url_for('main.dashboard'))
    
    existing_github_user = User.query.filter_by(github_id=github_id).first()
    if existing_github_user:
        flash('This GitHub account is already linked to another user', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.github_id = github_id
    current_user.github_token = access_token
    if not current_user.avatar_url:
        current_user.avatar_url = user_data.get('avatar_url')
        current_user.avatar_source = 'github'
    
    db.session.commit()
    
    flash('GitHub account linked successfully!', 'success')
    if current_user.email:
        user_lang = current_user.language or 'en'
        email_sender.send_account_linked_email(
            current_user.email, 
            current_user.username, 
            'GitHub',
            user_lang
        )
    
    return redirect(url_for('main.dashboard'))


def _create_github_user(user_data: dict, github_id: str, access_token: str, email: str) -> User:
    """Create new user from GitHub data"""
    from models import SiteSettings
    
    # Check if signups are disabled
    if not SiteSettings.get('enable_signup', True):
        return None
    
    username = User.generate_unique_username(user_data['login'], 'gh')
    
    logger.info(f"Creating new user: {username}")
    user = User(
        username=username,
        email=email,
        github_id=github_id,
        github_token=access_token,
        avatar_url=user_data.get('avatar_url'),
        bio=user_data.get('bio'),
        avatar_source='github'
    )
    # Make first user an admin
    if SiteSettings.get('first_user_is_admin', False):
        user.is_admin = True
        SiteSettings.set('first_user_is_admin', False)
        logger.info(f"First user {username} set as admin")
    
    db.session.add(user)
    db.session.commit()
    
    logger.info(f"Created new user with ID: {user.id}")
    return user


def _update_github_user(user: User, access_token: str, user_data: dict, email: str):
    """Update existing GitHub user"""
    logger.info(f"Updating existing user: {user.username}")
    user.github_token = access_token
    if user.avatar_source == 'github':
        user.avatar_url = user_data.get('avatar_url')
    if not user.email and email:
        user.email = email
    db.session.commit()


@github_auth_bp.route('/auth/github/disconnect')
@login_required
def disconnect_github():
    """Disconnect GitHub account"""
    if not current_user.github_id:
        flash('No GitHub account is linked', 'warning')
        return redirect(url_for('main.dashboard'))
    
    if not current_user.gitlab_id and not current_user.bitbucket_id:
        flash('Cannot disconnect GitHub - you need at least one connected account', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.github_id = None
    current_user.github_token = None
    
    if current_user.avatar_source == 'github':
        if current_user.gitlab_id:
            current_user.avatar_source = 'gitlab'
        elif current_user.bitbucket_id:
            current_user.avatar_source = 'bitbucket'
        else:
            current_user.avatar_url = None
            current_user.avatar_source = None
    
    db.session.commit()
    
    # Send notification email
    if current_user.email:
        user_lang = current_user.language or 'en'
        email_sender.send_account_disconnected_email(
            current_user.email,
            current_user.username,
            'GitHub',
            user_lang
        )
    
    flash('GitHub account disconnected successfully', 'success')
    return redirect(url_for('main.dashboard'))

@github_auth_bp.route('/logout')
def logout():
    """Log out the current user"""
    if current_user.is_authenticated:
        username = current_user.username
        logout_user()
        
        # Clear all session data
        session.clear()
        
        flash(f'Goodbye {username}! You have been logged out successfully.', 'info')
    else:
        # Clear session anyway in case of stale data
        session.clear()
    
    # Force redirect to index
    response = redirect(url_for('main.index'))
    # Clear any cached login state
    response.delete_cookie('remember_token')
    response.delete_cookie('codeinsight_session')
    return response