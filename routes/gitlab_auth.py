# routes/gitlab_auth.py
import logging
import secrets
from urllib.parse import urlencode
from datetime import datetime, timedelta

import requests
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, login_required

from models import db, User
from config import config
from utils.email_sender import email_sender

logger = logging.getLogger("gitlab_auth")

gitlab_auth_bp = Blueprint('gitlab_auth', __name__)

# GitLab OAuth endpoints
GITLAB_AUTH_URL = 'https://gitlab.com/oauth/authorize'
GITLAB_TOKEN_URL = 'https://gitlab.com/oauth/token'
GITLAB_USER_URL = 'https://gitlab.com/api/v4/user'

# Request timeout
REQUEST_TIMEOUT = 15


@gitlab_auth_bp.route('/auth/gitlab')
def gitlab_login():
    """Redirect user to GitLab for authorization"""
    if not config.GITLAB_CLIENT_ID or not config.GITLAB_CLIENT_SECRET:
        flash('GitLab OAuth is not configured.', 'error')
        return redirect(url_for('main.login'))
    
    if current_user.is_authenticated and not request.args.get('link'):
        return redirect(url_for('main.dashboard'))
    
    state = secrets.token_urlsafe(32)
    session['gitlab_oauth_state'] = state
    session['gitlab_oauth_action'] = 'link' if request.args.get('link') else 'login'
    
    params = {
        'client_id': config.GITLAB_CLIENT_ID,
        'redirect_uri': config.GITLAB_REDIRECT_URI,
        'response_type': 'code',
        'state': state,
        'scope': 'read_user api read_repository'
    }
    
    auth_url = f"{GITLAB_AUTH_URL}?{urlencode(params)}"
    logger.info("Redirecting to GitLab OAuth")
    
    return redirect(auth_url)


@gitlab_auth_bp.route('/auth/gitlab/callback')
def gitlab_callback():
    """Handle GitLab OAuth callback"""
    return _handle_gitlab_callback()


@gitlab_auth_bp.route('/callback/gitlab')
def gitlab_callback_alternate():
    """Handle GitLab OAuth callback - alternate route"""
    return _handle_gitlab_callback()


def _handle_gitlab_callback():
    """Handle GitLab OAuth callback"""
    logger.info("GitLab callback received")
    
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        logger.error(f"GitLab OAuth error: {error} - {error_description}")
        flash(f'GitLab authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state (CSRF protection)
    state_from_url = request.args.get('state')
    state_from_session = session.pop('gitlab_oauth_state', None)
    oauth_action = session.pop('gitlab_oauth_action', 'login')
    
    if not state_from_url or not state_from_session:
        logger.warning("Missing state parameter")
        flash('Security verification failed. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
    if not secrets.compare_digest(state_from_url, state_from_session):
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
            'client_id': config.GITLAB_CLIENT_ID,
            'client_secret': config.GITLAB_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': config.GITLAB_REDIRECT_URI
        }
        
        token_response = requests.post(GITLAB_TOKEN_URL, data=token_data, timeout=REQUEST_TIMEOUT)
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code}")
            flash('Failed to authenticate with GitLab', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in', 7200)
        
        if not access_token:
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Get user info
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        user_response = requests.get(GITLAB_USER_URL, headers=user_headers, timeout=REQUEST_TIMEOUT)
        
        if user_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_response.status_code}")
            flash('Failed to get user information from GitLab', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        logger.info(f"User data received for: {user_data.get('username')}")
        
        gitlab_id = str(user_data['id'])
        
        # Handle linking to existing account
        if oauth_action == 'link' and current_user.is_authenticated:
            return _handle_link_gitlab(gitlab_id, access_token, refresh_token, token_expires_at, user_data)
        
        # Find or create user
        user = User.query.filter_by(gitlab_id=gitlab_id).first()
        is_new_user = user is None
        
        if is_new_user:
            user = _create_gitlab_user(user_data, gitlab_id, access_token, refresh_token, token_expires_at)
        else:
            _update_gitlab_user(user, access_token, refresh_token, token_expires_at, user_data)
        
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
        logger.error("Request timeout during GitLab authentication")
        flash('Connection timeout. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error: {str(e)}")
        flash('Network error. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except Exception as e:
        logger.exception(f"Unexpected error during GitLab auth: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('main.login'))


def _handle_link_gitlab(gitlab_id: str, access_token: str, refresh_token: str, 
                        token_expires_at: datetime, user_data: dict):
    """Handle linking GitLab to existing account"""
    if current_user.gitlab_id:
        flash('Your account is already linked to GitLab', 'warning')
        return redirect(url_for('main.dashboard'))
    
    existing_gitlab_user = User.query.filter_by(gitlab_id=gitlab_id).first()
    if existing_gitlab_user:
        flash('This GitLab account is already linked to another user', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.gitlab_id = gitlab_id
    current_user.gitlab_token = access_token
    current_user.gitlab_refresh_token = refresh_token
    current_user.gitlab_token_expires_at = token_expires_at
    
    if not current_user.avatar_url:
        current_user.avatar_url = user_data.get('avatar_url')
        current_user.avatar_source = 'gitlab'
    
    db.session.commit()
    
    flash('GitLab account linked successfully!', 'success')
    if current_user.email:
        user_lang = current_user.language or 'en'
        email_sender.send_account_linked_email(
            current_user.email,
            current_user.username,
            'GitLab',
            user_lang
        )
    
    return redirect(url_for('main.dashboard'))


def _create_gitlab_user(user_data: dict, gitlab_id: str, access_token: str, 
                        refresh_token: str, token_expires_at: datetime) -> User:
    """Create new user from GitLab data"""
    username = User.generate_unique_username(user_data.get('username'), 'gl')
    email = user_data.get('email')
    
    logger.info(f"Creating new user: {username}")
    user = User(
        username=username,
        email=email,
        gitlab_id=gitlab_id,
        gitlab_token=access_token,
        gitlab_refresh_token=refresh_token,
        gitlab_token_expires_at=token_expires_at,
        avatar_url=user_data.get('avatar_url'),
        bio=user_data.get('bio'),
        avatar_source='gitlab'
    )
    
    db.session.add(user)
    db.session.commit()
    
    logger.info(f"Created new user with ID: {user.id}")
    return user


def _update_gitlab_user(user: User, access_token: str, refresh_token: str, 
                        token_expires_at: datetime, user_data: dict):
    """Update existing GitLab user"""
    logger.info(f"Updating existing user: {user.username}")
    user.gitlab_token = access_token
    user.gitlab_refresh_token = refresh_token
    user.gitlab_token_expires_at = token_expires_at
    
    if user.avatar_source == 'gitlab':
        user.avatar_url = user_data.get('avatar_url')
    
    if not user.email and user_data.get('email'):
        user.email = user_data.get('email')
    
    db.session.commit()


@gitlab_auth_bp.route('/auth/gitlab/refresh')
@login_required
def refresh_gitlab_token():
    """Refresh GitLab access token"""
    if not current_user.gitlab_refresh_token:
        flash('No GitLab refresh token available', 'error')
        return redirect(url_for('main.dashboard'))
    
    try:
        logger.info(f"Refreshing GitLab token for user: {current_user.username}")
        
        token_data = {
            'client_id': config.GITLAB_CLIENT_ID,
            'client_secret': config.GITLAB_CLIENT_SECRET,
            'refresh_token': current_user.gitlab_refresh_token,
            'grant_type': 'refresh_token',
            'redirect_uri': config.GITLAB_REDIRECT_URI
        }
        
        token_response = requests.post(GITLAB_TOKEN_URL, data=token_data, timeout=REQUEST_TIMEOUT)
        
        if token_response.status_code != 200:
            logger.error(f"Token refresh failed: {token_response.status_code}")
            flash('Failed to refresh GitLab token', 'error')
            return redirect(url_for('main.dashboard'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in', 7200)
        
        if not access_token:
            flash('Failed to refresh GitLab token', 'error')
            return redirect(url_for('main.dashboard'))
        
        current_user.gitlab_token = access_token
        if refresh_token:
            current_user.gitlab_refresh_token = refresh_token
        current_user.gitlab_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        db.session.commit()
        logger.info("GitLab token refreshed successfully")
        flash('GitLab token refreshed successfully', 'success')
        
        return redirect(url_for('main.dashboard'))
        
    except Exception as e:
        logger.exception(f"Error refreshing token: {str(e)}")
        flash('Failed to refresh GitLab token', 'error')
        return redirect(url_for('main.dashboard'))


@gitlab_auth_bp.route('/auth/gitlab/disconnect')
@login_required
def disconnect_gitlab():
    """Disconnect GitLab account"""
    if not current_user.gitlab_id:
        flash('No GitLab account is linked', 'warning')
        return redirect(url_for('main.dashboard'))
    
    if not current_user.github_id and not current_user.bitbucket_id:
        flash('Cannot disconnect GitLab - you need at least one connected account', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.gitlab_id = None
    current_user.gitlab_token = None
    current_user.gitlab_refresh_token = None
    current_user.gitlab_token_expires_at = None
    
    if current_user.avatar_source == 'gitlab':
        if current_user.github_id:
            current_user.avatar_source = 'github'
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
            'GitLab',
            user_lang
        )
    
    flash('GitLab account disconnected successfully', 'success')
    return redirect(url_for('main.dashboard'))