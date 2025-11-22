# routes/bitbucket_auth.py
import logging
import secrets
from urllib.parse import urlencode

import requests
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, login_required

from models import db, User
from config import config
from utils.email_sender import email_sender

logger = logging.getLogger("bitbucket_auth")

bitbucket_auth_bp = Blueprint('bitbucket_auth', __name__)

# Bitbucket OAuth endpoints
BITBUCKET_AUTH_URL = 'https://bitbucket.org/site/oauth2/authorize'
BITBUCKET_TOKEN_URL = 'https://bitbucket.org/site/oauth2/access_token'
BITBUCKET_USER_URL = 'https://api.bitbucket.org/2.0/user'
BITBUCKET_EMAIL_URL = 'https://api.bitbucket.org/2.0/user/emails'

# Request timeout
REQUEST_TIMEOUT = 15


@bitbucket_auth_bp.route('/auth/bitbucket')
def bitbucket_login():
    """Redirect user to Bitbucket for authorization"""
    if not config.BITBUCKET_CLIENT_ID or not config.BITBUCKET_CLIENT_SECRET:
        flash('Bitbucket OAuth is not configured.', 'error')
        return redirect(url_for('main.login'))
    
    if current_user.is_authenticated and not request.args.get('link'):
        return redirect(url_for('main.dashboard'))
    
    state = secrets.token_urlsafe(32)
    session['bitbucket_oauth_state'] = state
    session['bitbucket_oauth_action'] = 'link' if request.args.get('link') else 'login'
    
    params = {
        'client_id': config.BITBUCKET_CLIENT_ID,
        'redirect_uri': config.BITBUCKET_REDIRECT_URI,
        'response_type': 'code',
        'state': state
    }
    
    auth_url = f"{BITBUCKET_AUTH_URL}?{urlencode(params)}"
    logger.info("Redirecting to Bitbucket OAuth")
    
    return redirect(auth_url)


@bitbucket_auth_bp.route('/auth/bitbucket/callback')
def bitbucket_callback():
    """Handle Bitbucket OAuth callback"""
    return _handle_bitbucket_callback()


@bitbucket_auth_bp.route('/callback/bitbucket')
def bitbucket_callback_alternate():
    """Handle Bitbucket OAuth callback - alternate route"""
    return _handle_bitbucket_callback()


def _handle_bitbucket_callback():
    """Handle Bitbucket OAuth callback"""
    logger.info("Bitbucket callback received")
    
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        logger.error(f"Bitbucket OAuth error: {error} - {error_description}")
        flash(f'Bitbucket authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state (CSRF protection)
    state_from_url = request.args.get('state')
    state_from_session = session.pop('bitbucket_oauth_state', None)
    oauth_action = session.pop('bitbucket_oauth_action', 'login')
    
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
            'client_id': config.BITBUCKET_CLIENT_ID,
            'client_secret': config.BITBUCKET_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': config.BITBUCKET_REDIRECT_URI
        }
        
        token_response = requests.post(
            BITBUCKET_TOKEN_URL, 
            data=token_data, 
            auth=(config.BITBUCKET_CLIENT_ID, config.BITBUCKET_CLIENT_SECRET), 
            timeout=REQUEST_TIMEOUT
        )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code}")
            flash('Failed to authenticate with Bitbucket', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        
        if not access_token:
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        # Get user info from Bitbucket
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        user_response = requests.get(BITBUCKET_USER_URL, headers=user_headers, timeout=REQUEST_TIMEOUT)
        
        if user_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_response.status_code}")
            flash('Failed to get user information from Bitbucket', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        logger.info(f"User data received for: {user_data.get('username')}")
        
        bitbucket_id = str(user_data['uuid'])
        
        # Get user email
        email = _get_bitbucket_email(user_headers)
        
        # Handle linking to existing account
        if oauth_action == 'link' and current_user.is_authenticated:
            return _handle_link_bitbucket(bitbucket_id, access_token, refresh_token, user_data)
        
        # Find or create user
        user = User.query.filter_by(bitbucket_id=bitbucket_id).first()
        is_new_user = user is None
        
        if is_new_user:
            user = _create_bitbucket_user(user_data, bitbucket_id, access_token, refresh_token, email)
        else:
            _update_bitbucket_user(user, access_token, refresh_token, user_data, email)
        
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
        logger.error("Request timeout during Bitbucket authentication")
        flash('Connection timeout. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error: {str(e)}")
        flash('Network error. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except Exception as e:
        logger.exception(f"Unexpected error during Bitbucket auth: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('main.login'))


def _get_bitbucket_email(headers: dict) -> str:
    """Get primary email from Bitbucket"""
    try:
        email_response = requests.get(BITBUCKET_EMAIL_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        if email_response.status_code == 200:
            emails_data = email_response.json()
            # Try to get primary confirmed email first
            for email_data in emails_data.get('values', []):
                if email_data.get('is_primary') and email_data.get('is_confirmed'):
                    return email_data.get('email')
            # Fallback to any confirmed email
            for email_data in emails_data.get('values', []):
                if email_data.get('is_confirmed'):
                    return email_data.get('email')
    except Exception as e:
        logger.warning(f"Could not fetch Bitbucket email: {e}")
    return None


def _handle_link_bitbucket(bitbucket_id: str, access_token: str, refresh_token: str, user_data: dict):
    """Handle linking Bitbucket to existing account"""
    if current_user.bitbucket_id:
        flash('Your account is already linked to Bitbucket', 'warning')
        return redirect(url_for('main.dashboard'))
    
    existing_bitbucket_user = User.query.filter_by(bitbucket_id=bitbucket_id).first()
    if existing_bitbucket_user:
        flash('This Bitbucket account is already linked to another user', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.bitbucket_id = bitbucket_id
    current_user.bitbucket_token = access_token
    current_user.bitbucket_refresh_token = refresh_token
    
    if not current_user.avatar_url:
        current_user.avatar_url = user_data.get('links', {}).get('avatar', {}).get('href')
        current_user.avatar_source = 'bitbucket'
    
    db.session.commit()
    
    flash('Bitbucket account linked successfully!', 'success')
    if current_user.email:
        user_lang = current_user.language or 'en'
        email_sender.send_account_linked_email(
            current_user.email,
            current_user.username,
            'Bitbucket',
            user_lang
        )
    
    return redirect(url_for('main.dashboard'))


def _create_bitbucket_user(user_data: dict, bitbucket_id: str, access_token: str, 
                           refresh_token: str, email: str) -> User:
    """Create new user from Bitbucket data"""
    username = User.generate_unique_username(user_data.get('username'), 'bb')
    
    logger.info(f"Creating new user: {username}")
    user = User(
        username=username,
        email=email,
        bitbucket_id=bitbucket_id,
        bitbucket_token=access_token,
        bitbucket_refresh_token=refresh_token,
        avatar_url=user_data.get('links', {}).get('avatar', {}).get('href'),
        avatar_source='bitbucket'
    )
    
    db.session.add(user)
    db.session.commit()
    
    logger.info(f"Created new user with ID: {user.id}")
    return user


def _update_bitbucket_user(user: User, access_token: str, refresh_token: str, 
                           user_data: dict, email: str):
    """Update existing Bitbucket user"""
    logger.info(f"Updating existing user: {user.username}")
    user.bitbucket_token = access_token
    user.bitbucket_refresh_token = refresh_token
    
    if user.avatar_source == 'bitbucket':
        user.avatar_url = user_data.get('links', {}).get('avatar', {}).get('href')
    
    if not user.email and email:
        user.email = email
    
    db.session.commit()


@bitbucket_auth_bp.route('/auth/bitbucket/disconnect')
@login_required
def disconnect_bitbucket():
    """Disconnect Bitbucket account"""
    if not current_user.bitbucket_id:
        flash('No Bitbucket account is linked', 'warning')
        return redirect(url_for('main.dashboard'))
    
    if not current_user.github_id and not current_user.gitlab_id:
        flash('Cannot disconnect Bitbucket - you need at least one connected account', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.bitbucket_id = None
    current_user.bitbucket_token = None
    current_user.bitbucket_refresh_token = None
    
    if current_user.avatar_source == 'bitbucket':
        if current_user.github_id:
            current_user.avatar_source = 'github'
        elif current_user.gitlab_id:
            current_user.avatar_source = 'gitlab'
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
            'Bitbucket',
            user_lang
        )
    
    flash('Bitbucket account disconnected successfully', 'success')
    return redirect(url_for('main.dashboard'))