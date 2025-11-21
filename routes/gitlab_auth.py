# routes/gitlab_auth.py
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, login_required
import requests
import secrets
from datetime import datetime, timedelta
from models import db, User
from config import config
from utils.email_sender import email_sender

gitlab_auth_bp = Blueprint('gitlab_auth', __name__)

# GitLab OAuth endpoints
GITLAB_AUTH_URL = 'https://gitlab.com/oauth/authorize'
GITLAB_TOKEN_URL = 'https://gitlab.com/oauth/token'
GITLAB_USER_URL = 'https://gitlab.com/api/v4/user'

@gitlab_auth_bp.route('/auth/gitlab')
def gitlab_login():
    """Redirect user to GitLab for authorization"""
    # Check if GitLab credentials are configured
    if not config.GITLAB_CLIENT_ID or not config.GITLAB_CLIENT_SECRET:
        flash('GitLab OAuth is not configured. Please set GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('main.login'))
    
    # If already authenticated and not linking, redirect to dashboard
    if current_user.is_authenticated and not request.args.get('link'):
        return redirect(url_for('main.dashboard'))
    
    # Generate state token
    state = secrets.token_urlsafe(32)
    session['gitlab_oauth_state'] = state
    session['gitlab_oauth_action'] = 'link' if request.args.get('link') else 'login'
    
    # Build the authorization URL
    params = {
        'client_id': config.GITLAB_CLIENT_ID,
        'redirect_uri': config.GITLAB_REDIRECT_URI,
        'response_type': 'code',
        'state': state,
        'scope': 'read_user api read_repository'
    }
    
    from urllib.parse import urlencode
    auth_url = f"{GITLAB_AUTH_URL}?{urlencode(params)}"
    
    print(f"🔗 Redirecting to GitLab OAuth")
    print(f"   Client ID: {config.GITLAB_CLIENT_ID[:10]}...")
    print(f"   Redirect URI: {config.GITLAB_REDIRECT_URI}")
    
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
    print("📥 GitLab callback received!")
    
    # Check for errors
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        print(f"❌ GitLab OAuth error: {error} - {error_description}")
        flash(f'GitLab authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state
    state_from_url = request.args.get('state')
    state_from_session = session.pop('gitlab_oauth_state', None)
    oauth_action = session.pop('gitlab_oauth_action', 'login')
    
    if not state_from_url or not state_from_session or state_from_url != state_from_session:
        print("❌ State mismatch or missing")
        flash('Invalid state parameter. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
    print("✅ State verified successfully")
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        print("❌ No authorization code received")
        flash('Authorization failed: No code received', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Exchange code for access token
        print("🔄 Exchanging code for access token...")
        token_data = {
            'client_id': config.GITLAB_CLIENT_ID,
            'client_secret': config.GITLAB_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': config.GITLAB_REDIRECT_URI
        }
        
        token_response = requests.post(GITLAB_TOKEN_URL, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            print(f"❌ Token exchange failed: {token_response.status_code}")
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
        
        print("✅ Access token received")
        
        # Calculate token expiration
        token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Get user info
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        user_response = requests.get(GITLAB_USER_URL, headers=user_headers, timeout=10)
        
        if user_response.status_code != 200:
            print(f"❌ Failed to fetch user info: {user_response.status_code}")
            flash('Failed to get user information from GitLab', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        print(f"✅ User data received for: {user_data.get('username')}")
        
        gitlab_id = str(user_data['id'])
        
        # Handle linking to existing account
        if oauth_action == 'link' and current_user.is_authenticated:
            if current_user.gitlab_id:
                flash('Your account is already linked to GitLab', 'warning')
                return redirect(url_for('main.dashboard'))
            
            # Check if this GitLab account is already linked to another user
            existing_gitlab_user = User.query.filter_by(gitlab_id=gitlab_id).first()
            if existing_gitlab_user:
                flash('This GitLab account is already linked to another user', 'error')
                return redirect(url_for('main.dashboard'))
            
            # Link GitLab to current user
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
                email_sender.send_email(
                    to_email=current_user.email,
                    subject='✅ GitLab Account Linked',
                    html_content=f"Hello {current_user.username}, your GitLab account has been successfully linked!"
                )
            return redirect(url_for('main.dashboard'))
        
        # Find user by GitLab ID
        user = User.query.filter_by(gitlab_id=gitlab_id).first()
        
        if not user:
            # Create unique username
            base_username = user_data.get('username')
            username = base_username
            counter = 1
            
            while User.query.filter_by(username=username).first():
                username = f"{base_username}_gl{counter}"
                counter += 1
            
            email = user_data.get('email')
            
            # Create new user
            print(f"✨ Creating new user: {username}")
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
            
            if user.email:
                email_sender.send_email(
                    to_email=user.email,
                    subject='✅ Welcome to CodeInsight',
                    html_content=f"Hello {user.username}, welcome to CodeInsight!"
                )
            
            print(f"✅ Created new user with ID: {user.id}")
        else:
            # Update existing user
            print(f"🔄 Updating existing user: {user.username}")
            user.gitlab_token = access_token
            user.gitlab_refresh_token = refresh_token
            user.gitlab_token_expires_at = token_expires_at
            
            if user.avatar_source == 'gitlab':
                user.avatar_url = user_data.get('avatar_url')
            
            if not user.email and user_data.get('email'):
                user.email = user_data.get('email')
            
            db.session.commit()
        
        # Log the user in
        login_user(user, remember=True)
        print(f"🎉 User {user.username} logged in successfully")
        flash(f'Welcome back, {user.username}!', 'success')
        
        if user.email:
            email_sender.send_email(
                to_email=user.email,
                subject='✅ New Login',
                html_content=f"Welcome back, {user.username}"
            )
        
        return redirect(url_for('main.dashboard'))
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error: {str(e)}")
        flash('Network error. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('main.login'))

@gitlab_auth_bp.route('/auth/gitlab/refresh')
@login_required
def refresh_gitlab_token():
    """Refresh GitLab access token"""
    if not current_user.gitlab_refresh_token:
        flash('No GitLab refresh token available', 'error')
        return redirect(url_for('main.dashboard'))
    
    try:
        print(f"🔄 Refreshing GitLab token for user: {current_user.username}")
        
        token_data = {
            'client_id': config.GITLAB_CLIENT_ID,
            'client_secret': config.GITLAB_CLIENT_SECRET,
            'refresh_token': current_user.gitlab_refresh_token,
            'grant_type': 'refresh_token',
            'redirect_uri': config.GITLAB_REDIRECT_URI
        }
        
        token_response = requests.post(GITLAB_TOKEN_URL, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            print(f"❌ Token refresh failed: {token_response.status_code}")
            flash('Failed to refresh GitLab token', 'error')
            return redirect(url_for('main.dashboard'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in', 7200)
        
        if not access_token:
            flash('Failed to refresh GitLab token', 'error')
            return redirect(url_for('main.dashboard'))
        
        # Update tokens
        current_user.gitlab_token = access_token
        if refresh_token:
            current_user.gitlab_refresh_token = refresh_token
        current_user.gitlab_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        db.session.commit()
        print("✅ GitLab token refreshed successfully")
        flash('GitLab token refreshed successfully', 'success')
        
        return redirect(url_for('main.dashboard'))
        
    except Exception as e:
        print(f"❌ Error refreshing token: {str(e)}")
        flash('Failed to refresh GitLab token', 'error')
        return redirect(url_for('main.dashboard'))

@gitlab_auth_bp.route('/auth/gitlab/disconnect')
@login_required
def disconnect_gitlab():
    """Disconnect GitLab account"""
    if not current_user.gitlab_id:
        flash('No GitLab account is linked', 'warning')
        return redirect(url_for('main.dashboard'))
    
    # Check if user has at least one OAuth provider
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
    flash('GitLab account disconnected successfully', 'success')
    return redirect(url_for('main.dashboard'))