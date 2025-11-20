# routes/github_auth.py
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, logout_user, login_required
import requests
from models import db, User
from config import config
from utils.email_sender import email_sender
import secrets

github_auth_bp = Blueprint('auth', __name__)

# GitHub OAuth endpoints
GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USER_URL = 'https://api.github.com/user'
GITHUB_EMAIL_URL = 'https://api.github.com/user/emails'

@github_auth_bp.route('/auth/github')
def github_login():
    """Redirect user to GitHub for authorization"""
    # Check if GitHub credentials are configured
    if not config.GITHUB_CLIENT_ID or not config.GITHUB_CLIENT_SECRET:
        flash('GitHub OAuth is not configured. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('main.login'))
    
    # If already authenticated and not linking, redirect to dashboard
    if current_user.is_authenticated and not request.args.get('link'):
        return redirect(url_for('main.dashboard'))
    
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['oauth_action'] = 'link' if request.args.get('link') else 'login'
    
    # Build the authorization URL
    params = {
        'client_id': config.GITHUB_CLIENT_ID,
        'redirect_uri': config.GITHUB_REDIRECT_URI,
        'scope': 'user:email read:user',
        'state': state,
        'allow_signup': 'true'
    }
    
    from urllib.parse import urlencode
    auth_url = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
    
    print(f"🔗 Redirecting to GitHub OAuth")
    print(f"   Client ID: {config.GITHUB_CLIENT_ID[:10]}...")
    print(f"   Redirect URI: {config.GITHUB_REDIRECT_URI}")
    
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
    print("📥 GitHub callback received!")
    
    # Check for errors from GitHub
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        print(f"❌ GitHub OAuth error: {error} - {error_description}")
        flash(f'GitHub authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state parameter
    state = request.args.get('state')
    stored_state = session.pop('oauth_state', None)
    oauth_action = session.pop('oauth_action', 'login')
    
    if not state or state != stored_state:
        print(f"❌ State mismatch")
        flash('Invalid state parameter. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
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
            'client_id': config.GITHUB_CLIENT_ID,
            'client_secret': config.GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': config.GITHUB_REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        
        token_response = requests.post(GITHUB_TOKEN_URL, data=token_data, headers=headers, timeout=10)
        
        if token_response.status_code != 200:
            print(f"❌ Token exchange failed: {token_response.status_code}")
            flash('Failed to authenticate with GitHub', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        if not access_token:
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        print("✅ Access token received")
        
        # Get user info from GitHub
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        user_response = requests.get(GITHUB_USER_URL, headers=user_headers, timeout=10)
        
        if user_response.status_code != 200:
            flash('Failed to get user information from GitHub', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        print(f"✅ User data received for: {user_data.get('login')}")
        
        # Get user email if not public
        email = user_data.get('email')
        if not email:
            email_response = requests.get(GITHUB_EMAIL_URL, headers=user_headers, timeout=10)
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
            if current_user.github_id:
                flash('Your account is already linked to GitHub', 'warning')
                return redirect(url_for('main.dashboard'))
            
            # Check if this GitHub account is already linked to another user
            existing_github_user = User.query.filter_by(github_id=github_id).first()
            if existing_github_user:
                flash('This GitHub account is already linked to another user', 'error')
                return redirect(url_for('main.dashboard'))
            
            # Link GitHub to current user
            current_user.github_id = github_id
            current_user.github_token = access_token
            if not current_user.avatar_url:
                current_user.avatar_url = user_data.get('avatar_url')
                current_user.avatar_source = 'github'
            db.session.commit()
            
            flash('GitHub account linked successfully!', 'success')
            if current_user.email:
                email_sender.send_email(
                    to_email=current_user.email,
                    subject='✅ GitHub Account Linked',
                    html_content=f"Hello {current_user.username}, your GitHub account has been successfully linked!"
                )
            return redirect(url_for('main.dashboard'))
        
        # Find user by GitHub ID
        user = User.query.filter_by(github_id=github_id).first()
        
        if not user:
            # Create unique username
            base_username = user_data['login']
            username = base_username
            counter = 1
            
            while User.query.filter_by(username=username).first():
                username = f"{base_username}_gh{counter}"
                counter += 1
            
            # Create new user
            print(f"✨ Creating new user: {username}")
            user = User(
                username=username,
                email=email,
                github_id=github_id,
                github_token=access_token,
                avatar_url=user_data.get('avatar_url'),
                bio=user_data.get('bio'),
                avatar_source='github'
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
            user.github_token = access_token
            if user.avatar_source == 'github':
                user.avatar_url = user_data.get('avatar_url')
            if not user.email and email:
                user.email = email
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

@github_auth_bp.route('/auth/github/disconnect')
@login_required
def disconnect_github():
    """Disconnect GitHub account"""
    if not current_user.github_id:
        flash('No GitHub account is linked', 'warning')
        return redirect(url_for('main.dashboard'))
    
    # Check if user has at least one OAuth provider
    if not current_user.gitlab_id:
        flash('Cannot disconnect GitHub - you need at least one connected account', 'error')
        return redirect(url_for('main.dashboard'))
    
    current_user.github_id = None
    current_user.github_token = None
    
    if current_user.avatar_source == 'github':
        if current_user.gitlab_id:
            current_user.avatar_source = 'gitlab'
        else:
            current_user.avatar_url = None
            current_user.avatar_source = None
    
    db.session.commit()
    flash('GitHub account disconnected successfully', 'success')
    return redirect(url_for('main.dashboard'))

@github_auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user"""
    username = current_user.username
    logout_user()
    flash(f'Goodbye {username}! You have been logged out successfully.', 'info')
    return redirect(url_for('main.index'))