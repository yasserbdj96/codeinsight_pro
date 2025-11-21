# routes/bitbucket_auth.py
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, login_required
import requests
import secrets
from datetime import datetime
from models import db, User
from config import config
from utils.email_sender import email_sender

bitbucket_auth_bp = Blueprint('bitbucket_auth', __name__)

# Bitbucket OAuth endpoints
BITBUCKET_AUTH_URL = 'https://bitbucket.org/site/oauth2/authorize'
BITBUCKET_TOKEN_URL = 'https://bitbucket.org/site/oauth2/access_token'
BITBUCKET_USER_URL = 'https://api.bitbucket.org/2.0/user'
BITBUCKET_EMAIL_URL = 'https://api.bitbucket.org/2.0/user/emails'

@bitbucket_auth_bp.route('/auth/bitbucket')
def bitbucket_login():
    """Redirect user to Bitbucket for authorization"""
    # Check if Bitbucket credentials are configured
    if not config.BITBUCKET_CLIENT_ID or not config.BITBUCKET_CLIENT_SECRET:
        flash('Bitbucket OAuth is not configured. Please set BITBUCKET_CLIENT_ID and BITBUCKET_CLIENT_SECRET environment variables.', 'error')
        return redirect(url_for('main.login'))
    
    # If already authenticated and not linking, redirect to dashboard
    if current_user.is_authenticated and not request.args.get('link'):
        return redirect(url_for('main.dashboard'))
    
    # Generate state token
    state = secrets.token_urlsafe(32)
    session['bitbucket_oauth_state'] = state
    session['bitbucket_oauth_action'] = 'link' if request.args.get('link') else 'login'
    
    # Build the authorization URL
    params = {
        'client_id': config.BITBUCKET_CLIENT_ID,
        'redirect_uri': config.BITBUCKET_REDIRECT_URI,
        'response_type': 'code',
        'state': state
    }
    
    from urllib.parse import urlencode
    auth_url = f"{BITBUCKET_AUTH_URL}?{urlencode(params)}"
    
    print(f"🔗 Redirecting to Bitbucket OAuth")
    print(f"   Client ID: {config.BITBUCKET_CLIENT_ID[:10]}...")
    print(f"   Redirect URI: {config.BITBUCKET_REDIRECT_URI}")
    
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
    print("📥 Bitbucket callback received!")
    
    # Check for errors
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        print(f"❌ Bitbucket OAuth error: {error} - {error_description}")
        flash(f'Bitbucket authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state
    state_from_url = request.args.get('state')
    state_from_session = session.pop('bitbucket_oauth_state', None)
    oauth_action = session.pop('bitbucket_oauth_action', 'login')
    
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
            'client_id': config.BITBUCKET_CLIENT_ID,
            'client_secret': config.BITBUCKET_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': config.BITBUCKET_REDIRECT_URI
        }
        
        token_response = requests.post(BITBUCKET_TOKEN_URL, data=token_data, auth=(config.BITBUCKET_CLIENT_ID, config.BITBUCKET_CLIENT_SECRET), timeout=10)
        
        if token_response.status_code != 200:
            print(f"❌ Token exchange failed: {token_response.status_code}")
            flash('Failed to authenticate with Bitbucket', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        
        if not access_token:
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        print("✅ Access token received")
        
        # Get user info from Bitbucket
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        user_response = requests.get(BITBUCKET_USER_URL, headers=user_headers, timeout=10)
        
        if user_response.status_code != 200:
            print(f"❌ Failed to fetch user info: {user_response.status_code}")
            flash('Failed to get user information from Bitbucket', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        print(f"✅ User data received for: {user_data.get('username')}")
        
        bitbucket_id = str(user_data['uuid'])
        
        # Get user email
        email_response = requests.get(BITBUCKET_EMAIL_URL, headers=user_headers, timeout=10)
        email = None
        if email_response.status_code == 200:
            emails_data = email_response.json()
            for email_data in emails_data.get('values', []):
                if email_data.get('is_primary') and email_data.get('is_confirmed'):
                    email = email_data.get('email')
                    break
            if not email:
                for email_data in emails_data.get('values', []):
                    if email_data.get('is_confirmed'):
                        email = email_data.get('email')
                        break
        
        # Handle linking to existing account
        if oauth_action == 'link' and current_user.is_authenticated:
            if current_user.bitbucket_id:
                flash('Your account is already linked to Bitbucket', 'warning')
                return redirect(url_for('main.dashboard'))
            
            # Check if this Bitbucket account is already linked to another user
            existing_bitbucket_user = User.query.filter_by(bitbucket_id=bitbucket_id).first()
            if existing_bitbucket_user:
                flash('This Bitbucket account is already linked to another user', 'error')
                return redirect(url_for('main.dashboard'))
            
            # Link Bitbucket to current user
            current_user.bitbucket_id = bitbucket_id
            current_user.bitbucket_token = access_token
            current_user.bitbucket_refresh_token = refresh_token
            
            if not current_user.avatar_url:
                current_user.avatar_url = user_data.get('links', {}).get('avatar', {}).get('href')
                current_user.avatar_source = 'bitbucket'
            
            db.session.commit()
            
            flash('Bitbucket account linked successfully!', 'success')
            if current_user.email:
                email_sender.send_email(
                    to_email=current_user.email,
                    subject='✅ Bitbucket Account Linked',
                    html_content=f"Hello {current_user.username}, your Bitbucket account has been successfully linked!"
                )
            return redirect(url_for('main.dashboard'))
        
        # Find user by Bitbucket ID
        user = User.query.filter_by(bitbucket_id=bitbucket_id).first()
        
        if not user:
            # Create unique username
            base_username = user_data.get('username')
            username = base_username
            counter = 1
            
            while User.query.filter_by(username=username).first():
                username = f"{base_username}_bb{counter}"
                counter += 1
            
            # Create new user
            print(f"✨ Creating new user: {username}")
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
            user.bitbucket_token = access_token
            user.bitbucket_refresh_token = refresh_token
            
            if user.avatar_source == 'bitbucket':
                user.avatar_url = user_data.get('links', {}).get('avatar', {}).get('href')
            
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

@bitbucket_auth_bp.route('/auth/bitbucket/disconnect')
@login_required
def disconnect_bitbucket():
    """Disconnect Bitbucket account"""
    if not current_user.bitbucket_id:
        flash('No Bitbucket account is linked', 'warning')
        return redirect(url_for('main.dashboard'))
    
    # Check if user has at least one OAuth provider
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
    flash('Bitbucket account disconnected successfully', 'success')
    return redirect(url_for('main.dashboard'))