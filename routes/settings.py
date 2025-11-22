# routes/settings.py
import logging
import re
import base64
from io import BytesIO
import requests
import os
from werkzeug.utils import secure_filename
from PIL import Image
import uuid


from flask import Blueprint, request, jsonify, session, url_for
from flask_login import login_required, current_user

from models import db, User
from utils.email_sender import email_sender
from lang import language_manager

logger = logging.getLogger("settings")

settings_bp = Blueprint('settings', __name__, url_prefix='/api/settings')

# Add these constants after the existing ones
AVATAR_UPLOAD_FOLDER = 'static/uploads/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
AVATAR_SIZES = {
    'small': (64, 64),
    'medium': (128, 128),
    'large': (256, 256)
}

# Ensure upload directory exists
os.makedirs(AVATAR_UPLOAD_FOLDER, exist_ok=True)

def get_translated_text(key, **kwargs):
    """Helper function to get translated text"""
    language = session.get('language', 'en')
    return language_manager.get_text(key, language=language, **kwargs)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_avatar_filename(user_id, extension):
    """Generate unique filename for avatar"""
    unique_id = uuid.uuid4().hex[:8]
    return f"avatar_{user_id}_{unique_id}.{extension}"

def process_and_save_avatar(image_file, user_id):
    """Process avatar image and save in multiple sizes"""
    try:
        # Open image
        img = Image.open(image_file)
        
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        
        # Get file extension
        extension = image_file.filename.rsplit('.', 1)[1].lower()
        base_filename = generate_avatar_filename(user_id, extension)
        
        # Save different sizes
        saved_files = {}
        for size_name, dimensions in AVATAR_SIZES.items():
            # Resize image
            resized_img = img.resize(dimensions, Image.Resampling.LANCZOS)
            
            # Create filename for this size
            if size_name == 'large':
                filename = base_filename  # Large is the default
            else:
                name_without_ext = base_filename.rsplit('.', 1)[0]
                filename = f"{name_without_ext}_{size_name}.{extension}"
            
            filepath = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
            resized_img.save(filepath, optimize=True, quality=85)
            saved_files[size_name] = filename
        
        return saved_files
        
    except Exception as e:
        logger.error(f"Error processing avatar: {e}")
        return None

def delete_old_avatars(user_id):
    """Delete old avatar files for user"""
    try:
        pattern = f"avatar_{user_id}_"
        for filename in os.listdir(AVATAR_UPLOAD_FOLDER):
            if filename.startswith(pattern):
                filepath = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
                if os.path.isfile(filepath):
                    os.remove(filepath)
    except Exception as e:
        logger.error(f"Error deleting old avatars: {e}")

def get_avatar_url(filename, size='large'):
    """Get URL for avatar file"""
    if not filename:
        return None
    
    # If filename already has a size suffix, use it as is
    if any(f"_{size_name}." in filename for size_name in AVATAR_SIZES.keys()):
        return url_for('static', filename=f'uploads/avatars/{filename}')
    
    # Otherwise, construct the appropriate filename based on requested size
    if size == 'large':
        return url_for('static', filename=f'uploads/avatars/{filename}')
    else:
        name_without_ext = filename.rsplit('.', 1)[0]
        extension = filename.rsplit('.', 1)[1]
        sized_filename = f"{name_without_ext}_{size}.{extension}"
        return url_for('static', filename=f'uploads/avatars/{sized_filename}')

# Constants
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2MB
ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]{3,30}$')
URL_REGEX = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')


@settings_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    return jsonify({
        'success': True,
        'user': current_user.to_dict(include_sensitive=True),
        'avatar_sources': current_user.get_available_avatar_sources()
    })


@settings_bp.route('/profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile (bio, website, location)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    try:
        # Update bio
        if 'bio' in data:
            bio = data['bio']
            if bio and len(bio) > 500:
                return jsonify({'success': False, 'error': 'Bio must be under 500 characters'}), 400
            current_user.bio = bio.strip() if bio else None
        
        # Update website
        if 'website' in data:
            website = data['website']
            if website:
                if not URL_REGEX.match(website):
                    return jsonify({'success': False, 'error': 'Invalid website URL'}), 400
                if len(website) > 255:
                    return jsonify({'success': False, 'error': 'Website URL too long'}), 400
            current_user.website = website.strip() if website else None
        
        # Update location
        if 'location' in data:
            location = data['location']
            if location and len(location) > 100:
                return jsonify({'success': False, 'error': 'Location must be under 100 characters'}), 400
            current_user.location = location.strip() if location else None
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': current_user.to_dict(include_sensitive=True)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating profile: {e}")
        return jsonify({'success': False, 'error': 'Failed to update profile'}), 500


@settings_bp.route('/username', methods=['POST'])
@login_required
def change_username():
    """Change username (7 day cooldown)"""
    data = request.get_json()
    
    if not data or 'username' not in data:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    
    new_username = data['username'].strip()
    
    # Validate username format
    if not USERNAME_REGEX.match(new_username):
        return jsonify({
            'success': False, 
            'error': 'Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens'
        }), 400
    
    # Check if same as current
    if new_username == current_user.username:
        return jsonify({'success': False, 'error': 'This is already your username'}), 400
    
    # Check cooldown
    if not current_user.can_change_username():
        days = current_user.days_until_username_change()
        return jsonify({
            'success': False, 
            'error': f'You can change your username in {days} day(s)'
        }), 400
    
    # Check availability
    if User.username_exists(new_username):
        return jsonify({'success': False, 'error': 'Username already taken'}), 400
    
    try:
        old_username = current_user.username
        success, message = current_user.change_username(new_username)
        
        if not success:
            return jsonify({'success': False, 'error': message}), 400
        
        db.session.commit()
        
        # Send notification email
        if current_user.email and current_user.email_on_login:
            # Get translated subject and content
            subject = get_translated_text('email.username_changed_subject')
            heading = get_translated_text('email.username_changed')
            content_text = get_translated_text('email.username_changed_from_to', old_username=old_username, new_username=new_username)
            security_notice = get_translated_text('email.if_you_didnt_make_this_change')
            content = f'''<h2>{heading}</h2>
            <p>{content_text}</p>
            <p>{security_notice}</p>'''
            email_sender.send_email(current_user.email, subject, content)
        
        return jsonify({
            'success': True,
            'message': 'Username changed successfully',
            'username': new_username,
            'can_change_again': current_user.can_change_username(),
            'days_until_change': current_user.days_until_username_change()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error changing username: {e}")
        return jsonify({'success': False, 'error': 'Failed to change username'}), 500


@settings_bp.route('/email/request-change', methods=['POST'])
@login_required
def request_email_change():
    """Request email change - sends confirmation code"""
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    new_email = data['email'].strip().lower()
    
    # Validate email format
    email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    if not email_regex.match(new_email):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    # Check if same as current
    if new_email == current_user.email:
        return jsonify({'success': False, 'error': 'This is already your email'}), 400
    
    # Check if email is already in use
    if User.email_exists(new_email):
        return jsonify({'success': False, 'error': 'Email already in use'}), 400
    
    try:
        # Generate token and send email
        token = current_user.generate_email_change_token(new_email)
        db.session.commit()
        
        # Create 6-digit code from token
        code = token[:6].upper()
        
        # Send confirmation email to NEW email
        email_sender.send_email(
            new_email,
            get_translated_text('email.change_verification_subject'),
            f'''
            <h2>{get_translated_text('email.change_verification_heading')}</h2>
            <p>{get_translated_text('email.change_verification_description')}</p>
            <p>{get_translated_text('email.your_verification_code')}</p>
            <div style="background: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                {code}
            </div>
            <p>{get_translated_text('email.code_expires_in')}</p>
            <p>{get_translated_text('email.if_not_requested')}</p>
            '''
        )
        
        # Also notify current email
        if current_user.email:
            email_sender.send_email(
                current_user.email,
                get_translated_text('email.change_requested_subject'),
                f'''
                <h2>{get_translated_text('email.change_requested_heading')}</h2>
                <p>{get_translated_text('email.change_requested_description', new_email=new_email)}</p>
                <p>{get_translated_text('email.secure_account_warning')}</p>
                '''
            )
        
        return jsonify({
            'success': True,
            'message': f'Verification code sent to {new_email}'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error requesting email change: {e}")
        return jsonify({'success': False, 'error': 'Failed to send verification code'}), 500


@settings_bp.route('/email/verify', methods=['POST'])
@login_required
def verify_email_change():
    """Verify email change with code"""
    data = request.get_json()
    
    if not data or 'code' not in data:
        return jsonify({'success': False, 'error': 'Verification code is required'}), 400
    
    code = data['code'].strip().upper()
    
    if not current_user.email_change_token:
        return jsonify({'success': False, 'error': 'No pending email change'}), 400
    
    # Check if code matches first 6 chars of token
    expected_code = current_user.email_change_token[:6].upper()
    
    if code != expected_code:
        return jsonify({'success': False, 'error': 'Invalid verification code'}), 400
    
    try:
        success, message = current_user.verify_email_change_token(current_user.email_change_token)
        
        if not success:
            return jsonify({'success': False, 'error': message}), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Email changed successfully',
            'email': current_user.email
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error verifying email change: {e}")
        return jsonify({'success': False, 'error': 'Failed to verify email change'}), 500


@settings_bp.route('/avatar/source', methods=['POST'])
@login_required
def change_avatar_source():
    """Change avatar source (github, gitlab, bitbucket, custom, letter)"""
    data = request.get_json()
    
    if not data or 'source' not in data:
        return jsonify({'success': False, 'error': 'Avatar source is required'}), 400
    
    source = data['source']
    valid_sources = ['github', 'gitlab', 'bitbucket', 'custom', 'letter']
    
    if source not in valid_sources:
        return jsonify({'success': False, 'error': 'Invalid avatar source'}), 400
    
    # Validate source is available
    if source == 'github' and not current_user.has_github():
        return jsonify({'success': False, 'error': 'GitHub not connected'}), 400
    if source == 'gitlab' and not current_user.has_gitlab():
        return jsonify({'success': False, 'error': 'GitLab not connected'}), 400
    if source == 'bitbucket' and not current_user.has_bitbucket():
        return jsonify({'success': False, 'error': 'Bitbucket not connected'}), 400
    if source == 'custom' and not current_user.custom_avatar:
        return jsonify({'success': False, 'error': 'No custom avatar uploaded'}), 400
    
    try:
        current_user.avatar_source = source
        # Fetch fresh avatar URL from the provider's API
        if source == 'github' and current_user.has_github():
            avatar_url = fetch_github_avatar(current_user.github_token)
            if avatar_url:
                current_user.avatar_url = avatar_url
                
        elif source == 'gitlab' and current_user.has_gitlab():
            avatar_url = fetch_gitlab_avatar(current_user.gitlab_token)
            if avatar_url:
                current_user.avatar_url = avatar_url
                
        elif source == 'bitbucket' and current_user.has_bitbucket():
            avatar_url = fetch_bitbucket_avatar(current_user.bitbucket_token)
            if avatar_url:
                current_user.avatar_url = avatar_url
                
        elif source == 'custom':
            # For custom avatars, we use the custom_avatar field, not avatar_url
            current_user.avatar_url = None
            
        elif source == 'letter':
            # For letter avatars, clear any external URL
            current_user.avatar_url = None
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Avatar source updated',
            'avatar_source': source,
            'avatar_url': current_user.get_avatar_url(),
            'letter_color': current_user.get_letter_avatar_color()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error changing avatar source: {e}")
        return jsonify({'success': False, 'error': 'Failed to update avatar source'}), 500


@settings_bp.route('/avatar/upload', methods=['POST'])
@login_required
def upload_avatar():
    """Upload custom avatar"""
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['avatar']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type. Use JPEG, PNG, GIF, or WebP'}), 400
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)  # Reset file pointer
    
    if file_length > MAX_AVATAR_SIZE:
        return jsonify({'success': False, 'error': 'File too large. Maximum size is 2MB'}), 400
    
    try:
        # Delete old avatar files
        delete_old_avatars(current_user.id)
        
        # Process and save new avatar
        saved_files = process_and_save_avatar(file, current_user.id)
        
        if not saved_files:
            return jsonify({'success': False, 'error': 'Failed to process image'}), 500
        
        # Store the large avatar filename in database
        current_user.custom_avatar = saved_files['large']
        current_user.avatar_source = 'custom'
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Avatar uploaded successfully',
            'avatar_url': get_avatar_url(current_user.custom_avatar),
            'avatar_source': 'custom'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error uploading avatar: {e}")
        return jsonify({'success': False, 'error': 'Failed to upload avatar'}), 500


@settings_bp.route('/avatar/remove', methods=['POST'])
@login_required
def remove_avatar():
    """Remove custom avatar and switch to letter avatar"""
    try:
        # Delete avatar files
        if current_user.custom_avatar:
            delete_old_avatars(current_user.id)
        
        current_user.custom_avatar = None
        current_user.avatar_source = 'letter'
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Avatar removed',
            'avatar_source': 'letter',
            'letter_color': current_user.get_letter_avatar_color()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error removing avatar: {e}")
        return jsonify({'success': False, 'error': 'Failed to remove avatar'}), 500

@settings_bp.route('/privacy', methods=['POST'])
@login_required
def update_privacy():
    """Update privacy settings"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    try:
        if 'public_profile' in data:
            current_user.public_profile = bool(data['public_profile'])
        
        if 'publish_private_repos' in data:
            current_user.publish_private_repos = bool(data['publish_private_repos'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Privacy settings updated',
            'public_profile': current_user.public_profile,
            'publish_private_repos': current_user.publish_private_repos
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating privacy: {e}")
        return jsonify({'success': False, 'error': 'Failed to update privacy settings'}), 500


@settings_bp.route('/notifications', methods=['POST'])
@login_required
def update_notifications():
    """Update notification settings"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    try:
        if 'email_on_login' in data:
            current_user.email_on_login = bool(data['email_on_login'])
        
        if 'email_on_analysis' in data:
            current_user.email_on_analysis = bool(data['email_on_analysis'])
        
        if 'email_marketing' in data:
            current_user.email_marketing = bool(data['email_marketing'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Notification settings updated',
            'email_on_login': current_user.email_on_login,
            'email_on_analysis': current_user.email_on_analysis,
            'email_marketing': current_user.email_marketing
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating notifications: {e}")
        return jsonify({'success': False, 'error': 'Failed to update notification settings'}), 500


@settings_bp.route('/preferences', methods=['POST'])
@login_required
def update_preferences():
    """Update user preferences (language, timezone, theme)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    try:
        if 'language' in data:
            lang = data['language']
            if lang in ['en', 'ar']:
                current_user.language = lang
                session['language'] = lang
        
        if 'timezone' in data:
            current_user.timezone = data['timezone']
        
        if 'theme' in data:
            if data['theme'] in ['light', 'dark', 'system']:
                current_user.theme = data['theme']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Preferences updated',
            'language': current_user.language,
            'timezone': current_user.timezone,
            'theme': current_user.theme
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating preferences: {e}")
        return jsonify({'success': False, 'error': 'Failed to update preferences'}), 500


@settings_bp.route('/account/request-delete', methods=['POST'])
@login_required
def request_delete_account():
    """Request account deletion - sends confirmation code"""
    try:
        code = current_user.generate_delete_token()
        db.session.commit()
        
        # Send confirmation email
        if current_user.email:
            user_lang = current_user.language or 'en'
            
            if user_lang == 'ar':
                subject = '⚠️ تأكيد حذف الحساب'
                content = f'''
                <h2>تأكيد حذف الحساب</h2>
                <p>لقد طلبت حذف حسابك في CodeInsight.</p>
                <p>رمز التأكيد الخاص بك هو:</p>
                <div style="background: #fee2e2; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; color: #dc2626;">
                    {code}
                </div>
                <p>ينتهي صلاحية هذا الرمز خلال 15 دقيقة.</p>
                <p><strong>تحذير:</strong> هذا الإجراء لا يمكن التراجع عنه!</p>
                '''
            else:
                subject = '⚠️ Account Deletion Confirmation'
                content = f'''
                <h2>Account Deletion Confirmation</h2>
                <p>You have requested to delete your CodeInsight account.</p>
                <p>Your confirmation code is:</p>
                <div style="background: #fee2e2; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; color: #dc2626;">
                    {code}
                </div>
                <p>This code expires in 15 minutes.</p>
                <p><strong>Warning:</strong> This action cannot be undone!</p>
                '''
            
            email_sender.send_email(current_user.email, subject, content)
        
        return jsonify({
            'success': True,
            'message': 'Confirmation code sent to your email'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error requesting account deletion: {e}")
        return jsonify({'success': False, 'error': 'Failed to send confirmation code'}), 500


@settings_bp.route('/account/confirm-delete', methods=['POST'])
@login_required
def confirm_delete_account():
    """Confirm account deletion with username and code"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    code = data.get('code', '').strip().upper()
    
    if not username or not code:
        return jsonify({'success': False, 'error': 'Username and code are required'}), 400
    
    # Verify username
    if username != current_user.username:
        return jsonify({'success': False, 'error': 'Username does not match'}), 400
    
    # Verify code
    success, message = current_user.verify_delete_token(code)
    if not success:
        return jsonify({'success': False, 'error': message}), 400
    
    try:
        user_id = current_user.id
        user_email = current_user.email
        user_lang = current_user.language or 'en'
        
        # Soft delete - mark as deleted
        current_user.deleted_at = db.func.now()
        current_user.email = f"deleted_{user_id}@deleted.local"
        current_user.username = f"deleted_user_{user_id}"
        current_user.github_id = None
        current_user.gitlab_id = None
        current_user.bitbucket_id = None
        current_user.github_token = None
        current_user.gitlab_token = None
        current_user.bitbucket_token = None
        
        db.session.commit()
        
        # Send farewell email
        if user_email:
            if user_lang == 'ar':
                subject = '👋 تم حذف حسابك'
                content = '''
                <h2>وداعاً!</h2>
                <p>تم حذف حسابك في CodeInsight بنجاح.</p>
                <p>نأسف لرؤيتك تذهب. إذا غيرت رأيك، يمكنك دائمًا إنشاء حساب جديد.</p>
                '''
            else:
                subject = '👋 Your Account Has Been Deleted'
                content = '''
                <h2>Goodbye!</h2>
                <p>Your CodeInsight account has been successfully deleted.</p>
                <p>We're sorry to see you go. If you change your mind, you can always create a new account.</p>
                '''
            
            email_sender.send_email(user_email, subject, content)
        
        return jsonify({
            'success': True,
            'message': 'Account deleted successfully',
            'redirect': url_for('main.logout')
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting account: {e}")
        return jsonify({'success': False, 'error': 'Failed to delete account'}), 500
    
def fetch_github_avatar(github_token):
    """Fetch user avatar from GitHub API"""
    try:
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get('https://api.github.com/user', headers=headers, timeout=10)
        if response.status_code == 200:
            user_data = response.json()
            return user_data.get('avatar_url')
    except Exception as e:
        logger.error(f"Failed to fetch GitHub avatar: {e}")
    return None

def fetch_gitlab_avatar(gitlab_token):
    """Fetch user avatar from GitLab API"""
    try:
        headers = {
            'Authorization': f'Bearer {gitlab_token}'
        }
        response = requests.get('https://gitlab.com/api/v4/user', headers=headers, timeout=10)
        if response.status_code == 200:
            user_data = response.json()
            return user_data.get('avatar_url')
    except Exception as e:
        logger.error(f"Failed to fetch GitLab avatar: {e}")
    return None

def fetch_bitbucket_avatar(bitbucket_token):
    """Fetch user avatar from Bitbucket API"""
    try:
        headers = {
            'Authorization': f'Bearer {bitbucket_token}',
            'Accept': 'application/json'
        }
        response = requests.get('https://api.bitbucket.org/2.0/user', headers=headers, timeout=10)
        if response.status_code == 200:
            user_data = response.json()
            # Bitbucket avatar is in links.avatar.href
            links = user_data.get('links', {})
            avatar_links = links.get('avatar', {})
            return avatar_links.get('href')
    except Exception as e:
        logger.error(f"Failed to fetch Bitbucket avatar: {e}")
    return None