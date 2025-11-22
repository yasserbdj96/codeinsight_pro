# routes/admin.py
import logging
import json
import os
from functools import wraps
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from models import db, User, SiteSettings, AdminLog

logger = logging.getLogger("admin")

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('main.login'))
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def log_admin_action(action, target_type=None, target_id=None, details=None):
    """Helper to log admin actions"""
    AdminLog.log(
        admin_id=current_user.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip_address=request.remote_addr
    )


# ==================== PAGE ROUTES ====================

@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    """Admin dashboard"""
    # Get statistics
    stats = {
        'total_users': User.query.filter(User.deleted_at.is_(None)).count(),
        'premium_users': User.query.filter(User.is_premium == True, User.deleted_at.is_(None)).count(),
        'new_users_today': User.query.filter(
            User.created_at >= datetime.utcnow().date(),
            User.deleted_at.is_(None)
        ).count(),
        'new_users_week': User.query.filter(
            User.created_at >= datetime.utcnow() - timedelta(days=7),
            User.deleted_at.is_(None)
        ).count(),
    }
    
    # Recent users
    recent_users = User.query.filter(User.deleted_at.is_(None))\
        .order_by(User.created_at.desc()).limit(10).all()
    
    # Recent admin logs
    recent_logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(20).all()
    
    # Site settings
    settings = SiteSettings.get_all()
    
    return render_template('admin/dashboard.html', 
                          stats=stats, 
                          recent_users=recent_users,
                          recent_logs=recent_logs,
                          settings=settings)


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """User management page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    
    # Start with base query
    query = User.query
    
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    # Apply filters
    if filter_type == 'premium':
        query = query.filter(User.is_premium == True, User.deleted_at.is_(None))
    elif filter_type == 'admin':
        query = query.filter(User.is_admin == True, User.deleted_at.is_(None))
    elif filter_type == 'github':
        query = query.filter(User.github_id.isnot(None), User.deleted_at.is_(None))
    elif filter_type == 'gitlab':
        query = query.filter(User.gitlab_id.isnot(None), User.deleted_at.is_(None))
    elif filter_type == 'bitbucket':
        query = query.filter(User.bitbucket_id.isnot(None), User.deleted_at.is_(None))
    elif filter_type == 'banned':
        query = query.filter(User.deleted_at.isnot(None))
    else:  # 'all' or any other value
        query = query.filter(User.deleted_at.is_(None))
    
    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('admin/users.html', users=users, search=search, filter_type=filter_type)


@admin_bp.route('/settings')
@login_required
@admin_required
def settings():
    """Site settings page"""
    settings = SiteSettings.get_all()
    return render_template('admin/settings.html', settings=settings)


@admin_bp.route('/languages')
@login_required
@admin_required
def languages():
    """Language management page"""
    from lang import language_manager
    return render_template('admin/languages.html', 
                          languages=language_manager.languages,
                          supported=language_manager.supported_languages)


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    """Admin logs page"""
    page = request.args.get('page', 1, type=int)
    logs = AdminLog.query.order_by(AdminLog.created_at.desc()).paginate(page=page, per_page=50)
    return render_template('admin/logs.html', logs=logs)


# ==================== API ROUTES ====================

@admin_bp.route('/api/stats')
@login_required
@admin_required
def api_stats():
    """Get dashboard statistics"""
    stats = {
        'total_users': User.query.filter(User.deleted_at.is_(None)).count(),
        'premium_users': User.query.filter(User.is_premium == True, User.deleted_at.is_(None)).count(),
        'github_users': User.query.filter(User.github_id.isnot(None), User.deleted_at.is_(None)).count(),
        'gitlab_users': User.query.filter(User.gitlab_id.isnot(None), User.deleted_at.is_(None)).count(),
        'bitbucket_users': User.query.filter(User.bitbucket_id.isnot(None), User.deleted_at.is_(None)).count(),
        'deleted_users': User.query.filter(User.deleted_at.isnot(None)).count(),
    }
    return jsonify({'success': True, 'stats': stats})


@admin_bp.route('/api/users/<int:user_id>')
@login_required
@admin_required
def api_get_user(user_id):
    """Get user details"""
    user = User.query.get_or_404(user_id)
    return jsonify({'success': True, 'user': user.to_dict(include_sensitive=True)})


@admin_bp.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def api_update_user(user_id):
    """Update user"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    changes = []
    
    if 'is_premium' in data and data['is_premium'] != user.is_premium:
        user.is_premium = data['is_premium']
        changes.append(f"is_premium: {data['is_premium']}")
    
    if 'is_admin' in data and data['is_admin'] != user.is_admin:
        # Prevent removing own admin
        if user.id == current_user.id and not data['is_admin']:
            return jsonify({'success': False, 'error': 'Cannot remove your own admin status'}), 400
        user.is_admin = data['is_admin']
        changes.append(f"is_admin: {data['is_admin']}")
    
    if 'is_verified' in data and data['is_verified'] != user.is_verified:
        user.is_verified = data['is_verified']
        changes.append(f"is_verified: {data['is_verified']}")
    
    if 'email' in data and data['email'] != user.email:
        user.email = data['email']
        changes.append(f"email changed")
    
    if 'username' in data and data['username'] != user.username:
        if User.username_exists(data['username']):
            return jsonify({'success': False, 'error': 'Username already taken'}), 400
        user.username = data['username']
        changes.append(f"username: {data['username']}")
    
    if changes:
        db.session.commit()
        log_admin_action('update_user', 'user', user_id, ', '.join(changes))
    
    return jsonify({'success': True, 'message': 'User updated', 'user': user.to_dict(include_sensitive=True)})


@admin_bp.route('/api/users/<int:user_id>/ban', methods=['POST'])
@login_required
@admin_required
def api_ban_user(user_id):
    """Ban/delete user"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot ban yourself'}), 400
    
    if user.is_admin:
        return jsonify({'success': False, 'error': 'Cannot ban an admin'}), 400
    
    user.deleted_at = datetime.utcnow()
    user.github_id = None
    user.gitlab_id = None
    user.bitbucket_id = None
    user.github_token = None
    user.gitlab_token = None
    user.bitbucket_token = None
    
    db.session.commit()
    log_admin_action('ban_user', 'user', user_id, f"Banned user: {user.username}")
    
    return jsonify({'success': True, 'message': 'User banned'})


@admin_bp.route('/api/users/<int:user_id>/unban', methods=['POST'])
@login_required
@admin_required
def api_unban_user(user_id):
    """Unban/restore user"""
    user = User.query.get_or_404(user_id)
    
    if not user.deleted_at:
        return jsonify({'success': False, 'error': 'User is not banned'}), 400
    
    user.deleted_at = None
    db.session.commit()
    log_admin_action('unban_user', 'user', user_id, f"Unbanned user: {user.username}")
    
    return jsonify({'success': True, 'message': 'User unbanned'})


@admin_bp.route('/api/users/<int:user_id>/impersonate', methods=['POST'])
@login_required
@admin_required
def api_impersonate_user(user_id):
    """Impersonate a user (login as them)"""
    from flask_login import login_user
    
    user = User.query.get_or_404(user_id)
    
    if user.deleted_at:
        return jsonify({'success': False, 'error': 'Cannot impersonate deleted user'}), 400
    
    log_admin_action('impersonate_user', 'user', user_id, f"Impersonated: {user.username}")
    login_user(user)
    
    return jsonify({'success': True, 'message': f'Now logged in as {user.username}', 'redirect': url_for('main.dashboard')})


# ==================== SETTINGS API ====================

@admin_bp.route('/api/settings', methods=['GET'])
@login_required
@admin_required
def api_get_settings():
    """Get all settings"""
    return jsonify({'success': True, 'settings': SiteSettings.get_all()})


@admin_bp.route('/api/settings', methods=['POST'])
@login_required
@admin_required
def api_update_settings():
    """Update settings"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    updated = []
    for key, value in data.items():
        old_value = SiteSettings.get(key)
        if old_value != value:
            SiteSettings.set(key, value, current_user.id)
            updated.append(key)
    
    if updated:
        log_admin_action('update_settings', 'settings', None, f"Updated: {', '.join(updated)}")
    
    return jsonify({'success': True, 'message': 'Settings updated', 'updated': updated})


@admin_bp.route('/api/settings/maintenance', methods=['POST'])
@login_required
@admin_required
def api_toggle_maintenance():
    """Toggle maintenance mode"""
    data = request.get_json()
    enabled = data.get('enabled', False)
    message = data.get('message', '')
    
    SiteSettings.set('maintenance_mode', enabled, current_user.id)
    if message:
        SiteSettings.set('maintenance_message', message, current_user.id)
    
    log_admin_action('toggle_maintenance', 'settings', None, f"Maintenance mode: {enabled}")
    
    return jsonify({'success': True, 'message': f"Maintenance mode {'enabled' if enabled else 'disabled'}"})


@admin_bp.route('/api/settings/auth', methods=['POST'])
@login_required
@admin_required
def api_update_auth_settings():
    """Update authentication settings"""
    data = request.get_json()
    
    if 'enable_github' in data:
        SiteSettings.set('enable_github', data['enable_github'], current_user.id)
    if 'enable_gitlab' in data:
        SiteSettings.set('enable_gitlab', data['enable_gitlab'], current_user.id)
    if 'enable_bitbucket' in data:
        SiteSettings.set('enable_bitbucket', data['enable_bitbucket'], current_user.id)
    if 'enable_signup' in data:
        SiteSettings.set('enable_signup', data['enable_signup'], current_user.id)
    
    log_admin_action('update_auth_settings', 'settings', None, json.dumps(data))
    
    return jsonify({'success': True, 'message': 'Authentication settings updated'})


# ==================== LANGUAGE API ====================

@admin_bp.route('/api/languages')
@login_required
@admin_required
def api_get_languages():
    """Get all language data"""
    from lang import language_manager
    return jsonify({
        'success': True, 
        'languages': language_manager.languages,
        'supported': language_manager.supported_languages
    })


@admin_bp.route('/api/languages/<lang_code>', methods=['GET'])
@login_required
@admin_required
def api_get_language(lang_code):
    """Get specific language data"""
    from lang import language_manager
    if lang_code not in language_manager.languages:
        return jsonify({'success': False, 'error': 'Language not found'}), 404
    return jsonify({'success': True, 'language': language_manager.languages[lang_code]})


@admin_bp.route('/api/languages/<lang_code>', methods=['PUT'])
@login_required
@admin_required
def api_update_language(lang_code):
    """Update language strings"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    try:
        # Get the lang directory path
        lang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'lang')
        file_path = os.path.join(lang_dir, f'{lang_code}.json')
        
        # Write updated language file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        # Reload languages
        from lang import language_manager
        language_manager.languages[lang_code] = data
        
        log_admin_action('update_language', 'language', lang_code, f"Updated {lang_code} language file")
        
        return jsonify({'success': True, 'message': f'Language {lang_code} updated'})
        
    except Exception as e:
        logger.exception(f"Error updating language: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/api/languages', methods=['POST'])
@login_required
@admin_required
def api_create_language():
    """Create new language"""
    data = request.get_json()
    
    lang_code = data.get('code', '').strip().lower()
    lang_name = data.get('name', '').strip()
    
    if not lang_code or not lang_name:
        return jsonify({'success': False, 'error': 'Code and name are required'}), 400
    
    if len(lang_code) != 2:
        return jsonify({'success': False, 'error': 'Language code must be 2 characters'}), 400
    
    from lang import language_manager
    if lang_code in language_manager.supported_languages:
        return jsonify({'success': False, 'error': 'Language already exists'}), 400
    
    try:
        # Create language file from English template
        lang_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'lang')
        
        # Copy English as template
        template = language_manager.languages.get('en', language_manager._create_fallback_language())
        
        file_path = os.path.join(lang_dir, f'{lang_code}.json')
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(template, f, ensure_ascii=False, indent=2)
        
        # Add to supported languages
        language_manager.supported_languages.append(lang_code)
        language_manager.languages[lang_code] = template
        
        # Update site settings
        supported = SiteSettings.get('supported_languages', ['en', 'ar'])
        if lang_code not in supported:
            supported.append(lang_code)
            SiteSettings.set('supported_languages', supported, current_user.id)
        
        log_admin_action('create_language', 'language', lang_code, f"Created language: {lang_name}")
        
        return jsonify({'success': True, 'message': f'Language {lang_name} created'})
        
    except Exception as e:
        logger.exception(f"Error creating language: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== BULK ACTIONS ====================

@admin_bp.route('/api/users/bulk', methods=['POST'])
@login_required
@admin_required
def api_bulk_user_action():
    """Perform bulk actions on users"""
    data = request.get_json()
    
    action = data.get('action')
    user_ids = data.get('user_ids', [])
    
    if not action or not user_ids:
        return jsonify({'success': False, 'error': 'Action and user IDs required'}), 400
    
    # Remove current user from list
    user_ids = [uid for uid in user_ids if uid != current_user.id]
    
    if not user_ids:
        return jsonify({'success': False, 'error': 'No valid users selected'}), 400
    
    affected = 0
    
    if action == 'ban':
        User.query.filter(User.id.in_(user_ids), User.is_admin == False)\
            .update({User.deleted_at: datetime.utcnow()}, synchronize_session=False)
        affected = len(user_ids)
    
    elif action == 'unban':
        User.query.filter(User.id.in_(user_ids))\
            .update({User.deleted_at: None}, synchronize_session=False)
        affected = len(user_ids)
    
    elif action == 'make_premium':
        User.query.filter(User.id.in_(user_ids))\
            .update({User.is_premium: True}, synchronize_session=False)
        affected = len(user_ids)
    
    elif action == 'remove_premium':
        User.query.filter(User.id.in_(user_ids))\
            .update({User.is_premium: False}, synchronize_session=False)
        affected = len(user_ids)
    
    elif action == 'verify':
        User.query.filter(User.id.in_(user_ids))\
            .update({User.is_verified: True}, synchronize_session=False)
        affected = len(user_ids)
    
    else:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    
    db.session.commit()
    log_admin_action(f'bulk_{action}', 'users', None, f"Affected {affected} users")
    
    return jsonify({'success': True, 'message': f'{action} applied to {affected} users', 'affected': affected})