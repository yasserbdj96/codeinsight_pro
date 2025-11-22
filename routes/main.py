from flask import Blueprint, render_template, jsonify, session, redirect, url_for, flash, make_response
from flask_login import login_required, current_user, logout_user
from lang import language_manager

# Create a blueprint
main_bp = Blueprint('main', __name__)

# Define routes
@main_bp.route('/')
def index():
    return render_template('home.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@main_bp.route('/login')
def login():
    return render_template('login.html')

@main_bp.route('/logout')
def logout():
    """Log out the current user"""
    username = None
    
    if current_user.is_authenticated:
        username = current_user.username
        logout_user()
    
    # Clear all session data
    session.clear()
    
    # Create response with redirect
    response = make_response(redirect(url_for('main.index')))
    
    # Delete cookies to ensure clean logout
    response.delete_cookie('remember_token')
    response.delete_cookie('codeinsight_session')
    response.delete_cookie('session')
    
    if username:
        flash(f'Goodbye {username}! You have been logged out successfully.', 'info')
    
    return response

@main_bp.route('/change-language/<lang_code>')
def change_language(lang_code):
    """Change the application language"""
    if lang_code in language_manager.supported_languages:
        session['language'] = lang_code
        
        # Update user preference if logged in
        if current_user.is_authenticated:
            current_user.language = lang_code
            from models import db
            db.session.commit()
        
        return jsonify({'success': True, 'language': lang_code})
    
    return jsonify({'success': False, 'error': 'Unsupported language'})

@main_bp.route('/change-template/<temp_code>')
def change_template(temp_code):
    """Change the application template"""
    # Update user preference if logged in
    if current_user.is_authenticated:
        current_user.theme = temp_code
        from models import db
        db.session.commit()
        return jsonify({'success': True, 'language': temp_code})
    
    return jsonify({'success': False, 'error': 'Unsupported language'})

@main_bp.route('/u/<username>')
def public_profile(username):
    """View public profile of a user"""
    from models import User
    user = User.query.filter_by(username=username).first_or_404()
    if not user.public_profile and (not current_user.is_authenticated or current_user.id != user.id):
        flash('This profile is private.', 'warning')
        return render_template('errors/404.html'), 404
    return render_template('profile_public.html', profile_user=user)

@main_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@main_bp.route('/.well-known/appspecific/com.chrome.devtools.json')
def devtools_file():
    return {"status": "ok"}, 200