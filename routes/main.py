from flask import Blueprint, render_template, jsonify, session
from flask_login import login_required, current_user
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
    user = User.query.filter_by(username=username, public_profile=True).first()
    if not user:
        return render_template('errors/404.html'), 404
    
    return render_template('profile_public.html', profile_user=user)

@main_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')