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