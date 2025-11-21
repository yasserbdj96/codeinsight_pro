# app.py
from config import config
from flask import Flask, render_template
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from datetime import timedelta

# 
from lang import LanguageManager
from routes.main import main_bp
from models import db
from routes.github_auth import github_auth_bp
from routes.gitlab_auth import gitlab_auth_bp
from routes.bitbucket_auth import bitbucket_auth_bp


# app.py
def create_app():
    # Initialize Flask app
    app = Flask(__name__)
    app.config.from_object(config)
    
    # Enhanced session configuration
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
    app.config['SESSION_COOKIE_SECURE'] = False  # Should be True in production
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_NAME'] = 'codeinsight_session'
    app.config['SESSION_FILE_DIR'] = './flask_session'  # Add this line

    # Initialize database with app
    db.init_app(app)

    # Initialize Flask-Session BEFORE other extensions
    Session(app)

    # Initialize Language Manager
    language_manager = LanguageManager()
    language_manager.init_app(app)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    # Fixed user loader
    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return db.session.get(User, int(user_id))

    # Initialize CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(github_auth_bp)
    app.register_blueprint(gitlab_auth_bp)
    app.register_blueprint(bitbucket_auth_bp)

    # Make language_manager available to templates
    @app.context_processor
    def inject_language():
        from lang import language_manager
        return dict(_=language_manager.get_text, get_language=language_manager.get_text)

    return app

# Create the Flask app
app = create_app()

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Run the app
if __name__ == '__main__':
    with app.app_context():
        # Always initialize database on first run
        from utils.helpers import start_background_tasks, init_app
        
        # Check if this is the reloader child process
        import os
        is_reloader = os.environ.get('WERKZEUG_RUN_MAIN') == 'true'
        
        if not is_reloader:
            # This is the main process - always initialize
            print("🔧 Initializing application...")
            init_app()
            #if not config.FLASK_DEBUG:
            start_background_tasks()
        else:
            print("✓ Reloader child process - skipping initialization")
    
    app.run(host=str(config.FLASK_RUN_HOST), port=config.FLASK_RUN_PORT, debug=config.FLASK_DEBUG)