# middleware.py
"""
Middleware functions for site-wide checks like maintenance mode and auth settings.
"""
from functools import wraps
from flask import render_template, redirect, url_for, flash, request
from flask_login import current_user


def check_maintenance_mode(app):
    """Register maintenance mode check for all requests"""
    
    @app.before_request
    def maintenance_check():
        from models import SiteSettings
        
        # Skip for static files
        if request.path.startswith('/static'):
            return None
        
        # Skip for admin routes
        if request.path.startswith('/admin'):
            return None
        
        # Check maintenance mode
        if SiteSettings.get('maintenance_mode', False):
            # Allow admins through
            if current_user.is_authenticated and current_user.is_admin:
                return None
            
            # Allow logout
            if request.path == '/logout':
                return None
            
            # Show maintenance page
            message = SiteSettings.get('maintenance_message', 'We are currently performing maintenance.')
            return render_template('errors/maintenance.html', message=message), 503


def check_auth_settings(app):
    """Register auth settings check for login routes"""
    
    @app.before_request
    def auth_settings_check():
        from models import SiteSettings
        
        # Check if signups are disabled for new users
        if not SiteSettings.get('enable_signup', True):
            # Block GitHub callback for new users
            if request.path in ['/auth/github/callback', '/callback/github']:
                if not current_user.is_authenticated:
                    # Will be checked in the callback - we set a flag
                    request.signup_disabled = True
            
            # Block GitLab callback for new users
            if request.path in ['/auth/gitlab/callback', '/callback/gitlab']:
                if not current_user.is_authenticated:
                    request.signup_disabled = True
            
            # Block Bitbucket callback for new users
            if request.path in ['/auth/bitbucket/callback', '/callback/bitbucket']:
                if not current_user.is_authenticated:
                    request.signup_disabled = True
        
        # Check if specific providers are disabled
        if request.path == '/auth/github' and not SiteSettings.get('enable_github', True):
            flash('GitHub login is currently disabled.', 'warning')
            return redirect(url_for('main.login'))
        
        if request.path == '/auth/gitlab' and not SiteSettings.get('enable_gitlab', True):
            flash('GitLab login is currently disabled.', 'warning')
            return redirect(url_for('main.login'))
        
        if request.path == '/auth/bitbucket' and not SiteSettings.get('enable_bitbucket', True):
            flash('Bitbucket login is currently disabled.', 'warning')
            return redirect(url_for('main.login'))


def init_middleware(app):
    """Initialize all middleware"""
    check_maintenance_mode(app)
    check_auth_settings(app)