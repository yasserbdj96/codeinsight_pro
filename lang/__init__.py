# lang/__init__.py
import json
import os
from flask import session, request

class LanguageManager:
    def __init__(self, app=None):
        self.app = app
        self.languages = {}
        self.default_language = 'en'
        self.supported_languages = ['en', 'ar']
        
        # Load languages immediately
        self.load_languages()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        
        # Set default language from user preference or browser
        @app.before_request
        def set_language():
            # Check if user is authenticated and has language preference
            from flask_login import current_user
            if current_user.is_authenticated and current_user.language:
                session['language'] = current_user.language
            elif 'language' not in session:
                # Detect browser language
                browser_lang = request.accept_languages.best_match(self.supported_languages)
                session['language'] = browser_lang or self.default_language
    
    def load_languages(self):
        """Load all language files"""
        lang_dir = os.path.join(os.path.dirname(__file__))
        
        for lang_code in self.supported_languages:
            file_path = os.path.join(lang_dir, f'{lang_code}.json')
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.languages[lang_code] = json.load(f)
                    print(f"✓ Loaded language: {lang_code}")
            except FileNotFoundError:
                print(f"✗ Warning: Language file {file_path} not found")
                # Create a basic structure if file doesn't exist
                self.languages[lang_code] = self._create_fallback_language()
            except json.JSONDecodeError as e:
                print(f"✗ Error: Invalid JSON in {file_path}: {e}")
                self.languages[lang_code] = self._create_fallback_language()
            except Exception as e:
                print(f"✗ Error loading {file_path}: {e}")
                self.languages[lang_code] = self._create_fallback_language()
        
        # Ensure default language exists
        if self.default_language not in self.languages:
            print(f"✗ Critical: Default language '{self.default_language}' not loaded, creating fallback")
            self.languages[self.default_language] = self._create_fallback_language()
    
    def _create_fallback_language(self):
        """Create a basic fallback language structure"""
        return {
            "app": {
                "name": "CodeInsight",
                "description": "Your code analysis companion"
            },
            "navigation": {
                "home": "Home",
                "dashboard": "Dashboard", 
                "login": "Login",
                "logout": "Logout",
                "profile": "Profile"
            },
            "auth": {
                "welcome": "Welcome",
                "login_with_github": "Login with GitHub",
                "login_with_gitlab": "Login with GitLab"
            },
            "errors": {
                "generic": "An error occurred"
            }
        }
    
    def get_text(self, key, language=None, **kwargs):
        """Get translated text for a key"""
        if language is None:
            language = session.get('language', self.default_language)
        
        # Fallback to default language if requested language not found
        if language not in self.languages:
            print(f"✗ Language '{language}' not found, falling back to '{self.default_language}'")
            language = self.default_language
        
        # Ensure default language exists
        if self.default_language not in self.languages:
            print(f"✗ Critical: Default language '{self.default_language}' not available")
            return f"[{key}]"
        
        # Navigate through the nested keys (e.g., "auth.welcome")
        keys = key.split('.')
        value = self.languages[language]
        
        try:
            for k in keys:
                value = value[k]
            
            # Format the string with provided arguments
            if isinstance(value, str) and kwargs:
                return value.format(**kwargs)
            return value
            
        except (KeyError, TypeError):
            # Fallback to default language
            if language != self.default_language:
                print(f"✗ Key '{key}' not found in '{language}', trying '{self.default_language}'")
                return self.get_text(key, self.default_language, **kwargs)
            
            # Return the key itself if not found anywhere
            print(f"✗ Key '{key}' not found in any language")
            return f"[{key}]"
    
    def get_available_languages(self):
        """Get list of available languages with their display names"""
        return {
            'en': 'English',
            'ar': 'العربية'
        }

# Create global instance
language_manager = LanguageManager()