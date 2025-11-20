# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    FLASK_RUN_HOST = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    FLASK_RUN_PORT = int(os.environ.get('FLASK_RUN_PORT', 5000))
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    SESSION_COOKIE_SECURE = False  # Should be True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Database Configuration
    database_name = os.environ.get('DATABASE_NAME', 'codeinsight.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{database_name}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True, 
        'pool_recycle': 300, 
        'connect_args': {'timeout': 30, 'check_same_thread': False}
    }

    # Background task scheduling
    CHECK_HOUR = int(os.environ.get('CHECK_HOUR', 0))
    CHECK_MINUTE = int(os.environ.get('CHECK_MINUTE', 0))
    CHECK_SECOND = int(os.environ.get('CHECK_SECOND', 0))
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@codeinsight.com')
    
    # GitHub OAuth Configuration
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', '')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')
    GITHUB_REDIRECT_URI = os.environ.get('GITHUB_REDIRECT_URI', 'http://localhost:5000/auth/github/callback')
    
    # GitLab OAuth Configuration
    GITLAB_CLIENT_ID = os.environ.get('GITLAB_CLIENT_ID', '')
    GITLAB_CLIENT_SECRET = os.environ.get('GITLAB_CLIENT_SECRET', '')
    GITLAB_REDIRECT_URI = os.environ.get('GITLAB_REDIRECT_URI', 'http://localhost:5000/auth/gitlab/callback')
    GITLAB_TOKEN_URL = 'https://gitlab.com/oauth/token'
    
    # Stripe Configuration
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
    STRIPE_MONTHLY_PRICE_ID = os.environ.get('STRIPE_MONTHLY_PRICE_ID', '')
    STRIPE_ANNUAL_PRICE_ID = os.environ.get('STRIPE_ANNUAL_PRICE_ID', '')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    REDIS_ENABLED = os.environ.get('REDIS_ENABLED', 'False') == 'True'
    
    # Application Settings
    FREE_REPO_LIMIT = int(os.environ.get('FREE_REPO_LIMIT', 10))
    CACHE_DURATION = int(os.environ.get('CACHE_DURATION', 300))
    AUTO_ANALYSIS = os.environ.get('AUTO_ANALYSIS', 'False') == 'True'
    MAINTENANCE_MODE = os.environ.get('MAINTENANCE_MODE', 'False') == 'True'
    
    # Security & Rate Limiting
    RATE_LIMIT_STORAGE_URL = os.environ.get('RATE_LIMIT_STORAGE_URL', 'memory://')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))  # 16MB
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/codeinsight.log')
    
    # Performance Configuration
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', 4))
    BACKGROUND_TASK_TIMEOUT = int(os.environ.get('BACKGROUND_TASK_TIMEOUT', 3600))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 300))
    
    # File Processing Limits
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 5242880))  # 5MB
    MAX_FILES_PER_REPO = int(os.environ.get('MAX_FILES_PER_REPO', 10000))
    MAX_REPOS_PER_USER = int(os.environ.get('MAX_REPOS_PER_USER', 100))
    
    # Feature Flags
    ENABLE_GITLAB = os.environ.get('ENABLE_GITLAB', 'True') == 'True'
    ENABLE_PREMIUM_FEATURES = os.environ.get('ENABLE_PREMIUM_FEATURES', 'True') == 'True'
    ENABLE_ACHIEVEMENTS = os.environ.get('ENABLE_ACHIEVEMENTS', 'True') == 'True'
    ENABLE_BADGES = os.environ.get('ENABLE_BADGES', 'True') == 'True'
    ENABLE_PUBLIC_PROFILES = os.environ.get('ENABLE_PUBLIC_PROFILES', 'True') == 'True'

# Create config instance
config = Config()

# Print loaded configuration (for debugging)
if __name__ == '__main__':
    print("=" * 60)
    print("Configuration Loaded:")
    print("=" * 60)
    print(f"Database: {config.SQLALCHEMY_DATABASE_URI}")
    print(f"GitHub Client ID: {config.GITHUB_CLIENT_ID[:10]}..." if config.GITHUB_CLIENT_ID else "GitHub Client ID: NOT SET")
    print(f"GitHub Redirect URI: {config.GITHUB_REDIRECT_URI}")
    print(f"GitLab Client ID: {config.GITLAB_CLIENT_ID[:10]}..." if config.GITLAB_CLIENT_ID else "GitLab Client ID: NOT SET")
    print(f"GitLab Redirect URI: {config.GITLAB_REDIRECT_URI}")
    print(f"Email Username: {config.MAIL_USERNAME}")
    print(f"Redis Enabled: {config.REDIS_ENABLED}")
    print(f"Debug Mode: {config.FLASK_DEBUG}")
    print("=" * 60)