# models/user.py
from . import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    # Primary Key
    id = db.Column(db.Integer, primary_key=True)
    
    # Basic User Information
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    avatar_url = db.Column(db.String(500))
    bio = db.Column(db.Text)
    
    # GitHub OAuth
    github_id = db.Column(db.String(100), unique=True, index=True)
    github_token = db.Column(db.String(500))
    
    # GitLab OAuth
    gitlab_id = db.Column(db.String(100), unique=True, index=True)
    gitlab_token = db.Column(db.String(500))
    gitlab_refresh_token = db.Column(db.String(500))
    gitlab_token_expires_at = db.Column(db.DateTime)
    
    # Account Status
    is_premium = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Privacy Settings
    public_profile = db.Column(db.Boolean, default=False)
    publish_private_repos = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_analysis = db.Column(db.DateTime)
    last_username_change = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
    
    # Preferences
    language = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(10), default='light')
    avatar_source = db.Column(db.String(20), default='github')  # 'github' or 'gitlab'
    
    # Payment Information
    stripe_customer_id = db.Column(db.String(100))
    premium_expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.created_at is None:
            self.created_at = datetime.utcnow()
    
    # Helper Methods
    
    def has_github(self):
        """Check if user has GitHub connected"""
        return self.github_id is not None
    
    def has_gitlab(self):
        """Check if user has GitLab connected"""
        return self.gitlab_id is not None
    
    def has_any_oauth(self):
        """Check if user has any OAuth provider connected"""
        return self.has_github() or self.has_gitlab()
    
    def can_disconnect_github(self):
        """Check if user can safely disconnect GitHub"""
        return self.has_github() and self.has_gitlab()
    
    def can_disconnect_gitlab(self):
        """Check if user can safely disconnect GitLab"""
        return self.has_gitlab() and self.has_github()
    
    def get_primary_oauth_provider(self):
        """Get the primary OAuth provider"""
        if self.github_id and not self.gitlab_id:
            return 'github'
        elif self.gitlab_id and not self.github_id:
            return 'gitlab'
        elif self.avatar_source:
            return self.avatar_source
        elif self.github_id:
            return 'github'
        else:
            return None
    
    def update_avatar_source(self, provider):
        """Update the avatar source"""
        if provider in ['github', 'gitlab']:
            self.avatar_source = provider
    
    def is_premium_active(self):
        """Check if premium subscription is active"""
        if not self.is_premium:
            return False
        if self.premium_expires_at is None:
            return True  # Lifetime premium
        return datetime.utcnow() < self.premium_expires_at
    
    def days_until_premium_expires(self):
        """Get number of days until premium expires"""
        if not self.is_premium or self.premium_expires_at is None:
            return None
        delta = self.premium_expires_at - datetime.utcnow()
        return max(0, delta.days)
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email if include_sensitive else None,
            'avatar_url': self.avatar_url,
            'bio': self.bio,
            'is_premium': self.is_premium,
            'is_verified': self.is_verified,
            'public_profile': self.public_profile,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'has_github': self.has_github(),
            'has_gitlab': self.has_gitlab(),
            'avatar_source': self.avatar_source,
            'language': self.language,
            'theme': self.theme
        }
        
        if include_sensitive:
            data.update({
                'is_admin': self.is_admin,
                'last_analysis': self.last_analysis.isoformat() if self.last_analysis else None,
                'premium_expires_at': self.premium_expires_at.isoformat() if self.premium_expires_at else None,
                'stripe_customer_id': self.stripe_customer_id
            })
        
        return data
    
    @staticmethod
    def find_by_github_id(github_id):
        """Find user by GitHub ID"""
        return User.query.filter_by(github_id=str(github_id)).first()
    
    @staticmethod
    def find_by_gitlab_id(gitlab_id):
        """Find user by GitLab ID"""
        return User.query.filter_by(gitlab_id=str(gitlab_id)).first()
    
    @staticmethod
    def find_by_username(username):
        """Find user by username"""
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def find_by_email(email):
        """Find user by email"""
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def username_exists(username):
        """Check if username already exists"""
        return User.query.filter_by(username=username).first() is not None
    
    @staticmethod
    def email_exists(email):
        """Check if email already exists"""
        if not email:
            return False
        return User.query.filter_by(email=email).first() is not None
    
    @staticmethod
    def generate_unique_username(base_username, provider='gh'):
        """Generate a unique username by appending numbers"""
        username = base_username
        counter = 1
        
        while User.username_exists(username):
            username = f"{base_username}_{provider}{counter}"
            counter += 1
        
        return username