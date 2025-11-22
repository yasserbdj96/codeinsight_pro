# models/user.py
from . import db
from flask_login import UserMixin
from datetime import datetime, timedelta
import secrets
import hashlib

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    # Primary Key
    id = db.Column(db.Integer, primary_key=True)
    
    # Basic User Information
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    avatar_url = db.Column(db.String(500))
    bio = db.Column(db.Text)
    website = db.Column(db.String(255))
    location = db.Column(db.String(100))
    
    # GitHub OAuth
    github_id = db.Column(db.String(100), unique=True, index=True)
    github_token = db.Column(db.String(500))
    
    # GitLab OAuth
    gitlab_id = db.Column(db.String(100), unique=True, index=True)
    gitlab_token = db.Column(db.String(500))
    gitlab_refresh_token = db.Column(db.String(500))
    gitlab_token_expires_at = db.Column(db.DateTime)

    # Bitbucket OAuth
    bitbucket_id = db.Column(db.String(100), unique=True, index=True)
    bitbucket_token = db.Column(db.String(500))
    bitbucket_refresh_token = db.Column(db.String(500))
    
    # Account Status
    is_premium = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Privacy Settings
    public_profile = db.Column(db.Boolean, default=False)
    publish_private_repos = db.Column(db.Boolean, default=False)
    
    # Notification Settings
    email_on_login = db.Column(db.Boolean, default=True)
    email_on_analysis = db.Column(db.Boolean, default=True)
    email_marketing = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_analysis = db.Column(db.DateTime)
    last_username_change = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
    
    # Preferences
    language = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(10), default='light')
    timezone = db.Column(db.String(50), default='UTC')
    avatar_source = db.Column(db.String(20), default='github')  # 'github', 'gitlab', 'bitbucket', 'custom', 'letter'
    custom_avatar = db.Column(db.Text)  # Base64 encoded custom avatar
    
    # Email Change
    pending_email = db.Column(db.String(120))
    email_change_token = db.Column(db.String(100))
    email_change_token_expires = db.Column(db.DateTime)
    
    # Account Deletion
    delete_token = db.Column(db.String(100))
    delete_token_expires = db.Column(db.DateTime)
    
    # Payment Information
    stripe_customer_id = db.Column(db.String(100))
    premium_expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.created_at is None:
            self.created_at = datetime.utcnow()
    
    # Avatar Methods
    def get_avatar_url(self, size='large'):
        """Get the appropriate avatar URL based on avatar_source"""
        if self.avatar_source == 'custom' and self.custom_avatar:
            return f"/static/uploads/avatars/{self.custom_avatar}"
        elif self.avatar_source == 'letter':
            return None  # Will use letter avatar
        elif self.avatar_source == 'github' and self.github_id:
            return self.avatar_url if self.avatar_url else None
        elif self.avatar_source == 'gitlab' and self.gitlab_id:
            return self.avatar_url if self.avatar_url else None
        elif self.avatar_source == 'bitbucket' and self.bitbucket_id:
            return self.avatar_url if self.avatar_url else None
        return self.avatar_url
    
    def get_letter_avatar_color(self):
        """Get consistent color for letter avatar based on username"""
        colors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7',
            '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9',
            '#F8B500', '#00CED1', '#FF69B4', '#32CD32', '#FFD700',
            '#8A2BE2', '#00FA9A', '#FF4500', '#1E90FF', '#FF1493'
        ]
        # Use hash of username to get consistent color
        hash_val = int(hashlib.md5(self.username.encode()).hexdigest(), 16)
        return colors[hash_val % len(colors)]
    
    # Username Change Methods
    def can_change_username(self):
        """Check if user can change username (7 day cooldown)"""
        if not self.last_username_change:
            return True
        return datetime.utcnow() >= self.last_username_change + timedelta(days=7)
    
    def days_until_username_change(self):
        """Get days until username can be changed"""
        if self.can_change_username():
            return 0
        delta = (self.last_username_change + timedelta(days=7)) - datetime.utcnow()
        return max(0, delta.days + 1)
    
    def change_username(self, new_username):
        """Change username if allowed"""
        if not self.can_change_username():
            return False, f"You can change your username in {self.days_until_username_change()} days"
        
        if User.username_exists(new_username) and new_username != self.username:
            return False, "Username already taken"
        
        self.username = new_username
        self.last_username_change = datetime.utcnow()
        return True, "Username changed successfully"
    
    # Email Change Methods
    def generate_email_change_token(self, new_email):
        """Generate token for email change confirmation"""
        self.pending_email = new_email
        self.email_change_token = secrets.token_urlsafe(32)
        self.email_change_token_expires = datetime.utcnow() + timedelta(hours=1)
        return self.email_change_token
    
    def verify_email_change_token(self, token):
        """Verify email change token and update email"""
        if not self.email_change_token or not self.pending_email:
            return False, "No pending email change"
        
        if datetime.utcnow() > self.email_change_token_expires:
            self.clear_email_change()
            return False, "Token expired"
        
        if not secrets.compare_digest(token, self.email_change_token):
            return False, "Invalid token"
        
        # Check if email is already taken
        if User.email_exists(self.pending_email):
            self.clear_email_change()
            return False, "Email already in use"
        
        self.email = self.pending_email
        self.clear_email_change()
        return True, "Email changed successfully"
    
    def clear_email_change(self):
        """Clear pending email change data"""
        self.pending_email = None
        self.email_change_token = None
        self.email_change_token_expires = None
    
    # Account Deletion Methods
    def generate_delete_token(self):
        """Generate token for account deletion confirmation"""
        self.delete_token = secrets.token_urlsafe(6).upper()[:6]  # 6 character code
        self.delete_token_expires = datetime.utcnow() + timedelta(minutes=15)
        return self.delete_token
    
    def verify_delete_token(self, token):
        """Verify deletion token"""
        if not self.delete_token:
            return False, "No deletion request pending"
        
        if datetime.utcnow() > self.delete_token_expires:
            self.clear_delete_token()
            return False, "Token expired"
        
        if not secrets.compare_digest(token.upper(), self.delete_token):
            return False, "Invalid code"
        
        return True, "Token verified"
    
    def clear_delete_token(self):
        """Clear deletion token"""
        self.delete_token = None
        self.delete_token_expires = None
    
    # OAuth Helper Methods
    def has_github(self):
        return self.github_id is not None
    
    def has_gitlab(self):
        return self.gitlab_id is not None
    
    def has_bitbucket(self):
        return self.bitbucket_id is not None

    def has_any_oauth(self):
        return self.has_github() or self.has_gitlab() or self.has_bitbucket()
    
    def get_available_avatar_sources(self):
        """Get list of available avatar sources"""
        sources = [{'value': 'letter', 'label': 'Letter Avatar'}]
        if self.has_github():
            sources.append({'value': 'github', 'label': 'GitHub'})
        if self.has_gitlab():
            sources.append({'value': 'gitlab', 'label': 'GitLab'})
        if self.has_bitbucket():
            sources.append({'value': 'bitbucket', 'label': 'Bitbucket'})
        if self.custom_avatar:
            sources.append({'value': 'custom', 'label': 'Custom Upload'})
        return sources
    
    def can_disconnect_github(self):
        return self.has_github() and (self.has_gitlab() or self.has_bitbucket())
    
    def can_disconnect_gitlab(self):
        return self.has_gitlab() and (self.has_github() or self.has_bitbucket())
    
    def can_disconnect_bitbucket(self):
        return self.has_bitbucket() and (self.has_github() or self.has_gitlab())
    
    def get_primary_oauth_provider(self):
        if self.github_id and not self.gitlab_id and not self.bitbucket_id:
            return 'github'
        elif self.gitlab_id and not self.github_id and not self.bitbucket_id:
            return 'gitlab'
        elif self.bitbucket_id and not self.github_id and not self.gitlab_id:
            return 'bitbucket'
        elif self.avatar_source in ['github', 'gitlab', 'bitbucket']:
            return self.avatar_source
        elif self.github_id:
            return 'github'
        return None
    
    def is_premium_active(self):
        if not self.is_premium:
            return False
        if self.premium_expires_at is None:
            return True
        return datetime.utcnow() < self.premium_expires_at
    
    def days_until_premium_expires(self):
        if not self.is_premium or self.premium_expires_at is None:
            return None
        delta = self.premium_expires_at - datetime.utcnow()
        return max(0, delta.days)
    
    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email if include_sensitive else None,
            'avatar_url': self.get_avatar_url(),
            'avatar_source': self.avatar_source,
            'letter_color': self.get_letter_avatar_color(),
            'bio': self.bio,
            'website': self.website,
            'location': self.location,
            'is_premium': self.is_premium,
            'is_verified': self.is_verified,
            'public_profile': self.public_profile,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'has_github': self.has_github(),
            'has_gitlab': self.has_gitlab(),
            'has_bitbucket': self.has_bitbucket(),
            'language': self.language,
            'theme': self.theme,
            'timezone': self.timezone,
            'can_change_username': self.can_change_username(),
            'days_until_username_change': self.days_until_username_change()
        }
        
        if include_sensitive:
            data.update({
                'is_admin': self.is_admin,
                'email_on_login': self.email_on_login,
                'email_on_analysis': self.email_on_analysis,
                'email_marketing': self.email_marketing,
                'publish_private_repos': self.publish_private_repos,
                'last_analysis': self.last_analysis.isoformat() if self.last_analysis else None,
                'premium_expires_at': self.premium_expires_at.isoformat() if self.premium_expires_at else None,
                'stripe_customer_id': self.stripe_customer_id
            })
        
        return data
    
    @staticmethod
    def find_by_github_id(github_id):
        return User.query.filter_by(github_id=str(github_id)).first()
    
    @staticmethod
    def find_by_gitlab_id(gitlab_id):
        return User.query.filter_by(gitlab_id=str(gitlab_id)).first()
    
    @staticmethod
    def find_by_bitbucket_id(bitbucket_id):
        return User.query.filter_by(bitbucket_id=str(bitbucket_id)).first()
    
    @staticmethod
    def find_by_username(username):
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def find_by_email(email):
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def username_exists(username):
        return User.query.filter_by(username=username).first() is not None
    
    @staticmethod
    def email_exists(email):
        if not email:
            return False
        return User.query.filter_by(email=email).first() is not None
    
    @staticmethod
    def generate_unique_username(base_username, provider='gh'):
        username = base_username
        counter = 1
        while User.username_exists(username):
            username = f"{base_username}_{provider}{counter}"
            counter += 1
        return username