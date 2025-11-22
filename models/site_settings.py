# models/site_settings.py
from . import db
from datetime import datetime
import json

class SiteSettings(db.Model):
    __tablename__ = 'site_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')  # string, bool, int, json
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Default settings
    DEFAULTS = {
        # Maintenance
        'maintenance_mode': {'value': False, 'type': 'bool', 'desc': 'Enable maintenance mode'},
        'maintenance_message': {'value': 'We are currently performing maintenance. Please check back soon.', 'type': 'string', 'desc': 'Maintenance message'},
        
        # Authentication
        'enable_github': {'value': True, 'type': 'bool', 'desc': 'Enable GitHub OAuth'},
        'enable_gitlab': {'value': True, 'type': 'bool', 'desc': 'Enable GitLab OAuth'},
        'enable_bitbucket': {'value': True, 'type': 'bool', 'desc': 'Enable Bitbucket OAuth'},
        'enable_signup': {'value': True, 'type': 'bool', 'desc': 'Allow new user signups'},
        
        # Features
        'enable_public_profiles': {'value': True, 'type': 'bool', 'desc': 'Allow public profiles'},
        'enable_premium': {'value': True, 'type': 'bool', 'desc': 'Enable premium features'},
        'free_repo_limit': {'value': 10, 'type': 'int', 'desc': 'Free tier repository limit'},
        
        # Site Info
        'site_name': {'value': 'CodeInsight', 'type': 'string', 'desc': 'Site name'},
        'site_description': {'value': 'Your code analysis companion', 'type': 'string', 'desc': 'Site description'},
        'contact_email': {'value': 'support@codeinsight.com', 'type': 'string', 'desc': 'Contact email'},
        
        # Languages
        'supported_languages': {'value': ['en', 'ar'], 'type': 'json', 'desc': 'Supported languages'},
        'default_language': {'value': 'en', 'type': 'string', 'desc': 'Default language'},
    }
    
    def __repr__(self):
        return f'<SiteSettings {self.key}={self.value}>'
    
    def get_typed_value(self):
        """Get value converted to proper type"""
        if self.value_type == 'bool':
            return self.value.lower() in ('true', '1', 'yes') if isinstance(self.value, str) else bool(self.value)
        elif self.value_type == 'int':
            return int(self.value) if self.value else 0
        elif self.value_type == 'json':
            return json.loads(self.value) if self.value else {}
        return self.value
    
    @staticmethod
    def set_typed_value(value, value_type):
        """Convert value to string for storage"""
        if value_type == 'bool':
            return 'true' if value else 'false'
        elif value_type == 'int':
            return str(value)
        elif value_type == 'json':
            return json.dumps(value)
        return str(value) if value else ''
    
    @classmethod
    def get(cls, key, default=None):
        """Get a setting value"""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            return setting.get_typed_value()
        # Return from defaults
        if key in cls.DEFAULTS:
            return cls.DEFAULTS[key]['value']
        return default
    
    @classmethod
    def set(cls, key, value, user_id=None):
        """Set a setting value"""
        setting = cls.query.filter_by(key=key).first()
        
        # Determine type from defaults or existing
        if key in cls.DEFAULTS:
            value_type = cls.DEFAULTS[key]['type']
            description = cls.DEFAULTS[key]['desc']
        elif setting:
            value_type = setting.value_type
            description = setting.description
        else:
            value_type = 'string'
            description = ''
        
        typed_value = cls.set_typed_value(value, value_type)
        
        if setting:
            setting.value = typed_value
            setting.updated_by = user_id
        else:
            setting = cls(
                key=key,
                value=typed_value,
                value_type=value_type,
                description=description,
                updated_by=user_id
            )
            db.session.add(setting)
        
        db.session.commit()
        return setting
    
    @classmethod
    def get_all(cls):
        """Get all settings as dictionary"""
        settings = {}
        
        # Start with defaults
        for key, config in cls.DEFAULTS.items():
            settings[key] = {
                'value': config['value'],
                'type': config['type'],
                'description': config['desc']
            }
        
        # Override with database values
        for setting in cls.query.all():
            settings[setting.key] = {
                'value': setting.get_typed_value(),
                'type': setting.value_type,
                'description': setting.description
            }
        
        return settings
    
    @classmethod
    def initialize_defaults(cls):
        """Initialize all default settings in database"""
        for key, config in cls.DEFAULTS.items():
            if not cls.query.filter_by(key=key).first():
                setting = cls(
                    key=key,
                    value=cls.set_typed_value(config['value'], config['type']),
                    value_type=config['type'],
                    description=config['desc']
                )
                db.session.add(setting)
        db.session.commit()


class AdminLog(db.Model):
    """Audit log for admin actions"""
    __tablename__ = 'admin_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50))  # user, setting, etc.
    target_id = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    admin = db.relationship('User', backref='admin_logs')
    
    def __repr__(self):
        return f'<AdminLog {self.action} by {self.admin_id}>'
    
    @classmethod
    def log(cls, admin_id, action, target_type=None, target_id=None, details=None, ip_address=None):
        """Create an admin log entry"""
        log_entry = cls(
            admin_id=admin_id,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            details=details,
            ip_address=ip_address
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry