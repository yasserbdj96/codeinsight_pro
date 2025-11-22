# utils/helpers.py
import time
import logging
from datetime import datetime, timedelta
from threading import Thread

from config import config
from models import db

# Set up logger
logger = logging.getLogger("background_tasks")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def init_app():
    """Initialize the application database and default settings"""
    try:
        # Create all tables
        db.create_all()
        logger.info("✓ Database tables created")
        
        # Initialize site settings with defaults
        from models import SiteSettings
        SiteSettings.initialize_defaults()
        logger.info("✓ Site settings initialized")
        
        # Create default admin if none exists
        create_default_admin()
        
        logger.info("✓ Application initialized successfully")
        
    except Exception as e:
        logger.error(f"✗ Error initializing application: {e}")
        raise


def create_default_admin():
    """Create a default admin user if no admins exist"""
    from models import User
    
    # Check if any admin exists
    admin_exists = User.query.filter_by(is_admin=True).first()
    
    if not admin_exists:
        logger.info("No admin found. First user to login will become admin.")
        # We'll make the first user an admin via a flag
        from models import SiteSettings
        SiteSettings.set('first_user_is_admin', True)


def check_daily():
    """Background tasks that run daily"""
    while True:
        try:
            now = datetime.now()
            next_midnight = now.replace(
                hour=config.CHECK_HOUR, 
                minute=config.CHECK_MINUTE, 
                second=config.CHECK_SECOND, 
                microsecond=0
            ) + timedelta(days=1)
            
            seconds_until_midnight = (next_midnight - now).total_seconds()
            logger.info(f"✓ Next daily check at: {next_midnight} (in {seconds_until_midnight:.0f} seconds)")
            
            time.sleep(seconds_until_midnight)
            perform_daily_tasks()
            
        except Exception as e:
            logger.error(f"✗ Error in daily task scheduler: {e}")
            time.sleep(3600)


def perform_daily_tasks():
    """Perform daily maintenance tasks"""
    logger.info(f"★ Daily tasks started at {datetime.now()}")
    
    try:
        # Check premium expirations
        check_premium_expirations()
        
        # Clean up old sessions
        cleanup_old_sessions()
        
        # Other daily tasks...
        
        logger.info("✓ Daily tasks completed")
        
    except Exception as e:
        logger.error(f"✗ Error in daily tasks: {e}")


def check_premium_expirations():
    """Check and update expired premium subscriptions"""
    from models import User
    
    expired_users = User.query.filter(
        User.is_premium == True,
        User.premium_expires_at < datetime.utcnow()
    ).all()
    
    for user in expired_users:
        user.is_premium = False
        logger.info(f"Premium expired for user: {user.username}")
    
    if expired_users:
        db.session.commit()
        logger.info(f"✓ Expired {len(expired_users)} premium subscriptions")


def cleanup_old_sessions():
    """Clean up old session files"""
    import os
    import shutil
    
    session_dir = './flask_session'
    if not os.path.exists(session_dir):
        return
    
    try:
        cutoff = datetime.now() - timedelta(days=7)
        cleaned = 0
        
        for filename in os.listdir(session_dir):
            filepath = os.path.join(session_dir, filename)
            if os.path.isfile(filepath):
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                if file_time < cutoff:
                    os.remove(filepath)
                    cleaned += 1
        
        if cleaned > 0:
            logger.info(f"✓ Cleaned up {cleaned} old session files")
            
    except Exception as e:
        logger.warning(f"Could not clean sessions: {e}")


def start_background_tasks():
    """Start all background tasks"""
    try:
        Thread(target=check_daily, daemon=True).start()
        logger.info("✓ Background tasks started successfully")
    except Exception as e:
        logger.error(f"✗ Failed to start background tasks: {e}")