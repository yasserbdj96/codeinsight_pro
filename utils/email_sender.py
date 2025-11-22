# utils/email_sender.py
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, Dict, Any
from flask import request
from user_agents import parse as parse_user_agent
import requests

from config import config

logger = logging.getLogger("email_sender")

class EmailSender:
    def __init__(self):
        self.mail_server = config.MAIL_SERVER
        self.mail_port = config.EMAIL_PORT
        self.mail_username = config.MAIL_USERNAME
        self.mail_password = config.MAIL_PASSWORD
        self.mail_sender = config.MAIL_DEFAULT_SENDER
        self.app_name = "CodeInsight"
        self.app_url = "https://codeinsight.com"
    
    def _get_client_info(self) -> Dict[str, Any]:
        """Get client information from request"""
        info = {
            'ip': 'Unknown',
            'location': 'Unknown',
            'device': 'Unknown',
            'browser': 'Unknown',
            'os': 'Unknown',
            'time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        
        try:
            # Get IP address
            if request:
                info['ip'] = (
                    request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
                    request.headers.get('X-Real-IP') or
                    request.remote_addr or
                    'Unknown'
                )
                
                # Parse User Agent
                ua_string = request.headers.get('User-Agent', '')
                if ua_string:
                    ua = parse_user_agent(ua_string)
                    info['browser'] = f"{ua.browser.family} {ua.browser.version_string}"
                    info['os'] = f"{ua.os.family} {ua.os.version_string}"
                    info['device'] = ua.device.family if ua.device.family != 'Other' else 'Desktop'
                
                # Get location from IP (using free API)
                if info['ip'] not in ['Unknown', '127.0.0.1', 'localhost']:
                    try:
                        geo_response = requests.get(
                            f"http://ip-api.com/json/{info['ip']}?fields=city,country",
                            timeout=3
                        )
                        if geo_response.status_code == 200:
                            geo_data = geo_response.json()
                            city = geo_data.get('city', '')
                            country = geo_data.get('country', '')
                            if city and country:
                                info['location'] = f"{city}, {country}"
                            elif country:
                                info['location'] = country
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Could not get client info: {e}")
        
        return info
    
    def _get_email_template(self, template_type: str, lang: str = 'en') -> Dict[str, str]:
        """Get email template based on type and language"""
        templates = {
            'en': {
                'welcome': {
                    'subject': '🎉 Welcome to CodeInsight!',
                    'title': 'Welcome to CodeInsight!',
                    'greeting': 'Hello',
                    'main_text': 'Thank you for joining CodeInsight! We\'re excited to have you on board.',
                    'sub_text': 'Start exploring your code analytics and insights today.',
                    'button_text': 'Go to Dashboard',
                    'security_title': 'Account Created',
                    'footer_text': 'If you didn\'t create this account, please contact our support team immediately.'
                },
                'login': {
                    'subject': '🔐 New Login to Your CodeInsight Account',
                    'title': 'New Login Detected',
                    'greeting': 'Hello',
                    'main_text': 'We detected a new login to your CodeInsight account.',
                    'sub_text': 'If this was you, you can safely ignore this email.',
                    'button_text': 'Review Account Activity',
                    'security_title': 'Login Details',
                    'footer_text': 'If you didn\'t make this login, please secure your account immediately by changing your connected OAuth providers.'
                },
                'account_linked': {
                    'subject': '🔗 {provider} Account Linked Successfully',
                    'title': 'Account Linked Successfully',
                    'greeting': 'Hello',
                    'main_text': 'Your {provider} account has been successfully linked to your CodeInsight account.',
                    'sub_text': 'You can now use {provider} to sign in to CodeInsight.',
                    'button_text': 'Manage Connections',
                    'security_title': 'Connection Details',
                    'footer_text': 'If you didn\'t link this account, please disconnect it immediately from your settings.'
                },
                'account_disconnected': {
                    'subject': '🔓 {provider} Account Disconnected',
                    'title': 'Account Disconnected',
                    'greeting': 'Hello',
                    'main_text': 'Your {provider} account has been disconnected from your CodeInsight account.',
                    'sub_text': 'You can no longer use {provider} to sign in.',
                    'button_text': 'Manage Connections',
                    'security_title': 'Disconnection Details',
                    'footer_text': 'If you didn\'t disconnect this account, please secure your account immediately.'
                },
                'common': {
                    'time': 'Time',
                    'ip_address': 'IP Address',
                    'location': 'Location',
                    'device': 'Device',
                    'browser': 'Browser',
                    'operating_system': 'Operating System',
                    'copyright': '© {year} CodeInsight. All rights reserved.',
                    'unsubscribe': 'Unsubscribe from these emails',
                    'privacy': 'Privacy Policy',
                    'terms': 'Terms of Service'
                }
            },
            'ar': {
                'welcome': {
                    'subject': '🎉 مرحباً بك في كود إنسايت!',
                    'title': 'مرحباً بك في كود إنسايت!',
                    'greeting': 'مرحباً',
                    'main_text': 'شكراً لانضمامك إلى كود إنسايت! يسعدنا انضمامك إلينا.',
                    'sub_text': 'ابدأ استكشاف تحليلات ورؤى الكود الخاصة بك اليوم.',
                    'button_text': 'الذهاب إلى لوحة التحكم',
                    'security_title': 'تم إنشاء الحساب',
                    'footer_text': 'إذا لم تقم بإنشاء هذا الحساب، يرجى الاتصال بفريق الدعم فوراً.'
                },
                'login': {
                    'subject': '🔐 تسجيل دخول جديد إلى حسابك في كود إنسايت',
                    'title': 'تم اكتشاف تسجيل دخول جديد',
                    'greeting': 'مرحباً',
                    'main_text': 'اكتشفنا تسجيل دخول جديد إلى حسابك في كود إنسايت.',
                    'sub_text': 'إذا كان هذا أنت، يمكنك تجاهل هذا البريد الإلكتروني.',
                    'button_text': 'مراجعة نشاط الحساب',
                    'security_title': 'تفاصيل تسجيل الدخول',
                    'footer_text': 'إذا لم تقم بهذا تسجيل الدخول، يرجى تأمين حسابك فوراً.'
                },
                'account_linked': {
                    'subject': '🔗 تم ربط حساب {provider} بنجاح',
                    'title': 'تم ربط الحساب بنجاح',
                    'greeting': 'مرحباً',
                    'main_text': 'تم ربط حساب {provider} الخاص بك بنجاح بحسابك في كود إنسايت.',
                    'sub_text': 'يمكنك الآن استخدام {provider} لتسجيل الدخول إلى كود إنسايت.',
                    'button_text': 'إدارة الاتصالات',
                    'security_title': 'تفاصيل الاتصال',
                    'footer_text': 'إذا لم تقم بربط هذا الحساب، يرجى فصله فوراً من الإعدادات.'
                },
                'account_disconnected': {
                    'subject': '🔓 تم فصل حساب {provider}',
                    'title': 'تم فصل الحساب',
                    'greeting': 'مرحباً',
                    'main_text': 'تم فصل حساب {provider} الخاص بك من حسابك في كود إنسايت.',
                    'sub_text': 'لم يعد بإمكانك استخدام {provider} لتسجيل الدخول.',
                    'button_text': 'إدارة الاتصالات',
                    'security_title': 'تفاصيل الفصل',
                    'footer_text': 'إذا لم تقم بفصل هذا الحساب، يرجى تأمين حسابك فوراً.'
                },
                'common': {
                    'time': 'الوقت',
                    'ip_address': 'عنوان IP',
                    'location': 'الموقع',
                    'device': 'الجهاز',
                    'browser': 'المتصفح',
                    'operating_system': 'نظام التشغيل',
                    'copyright': '© {year} كود إنسايت. جميع الحقوق محفوظة.',
                    'unsubscribe': 'إلغاء الاشتراك من هذه الرسائل',
                    'privacy': 'سياسة الخصوصية',
                    'terms': 'شروط الخدمة'
                }
            }
        }
        
        lang = lang if lang in templates else 'en'
        return {**templates[lang].get(template_type, {}), 'common': templates[lang]['common']}
    
    def _build_html_email(self, template: Dict, username: str, client_info: Dict, 
                          lang: str = 'en', provider: str = None) -> str:
        """Build professional HTML email"""
        is_rtl = lang == 'ar'
        direction = 'rtl' if is_rtl else 'ltr'
        align = 'right' if is_rtl else 'left'
        
        # Replace provider placeholder if exists
        for key in template:
            if isinstance(template[key], str) and '{provider}' in template[key]:
                template[key] = template[key].replace('{provider}', provider or '')
        
        common = template.get('common', {})
        year = datetime.now().year
        
        html = f'''
<!DOCTYPE html>
<html lang="{lang}" dir="{direction}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{template.get('title', 'CodeInsight')}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f4f7fa; direction: {direction};">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f4f7fa; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08); overflow: hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 40px 30px; text-align: center;">
                            <img src="https://via.placeholder.com/60x60/ffffff/667eea?text=CI" alt="CodeInsight" style="width: 60px; height: 60px; border-radius: 12px; margin-bottom: 16px;">
                            <h1 style="color: #ffffff; font-size: 28px; font-weight: 700; margin: 0; letter-spacing: -0.5px;">{template.get('title', 'CodeInsight')}</h1>
                        </td>
                    </tr>
                    
                    <!-- Main Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <p style="font-size: 18px; color: #1a1a2e; margin: 0 0 8px; font-weight: 600; text-align: {align};">
                                {template.get('greeting', 'Hello')} {username}! 👋
                            </p>
                            <p style="font-size: 16px; color: #4a5568; line-height: 1.7; margin: 0 0 24px; text-align: {align};">
                                {template.get('main_text', '')}
                            </p>
                            <p style="font-size: 14px; color: #718096; line-height: 1.6; margin: 0 0 32px; text-align: {align};">
                                {template.get('sub_text', '')}
                            </p>
                            
                            <!-- CTA Button -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td align="center" style="padding-bottom: 32px;">
                                        <a href="{self.app_url}/dashboard" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; font-size: 16px; font-weight: 600; text-decoration: none; padding: 14px 32px; border-radius: 8px; box-shadow: 0 4px 14px rgba(102, 126, 234, 0.4);">
                                            {template.get('button_text', 'Go to Dashboard')}
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Security Info Box -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f8fafc; border-radius: 12px; border: 1px solid #e2e8f0;">
                                <tr>
                                    <td style="padding: 24px;">
                                        <p style="font-size: 14px; font-weight: 600; color: #1a1a2e; margin: 0 0 16px; text-align: {align};">
                                            🔒 {template.get('security_title', 'Security Details')}
                                        </p>
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">
                                                    <span style="font-size: 13px; color: #718096;">{common.get('time', 'Time')}:</span>
                                                    <span style="font-size: 13px; color: #1a1a2e; font-weight: 500; float: {'left' if is_rtl else 'right'};">{client_info['time']}</span>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">
                                                    <span style="font-size: 13px; color: #718096;">{common.get('ip_address', 'IP Address')}:</span>
                                                    <span style="font-size: 13px; color: #1a1a2e; font-weight: 500; float: {'left' if is_rtl else 'right'};">{client_info['ip']}</span>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">
                                                    <span style="font-size: 13px; color: #718096;">{common.get('location', 'Location')}:</span>
                                                    <span style="font-size: 13px; color: #1a1a2e; font-weight: 500; float: {'left' if is_rtl else 'right'};">{client_info['location']}</span>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">
                                                    <span style="font-size: 13px; color: #718096;">{common.get('device', 'Device')}:</span>
                                                    <span style="font-size: 13px; color: #1a1a2e; font-weight: 500; float: {'left' if is_rtl else 'right'};">{client_info['device']}</span>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">
                                                    <span style="font-size: 13px; color: #718096;">{common.get('browser', 'Browser')}:</span>
                                                    <span style="font-size: 13px; color: #1a1a2e; font-weight: 500; float: {'left' if is_rtl else 'right'};">{client_info['browser']}</span>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0;">
                                                    <span style="font-size: 13px; color: #718096;">{common.get('operating_system', 'OS')}:</span>
                                                    <span style="font-size: 13px; color: #1a1a2e; font-weight: 500; float: {'left' if is_rtl else 'right'};">{client_info['os']}</span>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Warning Footer -->
                            <p style="font-size: 13px; color: #e53e3e; line-height: 1.6; margin: 24px 0 0; padding: 16px; background-color: #fff5f5; border-radius: 8px; border-left: 4px solid #e53e3e; text-align: {align};">
                                ⚠️ {template.get('footer_text', '')}
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f8fafc; padding: 24px 40px; border-top: 1px solid #e2e8f0;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td align="center">
                                        <p style="font-size: 12px; color: #718096; margin: 0 0 8px;">
                                            {common.get('copyright', '').format(year=year)}
                                        </p>
                                        <p style="font-size: 12px; color: #718096; margin: 0;">
                                            <a href="{self.app_url}/privacy" style="color: #667eea; text-decoration: none;">{common.get('privacy', 'Privacy')}</a>
                                            &nbsp;•&nbsp;
                                            <a href="{self.app_url}/terms" style="color: #667eea; text-decoration: none;">{common.get('terms', 'Terms')}</a>
                                            &nbsp;•&nbsp;
                                            <a href="{self.app_url}/unsubscribe" style="color: #667eea; text-decoration: none;">{common.get('unsubscribe', 'Unsubscribe')}</a>
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
'''
        return html
    
    def send_welcome_email(self, to_email: str, username: str, lang: str = 'en') -> bool:
        """Send welcome email to new user"""
        template = self._get_email_template('welcome', lang)
        client_info = self._get_client_info()
        html_content = self._build_html_email(template, username, client_info, lang)
        return self.send_email(to_email, template['subject'], html_content)
    
    def send_login_email(self, to_email: str, username: str, lang: str = 'en') -> bool:
        """Send login notification email"""
        template = self._get_email_template('login', lang)
        client_info = self._get_client_info()
        html_content = self._build_html_email(template, username, client_info, lang)
        return self.send_email(to_email, template['subject'], html_content)
    
    def send_account_linked_email(self, to_email: str, username: str, provider: str, lang: str = 'en') -> bool:
        """Send account linked notification email"""
        template = self._get_email_template('account_linked', lang)
        client_info = self._get_client_info()
        subject = template['subject'].replace('{provider}', provider)
        html_content = self._build_html_email(template, username, client_info, lang, provider)
        return self.send_email(to_email, subject, html_content)
    
    def send_account_disconnected_email(self, to_email: str, username: str, provider: str, lang: str = 'en') -> bool:
        """Send account disconnected notification email"""
        template = self._get_email_template('account_disconnected', lang)
        client_info = self._get_client_info()
        subject = template['subject'].replace('{provider}', provider)
        html_content = self._build_html_email(template, username, client_info, lang, provider)
        return self.send_email(to_email, subject, html_content)
    
    def send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None) -> bool:
        """Send email using SMTP"""
        if not to_email:
            logger.warning("No email address provided")
            return False
            
        if not self.mail_username or not self.mail_password:
            logger.warning("Email credentials not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.app_name} <{self.mail_sender}>"
            msg['To'] = to_email
            msg['Reply-To'] = self.mail_sender
            
            if not text_content:
                import re
                text_content = re.sub('<[^<]+?>', '', html_content)
                text_content = re.sub(r'\n+', '\n', text_content).strip()
            
            part1 = MIMEText(text_content, 'plain', 'utf-8')
            part2 = MIMEText(html_content, 'html', 'utf-8')
            
            msg.attach(part1)
            msg.attach(part2)
            
            with smtplib.SMTP(self.mail_server, self.mail_port, timeout=30) as server:
                server.starttls()
                server.login(self.mail_username, self.mail_password)
                server.send_message(msg)
            
            logger.info(f"✓ Email sent successfully to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"✗ SMTP Authentication failed: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"✗ SMTP error sending to {to_email}: {e}")
            return False
        except Exception as e:
            logger.error(f"✗ Failed to send email to {to_email}: {e}")
            return False

# Create a global instance
email_sender = EmailSender()