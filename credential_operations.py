"""
modules/credential_operations.py
────────────────────────────────
Credential theft, extraction, cracking, and abuse.

Operations:
  - LSASS memory dumping (Mimikatz wrapper)
  - Hash extraction (NTLM, Kerberos)
  - Credential hunting (plaintext in registry, config, browser storage)
  - Hash cracking and wordlist attacks
  - Credential spraying (Kerberos, NTLM)
  - Pass-the-Hash (PTH) execution
  - Pass-the-Ticket (PTT) execution
  - Golden Ticket generation
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime

from modules.redteam_base import RedTeamModule
from modules.session import Session, SeverityLevel
from modules.logger import ARDFLogger, get_logger


class CredentialType(Enum):
    """Types of credentials."""
    PLAINTEXT = "plaintext"
    NTLM_HASH = "ntlm_hash"
    NTLM_V2_HASH = "ntlm_v2_hash"
    MD5 = "md5"
    KERBEROS_TICKET = "kerberos_ticket"
    SERVICE_ACCOUNT_HASH = "service_account_hash"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"


class CredentialSource(Enum):
    """Where credential was obtained."""
    LSASS_DUMP = "lsass_dump"
    SAM_DATABASE = "sam_database"
    NTDS_DIT = "ntds_dit"
    REGISTRY = "registry"
    CONFIG_FILE = "config_file"
    BROWSER_STORAGE = "browser_storage"
    MEMORY_SCAN = "memory_scan"
    NETWORK_CAPTURE = "network_capture"
    MANUAL_ENTRY = "manual_entry"


@dataclass
class Credential:
    """Single credential entry."""
    
    credential_id: str = ""
    username: str = ""
    password_hash: str = ""
    password_plaintext: Optional[str] = None
    domain: str = ""
    credential_type: CredentialType = CredentialType.NTLM_HASH
    source: CredentialSource = CredentialSource.LSASS_DUMP
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cracked: bool = False
    crack_time: Optional[float] = None  # seconds to crack
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "username": self.username,
            "domain": self.domain,
            "credential_type": self.credential_type.value,
            "source": self.source.value,
            "cracked": self.cracked,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class CredentialSprayTarget:
    """Target for credential spraying."""
    
    hostname: str = ""
    ip_address: str = ""
    service: str = "SMB"  # SMB, Kerberos, WinRM, SSH
    port: int = 445
    metadata: Dict[str, Any] = field(default_factory=dict)


class CredentialOperationsModule(RedTeamModule):
    """Credential theft, cracking, and abuse."""
    
    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        super().__init__(session, logger)
        self.credentials: Dict[str, Credential] = {}
        self.spray_targets: List[CredentialSprayTarget] = []
        self.successful_sprays: List[Dict[str, Any]] = []
        self.cracked_count = 0
        self.wordlist_loaded = False
    
    def execute(self) -> Dict[str, Any]:
        """Execute credential operations workflow."""
        self.set_opsec_profile(
            noise_level=0.8,
            detectability=0.85,
            evidence=["auth logs", "process execution logs", "network traffic"],
            recovery_time=1800,
        )
        
        self.log_info("Starting credential operations")
        
        try:
            # Step 1: Extract credentials from memory
            extracted = self._extract_credentials_from_lsass()
            
            # Step 2: Hunt for plaintext credentials
            plaintext = self._hunt_plaintext_credentials()
            
            # Step 3: Crack hashes
            cracked = self._crack_hashes()
            
            # Step 4: Prepare spray targets
            targets = self._enumerate_spray_targets()
            
            # Step 5: Perform credential spraying
            spray_results = self._spray_credentials(targets)
            
            # Step 6: Execute pass-the-hash
            pth_results = self._execute_pass_the_hash()
            
            return {
                "success": True,
                "findings": self.findings,
                "credentials_extracted": len(self.credentials),
                "credentials_cracked": self.cracked_count,
                "spray_successful": len(self.successful_sprays),
                "output": {
                    "credentials": len(self.credentials),
                    "spray_results": spray_results,
                    "pth_results": pth_results,
                }
            }
        except Exception as e:
            self.log_error(f"Credential operations failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": self.findings,
            }
    
    def _extract_credentials_from_lsass(self) -> List[Credential]:
        """Extract credentials from LSASS memory."""
        self.log_info("Dumping LSASS memory")
        
        extracted = []
        
        # Simulate LSASS dump with mimikatz
        lsass_data = [
            {
                "username": "Administrator",
                "domain": "DOMAIN",
                "ntlm": "8846f7eaee8fb117ad06bdd830b7586c",
                "status": "cached",
            },
            {
                "username": "john.doe",
                "domain": "DOMAIN",
                "ntlm": "5f4dcc3b5aa765d61d8327deb882cf99",
                "status": "active",
            },
            {
                "username": "service_account",
                "domain": "DOMAIN",
                "ntlm": "aad3b435b51404eeaad3b435b51404ee",
                "status": "service",
            },
            {
                "username": "krbtgt",
                "domain": "DOMAIN",
                "ntlm": "9d765b482771d33b35834e1e570a2d4b",
                "status": "krbtgt",
            },
        ]
        
        for data in lsass_data:
            cred = Credential(
                credential_id=f"cred_{len(self.credentials)}",
                username=data["username"],
                password_hash=data["ntlm"],
                domain=data["domain"],
                credential_type=CredentialType.NTLM_HASH,
                source=CredentialSource.LSASS_DUMP,
                metadata={
                    "status": data["status"],
                    "dumped_via": "mimikatz",
                },
            )
            
            self.credentials[cred.credential_id] = cred
            extracted.append(cred)
            
            self.log_debug(f"Extracted: {data['username']}@{data['domain']}")
        
        self.add_finding(
            title="LSASS Dumped",
            description=f"Extracted {len(extracted)} credentials from LSASS memory",
            severity=SeverityLevel.CRITICAL,
            category="credential_extraction",
            metadata={
                "method": "mimikatz",
                "count": len(extracted),
                "hashes": [c.password_hash for c in extracted],
            },
        )
        
        return extracted
    
    def _hunt_plaintext_credentials(self) -> List[Credential]:
        """Hunt for plaintext credentials in common locations."""
        self.log_info("Hunting for plaintext credentials")
        
        found = []
        
        hunt_locations = [
            {
                "location": "Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "cred": "admin:P@ssw0rd123",
            },
            {
                "location": "Config file: C:\\App\\config.xml",
                "cred": "dbuser:SecretPass456",
            },
            {
                "location": "Browser storage: SQLite database",
                "cred": "user@domain:BrowserPassword789",
            },
            {
                "location": "Script file: backup_script.ps1",
                "cred": "service_account:ServicePass2024",
            },
        ]
        
        for hunt in hunt_locations:
            username, password = hunt["cred"].split(":")
            
            cred = Credential(
                credential_id=f"cred_{len(self.credentials)}",
                username=username,
                password_plaintext=password,
                password_hash=hashlib.md5(password.encode()).hexdigest(),
                credential_type=CredentialType.PLAINTEXT,
                source=CredentialSource.CONFIG_FILE,
                metadata={"location": hunt["location"]},
            )
            
            self.credentials[cred.credential_id] = cred
            found.append(cred)
            
            self.log_info(f"Found plaintext credential: {username} in {hunt['location']}")
        
        self.add_finding(
            title="Plaintext Credentials Discovered",
            description=f"Found {len(found)} plaintext credentials in config files and registry",
            severity=SeverityLevel.CRITICAL,
            category="credential_discovery",
            metadata={"count": len(found), "locations": [h["location"] for h in hunt_locations]},
        )
        
        return found
    
    def _crack_hashes(self) -> int:
        """Attempt to crack extracted hashes."""
        self.log_info("Cracking credential hashes")
        
        # Simulated wordlist
        wordlist = [
            "password", "123456", "password123", "admin",
            "letmein", "qwerty", "monkey", "dragon",
            "master", "sunshine", "princess", "P@ssw0rd"
        ]
        
        cracked = 0
        
        for cred_id, cred in self.credentials.items():
            if cred.credential_type != CredentialType.PLAINTEXT and not cred.cracked:
                # Check each word against hash
                for word in wordlist:
                    test_hash = hashlib.md5(word.encode()).hexdigest()
                    
                    if test_hash == cred.password_hash or word.lower() == cred.username.lower():
                        cred.cracked = True
                        cred.password_plaintext = word
                        cred.crack_time = 0.5
                        cracked += 1
                        
                        self.log_info(f"Cracked: {cred.username}:{word}")
                        break
        
        self.cracked_count = cracked
        
        self.add_finding(
            title="Hashes Cracked",
            description=f"Successfully cracked {cracked} credential hashes",
            severity=SeverityLevel.HIGH,
            category="credential_cracking",
            metadata={
                "cracked_count": cracked,
                "method": "wordlist_attack",
            },
        )
        
        return cracked
    
    def _enumerate_spray_targets(self) -> List[CredentialSprayTarget]:
        """Enumerate targets for credential spraying."""
        self.log_info("Enumerating spray targets")
        
        targets = [
            CredentialSprayTarget(
                hostname="SERVER01",
                ip_address="192.168.1.50",
                service="SMB",
                port=445,
            ),
            CredentialSprayTarget(
                hostname="SERVER02",
                ip_address="192.168.1.51",
                service="Kerberos",
                port=88,
            ),
            CredentialSprayTarget(
                hostname="WORKSTATION01",
                ip_address="192.168.1.100",
                service="WinRM",
                port=5985,
            ),
            CredentialSprayTarget(
                hostname="DC01",
                ip_address="192.168.1.10",
                service="Kerberos",
                port=88,
            ),
        ]
        
        self.spray_targets = targets
        
        self.log_info(f"Enumerated {len(targets)} targets for spraying")
        
        return targets
    
    def _spray_credentials(self, targets: List[CredentialSprayTarget]) -> List[Dict[str, Any]]:
        """Perform credential spraying against targets."""
        self.log_info(f"Spraying credentials against {len(targets)} targets")
        
        results = []
        
        # Get cracked credentials
        spray_creds = [
            c for c in self.credentials.values()
            if c.password_plaintext or c.cracked
        ]
        
        for target in targets:
            for cred in spray_creds[:3]:  # Limit attempts
                # Simulate spray attempt
                success = (cred.username.lower() in target.hostname.lower() or
                          "admin" in cred.username.lower())
                
                result = {
                    "target": target.hostname,
                    "username": cred.username,
                    "service": target.service,
                    "success": success,
                    "response_time": 0.5 if success else 2.0,
                }
                
                results.append(result)
                
                if success:
                    self.successful_sprays.append(result)
                    self.log_warning(f"SPRAY SUCCESS: {cred.username}@{target.hostname}")
                    
                    self.add_finding(
                        title=f"Credential Spray Success",
                        description=f"Successfully sprayed {cred.username} to {target.hostname} ({target.service})",
                        severity=SeverityLevel.CRITICAL,
                        category="credential_spray",
                        metadata=result,
                    )
        
        return results
    
    def _execute_pass_the_hash(self) -> List[Dict[str, Any]]:
        """Execute pass-the-hash attacks."""
        self.log_info("Executing pass-the-hash attacks")
        
        results = []
        
        # Get NTLM hashes
        ntlm_creds = [
            c for c in self.credentials.values()
            if c.credential_type in [CredentialType.NTLM_HASH, CredentialType.NTLM_V2_HASH]
        ]
        
        for cred in ntlm_creds[:3]:  # Limit to 3
            target = self.spray_targets[0] if self.spray_targets else None
            
            if target:
                result = {
                    "method": "pass_the_hash",
                    "user": cred.username,
                    "domain": cred.domain,
                    "hash": cred.password_hash,
                    "target": target.hostname,
                    "service": target.service,
                    "success": True,
                    "shell_type": "SMB_shell" if target.service == "SMB" else "WinRM",
                }
                
                results.append(result)
                
                self.log_info(f"PTH successful: {cred.username}@{target.hostname}")
                
                self.add_finding(
                    title=f"Pass-the-Hash Success",
                    description=f"Successfully authenticated to {target.hostname} using hash for {cred.username}",
                    severity=SeverityLevel.CRITICAL,
                    category="privilege_escalation",
                    metadata=result,
                )
        
        return results
    
    def add_credential(
        self,
        username: str,
        domain: str,
        password_hash: Optional[str] = None,
        password_plaintext: Optional[str] = None,
        cred_type: CredentialType = CredentialType.PLAINTEXT,
        source: CredentialSource = CredentialSource.MANUAL_ENTRY,
    ) -> str:
        """Manually add credential."""
        cred = Credential(
            credential_id=f"cred_{len(self.credentials)}",
            username=username,
            domain=domain,
            password_hash=password_hash or "",
            password_plaintext=password_plaintext,
            credential_type=cred_type,
            source=source,
        )
        
        self.credentials[cred.credential_id] = cred
        return cred.credential_id
    
    def get_valid_credentials(self) -> List[Credential]:
        """Get all cracked or plaintext credentials."""
        return [
            c for c in self.credentials.values()
            if c.password_plaintext or c.cracked
        ]
    
    def get_mitre_techniques(self) -> List[str]:
        """Return MITRE techniques used."""
        return [
            "T1110",  # Brute Force
            "T1110.004",  # Brute Force: Credential Stuffing
            "T1555",  # Credentials from Password Managers
            "T1187",  # Forced Authentication
            "T1040",  # Network Sniffing
            "T1003",  # OS Credential Dumping
            "T1556",  # Modify Authentication Process
            "T1550.002",  # Use Alternate Authentication Material: Pass the Hash
        ]
