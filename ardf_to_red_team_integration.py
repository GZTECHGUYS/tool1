#!/usr/bin/env python3
"""
ARDF-to-Red-Team Integration Bridge
Connects pn2hh/ARDF orchestration + findings to red_team_suite offensive capabilities.
Handles playbook discovery, finding enrichment, adaptive exploitation chain generation.
"""

import json
import sqlite3
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from enum import Enum
import re
import hashlib


class PlaybookPhase(Enum):
    """pn2hh/ARDF playbook phases."""
    OSINT = "osint"
    RECON = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULN_ASSESSMENT = "vuln_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


class AttackSurface(Enum):
    """Attack surface categories for finding classification."""
    WEB_APP = "web_app"
    API = "api"
    NETWORK_SERVICE = "network_service"
    SYSTEM = "system"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    IDENTITY = "identity"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class ARDFFinding:
    """Parsed ARDF finding from session export."""
    finding_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    asset: str
    mitre_techniques: List[str]  # ["T1234", "T1235"]
    cves: List[str]
    evidence: str
    timestamp: str
    finding_type: str  # recon, vuln, config_issue, cred_exposure
    
    def surface(self) -> AttackSurface:
        """Infer attack surface from evidence."""
        evidence_lower = self.evidence.lower()
        if "sql" in evidence_lower or "xss" in evidence_lower or "csrf" in evidence_lower:
            return AttackSurface.WEB_APP
        if "api" in evidence_lower:
            return AttackSurface.API
        if "open port" in evidence_lower or "service" in evidence_lower:
            return AttackSurface.NETWORK_SERVICE
        if "privilege" in evidence_lower or "kernel" in evidence_lower:
            return AttackSurface.SYSTEM
        if "s3" in evidence_lower or "azure" in evidence_lower or "gcp" in evidence_lower:
            return AttackSurface.CLOUD_INFRASTRUCTURE
        if "ldap" in evidence_lower or "ad" in evidence_lower or "mfa" in evidence_lower:
            return AttackSurface.IDENTITY
        if "dependency" in evidence_lower or "package" in evidence_lower:
            return AttackSurface.SUPPLY_CHAIN
        return AttackSurface.SYSTEM


@dataclass
class ExploitationChain:
    """Ordered exploitation chain generated from findings."""
    chain_id: str
    findings: List[ARDFFinding]
    phases: List[PlaybookPhase]
    evasion_techniques: List[str]  # EDR, WAF, IDS bypass methods
    exploits: List[str]  # Specific module names from our suite
    success_probability: float
    detection_risk: float
    requires_credentials: bool
    estimated_execution_time: int  # seconds
    cleanup_required: bool


class ARDFSessionParser:
    """Parses pn2hh/ARDF session exports."""
    
    def __init__(self, session_export_path: str):
        """
        Load ARDF session export (findings.jsonl format).
        """
        self.session_path = session_export_path
        self.findings: List[ARDFFinding] = []
        self._parse_session()
    
    def _parse_session(self):
        """Read findings.jsonl and parse findings."""
        try:
            with open(self.session_path, 'r') as f:
                for line in f:
                    if line.strip():
                        raw = json.loads(line)
                        finding = ARDFFinding(
                            finding_id=raw.get('id', str(hashlib.md5(str(raw).encode()).hexdigest())),
                            title=raw.get('title', 'Unknown'),
                            description=raw.get('description', ''),
                            severity=raw.get('severity', 'medium').lower(),
                            asset=raw.get('asset', 'unknown'),
                            mitre_techniques=raw.get('mitre_techniques', []),
                            cves=raw.get('cves', []),
                            evidence=raw.get('evidence', ''),
                            timestamp=raw.get('timestamp', datetime.now().isoformat()),
                            finding_type=raw.get('type', 'vuln'),
                        )
                        self.findings.append(finding)
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"[!] Failed to parse {self.session_path}")
            self.findings = []
    
    def findings_by_severity(self) -> Dict[str, List[ARDFFinding]]:
        """Group findings by severity."""
        grouped = {}
        for severity in ['critical', 'high', 'medium', 'low']:
            grouped[severity] = [f for f in self.findings if f.severity == severity]
        return grouped
    
    def findings_by_surface(self) -> Dict[AttackSurface, List[ARDFFinding]]:
        """Group findings by attack surface."""
        grouped = {}
        for finding in self.findings:
            surface = finding.surface()
            if surface not in grouped:
                grouped[surface] = []
            grouped[surface].append(finding)
        return grouped


class MITREToEvasionMapper:
    """Maps MITRE techniques to our evasion modules."""
    
    # Mapping: MITRE technique ID -> evasion technique in our suite
    TECHNIQUE_EVASION_MAP = {
        # Discovery / Evasion combo
        'T1518': ['SandboxEvader'],  # Software Discovery
        'T1082': ['SandboxEvader'],  # System Information Discovery
        'T1007': ['ProcessMasquerader'],  # System Service Discovery
        'T1614': ['BehavioralEvader'],  # System Location Discovery
        
        # Defense Evasion
        'T1548': ['PrivilegeEscalationEngine'],  # Abuse Elevation Control
        'T1197': ['CloudSecurityEvader'],  # BITS Jobs
        'T1612': ['BehavioralEvader'],  # Build Image on Host
        'T1140': ['PayloadObfuscator'],  # Deobfuscate/Decode Files
        'T1197': ['CloudSecurityEvader'],  # BITS
        'T1027': ['PayloadObfuscator'],  # Obfuscated Files
        'T1036': ['ProcessMasquerader'],  # Masquerading
        'T1556': ['WAFEvader'],  # Modify Authentication Process
        'T1564': ['ProcessMasquerader'],  # Hide Artifacts
        'T1562': ['LogErasure'],  # Indicator Removal
        'T1070': ['LogErasure'],  # Indicator Removal on Host
        'T1202': ['IDSEvader'],  # Indirect Command Execution
        'T1578': ['CloudSecurityEvader'],  # Modify Cloud Instance
        'T1112': ['RegistryMasquerader'],  # Modify Registry
        'T1601': ['BehavioralEvader'],  # Modify System Image
        'T1599': ['EDREvader'],  # Network Boundary Bridging
        'T1542': ['PersistenceEngine'],  # Pre-OS Boot
        'T1207': ['IDSEvader'],  # Rogue Domain Controller
        'T1014': ['PayloadObfuscator'],  # Rootkit
        'T1218': ['ProcessInjection'],  # Signed Binary Proxy
        'T1216': ['ProcessInjection'],  # System Script Proxy
        'T1535': ['ProcessMasquerader'],  # Unused/Unsupported
        'T1550': ['MFABypass'],  # Use Alternate Auth
        'T1199': ['WirelessCompromise'],  # Trusted Relationship
        'T1078': ['CredentialAttackEngine'],  # Valid Accounts
        'T1197': ['CloudSecurityEvader'],  # BITS Jobs
        
        # Lateral Movement
        'T1570': ['LateralMovementEngine'],  # Lateral Tool Transfer
        'T1570': ['LateralMovementEngine'],  # Lateral Tool Transfer
        'T1570': ['LateralMovementEngine'],  # Lateral Tool Transfer
        
        # Persistence
        'T1098': ['PersistenceEngine'],  # Account Manipulation
        'T1547': ['PersistenceEngine'],  # Boot or Logon Init
        'T1547': ['PersistenceEngine'],  # Boot or Logon Init
        'T1037': ['PersistenceEngine'],  # Boot or Logon Init Scripts
        'T1547': ['PersistenceEngine'],  # Boot or Logon Init
        'T1547': ['PersistenceEngine'],  # Boot or Logon Init
        'T1547': ['PersistenceEngine'],  # Boot or Logon Init
        'T1547': ['PersistenceEngine'],  # Boot or Logon Init
    }
    
    @classmethod
    def techniques_to_evasion(cls, techniques: List[str]) -> List[str]:
        """Convert MITRE techniques to evasion modules."""
        evasion_set = set()
        for tech in techniques:
            if tech in cls.TECHNIQUE_EVASION_MAP:
                evasion_set.update(cls.TECHNIQUE_EVASION_MAP[tech])
        return list(evasion_set)


class ExploitationChainBuilder:
    """Builds exploitation chains from grouped findings."""
    
    def __init__(self):
        self.chains: List[ExploitationChain] = []
    
    def build_chains(self, findings: List[ARDFFinding]) -> List[ExploitationChain]:
        """
        Build chains from findings.
        Chains are ordered by: crit/high findings first, then medium/low.
        Each chain phases through exploitation → post-ex → persistence.
        """
        by_severity = {}
        for finding in findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)
        
        chains = []
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            if severity not in by_severity:
                continue
            for finding in by_severity[severity]:
                chain = self._finding_to_chain(finding, severity_order.index(severity))
                chains.append(chain)
        
        self.chains = chains
        return chains
    
    def _finding_to_chain(self, finding: ARDFFinding, priority: int) -> ExploitationChain:
        """Convert single finding to exploitation chain."""
        surface = finding.surface()
        evasion = MITREToEvasionMapper.techniques_to_evasion(finding.mitre_techniques)
        
        # Determine exploit modules based on surface and finding
        exploits = self._select_exploits(finding, surface)
        
        # Phase sequence depends on finding type
        phases = self._build_phase_sequence(finding)
        
        # Success probability: higher for known CVEs, lower for config issues
        if finding.cves:
            success_prob = 0.85
        else:
            success_prob = 0.60
        
        # Detection risk: higher for active scanning, lower for evasion
        detection_risk = 0.5 if evasion else 0.8
        
        requires_creds = "cred" in finding.evidence.lower() or "auth" in finding.evidence.lower()
        
        chain_id = f"chain_{hashlib.md5(finding.finding_id.encode()).hexdigest()[:12]}"
        
        return ExploitationChain(
            chain_id=chain_id,
            findings=[finding],
            phases=phases,
            evasion_techniques=evasion,
            exploits=exploits,
            success_probability=success_prob,
            detection_risk=detection_risk,
            requires_credentials=requires_creds,
            estimated_execution_time=300 + (priority * 60),
            cleanup_required=True,
        )
    
    def _select_exploits(self, finding: ARDFFinding, surface: AttackSurface) -> List[str]:
        """Select appropriate exploit modules."""
        exploits = []
        
        if surface == AttackSurface.WEB_APP:
            if "sql" in finding.evidence.lower():
                exploits.append("WebAppExploit.SQLi")
            if "xss" in finding.evidence.lower():
                exploits.append("WebAppExploit.XSS")
            if "xxe" in finding.evidence.lower():
                exploits.append("WebAppExploit.XXE")
            exploits.append("WebAppExploit.SSRF")
        
        elif surface == AttackSurface.NETWORK_SERVICE:
            if finding.cves:
                exploits.append("CVEExploitManager.query_by_cve")
            exploits.append("CredentialAttackEngine.spray")
        
        elif surface == AttackSurface.SYSTEM:
            if "privilege" in finding.evidence.lower():
                exploits.append("PrivilegeEscalationEngine.windows_uac_bypass")
                exploits.append("PrivilegeEscalationEngine.linux_sudo_exploit")
            if finding.cves:
                exploits.append("CVEExploitManager.query_by_cve")
        
        elif surface == AttackSurface.CLOUD_INFRASTRUCTURE:
            exploits.append("CloudSecurityEvader.aws_guardduty_bypass")
            exploits.append("DataExfiltrationEngine.cloud_storage_exfil")
        
        elif surface == AttackSurface.IDENTITY:
            exploits.append("MFABypass.token_interception")
            exploits.append("CredentialAttackEngine.spray")
        
        elif surface == AttackSurface.SUPPLY_CHAIN:
            exploits.append("SupplyChainAttack.dependency_injection")
            exploits.append("SupplyChainAttack.npm_hijacking")
        
        return exploits
    
    def _build_phase_sequence(self, finding: ARDFFinding) -> List[PlaybookPhase]:
        """Determine phase sequence."""
        phases = []
        
        # Always start with enumeration if not already done
        if finding.finding_type == 'recon':
            phases.append(PlaybookPhase.ENUMERATION)
        
        # Always attempt exploitation if surface allows
        phases.append(PlaybookPhase.EXPLOITATION)
        
        # Add post-ex if exploitation likely succeeds
        if finding.severity in ['critical', 'high']:
            phases.append(PlaybookPhase.POST_EXPLOITATION)
            phases.append(PlaybookPhase.LATERAL_MOVEMENT)
            phases.append(PlaybookPhase.PERSISTENCE)
        
        # Exfil is conditional on persistence success
        phases.append(PlaybookPhase.EXFILTRATION)
        
        # Always cleanup
        phases.append(PlaybookPhase.CLEANUP)
        
        return phases


class PlaybookDiscovery:
    """Discover playbooks in pn2hh/ARDF config and map to red team phases."""
    
    PLAYBOOK_PHASES = {
        'full': [
            PlaybookPhase.OSINT,
            PlaybookPhase.RECON,
            PlaybookPhase.SCANNING,
            PlaybookPhase.ENUMERATION,
            PlaybookPhase.VULN_ASSESSMENT,
            PlaybookPhase.EXPLOITATION,
            PlaybookPhase.POST_EXPLOITATION,
            PlaybookPhase.LATERAL_MOVEMENT,
            PlaybookPhase.PERSISTENCE,
            PlaybookPhase.EXFILTRATION,
            PlaybookPhase.CLEANUP,
        ],
        'passive': [
            PlaybookPhase.OSINT,
            PlaybookPhase.RECON,
        ],
        'web': [
            PlaybookPhase.RECON,
            PlaybookPhase.SCANNING,
            PlaybookPhase.ENUMERATION,
            PlaybookPhase.VULN_ASSESSMENT,
            PlaybookPhase.EXPLOITATION,
            PlaybookPhase.POST_EXPLOITATION,
        ],
        'purple': [
            PlaybookPhase.EXPLOITATION,
            PlaybookPhase.POST_EXPLOITATION,
            PlaybookPhase.LATERAL_MOVEMENT,
            PlaybookPhase.PERSISTENCE,
        ],
    }
    
    @classmethod
    def playbook_phases(cls, playbook_name: str) -> List[PlaybookPhase]:
        """Get phases for a playbook."""
        return cls.PLAYBOOK_PHASES.get(playbook_name.lower(), [])


class ARDFRedTeamBridge:
    """Main integration bridge: ARDF session → red team orchestrator."""
    
    def __init__(self, ardf_session_export: str):
        self.parser = ARDFSessionParser(ardf_session_export)
        self.chain_builder = ExploitationChainBuilder()
        self.chains: List[ExploitationChain] = []
    
    def analyze(self) -> Dict:
        """Analyze ARDF session and generate exploitation chains."""
        findings = self.parser.findings
        if not findings:
            return {"status": "no_findings"}
        
        self.chains = self.chain_builder.build_chains(findings)
        
        return {
            "status": "success",
            "total_findings": len(findings),
            "findings_by_severity": {
                k: len(v) for k, v in self.parser.findings_by_severity().items()
            },
            "findings_by_surface": {
                str(k): len(v) for k, v in self.parser.findings_by_surface().items()
            },
            "exploitation_chains": len(self.chains),
            "chains": [asdict(c) for c in self.chains],
        }
    
    def export_for_orchestrator(self) -> str:
        """Export chains as JSON for orchestrator input."""
        chains_data = [asdict(c) for c in self.chains]
        return json.dumps(chains_data, indent=2)
    
    def highest_value_chain(self) -> Optional[ExploitationChain]:
        """Return chain with highest success × lowest detection risk."""
        if not self.chains:
            return None
        scored = [
            (c, c.success_probability / (c.detection_risk + 0.1)) 
            for c in self.chains
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[0][0]


def main():
    """Demo: parse ARDF session, generate chains."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ardf_to_red_team_integration.py <findings.jsonl>")
        sys.exit(1)
    
    session_path = sys.argv[1]
    bridge = ARDFRedTeamBridge(session_path)
    
    analysis = bridge.analyze()
    print(json.dumps(analysis, indent=2))
    
    top_chain = bridge.highest_value_chain()
    if top_chain:
        print(f"\n[*] Highest-value chain: {top_chain.chain_id}")
        print(f"    Success prob: {top_chain.success_probability:.2f}")
        print(f"    Detection risk: {top_chain.detection_risk:.2f}")
        print(f"    Phases: {[p.value for p in top_chain.phases]}")


if __name__ == '__main__':
    main()
