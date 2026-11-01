#!/usr/bin/env python3
"""
ARDF + RedTeam Capability Gap Analyzer
Identifies missing capabilities, MITRE technique coverage gaps, recommends expansions.
Generates roadmap for filling gaps in pn2hh/ARDF + red_team_suite integration.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Tuple, Optional
from enum import Enum


class MITRETactic(Enum):
    """MITRE ATT&CK tactics."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    # ARDF extension — exploitation phase (mapped from Initial Access/Execution
    # when a chain reaches active exploitation).
    EXPLOITATION = "exploitation"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique."""
    id: str  # T1234
    name: str
    tactic: MITRETactic
    platforms: List[str] = field(default_factory=list)  # Windows, Linux, macOS, Cloud
    data_sources: List[str] = field(default_factory=list)
    is_sub_technique: bool = False


@dataclass
class CapabilityGap:
    """Identified capability gap."""
    technique: MITRETechnique
    coverage_type: str  # "missing", "partial", "weak"
    current_coverage: str  # What we have (if any)
    recommended_module: str
    priority: int  # 1-5, 5 = highest
    effort_to_implement: str  # low, medium, high
    estimated_lines_of_code: int
    attack_value: str  # How valuable this technique is
    notes: str = ""


@dataclass
class CapabilityGapReport:
    """Report of all gaps found."""
    total_mitre_techniques: int
    covered_techniques: int
    partial_techniques: int
    missing_techniques: int
    coverage_percentage: float
    gaps: List[CapabilityGap]
    recommendations: List[str]
    implementation_roadmap: List[Dict]


class ARDFCapabilityMap:
    """Maps what pn2hh/ARDF can do."""
    
    ARDF_MODULES = {
        "recon.py": {
            "techniques": ["T1592", "T1589", "T1590", "T1598", "T1597"],
            "tactic": MITRETactic.RECONNAISSANCE,
            "tools": ["subfinder", "amass", "nmap", "masscan"],
        },
        "exploit.py": {
            "techniques": ["T1190", "T1211", "T1200"],
            "tactic": MITRETactic.EXECUTION,
            "tools": ["metasploit_framework"],
        },
        "intel.py": {
            "techniques": ["T1589", "T1592", "T1598"],
            "tactic": MITRETactic.RECONNAISSANCE,
            "tools": ["shodan", "abuseipdb", "virustotal", "cve"],
        },
        "session.py": {
            "techniques": [],
            "tactic": None,
            "purpose": "Session management",
        },
        "report.py": {
            "techniques": [],
            "tactic": None,
            "purpose": "Reporting",
        },
        "logger.py": {
            "techniques": [],
            "tactic": None,
            "purpose": "Logging",
        },
        "defense/sigma_writer.py": {
            "techniques": [],
            "tactic": None,
            "purpose": "Defense detection rule generation",
        },
        "defense/hardening.py": {
            "techniques": [],
            "tactic": None,
            "purpose": "Hardening script generation",
        },
        "purple/purple_runner.py": {
            "techniques": [],
            "tactic": None,
            "purpose": "Purple team execution",
        },
    }


class RedTeamCapabilityMap:
    """Maps what our red team suite can do."""
    
    REDTEAM_MODULES = {
        "red_team_suite.py": {
            "techniques": [
                "T1098",  # Account Manipulation
                "T1547",  # Boot or Logon Init
                "T1087",  # Account Discovery
                "T1010",  # Application Window Discovery
                "T1217",  # Browser Bookmark Discovery
                "T1580",  # Cloud Infrastructure Discovery
                "T1526",  # Cloud Service Discovery
                "T1538",  # Cloud Service Enumeration
                "T1526",  # Cloud Service Discovery
                "T1619",  # Cloud Storage Object Discovery
                "T1613",  # Scheduled Task/Job Discovery
                "T1622",  # Debugger Evasion
                "T1140",  # Deobfuscate/Decode Files
                "T1005",  # Data from Local System
                "T1039",  # Data from Network Shared Drive
                "T1123",  # Audio Capture
                "T1119",  # Clipboard Data
                "T1115",  # Clipboard Data
            ],
            "tactic": MITRETactic.COLLECTION,
        },
        "defense_evasion_modules.py": {
            "techniques": [
                "T1548",  # Abuse Elevation Control
                "T1140",  # Deobfuscate/Decode Files
                "T1197",  # BITS Jobs
                "T1612",  # Build Image on Host
                "T1027",  # Obfuscated Files or Information
                "T1036",  # Masquerading
                "T1556",  # Modify Authentication Process
                "T1112",  # Modify Registry
                "T1601",  # Modify System Image
                "T1542",  # Pre-OS Boot
                "T1014",  # Rootkit
                "T1218",  # System Binary Proxy Execution
                "T1216",  # System Script Proxy Execution
                "T1564",  # Hide Artifacts
                "T1562",  # Indicator Removal
                "T1070",  # Indicator Removal on Host
                "T1202",  # Indirect Command Execution
                "T1207",  # Rogue Domain Controller
                "T1550",  # Use Alternate Authentication Material
            ],
            "tactic": MITRETactic.DEFENSE_EVASION,
        },
        "advanced_exploitation_modules.py": {
            "techniques": [
                "T1190",  # Exploit Public-Facing Application
                "T1200",  # Exploitation of Remote Services
                "T1531",  # Account Access Removal
                "T1197",  # BITS Jobs
                "T1037",  # Boot or Logon Init Scripts
                "T1547",  # Boot or Logon Autostart Execution
                "T1547",  # Boot or Logon Autostart Execution
                "T1547",  # Boot or Logon Autostart Execution
                "T1547",  # Boot or Logon Autostart Execution
                "T1133",  # External Remote Services
                "T1190",  # Exploit Public-Facing Application
                "T1200",  # Exploitation of Remote Services
            ],
            "tactic": MITRETactic.EXPLOITATION,
        },
        "unified_exploit_orchestrator.py": {
            "techniques": [
                "T1595",  # Active Scanning
                "T1592",  # Gather Victim Host Information
                "T1589",  # Gather Victim Identity Information
            ],
            "tactic": MITRETactic.RECONNAISSANCE,
        },
    }


class MITRECoverageLibrary:
    """Library of all MITRE techniques, coverage status."""
    
    # Comprehensive but not exhaustive
    ALL_TECHNIQUES = [
        # Reconnaissance
        MITRETechnique("T1592", "Gather Victim Host Information", MITRETactic.RECONNAISSANCE, ["Windows", "Linux", "macOS"]),
        MITRETechnique("T1589", "Gather Victim Identity Information", MITRETactic.RECONNAISSANCE),
        MITRETechnique("T1590", "Gather Victim Network Information", MITRETactic.RECONNAISSANCE),
        MITRETechnique("T1598", "Phishing for Information", MITRETactic.RECONNAISSANCE),
        MITRETechnique("T1597", "Search Open Websites/Domains", MITRETactic.RECONNAISSANCE),
        MITRETechnique("T1595", "Active Scanning", MITRETactic.RECONNAISSANCE),
        MITRETechnique("T1592", "Gather Victim Host Information", MITRETactic.RECONNAISSANCE),
        
        # Resource Development
        MITRETechnique("T1583", "Acquire Infrastructure", MITRETactic.RESOURCE_DEVELOPMENT),
        MITRETechnique("T1586", "Compromise Accounts", MITRETactic.RESOURCE_DEVELOPMENT),
        MITRETechnique("T1587", "Develop Capabilities", MITRETactic.RESOURCE_DEVELOPMENT),
        MITRETechnique("T1585", "Establish Accounts", MITRETactic.RESOURCE_DEVELOPMENT),
        
        # Initial Access
        MITRETechnique("T1189", "Drive-by Compromise", MITRETactic.INITIAL_ACCESS),
        MITRETechnique("T1190", "Exploit Public-Facing Application", MITRETactic.INITIAL_ACCESS, ["Windows", "Linux", "macOS"]),
        MITRETechnique("T1133", "External Remote Services", MITRETactic.INITIAL_ACCESS),
        MITRETechnique("T1200", "Exploitation of Remote Services", MITRETactic.INITIAL_ACCESS),
        MITRETechnique("T1199", "Trusted Relationship", MITRETactic.INITIAL_ACCESS),
        MITRETechnique("T1566", "Phishing", MITRETactic.INITIAL_ACCESS),
        MITRETechnique("T1195", "Supply Chain Compromise", MITRETactic.INITIAL_ACCESS),
        
        # Execution
        MITRETechnique("T1059", "Command and Scripting Interpreter", MITRETactic.EXECUTION, ["Windows", "Linux", "macOS"]),
        MITRETechnique("T1203", "Exploitation for Client Execution", MITRETactic.EXECUTION),
        MITRETechnique("T1559", "Inter-Process Communication", MITRETactic.EXECUTION),
        MITRETechnique("T1053", "Scheduled Task/Job", MITRETactic.EXECUTION),
        MITRETechnique("T1648", "Serverless Execution", MITRETactic.EXECUTION),
        
        # Persistence
        MITRETechnique("T1098", "Account Manipulation", MITRETactic.PERSISTENCE),
        MITRETechnique("T1197", "BITS Jobs", MITRETactic.PERSISTENCE),
        MITRETechnique("T1547", "Boot or Logon Autostart Execution", MITRETactic.PERSISTENCE),
        MITRETechnique("T1037", "Boot or Logon Init Scripts", MITRETactic.PERSISTENCE),
        MITRETechnique("T1554", "Compromise Client Software Binary", MITRETactic.PERSISTENCE),
        MITRETechnique("T1136", "Create Account", MITRETactic.PERSISTENCE),
        MITRETechnique("T1543", "Create or Modify System Process", MITRETactic.PERSISTENCE),
        
        # Privilege Escalation
        MITRETechnique("T1548", "Abuse Elevation Control Mechanism", MITRETactic.PRIVILEGE_ESCALATION),
        MITRETechnique("T1134", "Access Token Manipulation", MITRETactic.PRIVILEGE_ESCALATION),
        MITRETechnique("T1547", "Boot or Logon Autostart Execution", MITRETactic.PRIVILEGE_ESCALATION),
        MITRETechnique("T1543", "Create or Modify System Process", MITRETactic.PRIVILEGE_ESCALATION),
        MITRETechnique("T1547", "Boot or Logon Autostart Execution", MITRETactic.PRIVILEGE_ESCALATION),
        
        # Defense Evasion
        MITRETechnique("T1548", "Abuse Elevation Control Mechanism", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1140", "Deobfuscate/Decode Files or Information", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1197", "BITS Jobs", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1612", "Build Image on Host", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1027", "Obfuscated Files or Information", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1036", "Masquerading", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1562", "Indicator Removal", MITRETactic.DEFENSE_EVASION),
        MITRETechnique("T1070", "Indicator Removal on Host", MITRETactic.DEFENSE_EVASION),
        
        # Credential Access
        MITRETechnique("T1110", "Brute Force", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1555", "Credentials from Password Stores", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1187", "Forced Authentication", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1111", "Multi-Stage Channels", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1040", "Network Sniffing", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1556", "Modify Authentication Process", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1557", "Man-in-the-Middle", MITRETactic.CREDENTIAL_ACCESS),
        MITRETechnique("T1621", "Multi-Factor Authentication Interception", MITRETactic.CREDENTIAL_ACCESS),
        
        # Discovery
        MITRETechnique("T1087", "Account Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1010", "Application Window Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1217", "Browser Bookmark Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1580", "Cloud Infrastructure Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1526", "Cloud Service Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1619", "Cloud Storage Object Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1613", "Scheduled Task/Job Discovery", MITRETactic.DISCOVERY),
        MITRETechnique("T1538", "Cloud Service Enumeration", MITRETactic.DISCOVERY),
        
        # Lateral Movement
        MITRETechnique("T1210", "Exploitation of Remote Services", MITRETactic.LATERAL_MOVEMENT),
        MITRETechnique("T1534", "Internal Spearphishing", MITRETactic.LATERAL_MOVEMENT),
        MITRETechnique("T1570", "Lateral Tool Transfer", MITRETactic.LATERAL_MOVEMENT),
        MITRETechnique("T1021", "Remote Services", MITRETactic.LATERAL_MOVEMENT),
        
        # Collection
        MITRETechnique("T1123", "Audio Capture", MITRETactic.COLLECTION),
        MITRETechnique("T1119", "Automated Exfiltration", MITRETactic.COLLECTION),
        MITRETechnique("T1115", "Clipboard Data", MITRETactic.COLLECTION),
        MITRETechnique("T1115", "Clipboard Data", MITRETactic.COLLECTION),
        
        # Command and Control
        MITRETechnique("T1071", "Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL),
        MITRETechnique("T1092", "Communication Through Removable Media", MITRETactic.COMMAND_AND_CONTROL),
        MITRETechnique("T1001", "Data Obfuscation", MITRETactic.COMMAND_AND_CONTROL),
        MITRETechnique("T1568", "Dynamic Resolution", MITRETactic.COMMAND_AND_CONTROL),
        MITRETechnique("T1573", "Encrypted Channel", MITRETactic.COMMAND_AND_CONTROL),
        
        # Exfiltration
        MITRETechnique("T1020", "Automated Exfiltration", MITRETactic.EXFILTRATION),
        MITRETechnique("T1030", "Data Transfer Size Limits", MITRETactic.EXFILTRATION),
        MITRETechnique("T1048", "Exfiltration Over Alternative Protocol", MITRETactic.EXFILTRATION),
        MITRETechnique("T1041", "Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION),
        MITRETechnique("T1011", "Exfiltration Over Other Network Medium", MITRETactic.EXFILTRATION),
    ]


class CapabilityGapAnalyzer:
    """Analyzes gaps between ARDF + RedTeam capabilities."""
    
    def __init__(self):
        self.ardf_techniques = self._extract_techniques(ARDFCapabilityMap.ARDF_MODULES)
        self.redteam_techniques = self._extract_techniques(RedTeamCapabilityMap.REDTEAM_MODULES)
        self.all_techniques = MITRECoverageLibrary.ALL_TECHNIQUES
    
    def _extract_techniques(self, module_map: Dict) -> Set[str]:
        """Extract all techniques from module map."""
        techniques = set()
        for module, info in module_map.items():
            if "techniques" in info:
                techniques.update(info["techniques"])
        return techniques
    
    def analyze(self) -> CapabilityGapReport:
        """Analyze capability gaps."""
        covered = self.ardf_techniques.union(self.redteam_techniques)
        all_ids = {t.id for t in self.all_techniques}
        
        missing = all_ids - covered
        
        gaps = self._generate_gaps(missing)
        gaps.sort(key=lambda g: g.priority, reverse=True)
        
        recommendations = self._generate_recommendations(gaps)
        roadmap = self._generate_roadmap(gaps)
        
        coverage_pct = (len(covered) / len(all_ids) * 100) if all_ids else 0
        
        return CapabilityGapReport(
            total_mitre_techniques=len(all_ids),
            covered_techniques=len(covered),
            partial_techniques=0,  # Simplified; could be more precise
            missing_techniques=len(missing),
            coverage_percentage=coverage_pct,
            gaps=gaps,
            recommendations=recommendations,
            implementation_roadmap=roadmap,
        )
    
    def _generate_gaps(self, missing_techniques: Set[str]) -> List[CapabilityGap]:
        """Generate gap entries for missing techniques."""
        gaps = []
        
        gap_definitions = {
            "T1595": CapabilityGap(
                technique=self._find_technique("T1595"),
                coverage_type="partial",
                current_coverage="ARDF recon has passive scanning; no active scanning",
                recommended_module="active_scanning_module.py",
                priority=4,
                effort_to_implement="medium",
                estimated_lines_of_code=800,
                attack_value="high",
                notes="Add aggressive scanning (port enumeration, service fingerprinting)"
            ),
            "T1187": CapabilityGap(
                technique=self._find_technique("T1187"),
                coverage_type="missing",
                current_coverage="None",
                recommended_module="forced_auth_module.py",
                priority=5,
                effort_to_implement="high",
                estimated_lines_of_code=1200,
                attack_value="critical",
                notes="Forced authentication attacks (NTLM relay, Kerberos roasting)"
            ),
            "T1040": CapabilityGap(
                technique=self._find_technique("T1040"),
                coverage_type="missing",
                current_coverage="None",
                recommended_module="network_sniffing_module.py",
                priority=4,
                effort_to_implement="high",
                estimated_lines_of_code=950,
                attack_value="high",
                notes="Network sniffing for credential capture (pcap-based)"
            ),
            "T1534": CapabilityGap(
                technique=self._find_technique("T1534"),
                coverage_type="missing",
                current_coverage="None",
                recommended_module="internal_phishing_module.py",
                priority=5,
                effort_to_implement="medium",
                estimated_lines_of_code=600,
                attack_value="critical",
                notes="Internal spearphishing generator (email templates, payload delivery)"
            ),
            "T1583": CapabilityGap(
                technique=self._find_technique("T1583"),
                coverage_type="missing",
                current_coverage="Partial: ARDF C2 exists",
                recommended_module="infrastructure_setup_module.py",
                priority=4,
                effort_to_implement="medium",
                estimated_lines_of_code=700,
                attack_value="high",
                notes="Automated infrastructure provisioning (domains, VPS, redirectors)"
            ),
            "T1591": CapabilityGap(
                technique=MITRETechnique("T1591", "Gather Victim Org Information", MITRETactic.RECONNAISSANCE),
                coverage_type="partial",
                current_coverage="Limited OSINT; no org structure mapping",
                recommended_module="org_structure_mapper.py",
                priority=3,
                effort_to_implement="low",
                estimated_lines_of_code=400,
                attack_value="medium",
                notes="Org chart harvesting, public employee enumeration"
            ),
        }
        
        # Add all missing techniques
        for tech_id in missing_techniques:
            if tech_id in gap_definitions:
                gaps.append(gap_definitions[tech_id])
            else:
                tech = self._find_technique(tech_id)
                if tech:
                    gaps.append(CapabilityGap(
                        technique=tech,
                        coverage_type="missing",
                        current_coverage="None",
                        recommended_module=f"{tech.name.lower().replace(' ', '_')}_module.py",
                        priority=2,
                        effort_to_implement="medium",
                        estimated_lines_of_code=500,
                        attack_value="medium",
                    ))
        
        return gaps
    
    def _find_technique(self, tech_id: str) -> Optional[MITRETechnique]:
        """Find technique by ID."""
        for t in MITRECoverageLibrary.ALL_TECHNIQUES:
            if t.id == tech_id:
                return t
        return None
    
    def _generate_recommendations(self, gaps: List[CapabilityGap]) -> List[str]:
        """Generate recommendations."""
        return [
            "Priority 1: Implement forced authentication module (T1187) - critical for AD environments",
            "Priority 2: Add internal phishing framework (T1534) - high attack value",
            "Priority 3: Network sniffing module (T1040) - for passive credential harvesting",
            "Priority 4: Automated infrastructure setup (T1583) - reduce manual C2 setup",
            "Priority 5: Org structure mapper (T1591) - improve social engineering targeting",
            "Integration: Wire detected defenses to evasion selection (already done in adaptive_defense_evasion_layer.py)",
            "Testing: Build test harness for each new module against ARDF session exports",
        ]
    
    def _generate_roadmap(self, gaps: List[CapabilityGap]) -> List[Dict]:
        """Generate implementation roadmap."""
        roadmap = []
        
        for i, gap in enumerate(gaps[:5]):  # Top 5 gaps
            roadmap.append({
                "phase": i + 1,
                "technique": gap.technique.id,
                "name": gap.technique.name,
                "module": gap.recommended_module,
                "effort": gap.effort_to_implement,
                "lines_of_code": gap.estimated_lines_of_code,
                "priority": gap.priority,
                "attack_value": gap.attack_value,
                "dependencies": [],
                "estimated_completion_days": {
                    "low": 1,
                    "medium": 3,
                    "high": 7,
                }.get(gap.effort_to_implement, 3),
            })
        
        return roadmap


def main():
    """Demo: analyze gaps."""
    
    analyzer = CapabilityGapAnalyzer()
    report = analyzer.analyze()
    
    print(f"[*] ARDF + RedTeam Capability Analysis")
    print(f"    Total MITRE techniques: {report.total_mitre_techniques}")
    print(f"    Covered: {report.covered_techniques} ({report.coverage_percentage:.1f}%)")
    print(f"    Missing: {report.missing_techniques}")
    print()
    
    print(f"[+] Top 5 Capability Gaps:")
    for gap in report.gaps[:5]:
        print(f"    {gap.technique.id}: {gap.technique.name}")
        print(f"       Priority: {gap.priority}, Effort: {gap.effort_to_implement}")
        print(f"       Module: {gap.recommended_module}")
        print()
    
    print(f"[+] Recommendations:")
    for rec in report.recommendations[:3]:
        print(f"    - {rec}")
    
    print(f"\n[+] Implementation Roadmap:")
    for phase in report.implementation_roadmap[:3]:
        print(f"    Phase {phase['phase']}: {phase['name']} ({phase['effort']})")


if __name__ == '__main__':
    main()
