"""
ARDF → Red Team Suite Integration Bridge
Feed ARDF discovery findings into offensive operations automatically.

Workflow:
  ARDF discovers vulns/misconfigs → Bridge parses findings
  → Creates appropriate exploitation workflows
  → Red Team Suite executes attack chains with credentials/payloads
  → Results feed back into ARDF for impact assessment
"""

import asyncio
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Integration types
@dataclass
class ARDFFinding:
    """ARDF finding normalized for exploitation."""
    id: str
    target: str
    type: str  # vulnerability, credential, exposure, misconfig
    severity: str
    title: str
    description: str
    exploit_path: Optional[str] = None
    required_credentials: List[str] = None
    cve: Optional[str] = None
    evidence: Dict[str, Any] = None

    def __post_init__(self):
        if self.required_credentials is None:
            self.required_credentials = []
        if self.evidence is None:
            self.evidence = {}


class ExploitationStrategy(Enum):
    """Strategy for exploiting a finding."""
    DIRECT = "direct"  # Direct RCE
    CREDENTIALED = "credentialed"  # Requires valid creds
    CHAINED = "chained"  # Part of multi-step attack
    SOCIAL = "social"  # Social engineering component
    HARDWARE = "hardware"  # Physical access required
    TIMING = "timing"  # Race condition or time-window required


class ARDFBridge:
    """Connect ARDF findings to red team offensive execution."""

    def __init__(self, orchestrator):
        """
        Initialize bridge.
        
        Args:
            orchestrator: Red team orchestrator instance
        """
        self.orchestrator = orchestrator
        self.finding_to_exploit = self._build_exploit_map()

    def _build_exploit_map(self) -> Dict[str, List[Tuple[str, str]]]:
        """
        Map common finding types to exploitation modules.
        Maps finding CVE/type to (exploit_module, payload_type)
        """
        return {
            # RCE vulnerabilities
            "CVE_2023_23752": [("joomla_rce", "reverse_shell")],  # Joomla RCE
            "CVE_2023_34362": [("wordpress_plugin_rce", "reverse_shell")],  # WP Plugin RCE
            "CVE_2023_38545": [("curl_rce", "shellcode")],  # curl vuln
            "CVE_2023_46604": [("apache_ofbiz_rce", "reverse_shell")],  # OFBiz RCE
            
            # SQL Injection
            "SQL_INJECTION": [("sqlmap_auto", "reverse_shell"), ("direct_query", "data_exfil")],
            
            # Authentication bypass
            "AUTH_BYPASS": [("default_creds", "reverse_shell")],
            "DEFAULT_CREDENTIALS": [("direct_login", "reverse_shell")],
            
            # Privilege escalation
            "PRIVESC_SUDO": [("sudo_exploit", "privesc_payload")],
            "PRIVESC_SUID": [("suid_exploit", "privesc_payload")],
            "PRIVESC_UNQUOTED": [("unquoted_path", "privesc_payload")],
            "PRIVESC_KERNEL": [("kernel_exploit", "privesc_payload")],
            
            # Information disclosure
            "SOURCE_CODE_LEAK": [("source_analysis", "cred_harvesting")],
            "CONFIG_EXPOSURE": [("config_parsing", "cred_harvesting")],
            "API_KEY_EXPOSURE": [("key_harvesting", "api_abuse")],
            
            # Misconfiguration
            "CLOUD_BUCKET_OPEN": [("bucket_access", "data_exfil")],
            "CORS_MISCONFIGURED": [("cors_bypass", "data_theft")],
            "INSECURE_DESERIALIZATION": [("deser_gadget", "rce_payload")],
            
            # Weak crypto
            "WEAK_CIPHER": [("downgrade_attack", "mitm_payload")],
            "HARDCODED_KEYS": [("key_extraction", "api_abuse")],
            
            # Network exposures
            "OPEN_DATABASE_PORT": [("direct_connect", "cred_spray")],
            "UNPROTECTED_API": [("api_fuzzing", "data_exfil")],
        }

    def parse_ardf_findings(self, findings_file: Path) -> List[ARDFFinding]:
        """Parse ARDF findings JSON export."""
        findings = []
        
        with open(findings_file) as f:
            data = json.load(f)
        
        for finding in data.get("findings", []):
            ardf_finding = ARDFFinding(
                id=finding["id"],
                target=finding.get("entity_id", "unknown"),
                type=finding["type"],
                severity=finding["severity"],
                title=finding["title"],
                description=finding["description"],
                cve=finding.get("cve"),
                evidence=finding.get("evidence", {}),
                exploit_path=finding.get("exploit_path"),
            )
            findings.append(ardf_finding)
        
        return findings

    def determine_exploitation_strategy(self, finding: ARDFFinding) -> ExploitationStrategy:
        """Determine best strategy for exploiting finding."""
        
        # RCE findings → direct exploitation
        if finding.type == "vulnerability" and "remote code execution" in finding.description.lower():
            return ExploitationStrategy.DIRECT
        
        # Credential findings → credentialed attacks
        elif finding.type == "credential":
            return ExploitationStrategy.CREDENTIALED
        
        # Misconfigurations → may be chained
        elif finding.type == "misconfiguration":
            if finding.severity == "critical":
                return ExploitationStrategy.DIRECT
            else:
                return ExploitationStrategy.CHAINED
        
        # Weak crypto → timing/mitm attacks
        elif "crypto" in finding.type.lower():
            return ExploitationStrategy.TIMING
        
        return ExploitationStrategy.CHAINED

    def create_exploitation_workflows(
        self,
        findings: List[ARDFFinding],
        target: str
    ) -> List[Dict[str, Any]]:
        """
        Create exploitation workflows from ARDF findings.
        
        Returns list of workflow specs ready for orchestrator.
        """
        workflows = []
        critical_findings = [f for f in findings if f.severity == "critical"]
        high_findings = [f for f in findings if f.severity == "high"]
        
        # Workflow 1: Direct RCE chain
        if critical_findings:
            rce_findings = [f for f in critical_findings if "execution" in f.type.lower()]
            if rce_findings:
                exploit = rce_findings[0]
                workflow = {
                    "name": f"Direct RCE: {exploit.title}",
                    "target": target,
                    "initial_access": self._get_exploit_module(exploit),
                    "exploitation_chain": [self._get_exploit_module(exploit)],
                    "phases": ["initial_access", "privilege_escalation", "persistence"],
                }
                workflows.append(workflow)
        
        # Workflow 2: Credentialed access chain
        cred_findings = [f for f in findings if f.type == "credential"]
        if cred_findings:
            workflow = {
                "name": f"Credentialed Access Chain",
                "target": target,
                "initial_access": "credential_spray",
                "exploitation_chain": ["credential_spray", "lateral_movement", "persistence"],
                "phases": ["credential_access", "lateral_movement", "persistence"],
                "credentials": cred_findings,
            }
            workflows.append(workflow)
        
        # Workflow 3: Multi-stage exploitation
        if high_findings and len(high_findings) >= 2:
            workflow = {
                "name": f"Multi-Stage Attack Chain",
                "target": target,
                "initial_access": self._get_exploit_module(high_findings[0]),
                "exploitation_chain": [
                    self._get_exploit_module(high_findings[0]),
                    self._get_exploit_module(high_findings[1]),
                    "privilege_escalation",
                ],
                "phases": ["initial_access", "privilege_escalation", "lateral_movement"],
            }
            workflows.append(workflow)
        
        return workflows

    def _get_exploit_module(self, finding: ARDFFinding) -> str:
        """Get exploit module name for finding."""
        
        if finding.cve:
            modules = self.finding_to_exploit.get(finding.cve.upper())
            if modules:
                return modules[0][0]
        
        # Fallback to type-based mapping
        finding_type = finding.type.upper().replace(" ", "_")
        modules = self.finding_to_exploit.get(finding_type)
        if modules:
            return modules[0][0]
        
        return "generic_exploit"

    def prioritize_findings(
        self,
        findings: List[ARDFFinding]
    ) -> Dict[str, List[ARDFFinding]]:
        """
        Prioritize findings for exploitation.
        
        Returns findings grouped by priority tier.
        """
        priorities = {
            "immediate": [],  # RCE, auth bypass, critical exposed creds
            "high": [],  # Privilege escalation, data exposure
            "medium": [],  # Weak crypto, CORS, misc
            "low": [],  # Info disclosure, low-risk
        }
        
        for finding in findings:
            if finding.severity == "critical":
                if "execution" in finding.type.lower() or finding.type == "credential":
                    priorities["immediate"].append(finding)
                else:
                    priorities["high"].append(finding)
            elif finding.severity == "high":
                priorities["high"].append(finding)
            elif finding.severity == "medium":
                priorities["medium"].append(finding)
            else:
                priorities["low"].append(finding)
        
        return priorities

    async def execute_exploitation_from_findings(
        self,
        findings: List[ARDFFinding],
        target: str,
        initial_shell=None
    ) -> Dict[str, Any]:
        """
        Execute exploitation directly from ARDF findings.
        
        Returns execution summary with success rates.
        """
        
        results = {
            "target": target,
            "findings_count": len(findings),
            "exploitation_count": 0,
            "successful_exploits": 0,
            "shells_obtained": 0,
            "credentials_harvested": 0,
            "workflows_executed": [],
        }
        
        # Prioritize findings
        priorities = self.prioritize_findings(findings)
        
        # Try immediate exploits first
        for finding in priorities["immediate"]:
            module = self._get_exploit_module(finding)
            success = await self._execute_exploit(module, target, finding)
            
            if success:
                results["successful_exploits"] += 1
                results["shells_obtained"] += 1
            results["exploitation_count"] += 1
        
        # Create and execute workflows
        workflows = self.create_exploitation_workflows(findings, target)
        
        for workflow_spec in workflows:
            try:
                workflow = self.orchestrator.create_workflow(
                    name=workflow_spec["name"],
                    target=workflow_spec["target"],
                    initial_access=workflow_spec["initial_access"],
                    exploitation_chain=workflow_spec["exploitation_chain"]
                )
                
                # Execute workflow (requires initial shell)
                if initial_shell:
                    success = await self.orchestrator.execute_workflow(workflow.id, initial_shell)
                    results["workflows_executed"].append({
                        "id": workflow.id,
                        "name": workflow.name,
                        "success": success,
                    })
                
            except Exception as e:
                print(f"[-] Workflow failed: {e}")
        
        return results

    async def _execute_exploit(self, module: str, target: str, finding: ARDFFinding) -> bool:
        """Execute individual exploit module."""
        
        # Placeholder: actual execution would call exploit modules
        print(f"[*] Executing {module} against {target}")
        print(f"    Finding: {finding.title}")
        print(f"    CVE: {finding.cve}")
        
        # Simulate exploit execution
        await asyncio.sleep(0.5)
        return True

    def generate_exploitation_report(
        self,
        findings: List[ARDFFinding],
        execution_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate post-exploitation report."""
        
        return {
            "timestamp": str(Path.cwd()),
            "initial_findings": len(findings),
            "exploitation_summary": execution_results,
            "critical_paths": self._extract_critical_paths(findings),
            "persistence_opportunities": self._identify_persistence_opportunities(findings),
            "lateral_movement_paths": self._identify_lateral_paths(findings),
        }

    def _extract_critical_paths(self, findings: List[ARDFFinding]) -> List[str]:
        """Extract critical exploitation paths from findings."""
        paths = []
        
        critical = [f for f in findings if f.severity == "critical"]
        for finding in critical:
            if "execution" in finding.type.lower():
                paths.append(f"Direct RCE via {finding.title}")
            elif finding.type == "credential":
                paths.append(f"Credentialed access via {finding.title}")
        
        return paths

    def _identify_persistence_opportunities(self, findings: List[ARDFFinding]) -> List[str]:
        """Identify where persistence can be installed."""
        opportunities = []
        
        for finding in findings:
            if "service" in finding.type.lower() or "rce" in finding.type.lower():
                opportunities.append(f"Service/RCE → Scheduled task persistence")
            elif "ssh" in finding.description.lower():
                opportunities.append(f"SSH key insertion for persistence")
            elif "sudo" in finding.description.lower():
                opportunities.append(f"Sudo privilege for root persistence")
        
        return opportunities

    def _identify_lateral_paths(self, findings: List[ARDFFinding]) -> List[str]:
        """Identify lateral movement paths."""
        paths = []
        
        for finding in findings:
            if "credential" in finding.type.lower():
                paths.append(f"Reuse credentials for {finding.title}")
            elif "network" in finding.description.lower():
                paths.append(f"Network service exploitation for lateral movement")
            elif "database" in finding.description.lower():
                paths.append(f"Database access for data exfiltration and lateral pivot")
        
        return paths


# ─────────────────────────────────────────────────────────────────────────────
# Usage Example
# ─────────────────────────────────────────────────────────────────────────────

async def main():
    """Example: Load ARDF findings and execute red team workflows."""
    
    print("""
╔═════════════════════════════════════════════════════════════════╗
║      ARDF → RED TEAM SUITE INTEGRATION - FINDINGS EXPLOITATION  ║
╚═════════════════════════════════════════════════════════════════╝
    """)
    
    # Import orchestrator (would be from red_team_suite)
    from red_team_suite import AttackOrchestrator
    
    # Initialize bridge
    orchestrator = AttackOrchestrator()
    bridge = ARDFBridge(orchestrator)
    
    # Example findings (would be loaded from ARDF export)
    example_findings = [
        ARDFFinding(
            id="f001",
            target="192.168.1.100",
            type="vulnerability",
            severity="critical",
            title="Joomla 4.0.0 RCE",
            description="Unauthenticated remote code execution via CVE-2023-23752",
            cve="CVE_2023_23752",
        ),
        ARDFFinding(
            id="f002",
            target="192.168.1.100",
            type="credential",
            severity="high",
            title="Exposed MySQL Root Credentials",
            description="Database credentials found in WordPress config.php",
        ),
        ARDFFinding(
            id="f003",
            target="192.168.1.100",
            type="misconfiguration",
            severity="high",
            title="Unpatched Sudo Privilege Escalation",
            description="sudo version vulnerable to CVE allowing privilege escalation",
        ),
    ]
    
    print(f"\n[*] Loaded {len(example_findings)} findings from ARDF\n")
    
    # Prioritize
    priorities = bridge.prioritize_findings(example_findings)
    print(f"[*] Finding prioritization:")
    for priority, findings in priorities.items():
        if findings:
            print(f"    {priority.upper()}: {len(findings)} findings")
    
    # Create workflows
    print(f"\n[*] Creating exploitation workflows...")
    workflows = bridge.create_exploitation_workflows(example_findings, "192.168.1.100")
    for workflow in workflows:
        print(f"    + {workflow['name']}")
        print(f"      Initial: {workflow['initial_access']}")
        print(f"      Chain: {', '.join(workflow['exploitation_chain'])}")
    
    # Execute
    print(f"\n[*] Executing exploitation...")
    results = await bridge.execute_exploitation_from_findings(
        example_findings,
        "192.168.1.100"
    )
    
    print(f"\n[+] Exploitation Results:")
    print(f"    Findings processed: {results['findings_count']}")
    print(f"    Exploits executed: {results['exploitation_count']}")
    print(f"    Successful: {results['successful_exploits']}")
    print(f"    Shells obtained: {results['shells_obtained']}")
    
    # Generate report
    report = bridge.generate_exploitation_report(example_findings, results)
    print(f"\n[+] Post-Exploitation Report:")
    print(f"    Critical paths: {len(report['critical_paths'])}")
    print(f"    Persistence opportunities: {len(report['persistence_opportunities'])}")
    print(f"    Lateral movement paths: {len(report['lateral_movement_paths'])}")


if __name__ == "__main__":
    asyncio.run(main())
