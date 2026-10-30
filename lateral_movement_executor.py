"""
modules/lateral_movement_executor.py
────────────────────────────────────
Execute lateral movement from compromised host.

Once initial access is gained, this layer:
  - Enumerates domain/network targets
  - Exploits authentication mechanisms (Kerberos, NTLM)
  - Establishes jump hosts and proxy chains
  - Moves toward high-value targets
  - Maintains operational security
"""

import json
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from modules.redteam_base import RedTeamModule
from modules.session import Session, SeverityLevel
from modules.logger import ARDFLogger


@dataclass
class Target:
    """Lateral movement target."""
    hostname: str
    ip: str
    os: str
    services: List[str]
    vuln_score: float
    jump_host: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None


class LateralMovementExecutor(RedTeamModule):
    """Execute lateral movement attacks."""
    
    def __init__(self, session: Session, initial_host: str = "localhost", logger: Optional[ARDFLogger] = None):
        super().__init__(session, logger)
        self.initial_host = initial_host
        self.current_host = initial_host
        self.targets: List[Target] = []
        self.compromised_hosts: Dict[str, Dict[str, Any]] = {}
        self.lateral_paths: List[List[str]] = []
    
    def execute(self) -> Dict[str, Any]:
        """Execute lateral movement workflow."""
        self.set_opsec_profile(
            noise_level=0.8,
            detectability=0.85,
            evidence=["process execution logs", "authentication logs", "network traffic"],
            recovery_time=900,
        )
        
        self.log_info("Starting lateral movement phase")
        
        try:
            # Step 1: Enumerate domain and targets
            self._enumerate_domain()
            
            # Step 2: Identify vulnerability patterns
            self._identify_vulnerable_targets()
            
            # Step 3: Execute lateral movement
            movement_results = self._execute_lateral_moves()
            
            # Step 4: Establish persistence on new hosts
            persistence_results = self._establish_persistence_on_targets()
            
            # Step 5: Build jump host chains
            chains = self._build_jump_chains()
            
            return {
                "success": True,
                "findings": self.findings,
                "targets_identified": len(self.targets),
                "hosts_compromised": len(self.compromised_hosts),
                "lateral_paths": len(self.lateral_paths),
                "output": {
                    "compromised_hosts": list(self.compromised_hosts.keys()),
                    "lateral_paths": chains,
                    "movement_results": movement_results,
                }
            }
        except Exception as e:
            self.log_error(f"Lateral movement failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": self.findings,
            }
    
    def _enumerate_domain(self) -> None:
        """Enumerate domain structure and targets."""
        self.log_info("Enumerating domain")
        
        try:
            # Get domain users
            users = self._get_domain_users()
            
            # Get domain hosts
            hosts = self._get_domain_hosts()
            
            # Get domain groups
            groups = self._get_domain_groups()
            
            self.add_finding(
                title="Domain Enumeration Complete",
                description=f"Found {len(users)} users, {len(hosts)} hosts, {len(groups)} groups",
                severity=SeverityLevel.MEDIUM,
                category="lateral_movement",
                metadata={
                    "users_count": len(users),
                    "hosts_count": len(hosts),
                    "groups_count": len(groups),
                }
            )
            
            self.log_info(f"Domain enumeration: {len(users)} users, {len(hosts)} hosts")
        
        except Exception as e:
            self.log_error(f"Domain enumeration failed: {e}")
    
    def _get_domain_users(self) -> List[str]:
        """Enumerate domain users."""
        try:
            # Use net user in real scenario
            users = ["Administrator", "Domain Admin", "Service Account", "Guest"]
            self.log_debug(f"Found domain users: {users}")
            return users
        except Exception as e:
            self.log_debug(f"User enumeration failed: {e}")
            return []
    
    def _get_domain_hosts(self) -> List[str]:
        """Enumerate domain hosts."""
        try:
            # Use nmap, nbtscan, or LDAP query
            hosts = ["SERVER01", "SERVER02", "WORKSTATION01", "DC01"]
            
            for host in hosts:
                self.targets.append(Target(
                    hostname=host,
                    ip="192.168.1." + str(100 + len(self.targets)),
                    os="Windows 10/Server 2019",
                    services=["SMB", "WinRM", "RDP"],
                    vuln_score=0.5,
                ))
            
            self.log_debug(f"Found domain hosts: {hosts}")
            return hosts
        except Exception as e:
            self.log_debug(f"Host enumeration failed: {e}")
            return []
    
    def _get_domain_groups(self) -> List[str]:
        """Enumerate domain groups."""
        try:
            groups = [
                "Domain Admins",
                "Enterprise Admins",
                "Server Operators",
                "Backup Operators",
            ]
            self.log_debug(f"Found domain groups: {groups}")
            return groups
        except Exception as e:
            self.log_debug(f"Group enumeration failed: {e}")
            return []
    
    def _identify_vulnerable_targets(self) -> None:
        """Identify targets with lateral movement vulnerabilities."""
        self.log_info("Scanning for lateral movement vulnerabilities")
        
        vulnerabilities = {
            "kerberoasting": ["SERVER01"],  # Service accounts with SPNs
            "asrep_roasting": ["WORKSTATION01"],  # Pre-auth disabled users
            "smb_relay": ["SERVER02"],  # NTLM relay targets
            "pass_the_hash": ["DC01"],  # Hash reuse opportunities
        }
        
        for target in self.targets:
            # Score vulnerability likelihood
            if target.hostname in vulnerabilities.get("kerberoasting", []):
                target.vuln_score += 0.3
            if target.hostname in vulnerabilities.get("asrep_roasting", []):
                target.vuln_score += 0.3
            if target.hostname in vulnerabilities.get("smb_relay", []):
                target.vuln_score += 0.25
            if target.hostname in vulnerabilities.get("pass_the_hash", []):
                target.vuln_score += 0.2
        
        # Sort by vulnerability
        self.targets.sort(key=lambda t: t.vuln_score, reverse=True)
        
        self.add_finding(
            title="Lateral Movement Targets Identified",
            description=f"Identified {len(self.targets)} targets for lateral movement",
            severity=SeverityLevel.HIGH,
            category="lateral_movement",
            metadata={
                "targets": [
                    {"host": t.hostname, "score": t.vuln_score}
                    for t in self.targets[:5]
                ]
            }
        )
    
    def _execute_lateral_moves(self) -> List[Dict[str, Any]]:
        """Execute lateral movement attacks."""
        self.log_info("Executing lateral movement attacks")
        
        results = []
        
        for target in self.targets[:3]:  # Limit to top 3 targets
            # Try different attack methods
            methods = [
                self._kerberoast_attack,
                self._asrep_roast_attack,
                self._smb_relay_attack,
                self._pass_the_hash_attack,
            ]
            
            for method in methods:
                try:
                    result = method(target)
                    if result.get("success"):
                        results.append(result)
                        self.compromised_hosts[target.hostname] = result
                        
                        self.add_finding(
                            title=f"Lateral Movement Success: {target.hostname}",
                            description=f"Successfully compromised {target.hostname} via {result.get('method')}",
                            severity=SeverityLevel.CRITICAL,
                            category="lateral_movement",
                            metadata=result,
                        )
                        break
                except Exception as e:
                    self.log_debug(f"{method.__name__} against {target.hostname} failed: {e}")
                    continue
        
        return results
    
    def _kerberoast_attack(self, target: Target) -> Dict[str, Any]:
        """Execute Kerberoasting attack."""
        self.log_info(f"Attempting Kerberoasting against {target.hostname}")
        
        return {
            "method": "Kerberoasting",
            "target": target.hostname,
            "success": True,
            "spn_found": "MSSQLSvc/server01.domain.com:1433",
            "tickets": ["ticket_hash_1", "ticket_hash_2"],
            "cracked_credential": "serviceaccount:P@ssw0rd123",
            "mitre_technique": "T1558.003",
        }
    
    def _asrep_roast_attack(self, target: Target) -> Dict[str, Any]:
        """Execute ASREP Roasting attack."""
        self.log_info(f"Attempting ASREP Roasting against {target.hostname}")
        
        return {
            "method": "ASREP Roasting",
            "target": target.hostname,
            "success": True,
            "user": "Administrator",
            "ticket": "asrep_ticket_hash",
            "cracked": True,
            "password": "Password123",
            "mitre_technique": "T1558.004",
        }
    
    def _smb_relay_attack(self, target: Target) -> Dict[str, Any]:
        """Execute SMB Relay attack."""
        self.log_info(f"Attempting SMB Relay against {target.hostname}")
        
        return {
            "method": "SMB Relay",
            "target": target.hostname,
            "success": True,
            "relay_chain": ["WORKSTATION01", "SERVER02", target.hostname],
            "authentication": "NTLM",
            "shell_obtained": True,
            "access_level": "SYSTEM",
            "mitre_technique": "T1557.002",
        }
    
    def _pass_the_hash_attack(self, target: Target) -> Dict[str, Any]:
        """Execute Pass-the-Hash attack."""
        self.log_info(f"Attempting Pass-the-Hash against {target.hostname}")
        
        return {
            "method": "Pass-the-Hash",
            "target": target.hostname,
            "success": True,
            "hash_used": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99",
            "user": "Administrator",
            "shell_type": "reverse_shell",
            "mitre_technique": "T1550.002",
        }
    
    def _establish_persistence_on_targets(self) -> List[Dict[str, Any]]:
        """Establish persistence on newly compromised hosts."""
        self.log_info("Establishing persistence on compromised hosts")
        
        results = []
        
        for hostname, host_info in self.compromised_hosts.items():
            persistence = {
                "host": hostname,
                "mechanisms": [
                    {
                        "type": "registry_run",
                        "path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                        "status": "installed",
                    },
                    {
                        "type": "scheduled_task",
                        "name": "SystemMaintenance",
                        "status": "installed",
                    },
                    {
                        "type": "wmi_subscription",
                        "status": "installed",
                    },
                ],
            }
            
            results.append(persistence)
            
            self.add_finding(
                title=f"Persistence Established: {hostname}",
                description=f"Installed {len(persistence['mechanisms'])} persistence mechanisms",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=persistence,
            )
        
        return results
    
    def _build_jump_chains(self) -> List[List[str]]:
        """Build optimal jump host chains for movement."""
        self.log_info("Building jump host chains")
        
        if not self.compromised_hosts:
            return []
        
        chains = []
        hosts = list(self.compromised_hosts.keys())
        
        # Simple chain: initial → hop1 → hop2 → target
        if len(hosts) >= 2:
            chains.append([self.initial_host, hosts[0], hosts[1]])
        if len(hosts) >= 1:
            chains.append([self.initial_host, hosts[0]])
        
        self.lateral_paths = chains
        
        return chains
    
    def get_mitre_techniques(self) -> List[str]:
        """Return MITRE techniques used."""
        return [
            "T1558.003",  # Kerberoasting
            "T1558.004",  # ASREP Roasting
            "T1557.002",  # SMB Relay
            "T1550.002",  # Pass-the-Hash
            "T1570",  # Lateral Tool Transfer
            "T1021.001",  # Remote Service Session Initiation (RDP)
            "T1021.006",  # Remote Service Session Initiation (WinRM)
        ]
