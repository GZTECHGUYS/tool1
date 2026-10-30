"""Lateral movement module for expanding network footprint."""

import asyncio
from typing import List

from core import (
    OffensiveModule, Finding, ExecutionContext, FindingType,
    Severity, TacticType
)


class LateralMovementModule(OffensiveModule):
    """Move laterally across network from compromised host."""
    
    module_name = "lateral_movement"
    module_version = "1.0.0"
    description = "Establish presence on adjacent targets using compromised credentials"
    
    finding_types = [FindingType.LATERAL_MOVE]
    tactics = [TacticType.LATERAL_MOVEMENT, TacticType.DISCOVERY]
    required_access = "user"
    timeout_seconds = 240
    
    LATERAL_TECHNIQUES = [
        {
            "name": "SSH Key-based Movement",
            "method": "SSH using harvested keys",
            "success_rate": 0.85,
            "detection": "SSH logs, .bash_history",
        },
        {
            "name": "SMB/CIFS Share Access",
            "method": "Use credentials to access admin$ share",
            "success_rate": 0.80,
            "detection": "Windows Event Log 4688, 5140",
        },
        {
            "name": "WinRM Execution",
            "method": "PowerShell remoting via WinRM",
            "success_rate": 0.75,
            "detection": "Windows Event Log 91/91, WinRM logs",
        },
        {
            "name": "RDP Connection",
            "method": "Remote Desktop Protocol lateral movement",
            "success_rate": 0.70,
            "detection": "Windows Event Log 4624, RDP logs",
        },
        {
            "name": "Kerberoasting",
            "method": "Request TGS tickets for password cracking",
            "success_rate": 0.65,
            "detection": "Event Log 4769",
        },
        {
            "name": "SSH Agent Hijacking",
            "method": "Hijack SSH-agent socket",
            "success_rate": 0.60,
            "detection": "Process monitoring",
        },
    ]
    
    async def execute(self, context: ExecutionContext) -> List[Finding]:
        """Execute lateral movement."""
        findings = []
        
        # Discover adjacent targets
        adjacent_targets = await self._discover_adjacent_targets(context.target)
        
        for target in adjacent_targets:
            # Try each lateral movement technique
            techniques = await self._get_applicable_techniques(context)
            
            for technique in techniques:
                movement_finding = self._create_finding(
                    title=f"Lateral movement to {target} via {technique['name']}",
                    description=f"Successfully moved laterally from {context.target} to {target}",
                    finding_type=FindingType.LATERAL_MOVE,
                    evidence={
                        "source": context.target,
                        "destination": target,
                        "method": technique["method"],
                        "technique": technique["name"],
                        "success_rate": technique["success_rate"],
                        "detection_vector": technique["detection"],
                        "access_level": "user",
                    },
                    severity="high",
                    exploitable=True,
                )
                
                movement_finding.target = target
                movement_finding.target_type = context.target_type
                
                # After lateral movement, can proceed with privilege escalation
                movement_finding.next_tactics = [
                    TacticType.PRIVILEGE_ESCALATION,
                    TacticType.PERSISTENCE,
                    TacticType.CREDENTIAL_ACCESS,
                ]
                
                findings.append(movement_finding)
                break  # Only report successful technique
        
        # Create network map finding
        if adjacent_targets:
            network_finding = self._create_finding(
                title=f"Network expansion: {len(adjacent_targets)} adjacent targets mapped",
                description=f"Identified {len(adjacent_targets)} targets reachable from {context.target}",
                finding_type=FindingType.RECONNAISSANCE,
                evidence={
                    "adjacent_targets": adjacent_targets,
                    "source_host": context.target,
                    "network_reach": "internal_network",
                },
                severity="high",
            )
            network_finding.next_tactics = [TacticType.LATERAL_MOVEMENT]
            findings.append(network_finding)
        
        self.logger.info(f"Lateral movement established presence on {len(findings)} targets")
        return findings
    
    async def _discover_adjacent_targets(self, source: str) -> List[str]:
        """Discover adjacent targets on network."""
        await asyncio.sleep(0.15)
        
        # Simulate network discovery from source
        # In real scenario: arp scan, nmap, AD enumeration, etc.
        adjacent = [
            "db-1.internal",
            "app-1.internal",
            "app-2.internal",
            "mail-1.internal",
            "backup-1.internal",
        ]
        
        return adjacent
    
    async def _get_applicable_techniques(self, context: ExecutionContext) -> List[dict]:
        """Get applicable lateral movement techniques."""
        await asyncio.sleep(0.1)
        
        # Filter techniques based on target OS and available credentials
        return self.LATERAL_TECHNIQUES[:2]
