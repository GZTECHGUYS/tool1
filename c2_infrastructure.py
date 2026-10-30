"""
modules/c2_infrastructure.py
────────────────────────────
Command & Control framework for agent management and persistence.

Provides:
  - Beacon generation (reverse shell, DNS exfil, HTTP polling)
  - Traffic obfuscation (DNS tunneling, steganography)
  - Agent callback scheduling with jitter
  - Multi-hop relay chains
  - Dead drop communication
  - Session recovery
"""

import json
import uuid
import base64
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime, timedelta
import hashlib

from modules.redteam_base import RedTeamModule
from modules.session import Session, SeverityLevel
from modules.logger import ARDFLogger, get_logger


class BeaconType(Enum):
    """Types of beacon callbacks."""
    HTTP_POLL = "http_poll"  # Regular HTTP GET/POST
    HTTPS_POLL = "https_poll"  # HTTPS polling
    DNS_EXFIL = "dns_exfil"  # DNS tunnel
    ICMP_TUNNEL = "icmp_tunnel"  # ICMP echo tunnel
    DEAD_DROP = "dead_drop"  # File-based communication
    P2P_MESH = "p2p_mesh"  # Peer-to-peer


class ObfuscationMethod(Enum):
    """Traffic obfuscation techniques."""
    NONE = "none"
    BASE64 = "base64"
    AES256 = "aes256"
    XOR = "xor"
    STEGANOGRAPHY = "steganography"
    DOMAIN_FRONTING = "domain_fronting"


@dataclass
class Beacon:
    """Individual beacon/implant configuration."""
    
    beacon_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    agent_type: str = "generic"  # windows, linux, macos, web
    beacon_type: BeaconType = BeaconType.HTTP_POLL
    callback_url: str = ""
    callback_port: int = 443
    callback_interval: int = 300  # seconds
    jitter: float = 0.2  # 20% random variance
    obfuscation: ObfuscationMethod = ObfuscationMethod.AES256
    encryption_key: str = ""
    implant_name: str = ""  # Spoof as legitimate service
    registry_key: Optional[str] = None  # Windows registry location
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    activated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "beacon_id": self.beacon_id,
            "agent_type": self.agent_type,
            "beacon_type": self.beacon_type.value,
            "callback_url": self.callback_url,
            "callback_port": self.callback_port,
            "callback_interval": self.callback_interval,
            "jitter": self.jitter,
            "obfuscation": self.obfuscation.value,
            "implant_name": self.implant_name,
            "activated": self.activated,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass
class Agent:
    """Connected implant/agent."""
    
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    beacon_id: str = ""
    hostname: str = ""
    username: str = ""
    os_version: str = ""
    last_callback: Optional[str] = None
    last_command_exec: Optional[str] = None
    privileges: str = "user"  # user, admin, system, root
    integrity_level: int = 2  # 1=low, 2=medium, 3=high, 4=system
    process_id: int = 0
    parent_process_id: int = 0
    network_adapters: List[str] = field(default_factory=list)
    session_key: str = ""
    active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "beacon_id": self.beacon_id,
            "hostname": self.hostname,
            "username": self.username,
            "os_version": self.os_version,
            "last_callback": self.last_callback,
            "privileges": self.privileges,
            "integrity_level": self.integrity_level,
            "active": self.active,
        }


@dataclass
class Command:
    """Command queued for agent execution."""
    
    command_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_id: str = ""
    command: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1=critical, 5=normal, 9=low
    timeout: int = 30
    execute_time: Optional[str] = None
    status: str = "queued"  # queued, sent, executing, completed, failed
    output: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "command_id": self.command_id,
            "agent_id": self.agent_id,
            "command": self.command,
            "status": self.status,
            "created_at": self.created_at,
        }


class C2Infrastructure(RedTeamModule):
    """Command & control infrastructure management."""
    
    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        super().__init__(session, logger)
        self.beacons: Dict[str, Beacon] = {}
        self.agents: Dict[str, Agent] = {}
        self.command_queue: Dict[str, List[Command]] = {}
        self.relays: List[Dict[str, Any]] = []
        self.c2_servers: List[Dict[str, str]] = []
    
    def execute(self) -> Dict[str, Any]:
        """Execute C2 infrastructure setup."""
        self.set_opsec_profile(
            noise_level=0.5,
            detectability=0.6,
            evidence=["network traffic", "registry entries", "running processes"],
            recovery_time=1200,
        )
        
        self.log_info("Setting up C2 infrastructure")
        
        try:
            # Step 1: Generate beacons
            beacons = self._generate_beacons()
            
            # Step 2: Establish C2 servers
            servers = self._establish_c2_servers()
            
            # Step 3: Build relay chains
            relays = self._build_relay_infrastructure()
            
            # Step 4: Register agents (simulated)
            agents = self._register_agents(beacons)
            
            return {
                "success": True,
                "findings": self.findings,
                "beacons_generated": len(beacons),
                "c2_servers": len(servers),
                "relay_chains": len(relays),
                "agents_active": len(self.agents),
                "output": {
                    "beacons": [b.to_dict() for b in beacons],
                    "c2_servers": servers,
                    "relays": relays,
                }
            }
        except Exception as e:
            self.log_error(f"C2 infrastructure setup failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": self.findings,
            }
    
    def _generate_beacons(self) -> List[Beacon]:
        """Generate beacon payloads for different platforms."""
        beacons = []
        
        # Windows beacon
        win_beacon = Beacon(
            agent_type="windows",
            beacon_type=BeaconType.HTTP_POLL,
            callback_url="https://c2.attacker.com/check",
            callback_port=443,
            callback_interval=300,
            jitter=0.2,
            obfuscation=ObfuscationMethod.AES256,
            implant_name="WindowsDefenderService",
            registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        )
        self.beacons[win_beacon.beacon_id] = win_beacon
        beacons.append(win_beacon)
        
        self.log_info(f"Generated Windows beacon: {win_beacon.beacon_id}")
        
        # Linux beacon
        linux_beacon = Beacon(
            agent_type="linux",
            beacon_type=BeaconType.HTTPS_POLL,
            callback_url="https://c2.attacker.com/check",
            callback_port=443,
            callback_interval=600,
            jitter=0.3,
            obfuscation=ObfuscationMethod.AES256,
            implant_name="systemd-update",
        )
        self.beacons[linux_beacon.beacon_id] = linux_beacon
        beacons.append(linux_beacon)
        
        self.log_info(f"Generated Linux beacon: {linux_beacon.beacon_id}")
        
        # DNS exfil beacon (stealthy)
        dns_beacon = Beacon(
            agent_type="generic",
            beacon_type=BeaconType.DNS_EXFIL,
            callback_url="ns.attacker.com",
            callback_interval=3600,
            jitter=0.5,
            obfuscation=ObfuscationMethod.BASE64,
            implant_name="dns_resolver",
        )
        self.beacons[dns_beacon.beacon_id] = dns_beacon
        beacons.append(dns_beacon)
        
        self.log_info(f"Generated DNS exfil beacon: {dns_beacon.beacon_id}")
        
        # Register findings
        for beacon in beacons:
            self.add_finding(
                title=f"Beacon Generated: {beacon.agent_type}",
                description=f"Beacon {beacon.beacon_id} ready for deployment",
                severity=SeverityLevel.CRITICAL,
                category="c2_infrastructure",
                metadata=beacon.to_dict(),
            )
        
        return beacons
    
    def _establish_c2_servers(self) -> List[Dict[str, str]]:
        """Establish C2 server infrastructure."""
        self.log_info("Establishing C2 servers")
        
        servers = [
            {
                "name": "Primary C2",
                "ip": "c2.attacker.com",
                "port": "443",
                "protocol": "HTTPS",
                "capacity": "100 agents",
                "database": "PostgreSQL",
            },
            {
                "name": "Secondary C2 (EU)",
                "ip": "c2-eu.attacker.com",
                "port": "443",
                "protocol": "HTTPS",
                "capacity": "50 agents",
                "database": "PostgreSQL",
            },
            {
                "name": "DNS Exfil Server",
                "ip": "ns.attacker.com",
                "port": "53",
                "protocol": "DNS",
                "capacity": "500+ agents",
                "database": "DNS Zone File",
            },
        ]
        
        self.c2_servers = servers
        
        self.add_finding(
            title="C2 Infrastructure Established",
            description=f"Deployed {len(servers)} C2 servers",
            severity=SeverityLevel.CRITICAL,
            category="c2_infrastructure",
            metadata={"servers": servers},
        )
        
        return servers
    
    def _build_relay_infrastructure(self) -> List[Dict[str, Any]]:
        """Build multi-hop relay chains."""
        self.log_info("Building relay infrastructure")
        
        relays = [
            {
                "relay_id": "relay_1",
                "type": "HTTP_PROXY",
                "path": "Agent 1 → Relay 1 → C2",
                "hops": 2,
                "obfuscation": "SSL_PINNING",
            },
            {
                "relay_id": "relay_2",
                "type": "DNS_TUNNEL",
                "path": "Agent 2 → Relay 2 → DNS_Server → C2",
                "hops": 3,
                "obfuscation": "DNS_OVER_HTTPS",
            },
            {
                "relay_id": "relay_3",
                "type": "P2P_MESH",
                "path": "Agent 3 ↔ Agent 1 ↔ Relay 1 → C2",
                "hops": 3,
                "obfuscation": "ENCRYPTION_END_TO_END",
            },
        ]
        
        self.relays = relays
        
        self.add_finding(
            title="Relay Chains Established",
            description=f"Built {len(relays)} multi-hop relay chains",
            severity=SeverityLevel.HIGH,
            category="c2_infrastructure",
            metadata={"relays": relays},
        )
        
        return relays
    
    def _register_agents(self, beacons: List[Beacon]) -> List[Agent]:
        """Register connected agents."""
        self.log_info("Registering agents")
        
        agents = []
        
        # Simulate agent from Windows beacon
        win_agent = Agent(
            beacon_id=beacons[0].beacon_id,
            hostname="WORKSTATION-01",
            username="john.doe",
            os_version="Windows 10 Pro (19045)",
            privileges="user",
            integrity_level=2,
            process_id=4532,
            parent_process_id=532,
            network_adapters=["192.168.1.100", "172.16.0.50"],
        )
        self.agents[win_agent.agent_id] = win_agent
        agents.append(win_agent)
        
        # Simulate agent from Linux beacon
        linux_agent = Agent(
            beacon_id=beacons[1].beacon_id,
            hostname="web-server-02",
            username="www-data",
            os_version="Ubuntu 22.04 LTS",
            privileges="user",
            integrity_level=2,
            process_id=2841,
            parent_process_id=1,
            network_adapters=["10.0.0.45", "172.31.0.100"],
        )
        self.agents[linux_agent.agent_id] = linux_agent
        agents.append(linux_agent)
        
        # Initialize command queues
        for agent in agents:
            self.command_queue[agent.agent_id] = []
        
        self.add_finding(
            title="Agents Connected",
            description=f"Registered {len(agents)} agents to C2",
            severity=SeverityLevel.CRITICAL,
            category="c2_infrastructure",
            metadata={
                "agents": [a.to_dict() for a in agents],
            },
        )
        
        return agents
    
    def queue_command(
        self,
        agent_id: str,
        command: str,
        arguments: Optional[Dict[str, Any]] = None,
        priority: int = 5,
    ) -> str:
        """Queue command for agent execution."""
        if agent_id not in self.agents:
            self.log_warning(f"Agent {agent_id} not found")
            return ""
        
        cmd = Command(
            agent_id=agent_id,
            command=command,
            arguments=arguments or {},
            priority=priority,
        )
        
        if agent_id not in self.command_queue:
            self.command_queue[agent_id] = []
        
        self.command_queue[agent_id].append(cmd)
        
        self.log_info(f"Queued command {cmd.command_id} for agent {agent_id}: {command}")
        
        return cmd.command_id
    
    def execute_command(self, agent_id: str, command_id: str) -> Dict[str, Any]:
        """Execute queued command on agent."""
        if agent_id not in self.command_queue:
            return {"success": False, "error": "Agent not found"}
        
        for cmd in self.command_queue[agent_id]:
            if cmd.command_id == command_id:
                cmd.status = "executing"
                cmd.execute_time = datetime.now().isoformat()
                
                # Simulate execution
                cmd.output = f"Executed: {cmd.command}\nResult: Success"
                cmd.status = "completed"
                
                self.agents[agent_id].last_command_exec = datetime.now().isoformat()
                
                return {
                    "success": True,
                    "command_id": command_id,
                    "output": cmd.output,
                }
        
        return {"success": False, "error": "Command not found"}
    
    def get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        """Get current agent status."""
        if agent_id not in self.agents:
            return {"error": "Agent not found"}
        
        agent = self.agents[agent_id]
        
        return {
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "active": agent.active,
            "privileges": agent.privileges,
            "last_callback": agent.last_callback,
            "pending_commands": len(self.command_queue.get(agent_id, [])),
        }
    
    def get_mitre_techniques(self) -> List[str]:
        """Return MITRE techniques used."""
        return [
            "T1071",  # Application Layer Protocol
            "T1001",  # Data Obfuscation
            "T1041",  # Exfiltration Over C2 Channel
            "T1105",  # Ingress Tool Transfer
            "T1571",  # Non-Standard Port
            "T1573",  # Encrypted Channel
            "T1008",  # Fallback Channels
            "T1095",  # Non-Application Layer Protocol
        ]
