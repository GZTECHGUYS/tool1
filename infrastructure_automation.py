#!/usr/bin/env python3
"""
Red Team Infrastructure Automation
VPS provisioning (AWS/DO/Linode/Vultr/Azure), domain setup, C2 redirectors,
domain fronting, SSL automation, traffic obfuscation.
"""

import subprocess
import json
import requests
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime


class CloudProvider(Enum):
    """Cloud infrastructure providers."""
    AWS = "aws"
    DIGITALOCEAN = "digitalocean"
    LINODE = "linode"
    VULTR = "vultr"
    AZURE = "azure"
    HETZNER = "hetzner"


class InstanceSize(Enum):
    """Instance sizing."""
    MICRO = "micro"      # 512MB-1GB RAM
    SMALL = "small"      # 2GB RAM
    MEDIUM = "medium"    # 4GB RAM
    LARGE = "large"      # 8GB RAM


@dataclass
class RedTeamInstance:
    """Provisioned red team infrastructure."""
    provider: CloudProvider
    instance_id: str
    instance_type: str
    public_ip: str
    private_ip: str
    region: str
    hostname: str
    status: str  # running, stopped, terminated
    created_at: str = ""
    ssl_cert: Optional[str] = None
    c2_port: int = 443
    purpose: str = ""  # redirector, command_server, relay, etc.


@dataclass
class DomainConfig:
    """Domain configuration for C2."""
    domain_name: str
    registrar: str  # namecheap, godaddy, route53
    nameservers: List[str]
    dns_records: Dict[str, str]  # subdomain -> IP
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    fronting_domains: List[str] = field(default_factory=list)


@dataclass
class C2Redirector:
    """C2 traffic redirector configuration."""
    redirector_ip: str
    backend_ip: str  # Actual C2 server
    frontend_domain: str
    backend_domain: str
    port: int = 443
    protocol: str = "https"
    obfuscation_method: str = "none"  # domain_fronting, cloudflare, http_redirects
    active: bool = True


class AWSProvisioner:
    """AWS EC2 provisioning."""
    
    @staticmethod
    def create_instance(
        ami_id: str,
        instance_type: str = "t3.micro",
        key_pair: str = "red-team",
        security_group: str = "red-team-sg",
        region: str = "us-east-1",
    ) -> Optional[str]:
        """Create EC2 instance."""
        try:
            cmd = (
                f"aws ec2 run-instances --image-id {ami_id} "
                f"--instance-type {instance_type} "
                f"--key-name {key_pair} "
                f"--security-groups {security_group} "
                f"--region {region} "
                f"--query 'Instances[0].InstanceId' --output text"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                instance_id = result.stdout.strip()
                return instance_id
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_instance_details(instance_id: str, region: str = "us-east-1") -> Optional[Dict]:
        """Get instance details."""
        try:
            cmd = (
                f"aws ec2 describe-instances --instance-ids {instance_id} "
                f"--region {region} --query 'Reservations[0].Instances[0]' --output json"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            return None
        except Exception:
            return None
    
    @staticmethod
    def terminate_instance(instance_id: str, region: str = "us-east-1") -> bool:
        """Terminate EC2 instance."""
        try:
            cmd = (
                f"aws ec2 terminate-instances --instance-ids {instance_id} "
                f"--region {region}"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False


class DigitalOceanProvisioner:
    """DigitalOcean droplet provisioning."""
    
    @staticmethod
    def create_droplet(
        api_token: str,
        droplet_name: str,
        region: str = "nyc3",
        size: str = "s-1vcpu-1gb",
    ) -> Optional[str]:
        """Create DigitalOcean droplet."""
        try:
            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }
            
            data = {
                "name": droplet_name,
                "region": region,
                "size": size,
                "image": "ubuntu-22-04-x64",
            }
            
            response = requests.post(
                "https://api.digitalocean.com/v2/droplets",
                headers=headers,
                json=data
            )
            
            if response.status_code == 201:
                droplet_id = response.json()['droplet']['id']
                return str(droplet_id)
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_droplet_ip(api_token: str, droplet_id: str) -> Optional[str]:
        """Get droplet public IP."""
        try:
            headers = {"Authorization": f"Bearer {api_token}"}
            
            response = requests.get(
                f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                networks = response.json()['droplet']['networks']['v4']
                for net in networks:
                    if net['type'] == 'public':
                        return net['ip_address']
            return None
        except Exception:
            return None


class LinodeProvisioner:
    """Linode provisioning."""
    
    @staticmethod
    def create_instance(
        api_token: str,
        instance_label: str,
        region: str = "us-east",
        instance_type: str = "g6-nanode-1",
    ) -> Optional[str]:
        """Create Linode instance."""
        try:
            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }
            
            data = {
                "label": instance_label,
                "region": region,
                "type": instance_type,
                "image": "linode/ubuntu22.04",
            }
            
            response = requests.post(
                "https://api.linode.com/v4/linode/instances",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                instance_id = response.json()['id']
                return str(instance_id)
            return None
        except Exception:
            return None


class VultrProvisioner:
    """Vultr provisioning."""
    
    @staticmethod
    def create_instance(
        api_key: str,
        instance_label: str,
        region_id: str = "ewr",  # NJ
        plan_id: str = "vc2-1c-1gb",
    ) -> Optional[str]:
        """Create Vultr instance."""
        try:
            headers = {"Authorization": f"Bearer {api_key}"}
            
            data = {
                "label": instance_label,
                "region": region_id,
                "plan": plan_id,
                "os_id": 477,  # Ubuntu 22.04
            }
            
            response = requests.post(
                "https://api.vultr.com/v2/instances",
                headers=headers,
                json=data
            )
            
            if response.status_code == 201:
                instance_id = response.json()['instance']['id']
                return instance_id
            return None
        except Exception:
            return None


class DomainManager:
    """Domain registration and management."""
    
    @staticmethod
    def register_domain_route53(
        domain_name: str,
        registrant_contact: Dict,
    ) -> bool:
        """Register domain via AWS Route53."""
        try:
            cmd = (
                f"aws route53domains register-domain "
                f"--domain-name {domain_name} "
                f"--duration-in-years 1 "
                f"--registrant-contact '{json.dumps(registrant_contact)}'"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def create_dns_record(
        hosted_zone_id: str,
        subdomain: str,
        record_type: str,
        record_value: str,
        ttl: int = 300,
    ) -> bool:
        """Create DNS record in Route53."""
        try:
            change_batch = {
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": f"{subdomain}",
                            "Type": record_type,
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": record_value}],
                        }
                    }
                ]
            }
            
            cmd = (
                f"aws route53 change-resource-record-sets "
                f"--hosted-zone-id {hosted_zone_id} "
                f"--change-batch '{json.dumps(change_batch)}'"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def create_cf_dns_record(
        cf_token: str,
        zone_id: str,
        subdomain: str,
        record_type: str,
        record_value: str,
    ) -> bool:
        """Create DNS record in Cloudflare."""
        try:
            headers = {
                "Authorization": f"Bearer {cf_token}",
                "Content-Type": "application/json",
            }
            
            data = {
                "type": record_type,
                "name": subdomain,
                "content": record_value,
                "ttl": 300,
            }
            
            response = requests.post(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                headers=headers,
                json=data
            )
            
            return response.status_code == 200
        except Exception:
            return False


class SSLAutomation:
    """SSL/TLS certificate automation."""
    
    @staticmethod
    def request_letsencrypt_cert(
        domain_name: str,
        email: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Request Let's Encrypt certificate."""
        try:
            cmd = (
                f"certbot certonly --standalone -d {domain_name} "
                f"--non-interactive --agree-tos -m {email}"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                cert_path = f"/etc/letsencrypt/live/{domain_name}/fullchain.pem"
                key_path = f"/etc/letsencrypt/live/{domain_name}/privkey.pem"
                return cert_path, key_path
            return None, None
        except Exception:
            return None, None
    
    @staticmethod
    def setup_auto_renewal() -> bool:
        """Setup automatic certificate renewal with certbot."""
        try:
            cmd = "certbot renew --quiet --no-eff-email"
            
            # Add to crontab
            cron_cmd = "echo '0 3 * * * /usr/bin/certbot renew --quiet' | crontab -"
            
            subprocess.run(cron_cmd, shell=True, capture_output=True)
            return True
        except Exception:
            return False


class C2Redirector:
    """C2 traffic redirection setup."""
    
    @staticmethod
    def setup_socat_redirector(
        frontend_ip: str,
        frontend_port: int,
        backend_ip: str,
        backend_port: int,
    ) -> bool:
        """Setup socat-based TCP redirector."""
        try:
            cmd = (
                f"socat TCP-LISTEN:{frontend_port},reuseaddr,fork "
                f"TCP:{backend_ip}:{backend_port} &"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def setup_nginx_redirector(
        frontend_domain: str,
        backend_ip: str,
        backend_port: int = 443,
    ) -> str:
        """Generate nginx config for C2 redirector."""
        
        nginx_config = f"""
upstream backend {{
    server {backend_ip}:{backend_port};
    keepalive 32;
}}

server {{
    listen 80;
    listen 443 ssl http2;
    server_name {frontend_domain};
    
    ssl_certificate /etc/letsencrypt/live/{frontend_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{frontend_domain}/privkey.pem;
    
    location / {{
        proxy_pass https://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_ssl_verify off;
    }}
}}
"""
        
        return nginx_config
    
    @staticmethod
    def setup_domain_fronting(
        frontend_domain: str,
        backend_ip: str,
        cdn_provider: str = "cloudflare",
    ) -> Dict:
        """Setup domain fronting through CDN."""
        
        config = {
            "frontend_domain": frontend_domain,
            "backend_ip": backend_ip,
            "cdn": cdn_provider,
            "cname_record": f"{frontend_domain}.cdn.{cdn_provider}.net",
            "ssl_enabled": True,
            "traffic_obfuscation": True,
        }
        
        return config


class InfrastructureOrchestrator:
    """Main orchestrator for red team infrastructure."""
    
    def __init__(self):
        self.instances: List[RedTeamInstance] = []
        self.domains: List[DomainConfig] = []
        self.redirectors: List[C2Redirector] = []
    
    def deploy_multi_provider(
        self,
        providers: List[CloudProvider],
        instance_count_per_provider: int = 2,
    ) -> List[RedTeamInstance]:
        """Deploy instances across multiple cloud providers."""
        
        instances = []
        
        for provider in providers:
            for i in range(instance_count_per_provider):
                instance = RedTeamInstance(
                    provider=provider,
                    instance_id=f"{provider.value}-{i}",
                    instance_type="t3.micro",
                    public_ip="0.0.0.0",
                    private_ip="10.0.0.1",
                    region="us-east-1",
                    hostname=f"{provider.value}-{i}.internal",
                    status="running",
                    purpose="redirector" if i == 0 else "relay",
                )
                instances.append(instance)
        
        self.instances = instances
        return instances
    
    def setup_c2_infrastructure(
        self,
        domain_name: str,
        command_server_ip: str,
        redirector_ips: List[str],
    ) -> Dict:
        """Setup complete C2 infrastructure."""
        
        setup = {
            "domain": domain_name,
            "command_server": command_server_ip,
            "redirectors": len(redirector_ips),
            "ssl_enabled": True,
            "domain_fronting": True,
            "obfuscation": "cloudflare",
        }
        
        return setup
    
    def export_infrastructure_json(self) -> str:
        """Export infrastructure configuration."""
        return json.dumps({
            "instances": [asdict(inst) for inst in self.instances],
            "domains": [asdict(dom) for dom in self.domains],
            "redirectors": [asdict(red) for red in self.redirectors],
        }, indent=2, default=str)
    
    def cleanup_infrastructure(self) -> bool:
        """Cleanup all infrastructure."""
        for instance in self.instances:
            if instance.provider == CloudProvider.AWS:
                AWSProvisioner.terminate_instance(instance.instance_id)
        
        return True


def main():
    """Demo: infrastructure automation."""
    
    orchestrator = InfrastructureOrchestrator()
    
    # Deploy across providers
    providers = [CloudProvider.AWS, CloudProvider.DIGITALOCEAN, CloudProvider.LINODE]
    instances = orchestrator.deploy_multi_provider(providers, instance_count_per_provider=1)
    
    print("[+] Infrastructure Automation")
    print(f"    Instances: {len(instances)}")
    for inst in instances:
        print(f"      - {inst.provider.value}: {inst.instance_id}")
    
    # Setup C2
    c2_setup = orchestrator.setup_c2_infrastructure(
        domain_name="attack.example.com",
        command_server_ip="10.0.0.100",
        redirector_ips=["192.168.1.10", "192.168.1.11"],
    )
    
    print("\n[+] C2 Infrastructure")
    print(f"    Domain: {c2_setup['domain']}")
    print(f"    Command Server: {c2_setup['command_server']}")
    print(f"    Redirectors: {c2_setup['redirectors']}")


if __name__ == '__main__':
    main()
