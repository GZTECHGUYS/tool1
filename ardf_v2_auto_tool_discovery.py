#!/usr/bin/env python3
"""
ARDF v2 Auto-Tool Discovery & Installation Module
GitHub-based tool marketplace integration
Self-healing workflows that find and install missing tools
Intelligent tool selection based on task requirements
"""

import asyncio
import subprocess
import json
import requests
import os
import sys
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TaskType(Enum):
    """Task types that need specific tools"""
    RECON = "reconnaissance"
    SCAN = "scanning"
    EXPLOIT = "exploitation"
    LATERAL = "lateral_movement"
    EXFIL = "exfiltration"
    EVASION = "evasion"
    REPORTING = "reporting"


@dataclass
class ToolMetadata:
    """Tool information"""
    name: str
    github_repo: str
    github_owner: str
    install_command: str
    executable_name: str
    test_command: str  # Command to verify installation
    task_types: List[TaskType]  # What tasks this tool is for
    alternatives: List[str] = None  # Alternative tools if this fails
    min_version: Optional[str] = None
    platform_specific: Dict[str, str] = None  # Platform-specific install commands


class ToolRegistry:
    """Registry of all tools ARDF can use"""
    
    def __init__(self):
        self.registry = {
            # RECONNAISSANCE TOOLS
            'subfinder': ToolMetadata(
                name='subfinder',
                github_repo='subfinder',
                github_owner='projectdiscovery',
                install_command='go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                executable_name='subfinder',
                test_command='subfinder --version',
                task_types=[TaskType.RECON],
                alternatives=['amass', 'assetfinder']
            ),
            'amass': ToolMetadata(
                name='amass',
                github_repo='amass',
                github_owner='owasp',
                install_command='go install -v github.com/owasp/amass/v3/...@master',
                executable_name='amass',
                test_command='amass --version',
                task_types=[TaskType.RECON],
                alternatives=['subfinder', 'assetfinder']
            ),
            'assetfinder': ToolMetadata(
                name='assetfinder',
                github_repo='assetfinder',
                github_owner='tomnomnom',
                install_command='go install github.com/tomnomnom/assetfinder@latest',
                executable_name='assetfinder',
                test_command='assetfinder --help',
                task_types=[TaskType.RECON],
                alternatives=['subfinder', 'amass']
            ),
            
            # SCANNING TOOLS
            'nmap': ToolMetadata(
                name='nmap',
                github_repo='nmap',
                github_owner='nmap',
                install_command='apt-get install -y nmap',
                executable_name='nmap',
                test_command='nmap --version',
                task_types=[TaskType.SCAN],
                alternatives=['masscan', 'zmap'],
                platform_specific={
                    'debian': 'apt-get install -y nmap',
                    'rhel': 'yum install -y nmap',
                    'macos': 'brew install nmap'
                }
            ),
            'masscan': ToolMetadata(
                name='masscan',
                github_repo='masscan',
                github_owner='robertdavidgraham',
                install_command='apt-get install -y masscan',
                executable_name='masscan',
                test_command='masscan --version',
                task_types=[TaskType.SCAN],
                alternatives=['nmap', 'zmap']
            ),
            'ffuf': ToolMetadata(
                name='ffuf',
                github_repo='ffuf',
                github_owner='ffuf',
                install_command='go install github.com/ffuf/ffuf/v2@latest',
                executable_name='ffuf',
                test_command='ffuf -h',
                task_types=[TaskType.SCAN],
                alternatives=['dirb', 'gobuster', 'dirbuster']
            ),
            'nuclei': ToolMetadata(
                name='nuclei',
                github_repo='nuclei',
                github_owner='projectdiscovery',
                install_command='go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
                executable_name='nuclei',
                test_command='nuclei --version',
                task_types=[TaskType.SCAN, TaskType.EXPLOIT],
                alternatives=['burp', 'zaproxy']
            ),
            
            # EXPLOITATION TOOLS
            'sqlmap': ToolMetadata(
                name='sqlmap',
                github_repo='sqlmap',
                github_owner='sqlmapproject',
                install_command='apt-get install -y sqlmap',
                executable_name='sqlmap.py',
                test_command='sqlmap --version',
                task_types=[TaskType.EXPLOIT],
                alternatives=['burp', 'havij']
            ),
            'xsstrike': ToolMetadata(
                name='xsstrike',
                github_repo='xsstrike',
                github_owner='s0md3v',
                install_command='git clone https://github.com/s0md3v/xsstrike.git /opt/xsstrike && cd /opt/xsstrike && pip3 install -r requirements.txt',
                executable_name='xsstrike',
                test_command='python3 /opt/xsstrike/xsstrike.py --help',
                task_types=[TaskType.EXPLOIT],
                alternatives=['dalfox', 'burp']
            ),
            'dalfox': ToolMetadata(
                name='dalfox',
                github_repo='dalfox',
                github_owner='hahwul',
                install_command='go install github.com/hahwul/dalfox/v2@latest',
                executable_name='dalfox',
                test_command='dalfox --version',
                task_types=[TaskType.EXPLOIT],
                alternatives=['xsstrike', 'burp']
            ),
            'impacket': ToolMetadata(
                name='impacket',
                github_repo='impacket',
                github_owner='SecureAuthCorp',
                install_command='pip3 install impacket',
                executable_name='impacket',
                test_command='python3 -c "import impacket; print(impacket.__version__)"',
                task_types=[TaskType.LATERAL, TaskType.EXPLOIT],
                alternatives=['metasploit', 'cobalt_strike']
            ),
            
            # LATERAL MOVEMENT
            'mimikatz': ToolMetadata(
                name='mimikatz',
                github_repo='mimikatz',
                github_owner='gentilkiwi',
                install_command='curl -L https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220419/mimikatz_trunk.zip -o /tmp/mimikatz.zip && unzip /tmp/mimikatz.zip -d /opt/mimikatz',
                executable_name='mimikatz.exe',
                test_command='file /opt/mimikatz/x64/mimikatz.exe',
                task_types=[TaskType.LATERAL, TaskType.EXPLOIT],
                alternatives=['pypykatz', 'lsassy']
            ),
            'bloodhound': ToolMetadata(
                name='bloodhound',
                github_repo='BloodHoundAD',
                github_owner='BloodHoundAD',
                install_command='pip3 install bloodhound',
                executable_name='bloodhound-python',
                test_command='bloodhound-python --help',
                task_types=[TaskType.LATERAL, TaskType.RECON],
                alternatives=['sharphound', 'adfind']
            ),
        }
    
    def get_tool(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get tool metadata by name"""
        return self.registry.get(tool_name.lower())
    
    def get_tools_for_task(self, task_type: TaskType) -> List[ToolMetadata]:
        """Get all tools that can perform a specific task"""
        return [tool for tool in self.registry.values() if task_type in tool.task_types]
    
    def get_alternatives(self, tool_name: str) -> List[str]:
        """Get alternative tools for a failed tool"""
        tool = self.get_tool(tool_name)
        if tool and tool.alternatives:
            return tool.alternatives
        return []


class GitHubToolDiscovery:
    """Search GitHub for tools needed for specific tasks"""
    
    def __init__(self, github_token: Optional[str] = None):
        """Initialize with optional GitHub token for higher rate limits"""
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {}
        
        if github_token:
            self.headers['Authorization'] = f'token {github_token}'
        
        self.headers['Accept'] = 'application/vnd.github.v3+json'
    
    async def search_tool_by_function(self, function: str, keywords: List[str] = None) -> List[Dict]:
        """
        Search GitHub for tools that perform a specific function
        E.g., search for "SQL injection" tools, "reconnaissance" tools, etc.
        """
        search_terms = keywords or [function]
        results = []
        
        for term in search_terms:
            query = f'"{term}" language:python OR language:go stars:>100'
            
            try:
                response = requests.get(
                    f'{self.base_url}/search/repositories',
                    params={'q': query, 'sort': 'stars', 'order': 'desc', 'per_page': 10},
                    headers=self.headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    repos = response.json().get('items', [])
                    
                    for repo in repos:
                        result = {
                            'name': repo['name'],
                            'owner': repo['owner']['login'],
                            'url': repo['clone_url'],
                            'description': repo['description'],
                            'stars': repo['stargazers_count'],
                            'language': repo['language'],
                            'last_updated': repo['updated_at']
                        }
                        results.append(result)
                        logger.info(f"[+] Found tool: {repo['name']} by {repo['owner']['login']}")
            
            except Exception as e:
                logger.error(f"[-] GitHub search failed for '{term}': {str(e)}")
        
        return results
    
    async def search_tool_by_task(self, task_type: TaskType) -> List[Dict]:
        """Search for tools specific to a task type"""
        
        task_keywords = {
            TaskType.RECON: ['subdomain enumeration', 'asset discovery', 'osint'],
            TaskType.SCAN: ['port scanning', 'vulnerability scanning', 'network scan'],
            TaskType.EXPLOIT: ['sql injection', 'rce', 'web exploitation', 'exploit'],
            TaskType.LATERAL: ['privilege escalation', 'lateral movement', 'post exploitation'],
            TaskType.EXFIL: ['data exfiltration', 'data extraction'],
            TaskType.EVASION: ['evasion', 'anti-forensics', 'log cleanup'],
            TaskType.REPORTING: ['reporting', 'vulnerability report']
        }
        
        keywords = task_keywords.get(task_type, [task_type.value])
        
        logger.info(f"[*] Searching GitHub for {task_type.value} tools...")
        return await self.search_tool_by_function(task_type.value, keywords)
    
    async def search_tool_by_missing_capability(self, capability: str) -> List[Dict]:
        """
        Search for tools that implement a missing capability
        Used when a task fails because of missing functionality
        """
        logger.info(f"[*] Searching for tools with capability: {capability}")
        return await self.search_tool_by_function(capability)


class ToolInstaller:
    """Automatically install and configure tools"""
    
    def __init__(self, registry: ToolRegistry):
        self.registry = registry
        self.installed_tools = set()
        self.failed_tools = set()
    
    async def install_tool(self, tool_name: str) -> bool:
        """Install a tool using its installation command"""
        
        tool = self.registry.get_tool(tool_name)
        if not tool:
            logger.error(f"[-] Tool not found in registry: {tool_name}")
            return False
        
        if tool_name in self.installed_tools:
            logger.info(f"[+] Tool already installed: {tool_name}")
            return True
        
        logger.info(f"[*] Installing tool: {tool_name}")
        
        try:
            # Use platform-specific install command if available
            install_cmd = tool.install_command
            
            if tool.platform_specific:
                platform = self._detect_platform()
                if platform in tool.platform_specific:
                    install_cmd = tool.platform_specific[platform]
            
            # Execute installation
            result = subprocess.run(install_cmd, shell=True, capture_output=True, timeout=300)
            
            if result.returncode == 0:
                # Verify installation
                if await self.verify_tool(tool_name):
                    self.installed_tools.add(tool_name)
                    logger.info(f"[+] Tool installed successfully: {tool_name}")
                    return True
            
            logger.error(f"[-] Installation failed for {tool_name}")
            self.failed_tools.add(tool_name)
            return False
        
        except Exception as e:
            logger.error(f"[-] Tool installation error: {str(e)}")
            self.failed_tools.add(tool_name)
            return False
    
    async def install_from_github(self, github_repo: str, github_owner: str) -> bool:
        """Install tool directly from GitHub repository"""
        
        logger.info(f"[*] Installing from GitHub: {github_owner}/{github_repo}")
        
        try:
            repo_url = f"https://github.com/{github_owner}/{github_repo}.git"
            install_dir = f"/opt/{github_repo}"
            
            # Clone repository
            clone_cmd = f"git clone {repo_url} {install_dir}"
            result = subprocess.run(clone_cmd, shell=True, capture_output=True, timeout=60)
            
            if result.returncode == 0:
                logger.info(f"[+] Repository cloned to {install_dir}")
                
                # Check for requirements.txt (Python) or go.mod (Go)
                if os.path.exists(f"{install_dir}/requirements.txt"):
                    req_cmd = f"pip3 install -r {install_dir}/requirements.txt"
                    subprocess.run(req_cmd, shell=True, capture_output=True, timeout=120)
                
                if os.path.exists(f"{install_dir}/go.mod"):
                    build_cmd = f"cd {install_dir} && go build"
                    subprocess.run(build_cmd, shell=True, capture_output=True, timeout=120)
                
                logger.info(f"[+] Tool installed from GitHub: {github_repo}")
                return True
        
        except Exception as e:
            logger.error(f"[-] GitHub installation failed: {str(e)}")
        
        return False
    
    async def verify_tool(self, tool_name: str) -> bool:
        """Verify tool is installed and working"""
        
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return False
        
        try:
            result = subprocess.run(tool.test_command, shell=True, capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def _detect_platform() -> str:
        """Detect operating system"""
        if sys.platform == 'darwin':
            return 'macos'
        elif sys.platform.startswith('linux'):
            # Further detect Linux distro
            if os.path.exists('/etc/debian_version'):
                return 'debian'
            elif os.path.exists('/etc/redhat-release'):
                return 'rhel'
        elif sys.platform == 'win32':
            return 'windows'
        return 'linux'


class AdaptiveWorkflow:
    """Workflow execution with auto-fallback and tool discovery"""
    
    def __init__(self, registry: ToolRegistry, installer: ToolInstaller, discovery: GitHubToolDiscovery):
        self.registry = registry
        self.installer = installer
        self.discovery = discovery
        self.execution_log = []
    
    async def execute_task(self, task_type: TaskType, primary_tool: str, 
                          task_function: Callable, *args, **kwargs) -> Dict:
        """
        Execute a task with automatic fallback mechanism
        If primary tool fails or doesn't exist, find alternatives
        """
        
        result = {
            'task': task_type.value,
            'primary_tool': primary_tool,
            'executed_tool': None,
            'success': False,
            'error': None,
            'fallback_used': False,
            'output': None
        }
        
        # Step 1: Check if primary tool is available
        logger.info(f"[*] Executing {task_type.value} with {primary_tool}")
        
        available = await self._check_tool_available(primary_tool)
        
        if not available:
            logger.warning(f"[!] Primary tool not available: {primary_tool}")
            
            # Step 2: Try to install primary tool
            if await self.installer.install_tool(primary_tool):
                logger.info(f"[+] Successfully installed {primary_tool}")
                available = True
            else:
                # Step 3: Find and try alternatives
                logger.warning(f"[-] Could not install {primary_tool}, searching for alternatives...")
                available = await self._find_and_install_alternative(primary_tool, task_type)
        
        # Step 4: Execute task
        if available:
            try:
                output = await task_function(*args, **kwargs)
                result['success'] = True
                result['executed_tool'] = primary_tool
                result['output'] = output
                self.execution_log.append(result)
                return result
            
            except Exception as e:
                logger.error(f"[-] Task execution failed: {str(e)}")
                result['error'] = str(e)
                
                # Try alternative tools
                alternatives = self.registry.get_alternatives(primary_tool)
                if alternatives:
                    for alt_tool in alternatives:
                        logger.info(f"[*] Trying alternative tool: {alt_tool}")
                        if await self.installer.install_tool(alt_tool):
                            try:
                                output = await task_function(*args, **kwargs)
                                result['success'] = True
                                result['executed_tool'] = alt_tool
                                result['fallback_used'] = True
                                result['output'] = output
                                self.execution_log.append(result)
                                return result
                            except:
                                continue
        
        # Step 5: Search GitHub for tool with required capability
        logger.warning(f"[!] No available tools for {task_type.value}, searching GitHub...")
        
        github_tools = await self.discovery.search_tool_by_task(task_type)
        
        if github_tools:
            for tool_info in github_tools[:3]:  # Try top 3 tools from GitHub
                logger.info(f"[*] Installing {tool_info['name']} from GitHub...")
                
                if await self.installer.install_from_github(tool_info['name'], tool_info['owner']):
                    try:
                        output = await task_function(*args, **kwargs)
                        result['success'] = True
                        result['executed_tool'] = tool_info['name']
                        result['fallback_used'] = True
                        result['output'] = output
                        result['from_github'] = True
                        self.execution_log.append(result)
                        return result
                    except:
                        continue
        
        # All attempts failed
        result['error'] = f"No available tools for {task_type.value}"
        self.execution_log.append(result)
        return result
    
    async def _check_tool_available(self, tool_name: str) -> bool:
        """Check if tool is installed and working"""
        return await self.installer.verify_tool(tool_name)
    
    async def _find_and_install_alternative(self, original_tool: str, task_type: TaskType) -> bool:
        """Find and install alternative tool for task"""
        
        alternatives = self.registry.get_alternatives(original_tool)
        
        for alt_tool in alternatives:
            logger.info(f"[*] Trying alternative tool: {alt_tool}")
            
            if await self.installer.install_tool(alt_tool):
                logger.info(f"[+] Alternative tool installed: {alt_tool}")
                return True
        
        # If no alternatives available, search GitHub
        logger.info(f"[*] No local alternatives, searching GitHub for {task_type.value} tools...")
        
        github_tools = await self.discovery.search_tool_by_task(task_type)
        
        for tool_info in github_tools[:3]:
            if await self.installer.install_from_github(tool_info['name'], tool_info['owner']):
                return True
        
        return False


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    async def demo():
        # Initialize components
        registry = ToolRegistry()
        installer = ToolInstaller(registry)
        discovery = GitHubToolDiscovery()
        workflow = AdaptiveWorkflow(registry, installer, discovery)
        
        # Example: Execute reconnaissance task
        async def sample_recon():
            return "Reconnaissance output"
        
        # This will:
        # 1. Try to use subfinder
        # 2. If not available, install it
        # 3. If installation fails, try amass
        # 4. If no tools available, search GitHub
        # 5. Download and install best match from GitHub
        # 6. Execute task with whatever tool is available
        
        result = await workflow.execute_task(
            TaskType.RECON,
            'subfinder',
            sample_recon
        )
        
        print(f"Task result: {result}")
    
    # asyncio.run(demo())
