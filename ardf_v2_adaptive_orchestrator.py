#!/usr/bin/env python3
"""
ARDF v2 Adaptive Orchestrator
Self-healing workflows that automatically find and install missing tools
Deep reconnaissance with tool auto-discovery
Intelligent task execution with fallback mechanisms
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class ExecutionStrategy(Enum):
    """How to handle missing tools"""
    FAIL_FAST = "fail_immediately"
    TRY_ALTERNATIVES = "use_alternatives"
    AUTO_INSTALL = "auto_install_from_github"
    ADAPTIVE = "try_all_strategies"


class DeepReconnaissanceOrchestrator:
    """
    Deep reconnaissance that automatically discovers needed tools
    Never fails due to missing tools - always finds alternatives
    """
    
    def __init__(self, tool_registry, tool_installer, github_discovery):
        self.registry = tool_registry
        self.installer = tool_installer
        self.discovery = github_discovery
        self.workflow = None
        self.recon_results = {}
        self.tool_execution_map = {}  # Maps what tools were used for what tasks
    
    async def run_deep_recon(self, target: str, strategy: ExecutionStrategy = ExecutionStrategy.ADAPTIVE) -> Dict:
        """
        Execute deep reconnaissance with auto-tool discovery
        Returns detailed recon data with tool metadata
        """
        
        logger.info(f"[*] Starting deep reconnaissance for {target}")
        logger.info(f"[*] Strategy: {strategy.value}")
        
        results = {
            'target': target,
            'strategy': strategy.value,
            'subdomains': [],
            'ips': [],
            'emails': [],
            'technologies': [],
            'open_ports': [],
            'services': [],
            'web_endpoints': [],
            'vulnerabilities': [],
            'tool_execution_map': {},
            'tools_installed': [],
            'tools_from_github': [],
            'fallbacks_used': [],
            'phases': {}
        }
        
        # PHASE 1: Subdomain Enumeration (Self-Healing)
        logger.info("[*] PHASE 1: Subdomain Enumeration")
        
        phase1_result = await self._execute_with_fallback(
            'recon_subdomains',
            'subfinder',
            self._recon_subdomains,
            target,
            strategy
        )
        
        results['subdomains'] = phase1_result.get('output', [])
        results['phases']['subdomain_enumeration'] = phase1_result
        results['tool_execution_map']['subdomains'] = phase1_result.get('executed_tool')
        
        # PHASE 2: DNS & Email Enumeration (Self-Healing)
        logger.info("[*] PHASE 2: DNS & Email Enumeration")
        
        phase2_result = await self._execute_with_fallback(
            'recon_emails',
            'hunter',
            self._recon_emails,
            target,
            strategy
        )
        
        results['emails'] = phase2_result.get('output', [])
        results['phases']['email_enumeration'] = phase2_result
        results['tool_execution_map']['emails'] = phase2_result.get('executed_tool')
        
        # PHASE 3: Technology Fingerprinting (Self-Healing)
        logger.info("[*] PHASE 3: Technology Fingerprinting")
        
        phase3_result = await self._execute_with_fallback(
            'recon_tech',
            'nuclei',
            self._recon_technologies,
            results['subdomains'],
            strategy
        )
        
        results['technologies'] = phase3_result.get('output', [])
        results['phases']['tech_fingerprinting'] = phase3_result
        results['tool_execution_map']['technologies'] = phase3_result.get('executed_tool')
        
        # PHASE 4: Port Scanning (Self-Healing - critical phase)
        logger.info("[*] PHASE 4: Port & Service Scanning")
        
        phase4_result = await self._execute_with_fallback(
            'scan_ports',
            'nmap',
            self._scan_ports,
            results['subdomains'],
            strategy
        )
        
        results['open_ports'] = phase4_result.get('output', {}).get('ports', [])
        results['services'] = phase4_result.get('output', {}).get('services', [])
        results['phases']['port_scanning'] = phase4_result
        results['tool_execution_map']['ports'] = phase4_result.get('executed_tool')
        
        # PHASE 5: Web Discovery (Self-Healing)
        logger.info("[*] PHASE 5: Web Endpoint Discovery")
        
        phase5_result = await self._execute_with_fallback(
            'web_discovery',
            'ffuf',
            self._discover_web_endpoints,
            results['subdomains'],
            strategy
        )
        
        results['web_endpoints'] = phase5_result.get('output', [])
        results['phases']['web_discovery'] = phase5_result
        results['tool_execution_map']['endpoints'] = phase5_result.get('executed_tool')
        
        # PHASE 6: Vulnerability Scanning (Self-Healing)
        logger.info("[*] PHASE 6: Vulnerability Scanning")
        
        phase6_result = await self._execute_with_fallback(
            'vuln_scan',
            'nuclei',
            self._scan_vulnerabilities,
            results['web_endpoints'],
            strategy
        )
        
        results['vulnerabilities'] = phase6_result.get('output', [])
        results['phases']['vulnerability_scanning'] = phase6_result
        results['tool_execution_map']['vulnerabilities'] = phase6_result.get('executed_tool')
        
        # Summary
        results['tools_installed'] = list(self.installer.installed_tools)
        results['tools_from_github'] = getattr(self, 'github_installed_tools', [])
        results['fallbacks_used'] = getattr(self, 'fallbacks_used_list', [])
        
        logger.info(f"[+] Deep reconnaissance complete")
        logger.info(f"[+] Tools used: {results['tool_execution_map']}")
        logger.info(f"[+] Tools installed: {results['tools_installed']}")
        
        return results
    
    async def _execute_with_fallback(self, phase_name: str, primary_tool: str, 
                                    task_func: Callable, task_args, 
                                    strategy: ExecutionStrategy) -> Dict:
        """
        Execute a task with fallback mechanism
        """
        
        result = {
            'phase': phase_name,
            'primary_tool': primary_tool,
            'executed_tool': None,
            'success': False,
            'fallback_used': False,
            'from_github': False,
            'output': None,
            'error': None
        }
        
        logger.info(f"[*] Executing phase: {phase_name} (primary tool: {primary_tool})")
        
        # Try primary tool
        if await self._try_tool(primary_tool):
            try:
                output = await task_func(task_args)
                result['executed_tool'] = primary_tool
                result['success'] = True
                result['output'] = output
                logger.info(f"[+] Phase {phase_name} executed with {primary_tool}")
                return result
            except Exception as e:
                logger.warning(f"[!] {primary_tool} execution failed: {str(e)}")
                result['error'] = str(e)
        
        # Strategy: Try alternatives
        if strategy in [ExecutionStrategy.TRY_ALTERNATIVES, ExecutionStrategy.ADAPTIVE]:
            alternatives = self.registry.get_alternatives(primary_tool)
            
            for alt_tool in alternatives:
                logger.info(f"[*] Trying alternative tool: {alt_tool}")
                
                if await self._try_tool(alt_tool):
                    try:
                        output = await task_func(task_args)
                        result['executed_tool'] = alt_tool
                        result['success'] = True
                        result['fallback_used'] = True
                        result['output'] = output
                        
                        if not hasattr(self, 'fallbacks_used_list'):
                            self.fallbacks_used_list = []
                        self.fallbacks_used_list.append({phase_name: alt_tool})
                        
                        logger.info(f"[+] Phase {phase_name} executed with fallback {alt_tool}")
                        return result
                    except Exception as e:
                        logger.warning(f"[!] {alt_tool} execution failed")
                        continue
        
        # Strategy: Auto-install from GitHub
        if strategy in [ExecutionStrategy.AUTO_INSTALL, ExecutionStrategy.ADAPTIVE]:
            logger.info(f"[*] Searching GitHub for tools to perform '{phase_name}'")
            
            # Map phase name to task type
            from ardf_v2_auto_tool_discovery import TaskType
            
            task_type_map = {
                'recon_subdomains': TaskType.RECON,
                'recon_emails': TaskType.RECON,
                'recon_tech': TaskType.RECON,
                'scan_ports': TaskType.SCAN,
                'web_discovery': TaskType.SCAN,
                'vuln_scan': TaskType.SCAN
            }
            
            task_type = task_type_map.get(phase_name, TaskType.RECON)
            github_tools = await self.discovery.search_tool_by_task(task_type)
            
            for tool_info in github_tools[:3]:
                logger.info(f"[*] Installing {tool_info['name']} from GitHub...")
                
                if await self.installer.install_from_github(tool_info['name'], tool_info['owner']):
                    try:
                        output = await task_func(task_args)
                        result['executed_tool'] = tool_info['name']
                        result['success'] = True
                        result['fallback_used'] = True
                        result['from_github'] = True
                        result['output'] = output
                        
                        if not hasattr(self, 'github_installed_tools'):
                            self.github_installed_tools = []
                        self.github_installed_tools.append(tool_info['name'])
                        
                        logger.info(f"[+] Phase {phase_name} executed with GitHub tool {tool_info['name']}")
                        return result
                    except Exception as e:
                        logger.warning(f"[!] GitHub tool {tool_info['name']} execution failed")
                        continue
        
        # All strategies failed
        result['error'] = f"Could not execute {phase_name} - no available tools"
        logger.error(f"[-] Phase {phase_name} FAILED - no available tools")
        
        return result
    
    async def _try_tool(self, tool_name: str) -> bool:
        """Try to use or install a tool"""
        
        # Check if already available
        if await self.installer.verify_tool(tool_name):
            return True
        
        # Try to install
        if await self.installer.install_tool(tool_name):
            return True
        
        return False
    
    # Task implementation stubs
    async def _recon_subdomains(self, target: str) -> List[str]:
        """Subdomain enumeration task"""
        return []
    
    async def _recon_emails(self, target: str) -> List[str]:
        """Email enumeration task"""
        return []
    
    async def _recon_technologies(self, targets: List[str]) -> List[Dict]:
        """Technology fingerprinting task"""
        return []
    
    async def _scan_ports(self, targets: List[str]) -> Dict:
        """Port scanning task"""
        return {'ports': [], 'services': []}
    
    async def _discover_web_endpoints(self, targets: List[str]) -> List[str]:
        """Web endpoint discovery task"""
        return []
    
    async def _scan_vulnerabilities(self, targets: List[str]) -> List[Dict]:
        """Vulnerability scanning task"""
        return []


class AdaptiveTaskExecutor:
    """
    Executor that adapts to available tools
    If a tool doesn't exist, finds and installs alternatives
    """
    
    def __init__(self, orchestrator: DeepReconnaissanceOrchestrator):
        self.orchestrator = orchestrator
        self.task_history = []
    
    async def execute(self, task_name: str, primary_tool: str, 
                     task_func: Callable, *args, **kwargs) -> Dict:
        """
        Execute a task adaptively
        Always finds a way to complete the task, even if tools must be auto-installed
        """
        
        logger.info(f"[*] Adaptive execution of: {task_name}")
        
        result = await self.orchestrator._execute_with_fallback(
            task_name,
            primary_tool,
            task_func,
            args[0] if args else kwargs,
            ExecutionStrategy.ADAPTIVE
        )
        
        self.task_history.append(result)
        return result
    
    def get_execution_report(self) -> Dict:
        """Get detailed report of all executions"""
        return {
            'total_tasks': len(self.task_history),
            'successful_tasks': sum(1 for t in self.task_history if t['success']),
            'fallbacks_used': sum(1 for t in self.task_history if t['fallback_used']),
            'github_tools_installed': sum(1 for t in self.task_history if t['from_github']),
            'task_history': self.task_history
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    async def demo():
        from ardf_v2_auto_tool_discovery import ToolRegistry, ToolInstaller, GitHubToolDiscovery
        
        registry = ToolRegistry()
        installer = ToolInstaller(registry)
        discovery = GitHubToolDiscovery()
        
        orchestrator = DeepReconnaissanceOrchestrator(registry, installer, discovery)
        
        # Run deep reconnaissance with automatic tool discovery
        results = await orchestrator.run_deep_recon(
            'example.com',
            strategy=ExecutionStrategy.ADAPTIVE
        )
        
        print(f"Reconnaissance complete: {results['tool_execution_map']}")
    
    # asyncio.run(demo())
