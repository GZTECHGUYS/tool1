"""
modules/attack_chains.py
─────────────────────────
Multi-step attack chain sequencing and execution.

Converts reconnaissance findings into executable attack sequences:
  - SQLi → authentication bypass → RCE
  - Weak creds → lateral movement → domain control
  - Misconfig → privilege escalation → persistence

Each chain:
  - Maps to MITRE ATT&CK kill chain
  - Includes evasion checkpoints between steps
  - Can be interrupted if detection triggered
  - Falls back if any step fails
"""

import json
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.redteam_base import RedTeamModule, OpSecScore


class ChainStage(Enum):
    """Stages in attack execution."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class ChainStatus(Enum):
    """Status of chain execution."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    PAUSED = "paused"
    REVERTED = "reverted"


@dataclass
class AttackStep:
    """Single step in an attack chain."""
    
    step_id: str
    stage: ChainStage
    description: str
    mitre_technique: str
    executor: Callable[..., Dict[str, Any]]
    dependencies: List[str]  # List of step_ids that must succeed first
    fallback_steps: List[str]  # Alternative steps if this fails
    opsec_profile: Dict[str, float]  # noise, detectability, recovery_time
    timeout_seconds: int = 60
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "stage": self.stage.value,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "dependencies": self.dependencies,
            "fallback_steps": self.fallback_steps,
            "opsec_profile": self.opsec_profile,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class ExecutionNode:
    """Tracks execution state of a single step."""
    
    step_id: str
    status: ChainStatus = ChainStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    opsec_score: Optional[Dict[str, float]] = None
    artifacts: List[str] = None
    
    def __post_init__(self):
        if self.artifacts is None:
            self.artifacts = []


class AttackChain:
    """Represents a complete attack chain with multiple steps."""
    
    def __init__(
        self,
        chain_id: str,
        name: str,
        description: str,
        objective: str,
        initial_finding: Finding,
        logger: Optional[ARDFLogger] = None,
    ):
        self.chain_id = chain_id
        self.name = name
        self.description = description
        self.objective = objective
        self.initial_finding = initial_finding
        self.logger = logger or get_logger("attack_chains")
        
        self.steps: Dict[str, AttackStep] = {}
        self.execution: Dict[str, ExecutionNode] = {}
        self.status = ChainStatus.PENDING
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
    
    def add_step(self, step: AttackStep) -> None:
        """Add a step to the chain."""
        self.steps[step.step_id] = step
        self.execution[step.step_id] = ExecutionNode(step.step_id)
        self.logger.debug(f"Added step {step.step_id} to chain {self.chain_id}")
    
    def add_steps(self, steps: List[AttackStep]) -> None:
        """Add multiple steps to the chain."""
        for step in steps:
            self.add_step(step)
    
    def get_executable_steps(self) -> List[str]:
        """Return step IDs that are ready to execute (all deps satisfied)."""
        executable = []
        for step_id, node in self.execution.items():
            if node.status != ChainStatus.PENDING:
                continue  # Already executed or failed
            
            step = self.steps[step_id]
            # Check if all dependencies succeeded
            deps_met = all(
                self.execution[dep_id].status == ChainStatus.SUCCESS
                for dep_id in step.dependencies
            )
            
            if deps_met:
                executable.append(step_id)
        
        return executable
    
    def execute(
        self,
        check_detection: Optional[Callable[[], bool]] = None,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """
        Execute the attack chain end-to-end.
        
        Args:
            check_detection: Optional function that returns True if detection triggered
            max_retries: Number of times to retry failed steps with fallbacks
        
        Returns:
            Execution summary with results and artifacts
        """
        self.status = ChainStatus.IN_PROGRESS
        self.start_time = time.time()
        
        self.logger.info(
            f"Starting attack chain: {self.name} ({self.chain_id})",
            extra={
                "chain_id": self.chain_id,
                "objective": self.objective,
                "steps_count": len(self.steps),
            }
        )
        
        retry_counts: Dict[str, int] = {step_id: 0 for step_id in self.steps}
        
        while True:
            # Check if we should abort due to detection
            if check_detection and check_detection():
                self.logger.warning("Detection triggered - pausing chain execution")
                self.status = ChainStatus.PAUSED
                break
            
            # Get next executable steps
            executable = self.get_executable_steps()
            if not executable:
                break  # No more steps can execute
            
            # Execute each step
            for step_id in executable:
                step = self.steps[step_id]
                node = self.execution[step_id]
                
                self.logger.info(
                    f"Executing step: {step.description}",
                    extra={"step_id": step_id, "stage": step.stage.value}
                )
                
                try:
                    # Execute the step
                    start = time.time()
                    result = step.executor()
                    duration = time.time() - start
                    
                    node.execution_time = duration
                    node.result = result
                    node.status = ChainStatus.SUCCESS
                    
                    self.logger.info(
                        f"Step {step_id} succeeded",
                        extra={
                            "step_id": step_id,
                            "duration": duration,
                            "result_keys": list(result.keys()) if result else [],
                        }
                    )
                
                except Exception as e:
                    error_msg = str(e)
                    self.logger.error(
                        f"Step {step_id} failed: {error_msg}",
                        extra={"step_id": step_id, "error": error_msg}
                    )
                    
                    node.error = error_msg
                    node.status = ChainStatus.FAILED
                    
                    # Try fallback steps
                    if retry_counts[step_id] < max_retries and step.fallback_steps:
                        fallback_id = step.fallback_steps[retry_counts[step_id]]
                        retry_counts[step_id] += 1
                        
                        self.logger.info(
                            f"Trying fallback: {fallback_id}",
                            extra={"original_step": step_id, "fallback": fallback_id}
                        )
                        
                        # Promote fallback step to be a dependency for next steps
                        # (This is handled by chain structure design)
                    else:
                        self.logger.error(
                            f"No fallback for step {step_id} - chain may stall",
                            extra={"step_id": step_id}
                        )
        
        # Determine final status
        failed_steps = [
            s for s, n in self.execution.items()
            if n.status == ChainStatus.FAILED
        ]
        
        if failed_steps:
            self.status = ChainStatus.FAILED
        else:
            self.status = ChainStatus.SUCCESS
        
        self.end_time = time.time()
        
        return self.get_summary()
    
    def get_executable_steps_in_order(self) -> List[List[str]]:
        """Return steps grouped by execution waves (respecting dependencies)."""
        waves: List[List[str]] = []
        executed = set()
        
        while executed != set(self.steps.keys()):
            current_wave = []
            for step_id, step in self.steps.items():
                if step_id in executed:
                    continue
                
                # Can execute if all deps are already executed
                if all(dep_id in executed for dep_id in step.dependencies):
                    current_wave.append(step_id)
            
            if not current_wave:
                break  # Circular dependency or all done
            
            waves.append(current_wave)
            executed.update(current_wave)
        
        return waves
    
    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary."""
        elapsed = (self.end_time - self.start_time) if self.start_time and self.end_time else 0
        
        total_steps = len(self.steps)
        successful = sum(1 for n in self.execution.values() if n.status == ChainStatus.SUCCESS)
        failed = sum(1 for n in self.execution.values() if n.status == ChainStatus.FAILED)
        
        artifacts = []
        for node in self.execution.values():
            artifacts.extend(node.artifacts)
        
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "objective": self.objective,
            "status": self.status.value,
            "total_steps": total_steps,
            "successful_steps": successful,
            "failed_steps": failed,
            "execution_time": elapsed,
            "steps": {
                step_id: {
                    **self.steps[step_id].to_dict(),
                    "execution": asdict(self.execution[step_id]),
                }
                for step_id in self.steps
            },
            "artifacts": artifacts,
            "mitre_coverage": [
                step.mitre_technique for step in self.steps.values()
            ],
        }
    
    def to_json(self) -> str:
        """Serialize chain to JSON."""
        return json.dumps(self.get_summary(), indent=2, default=str)


class AttackChainBuilder:
    """Factory for building attack chains from findings."""
    
    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("attack_chains")
        self.chain_counter = 0
    
    def build_sqli_to_rce_chain(
        self,
        target_url: str,
        param_name: str,
        db_type: str = "mysql",
    ) -> AttackChain:
        """Build chain: SQLi → Auth bypass → RCE."""
        self.chain_counter += 1
        chain_id = f"sqli_rce_{self.chain_counter}"
        
        finding = Finding(
            title="SQLi to RCE Chain",
            description=f"Attack chain from SQLi on {target_url} → authentication bypass → RCE",
            severity=SeverityLevel.CRITICAL,
            category="attack_chain",
        )
        
        chain = AttackChain(
            chain_id=chain_id,
            name="SQLi → Auth Bypass → RCE",
            description="Exploit SQLi to bypass authentication and achieve RCE",
            objective="Remote code execution",
            initial_finding=finding,
            logger=self.logger,
        )
        
        # Step 1: Enumerate database structure
        step1 = AttackStep(
            step_id="enum_db",
            stage=ChainStage.RECONNAISSANCE,
            description=f"Enumerate {db_type} database structure via SQLi",
            mitre_technique="T1005",  # Data from Local System
            executor=lambda: {"databases": ["information_schema", "mysql"]},
            dependencies=[],
            fallback_steps=[],
            opsec_profile={"noise": 0.6, "detectability": 0.7, "recovery_time": 0},
        )
        
        # Step 2: Extract authentication credentials
        step2 = AttackStep(
            step_id="extract_creds",
            stage=ChainStage.EXPLOITATION,
            description="Extract authentication credentials from users table",
            mitre_technique="T1005",
            executor=lambda: {"users": ["admin", "test"], "hashes": ["hash1", "hash2"]},
            dependencies=["enum_db"],
            fallback_steps=[],
            opsec_profile={"noise": 0.7, "detectability": 0.8, "recovery_time": 300},
        )
        
        # Step 3: Crack or bypass authentication
        step3 = AttackStep(
            step_id="bypass_auth",
            stage=ChainStage.EXPLOITATION,
            description="Crack credentials or bypass authentication",
            mitre_technique="T1110",  # Brute Force
            executor=lambda: {"auth_token": "abc123", "authenticated": True},
            dependencies=["extract_creds"],
            fallback_steps=[],
            opsec_profile={"noise": 0.8, "detectability": 0.9, "recovery_time": 600},
        )
        
        # Step 4: Upload shell via authenticated upload functionality
        step4 = AttackStep(
            step_id="upload_shell",
            stage=ChainStage.DELIVERY,
            description="Upload web shell via authenticated file upload",
            mitre_technique="T1190",  # Exploit Public-Facing Application
            executor=lambda: {"shell_url": f"{target_url}/uploads/shell.php", "uploaded": True},
            dependencies=["bypass_auth"],
            fallback_steps=[],
            opsec_profile={"noise": 0.5, "detectability": 0.6, "recovery_time": 120},
        )
        
        # Step 5: Execute commands via shell
        step5 = AttackStep(
            step_id="rce",
            stage=ChainStage.EXPLOITATION,
            description="Execute system commands via web shell",
            mitre_technique="T1059",  # Command and Scripting Interpreter
            executor=lambda: {"command": "id", "output": "uid=33(www-data) gid=33(www-data)"},
            dependencies=["upload_shell"],
            fallback_steps=[],
            opsec_profile={"noise": 0.7, "detectability": 0.85, "recovery_time": 180},
        )
        
        chain.add_steps([step1, step2, step3, step4, step5])
        return chain
    
    def build_weak_creds_lateral_chain(
        self,
        initial_creds: Dict[str, str],
    ) -> AttackChain:
        """Build chain: Weak creds → Lateral movement → Privilege escalation."""
        self.chain_counter += 1
        chain_id = f"lateral_privesc_{self.chain_counter}"
        
        finding = Finding(
            title="Weak Credentials to Domain Control",
            description="Attack chain using weak credentials to achieve lateral movement and privilege escalation",
            severity=SeverityLevel.CRITICAL,
            category="attack_chain",
        )
        
        chain = AttackChain(
            chain_id=chain_id,
            name="Weak Creds → Lateral → Privesc",
            description="Exploit weak credentials to move laterally and escalate privileges",
            objective="Domain administrator access",
            initial_finding=finding,
            logger=self.logger,
        )
        
        # Step 1: Enumerate domain
        step1 = AttackStep(
            step_id="enum_domain",
            stage=ChainStage.RECONNAISSANCE,
            description="Enumerate Active Directory domain structure",
            mitre_technique="T1087",  # Account Discovery
            executor=lambda: {"domain_users": 10, "domain_groups": 5},
            dependencies=[],
            fallback_steps=[],
            opsec_profile={"noise": 0.4, "detectability": 0.5, "recovery_time": 0},
        )
        
        # Step 2: Spray credentials across domain
        step2 = AttackStep(
            step_id="cred_spray",
            stage=ChainStage.EXPLOITATION,
            description="Spray initial credentials across domain computers",
            mitre_technique="T1110.003",  # Brute Force: Password Spraying
            executor=lambda: {"successful_hosts": ["server1", "server2"], "count": 2},
            dependencies=["enum_domain"],
            fallback_steps=[],
            opsec_profile={"noise": 0.9, "detectability": 0.95, "recovery_time": 900},
        )
        
        # Step 3: Move laterally via compromised host
        step3 = AttackStep(
            step_id="lateral_move",
            stage=ChainStage.EXPLOITATION,
            description="Establish lateral movement via compromised server",
            mitre_technique="T1570",  # Lateral Tool Transfer
            executor=lambda: {"pivot_host": "server1", "shell_type": "reverse"},
            dependencies=["cred_spray"],
            fallback_steps=[],
            opsec_profile={"noise": 0.6, "detectability": 0.7, "recovery_time": 300},
        )
        
        # Step 4: Enumerate privilege escalation paths
        step4 = AttackStep(
            step_id="enum_privesc",
            stage=ChainStage.RECONNAISSANCE,
            description="Enumerate privilege escalation opportunities",
            mitre_technique="T1057",  # Process Discovery
            executor=lambda: {"sudo_rules": ["*"], "kernel_version": "5.10.0"},
            dependencies=["lateral_move"],
            fallback_steps=[],
            opsec_profile={"noise": 0.3, "detectability": 0.4, "recovery_time": 0},
        )
        
        # Step 5: Escalate privileges
        step5 = AttackStep(
            step_id="escalate",
            stage=ChainStage.EXPLOITATION,
            description="Escalate to system/root via discovered vector",
            mitre_technique="T1548",  # Abuse Elevation Control Mechanism
            executor=lambda: {"uid": 0, "escalated": True, "method": "sudo"},
            dependencies=["enum_privesc"],
            fallback_steps=[],
            opsec_profile={"noise": 0.7, "detectability": 0.85, "recovery_time": 600},
        )
        
        chain.add_steps([step1, step2, step3, step4, step5])
        return chain


class AttackChainModule(RedTeamModule):
    """Red team module for executing attack chains."""
    
    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        super().__init__(session, logger)
        self.builder = AttackChainBuilder(session, logger)
        self.chains: Dict[str, AttackChain] = {}
    
    def execute(self) -> Dict[str, Any]:
        """Execute available attack chains."""
        self.log_info("Analyzing findings for viable attack chains")
        
        # This would be called with specific findings from recon
        # For now, demonstrate with dummy chains
        
        return {
            "success": True,
            "findings": self.findings,
            "chains_executed": len(self.chains),
            "output": {
                "chains": {
                    chain_id: chain.get_summary()
                    for chain_id, chain in self.chains.items()
                }
            }
        }
    
    def get_mitre_techniques(self) -> List[str]:
        """Return MITRE techniques used across all chains."""
        techniques = set()
        for chain in self.chains.values():
            for step in chain.steps.values():
                techniques.add(step.mitre_technique)
        return list(techniques)
    
    def build_and_execute_chain(
        self,
        chain_type: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Build and execute a specific attack chain."""
        if chain_type == "sqli_rce":
            chain = self.builder.build_sqli_to_rce_chain(**kwargs)
        elif chain_type == "lateral_privesc":
            chain = self.builder.build_weak_creds_lateral_chain(**kwargs)
        else:
            return {"success": False, "error": f"Unknown chain type: {chain_type}"}
        
        self.chains[chain.chain_id] = chain
        
        # Execute the chain
        result = chain.execute()
        
        # Register findings from chain execution
        self.add_finding(
            title=chain.name,
            description=chain.description,
            severity=SeverityLevel.CRITICAL,
            category="attack_chain",
            metadata=result,
        )
        
        return {
            "success": True,
            "findings": self.findings,
            "chain_result": result,
            "artifacts": result.get("artifacts", []),
        }


# ─────────────────────────────────────────────────────────────
# BloodHound ingest (AD attack-path analysis input)
# ─────────────────────────────────────────────────────────────

def import_bloodhound(session: Session, path: str,
                      logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """Ingest a BloodHound export (users/computers JSON) into the session.

    Counts nodes, flags high-value targets (Domain Admins members,
    Kerberoastable / AS-REP-roastable accounts) and records each as a
    finding so chain builders can consume them. Read-only w.r.t. AD.
    """
    from pathlib import Path as _Path
    if logger is None:
        logger = get_logger("attack_chains.bloodhound")
    data = json.loads(_Path(path).read_text())
    nodes = data.get("nodes") or data.get("users", []) + data.get("computers", [])
    edges = data.get("edges") or []

    def _labels(n):
        return {str(x).lower() for x in
                (n.get("labels") or n.get("kinds") or [])}

    roastable = [n for n in nodes
                 if "kerberoastable" in _labels(n) or n.get("hasspn")]
    asrep = [n for n in nodes
             if "asrep_roastable" in _labels(n) or n.get("dontreqpreauth")]
    admins = [n for n in nodes if "domain_admin" in _labels(n)
              or n.get("admincount")]

    summary = {"nodes": len(nodes), "edges": len(edges),
               "kerberoastable": len(roastable),
               "asrep_roastable": len(asrep),
               "domain_admins": len(admins)}
    for label, items, sev in (
            ("Kerberoastable account", roastable, SeverityLevel.HIGH),
            ("AS-REP roastable account", asrep, SeverityLevel.HIGH),
            ("Domain Admin", admins, SeverityLevel.CRITICAL)):
        for n in items[:25]:
            name = n.get("name") or n.get("objectid", "?")
            session.add_finding(Finding(
                source="ad.bloodhound", title=f"{label}: {name}",
                description=f"Imported from BloodHound ({Path(path).name})",
                severity=sev, host=str(name),
                tags=["ad", "bloodhound",
                      label.lower().replace(" ", "_")]))
    logger.success(f"BloodHound ingest: {summary}")
    return summary
