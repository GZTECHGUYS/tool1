"""ARDF v3 Complete Framework - All Core Components in One File"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
from abc import ABC, abstractmethod
from datetime import datetime
import uuid
import json


# ============================================================================
# ENUMERATIONS
# ============================================================================

class FindingType(Enum):
    RECONNAISSANCE = "recon"
    VULNERABILITY = "vuln"
    CREDENTIAL = "cred"
    PERSISTENCE = "persist"
    LATERAL_MOVE = "lateral"
    PRIVILEGE_ESCALATION = "privesc"
    DATA_EXFILTRATION = "exfil"
    C2_CHANNEL = "c2"
    EVASION = "evasion"
    EXPLOITATION = "exploit"


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TacticType(Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    finding_type: FindingType = FindingType.RECONNAISSANCE
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    
    source_module: str = ""
    target: str = ""
    target_type: str = ""
    
    confidence: float = 0.8
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    exploitable: bool = False
    exploit_paths: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    
    next_tactics: List[TacticType] = field(default_factory=list)
    tags: set = field(default_factory=set)
    chain_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
            "exploitable": self.exploitable,
            "confidence": self.confidence,
        }


@dataclass
class ExecutionContext:
    target: str
    target_type: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    parent_finding: Optional[Finding] = None
    findings: List[Finding] = field(default_factory=list)
    credentials: Dict[str, Any] = field(default_factory=dict)
    access_level: str = "unknown"
    environment: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionState:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    all_findings: List[Finding] = field(default_factory=list)
    current_access: str = "unauthenticated"
    compromised_targets: set = field(default_factory=set)
    executed_modules: set = field(default_factory=set)
    
    started: datetime = field(default_factory=datetime.utcnow)
    
    def add_finding(self, finding: Finding):
        self.all_findings.append(finding)
    
    def get_findings_by_type(self, finding_type: FindingType) -> List[Finding]:
        return [f for f in self.all_findings if f.finding_type == finding_type]


# ============================================================================
# MODULE SYSTEM
# ============================================================================

class OffensiveModule(ABC):
    module_name: str = "unnamed"
    module_version: str = "1.0.0"
    description: str = ""
    
    finding_types: List[FindingType] = []
    tactics: List[TacticType] = []
    required_access: str = "unauthenticated"
    timeout_seconds: int = 300
    
    def __init__(self, config=None):
        self.config = config
        self.logger = logging.getLogger(self.module_name)
    
    @abstractmethod
    async def execute(self, context: ExecutionContext) -> List[Finding]:
        pass
    
    async def validate(self, context: ExecutionContext) -> bool:
        access_levels = ["unauthenticated", "user", "admin", "system", "root"]
        required_idx = access_levels.index(self.required_access)
        current_idx = access_levels.index(context.access_level)
        return current_idx >= required_idx
    
    def _create_finding(self, title, description, finding_type, evidence, severity="medium", exploitable=False):
        return Finding(
            title=title,
            description=description,
            finding_type=finding_type,
            severity=Severity[severity.upper()],
            source_module=self.module_name,
            evidence=evidence,
            exploitable=exploitable,
        )


class ModuleRegistry:
    def __init__(self):
        self.modules: Dict[str, type] = {}
        self.instances: Dict[str, OffensiveModule] = {}
    
    def register(self, module_class: type, config=None):
        self.modules[module_class.module_name] = module_class
        logging.info(f"Registered: {module_class.module_name}")
    
    def get_module(self, name: str) -> Optional[OffensiveModule]:
        if name not in self.instances and name in self.modules:
            self.instances[name] = self.modules[name]()
        return self.instances.get(name)
    
    def get_modules_for_tactic(self, tactic: TacticType) -> List[OffensiveModule]:
        modules = []
        for module_class in self.modules.values():
            if tactic in module_class.tactics:
                modules.append(self.get_module(module_class.module_name))
        return [m for m in modules if m]
    
    def list_modules(self) -> Dict:
        result = {}
        for name, module_class in self.modules.items():
            result[name] = {
                "description": module_class.description,
                "tactics": [t.value for t in module_class.tactics],
                "version": module_class.module_version,
            }
        return result


class ExecutionEngine:
    def __init__(self, registry: ModuleRegistry):
        self.registry = registry
        self.logger = logging.getLogger("ExecutionEngine")
    
    async def execute_module(self, module_name: str, context: ExecutionContext) -> List[Finding]:
        module = self.registry.get_module(module_name)
        if not module:
            return []
        
        try:
            findings = await asyncio.wait_for(
                module.execute(context),
                timeout=module.timeout_seconds
            )
            return findings
        except Exception as e:
            self.logger.error(f"Module {module_name} failed: {e}")
            return []
    
    async def execute_tactic(self, tactic: TacticType, context: ExecutionContext, session: SessionState) -> List[Finding]:
        modules = self.registry.get_modules_for_tactic(tactic)
        all_findings = []
        
        tasks = [self.execute_module(m.module_name, context) for m in modules]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
        
        return all_findings


# ============================================================================
# ORCHESTRATOR
# ============================================================================

class ARDFOrchestrator:
    def __init__(self, module_paths: List[Path] = None):
        self.registry = ModuleRegistry()
        self.engine = ExecutionEngine(self.registry)
        self.session: Optional[SessionState] = None
        
        # Register built-in modules
        self._register_builtin_modules()
    
    def _register_builtin_modules(self):
        """Register built-in modules from modules/ directory"""
        import importlib.util
        import inspect
        
        modules_dir = Path(__file__).parent.parent / "modules"
        if modules_dir.exists():
            for py_file in modules_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                
                try:
                    spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        for name, obj in inspect.getmembers(module):
                            if (inspect.isclass(obj) and 
                                issubclass(obj, OffensiveModule) and
                                obj is not OffensiveModule):
                                self.registry.register(obj)
                except Exception as e:
                    logging.error(f"Error loading {py_file}: {e}")
    
    def new_session(self, target: str, target_type: str = "host") -> SessionState:
        self.session = SessionState()
        logging.info(f"New session: {self.session.session_id}")
        return self.session
    
    async def scan(self, target: str, target_type: str = "host", tactics: List[TacticType] = None) -> SessionState:
        if not self.session:
            self.session = self.new_session(target, target_type)
        
        if not tactics:
            tactics = [TacticType.RECONNAISSANCE]
        
        context = ExecutionContext(target=target, target_type=target_type, session_id=self.session.session_id)
        
        for tactic in tactics:
            findings = await self.engine.execute_tactic(tactic, context, self.session)
            for finding in findings:
                self.session.add_finding(finding)
        
        return self.session
    
    async def exploit(self, target: str) -> bool:
        if not self.session:
            return False
        
        context = ExecutionContext(target=target, target_type="host", session_id=self.session.session_id)
        
        findings = await self.engine.execute_tactic(TacticType.EXECUTION, context, self.session)
        for finding in findings:
            self.session.add_finding(finding)
        
        self.session.compromised_targets.add(target)
        return len(findings) > 0
    
    async def auto_run(self, target: str, iterations: int = 5) -> SessionState:
        if not self.session:
            self.session = self.new_session(target)
        
        for i in range(iterations):
            context = ExecutionContext(target=target, target_type="host", session_id=self.session.session_id)
            findings = await self.engine.execute_tactic(TacticType.RECONNAISSANCE, context, self.session)
            
            for finding in findings:
                self.session.add_finding(finding)
            
            if not findings:
                break
        
        return self.session
    
    def list_modules(self) -> Dict:
        return self.registry.list_modules()
    
    def get_session_summary(self) -> Dict:
        if not self.session:
            return {}
        
        return {
            "session_id": self.session.session_id,
            "total_findings": len(self.session.all_findings),
            "compromised_targets": list(self.session.compromised_targets),
        }
