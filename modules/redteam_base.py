"""
modules/redteam_base.py
───────────────────────
Base class for all red team attack modules.

Provides:
  - Unified logging to ARDF logger
  - OpSec scoring (detectability, noise, evidence)
  - MITRE ATT&CK technique mapping
  - Session/finding integration
  - Graceful failure and fallback handling
"""

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


class OpSecScore:
    """OpSec impact tracking for red team actions."""
    
    def __init__(self):
        self.noise_level = 0.0  # 0=silent, 1.0=very loud
        self.detectability = 0.0  # 0=undetectable, 1.0=guaranteed detection
        self.evidence_left = []  # List of artifacts left behind
        self.recovery_time = 0  # Seconds to clean up if detected
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "noise_level": self.noise_level,
            "detectability": self.detectability,
            "evidence_left": self.evidence_left,
            "recovery_time": self.recovery_time,
        }
    
    @property
    def risk_score(self) -> float:
        """Combined risk metric (0.0 = safest, 1.0 = riskiest)."""
        return (self.noise_level * 0.4) + (self.detectability * 0.6)


class RedTeamModule(ABC):
    """
    Base class for all red team attack modules.
    
    Subclasses must implement:
      - execute() — main attack logic
      - get_mitre_techniques() — list of ATT&CK techniques used
    """
    
    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("redteam")
        self.opsec = OpSecScore()
        self.start_time = None
        self.end_time = None
        self.findings: List[Finding] = []
        self.metadata = {}
    
    @abstractmethod
    def execute(self) -> Dict[str, Any]:
        """
        Execute the attack module.
        
        Returns:
            Dictionary with keys:
              - success: bool
              - findings: list of Finding objects
              - output: raw tool output or results
              - error: error message if failed
        """
        pass
    
    @abstractmethod
    def get_mitre_techniques(self) -> List[str]:
        """Return list of MITRE ATT&CK technique IDs used by this module."""
        pass
    
    def get_name(self) -> str:
        """Return human-readable module name."""
        return self.__class__.__name__
    
    def get_description(self) -> str:
        """Return module description."""
        return self.__class__.__doc__ or "No description"
    
    def add_finding(
        self,
        title: str,
        description: str,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        category: str = "red_team",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """Create and register a finding."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            metadata=metadata or {},
        )
        # Add MITRE techniques if available
        finding.metadata["mitre_techniques"] = self.get_mitre_techniques()
        finding.metadata["module"] = self.get_name()
        finding.metadata["opsec_score"] = self.opsec.to_dict()
        
        self.findings.append(finding)
        self.session.add_finding(finding)
        
        self.logger.info(
            f"[{self.get_name()}] Finding: {title} ({severity.value})",
            extra={
                "module": self.get_name(),
                "finding_id": finding.id,
                "severity": severity.value,
            },
        )
        return finding
    
    def log_info(self, message: str, **extra) -> None:
        """Log info message with module context."""
        self.logger.info(
            f"[{self.get_name()}] {message}",
            extra={**extra, "module": self.get_name()},
        )
    
    def log_warning(self, message: str, **extra) -> None:
        """Log warning with module context."""
        self.logger.warning(
            f"[{self.get_name()}] {message}",
            extra={**extra, "module": self.get_name()},
        )
    
    def log_error(self, message: str, **extra) -> None:
        """Log error with module context."""
        self.logger.error(
            f"[{self.get_name()}] {message}",
            extra={**extra, "module": self.get_name()},
        )
    
    def log_debug(self, message: str, **extra) -> None:
        """Log debug with module context."""
        self.logger.debug(
            f"[{self.get_name()}] {message}",
            extra={**extra, "module": self.get_name()},
        )
    
    def set_opsec_profile(
        self,
        noise_level: float = 0.5,
        detectability: float = 0.5,
        evidence: Optional[List[str]] = None,
        recovery_time: int = 0,
    ) -> None:
        """Set OpSec impact profile for this execution."""
        self.opsec.noise_level = max(0.0, min(1.0, noise_level))
        self.opsec.detectability = max(0.0, min(1.0, detectability))
        self.opsec.evidence_left = evidence or []
        self.opsec.recovery_time = recovery_time
    
    def with_jitter(self, base_delay: float, jitter_pct: float = 0.2) -> float:
        """Add random jitter to a delay."""
        import random
        jitter = base_delay * jitter_pct * random.uniform(-1, 1)
        return max(0.1, base_delay + jitter)
    
    def run_with_timeout(
        self,
        func: Callable,
        timeout_seconds: int = 30,
        *args,
        **kwargs,
    ) -> Optional[Any]:
        """Execute function with timeout."""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Execution exceeded {timeout_seconds}s")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout_seconds)
        
        try:
            result = func(*args, **kwargs)
            signal.alarm(0)  # Cancel alarm
            return result
        except TimeoutError as e:
            self.log_error(f"Timeout: {e}")
            return None
        finally:
            signal.alarm(0)  # Ensure alarm is cancelled
    
    def save_output(self, filename: str, content: str, subdir: str = "exploit") -> Path:
        """Save tool output to session output directory."""
        output_dir = self.session.output_dir / subdir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / filename
        output_path.write_text(content)
        
        self.log_debug(f"Saved output to {output_path}")
        return output_path
    
    def save_json(self, filename: str, data: Dict[str, Any], subdir: str = "exploit") -> Path:
        """Save JSON data to session output directory."""
        output_dir = self.session.output_dir / subdir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / filename
        output_path.write_text(json.dumps(data, indent=2))
        
        self.log_debug(f"Saved JSON to {output_path}")
        return output_path
    
    def execute_with_timing(self) -> Dict[str, Any]:
        """Execute module and record timing."""
        self.start_time = time.time()
        self.log_info(f"Starting execution of {self.get_name()}")
        
        try:
            result = self.execute()
            self.end_time = time.time()
            elapsed = self.end_time - self.start_time
            
            result["execution_time"] = elapsed
            result["opsec_score"] = self.opsec.to_dict()
            
            self.log_info(
                f"Completed in {elapsed:.2f}s - "
                f"Risk: {self.opsec.risk_score:.2f}, "
                f"Findings: {len(self.findings)}"
            )
            
            return result
        except Exception as e:
            self.end_time = time.time()
            elapsed = self.end_time - self.start_time
            
            self.log_error(f"Execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "execution_time": elapsed,
                "opsec_score": self.opsec.to_dict(),
            }
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize module state."""
        return {
            "module": self.get_name(),
            "description": self.get_description(),
            "mitre_techniques": self.get_mitre_techniques(),
            "opsec_score": self.opsec.to_dict(),
            "findings_count": len(self.findings),
            "execution_time": (self.end_time - self.start_time) if self.start_time and self.end_time else None,
            "metadata": self.metadata,
        }
