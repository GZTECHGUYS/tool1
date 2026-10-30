"""
ARDF Core Orchestration Layer
──────────────────────────────
The brain between the user interface and the execution modules.

Components
──────────
  orchestrator       AI-driven mission execution loop
  mission            Mission lifecycle manager
  task_graph         Dependency graph and execution ordering
  decision_engine    Tool output classifier and next-step selector
  response_classifier WAF / IDS / rate-limit response detection
  confirmation_gate  Human-in-the-loop checkpoint manager
"""

from core.mission            import Mission, MissionStatus
from core.task_graph         import TaskGraph, Task, TaskStatus
from core.confirmation_gate  import ConfirmationGate
from core.response_classifier import ResponseClassifier
from core.orchestrator       import Orchestrator

# ── Legacy compat re-exports ──────────────────────────────────
# Older flat modules (exploitation.py, lateral_movement.py,
# privilege_escalation.py, recon_modules.py, main.py) expect these
# names from `core`. They live in complete_framework.py (stdlib-only,
# no circular import risk). Re-exported here so those imports work.
try:
    from complete_framework import (
        OffensiveModule,
        Finding,
        ExecutionContext,
        FindingType,
        Severity,
        TacticType,
        SessionState,
    )
    ARDFOrchestrator = Orchestrator  # legacy alias; ctor differs, see main.py
except ImportError:  # pragma: no cover - framework root not on sys.path
    OffensiveModule = Finding = ExecutionContext = None
    FindingType = Severity = TacticType = SessionState = None
    ARDFOrchestrator = Orchestrator

__all__ = [
    "Mission",
    "MissionStatus",
    "TaskGraph",
    "Task",
    "TaskStatus",
    "ConfirmationGate",
    "ResponseClassifier",
    "Orchestrator",
    "ARDFOrchestrator",
    "OffensiveModule",
    "Finding",
    "ExecutionContext",
    "FindingType",
    "Severity",
    "TacticType",
    "SessionState",
]
