"""Attack-module base class and shared helpers (P1/P2 packs).

Every attack module:
  id       — stable registry key for the API/UI
  title    — human name
  phase    — "P1" | "P2" | "P3"
  tier     — 1 (read-only recon), 2 (active probing), 3 (offensive action,
             requires CONFIRM)
  plan()   — scoped reconnaissance/planning against the session (always safe)
  execute()— the offensive action itself (tier-gated by the registry)
"""
from __future__ import annotations

from typing import Any, Dict

from modules.logger import ARDFLogger
from modules.session import Session

from ops.scope import CONFIG_PATH as _SCOPE_CONFIG
from ops.scope import ScopeViolation, ScopeGuard

_SCOPE = ScopeGuard(config_path=_SCOPE_CONFIG)


def require_in_scope(target: str) -> None:
    """Scope-guarded entry for every offensive action."""
    _SCOPE.reload()
    ok, reason = _SCOPE.validate(target)
    if not ok:
        raise ScopeViolation(reason)


class AttackModule:
    id: str = ""
    title: str = ""
    phase: str = "P1"
    tier: int = 2
    summary: str = ""
    confirm_word: str = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        """Safe planning pass; default = gather scope-validated surface."""
        target = (spec.get("target") or
                  getattr(session.meta, "target", "") or "")
        require_in_scope(target)
        return {"module": self.id, "mode": "plan", "target": target,
                "note": "no plan override implemented"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        """Offensive pass; default = detailed runbook (no blind action)."""
        target = (spec.get("target") or
                  getattr(session.meta, "target", "") or "")
        require_in_scope(target)
        return {"module": self.id, "mode": "exec",
                "status": "runbook_only",
                "note": ("module scaffolded; implement execute() to fire for "
                         "real — plan() output lists the intended steps")}

    def emit(self, logger: ARDFLogger, msg: str) -> None:
        logger.info(f"[{self.id}] {msg}")
