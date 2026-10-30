"""Attack module registry — P1 + P2 + P3 packs, tier-gated dispatch.

API contract used by ardf_v3_dashboard_api / TUI / CLI:
  list_attacks()                     -> [{id,title,phase,tier,summary}, ...]
  run_attack(session, id, spec, ...) -> {ok, mode, out, error}
Tier rules: tier1 read-only, tier2 -> "APPROVE" (or "CONFIRM"),
tier3 -> typed "CONFIRM".
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from modules.logger import ARDFLogger
from modules.session import Session

from .base import AttackModule

_MODULES: Dict[str, AttackModule] = {}


def _register(mods: List[AttackModule]) -> None:
    for m in mods:
        if not m.id:
            continue
        _MODULES[m.id] = m


try:
    from .p1_pack import PACK1 as _P1
    _register(_P1)
except Exception:  # keep registry resilient to one bad pack
    pass
try:
    from .p2_pack import PACK2 as _P2
    _register(_P2)
except Exception:
    pass
try:
    from .p3_pack import PACK3 as _P3
    _register(_P3)
except Exception:
    pass


def list_attacks() -> List[Dict[str, Any]]:
    return [{"id": m.id, "title": m.title, "phase": m.phase,
             "tier": m.tier, "summary": m.summary,
             "confirm_word": _tier_word(m.tier)}
            for m in sorted(_MODULES.values(), key=lambda x: (x.phase,
                                                              x.tier,
                                                              x.id))]


def get_attack(attack_id: str) -> Optional[AttackModule]:
    return _MODULES.get(attack_id)


def run_attack(session: Session, attack_id: str, spec: Dict[str, Any],
               logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """Registry entry point: mode=plan always allowed; exec is tier-gated."""
    import re as _re

    mod = get_attack(attack_id)
    if mod is None:
        return {"ok": False, "error": f"unknown attack '{attack_id}'"}
    if logger is None:
        from modules.logger import get_logger

        logger = get_logger("attacks")
    mode = (spec or {}).get("mode") or "plan"
    try:
        if mode == "plan":
            out = mod.plan(session, spec or {}, logger)
        elif mod.tier <= 1:
            # Tier-1 modules are read-only observations: no gate by design.
            out = mod.execute(session, spec or {}, logger)
        else:
            need = _tier_word(mod.tier)
            got = _re.sub(r"\W+", "", (spec or {}).get("confirm_text", "")
                          ).upper()
            # A typed CONFIRM is strictly stronger than the Tier-2
            # one-click APPROVE word, so accept it there as well.
            allowed = bool(got) and (need in got or
                                     (mod.tier < 3 and "CONFIRM" in got))
            if allowed:
                out = mod.execute(session, spec or {}, logger)
            else:
                out = {"ok": False,
                       "error": (f"{mod.title} is Tier-{mod.tier}: pass "
                                 f"confirm_text='{need}' to run for real; "
                                 f"secret word: {need}")}
                return {"ok": False, "mode": "exec", "out": out}
        return {"ok": True, "mode": mode, "out": out}
    except PermissionError as e:
        return {"ok": False, "error": f"SCOPE: {e}"}
    except Exception as e:
        logger.warning(f"attack {attack_id} failed: {e}")
        return {"ok": False, "error": str(e)}


def _tier_word(tier: int) -> str:
    if tier >= 3:
        return "CONFIRM"
    if tier == 2:
        return "APPROVE"
    return "NOT_REQUIRED"
