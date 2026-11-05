"""Attack-module registry — explicit, observable P1–P4 wiring.

Design goals
------------
* **Nothing is silently dropped.** Each pack is imported independently and
  its load result (ok / error / count / ids) is recorded and surfaced by
  the CLI, dashboard and ``validate_registry()``.
* **Duplicate ids are an error, not a silent overwrite.**
* **Phase/tier are normalised and validated** for every module.
* **Tier gating is exact-match**, so "NOT APPROVE" / "NOTCONFIRM" cannot
  smuggle a module past the gate.
* Backwards compatible: ``list_attacks`` / ``get_attack`` / ``run_attack``
  keep the same signatures used by the CLI and dashboard.

Public API
----------
    load(force=False)              -> load every pack, return status dict
    list_attacks(phase=None)       -> [{id,title,phase,tier,summary,...}]
    get_attack(id)                 -> AttackModule | None
    run_attack(session, id, spec)  -> {ok, mode, out|error}
    pack_status()                  -> per-pack load results
    registry_status()              -> totals, counts, duplicates, problems
    validate_registry()            -> list[str] of problems (empty = healthy)
    manifest()                     -> machine-readable capability manifest
"""
from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from modules.logger import ARDFLogger
from modules.session import Session

from .base import AttackModule

PACK_ORDER = ("P1", "P2", "P3", "P4")

PACK_SPECS: Dict[str, Dict[str, str]] = {
    "P1": {"module": "modules.attacks.p1_pack", "attr": "PACK1"},
    "P2": {"module": "modules.attacks.p2_pack", "attr": "PACK2"},
    "P3": {"module": "modules.attacks.p3_pack", "attr": "PACK3"},
    "P4": {"module": "modules.attacks.p4_pack", "attr": "PACK4"},
}

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


@dataclass
class PackStatus:
    """Load result for one pack."""

    name: str
    module: str
    attr: str
    ok: bool = False
    count: int = 0
    ids: List[str] = field(default_factory=list)
    error: str = ""
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "module": self.module, "attr": self.attr,
                "ok": self.ok, "count": self.count, "ids": list(self.ids),
                "error": self.error, "warnings": list(self.warnings)}


_MODULES: Dict[str, AttackModule] = {}
_PACKS: Dict[str, PackStatus] = {}
_DUPLICATES: Dict[str, List[str]] = {}
_LOADED = False


# ─────────────────────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────────────────────

def _execution_status(mod: AttackModule) -> str:
    """Classify how much of the module is actually implemented."""
    fn = type(mod).execute
    qualname = getattr(fn, "__qualname__", "")
    if qualname.endswith("AttackModule.execute"):
        return "scaffold"
    if qualname.endswith("_RunbookModule.execute"):
        return "runbook"
    return "implemented"


def _validate_module(mod: Any, pack: str) -> List[str]:
    """Return a list of problems for one module (empty = valid)."""
    problems: List[str] = []
    if not isinstance(mod, AttackModule):
        return [f"{pack}: {type(mod).__name__} is not an AttackModule"]
    mid = str(getattr(mod, "id", "") or "").strip()
    if not mid:
        problems.append(f"{pack}: module {type(mod).__name__} has an empty id")
    elif not _ID_RE.match(mid):
        problems.append(f"{pack}: invalid module id {mid!r}")
    if not str(getattr(mod, "title", "") or "").strip():
        problems.append(f"{pack}: module {mid or type(mod).__name__} has no title")
    if not str(getattr(mod, "summary", "") or "").strip():
        problems.append(f"{pack}: module {mid or type(mod).__name__} has no summary")
    if int(getattr(mod, "tier", 0) or 0) not in (1, 2, 3):
        problems.append(f"{pack}: module {mid or type(mod).__name__} has invalid tier "
                        f"{getattr(mod, 'tier', None)!r}")
    if not callable(getattr(mod, "plan", None)):
        problems.append(f"{pack}: module {mid or type(mod).__name__} has no plan()")
    if not callable(getattr(mod, "execute", None)):
        problems.append(f"{pack}: module {mid or type(mod).__name__} has no execute()")
    return problems


def load(force: bool = False) -> Dict[str, Any]:
    """Import every P1–P4 pack and build the registry.

    Each pack is isolated: an exception while importing one pack is
    recorded in its ``PackStatus`` and never prevents the other packs
    from registering.
    """
    global _LOADED
    if _LOADED and not force:
        return registry_status()

    _MODULES.clear()
    _PACKS.clear()
    _DUPLICATES.clear()
    _LOADED = True

    for pack in PACK_ORDER:
        spec = PACK_SPECS[pack]
        status = PackStatus(name=pack, module=spec["module"], attr=spec["attr"])
        _PACKS[pack] = status
        try:
            module = importlib.import_module(spec["module"])
        except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed
            status.error = f"import failed: {type(exc).__name__}: {exc}"
            continue
        try:
            mods = getattr(module, spec["attr"])
        except AttributeError as exc:
            status.error = f"missing registry list {spec['attr']}: {exc}"
            continue
        if not isinstance(mods, (list, tuple)):
            status.error = (f"{spec['attr']} must be a list, got "
                            f"{type(mods).__name__}")
            continue

        for mod in mods:
            problems = _validate_module(mod, pack)
            if problems:
                status.warnings.extend(problems)
                # A structurally invalid module cannot be dispatched safely.
                if not isinstance(mod, AttackModule) or not getattr(mod, "id", ""):
                    continue
            mid = str(mod.id)
            # Normalise phase/tier so the UI and gate always agree.
            if getattr(mod, "phase", "") != pack:
                status.warnings.append(
                    f"{pack}: module {mid} declared phase "
                    f"{getattr(mod, 'phase', '')!r}; stamped {pack}")
                mod.phase = pack
            if mid in _MODULES:
                _DUPLICATES.setdefault(mid, []).append(pack)
                status.warnings.append(
                    f"{pack}: duplicate module id {mid!r} "
                    f"(already registered by another pack); kept the first")
                continue
            _MODULES[mid] = mod
            status.ids.append(mid)

        status.ok = bool(status.ids) and not status.error
        status.count = len(status.ids)

    return registry_status()


def reload_registry() -> Dict[str, Any]:
    """Force a full re-import of every pack."""
    return load(force=True)


# ─────────────────────────────────────────────────────────────
# Queries
# ─────────────────────────────────────────────────────────────

def _sort_key(mod: AttackModule):
    order = {p: i for i, p in enumerate(PACK_ORDER)}
    return (order.get(mod.phase, 99), int(mod.tier), mod.id)


def list_attacks(phase: Optional[str] = None,
                 tier: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return every registered module, with execution status included."""
    load()
    rows: List[Dict[str, Any]] = []
    for mod in sorted(_MODULES.values(), key=_sort_key):
        if phase and str(mod.phase).upper() != str(phase).upper():
            continue
        if tier is not None and int(mod.tier) != int(tier):
            continue
        rows.append({
            "id": mod.id,
            "title": mod.title,
            "phase": mod.phase,
            "tier": int(mod.tier),
            "summary": mod.summary,
            "confirm_word": _tier_word(int(mod.tier)),
            "status": _execution_status(mod),
        })
    return rows


def get_attack(attack_id: str) -> Optional[AttackModule]:
    load()
    return _MODULES.get(str(attack_id or "").strip())


def manifest() -> List[Dict[str, Any]]:
    """Full capability manifest for CLI/dashboard/debugging."""
    load()
    return [{
        **row,
        "class": type(get_attack(row["id"])).__name__,
        "module": type(get_attack(row["id"])).__module__,
    } for row in list_attacks()]


def pack_status() -> List[Dict[str, Any]]:
    if not _LOADED:
        load()
    return [_PACKS[p].to_dict() for p in PACK_ORDER if p in _PACKS]


def _problems() -> List[str]:
    """Compute wiring problems without triggering a (re)load."""
    problems: List[str] = []
    for pack in PACK_ORDER:
        status = _PACKS.get(pack)
        if status is None:
            problems.append(f"{pack}: pack was never loaded")
            continue
        if status.error:
            problems.append(f"{pack}: {status.error}")
        if status.count == 0:
            problems.append(f"{pack}: registered 0 modules")
        problems.extend(status.warnings)
    for mid, packs in _DUPLICATES.items():
        problems.append(f"duplicate module id {mid!r} seen in {', '.join(packs)}")
    if not _MODULES:
        problems.append("registry is empty")
    return problems


def registry_status() -> Dict[str, Any]:
    """Totals, per-phase/tier counts, duplicates and load problems."""
    if not _LOADED:
        load()
    by_phase: Dict[str, int] = {p: 0 for p in PACK_ORDER}
    by_tier: Dict[str, int] = {"1": 0, "2": 0, "3": 0}
    by_status: Dict[str, int] = {"implemented": 0, "runbook": 0, "scaffold": 0}
    for mod in _MODULES.values():
        by_phase[str(mod.phase)] = by_phase.get(str(mod.phase), 0) + 1
        by_tier[str(int(mod.tier))] = by_tier.get(str(int(mod.tier)), 0) + 1
        by_status[_execution_status(mod)] += 1
    return {
        "total": len(_MODULES),
        "packs": pack_status(),
        "duplicates": {k: list(v) for k, v in _DUPLICATES.items()},
        "by_phase": by_phase,
        "by_tier": by_tier,
        "by_status": by_status,
        "problems": _problems(),
    }


def validate_registry() -> List[str]:
    """Return every wiring problem. Empty list means the registry is healthy."""
    if not _LOADED:
        load()
    return _problems()


# ─────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────

def _tier_word(tier: int) -> str:
    if tier >= 3:
        return "CONFIRM"
    if tier == 2:
        return "APPROVE"
    return "NOT_REQUIRED"


def _gate_error(mod: AttackModule, spec: Dict[str, Any]) -> Optional[str]:
    """Return a gate error string, or None when the module may execute."""
    if int(mod.tier) <= 1:
        return None
    need = _tier_word(int(mod.tier))
    got = re.sub(r"\W+", "", str((spec or {}).get("confirm_text", ""))).upper()
    if got == need:
        return None
    # A typed CONFIRM is strictly stronger than the Tier-2 APPROVE word.
    if int(mod.tier) == 2 and got == "CONFIRM":
        return None
    return (f"{mod.title} is Tier-{mod.tier}: pass confirm_text='{need}' "
            f"to run for real; secret word: {need}")


def run_attack(session: Session, attack_id: str, spec: Dict[str, Any],
               logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """Registry entry point: mode=plan is always allowed; exec is gated."""
    load()
    mod = get_attack(attack_id)
    if mod is None:
        return {"ok": False, "id": attack_id,
                "error": f"unknown attack '{attack_id}'"}
    if logger is None:
        from modules.logger import get_logger

        logger = get_logger("attacks")

    spec = dict(spec or {})
    mode = str(spec.get("mode") or "plan").lower()
    if mode not in ("plan", "exec"):
        return {"ok": False, "id": attack_id,
                "error": f"invalid mode {mode!r}; use 'plan' or 'exec'"}

    # Always scope-check the target before plan or exec.
    target = (spec.get("target") or getattr(session.meta, "target", "") or "")
    try:
        from .base import require_in_scope

        if target:
            require_in_scope(target)
    except PermissionError as exc:
        return {"ok": False, "id": attack_id, "error": f"SCOPE: {exc}"}

    try:
        if mode == "plan":
            out = mod.plan(session, spec, logger)
        else:
            gate = _gate_error(mod, spec)
            if gate:
                return {"ok": False, "id": attack_id, "mode": "exec",
                        "out": {"ok": False, "error": gate},
                        "error": gate}
            out = mod.execute(session, spec, logger)
        return {"ok": True, "id": attack_id, "phase": mod.phase,
                "tier": int(mod.tier), "mode": mode, "out": out}
    except PermissionError as exc:
        return {"ok": False, "id": attack_id, "error": f"SCOPE: {exc}"}
    except Exception as exc:  # noqa: BLE001 - structured, never a crash
        logger.warning(f"attack {attack_id} failed: {exc}")
        return {"ok": False, "id": attack_id, "mode": mode,
                "error": f"{type(exc).__name__}: {exc}"}


# Convenience: load eagerly so ``from modules.attacks import list_attacks``
# always sees a populated registry.
load()
