"""Attack module registry — P1–P4 packs, tier-gated dispatch.

This package is intentionally a thin facade over
:mod:`modules.attacks.registry`. The registry imports every pack in
isolation, records load failures instead of swallowing them, normalises
phase/tier metadata, and rejects duplicate ids.

Public API (unchanged for existing callers)
-------------------------------------------
    list_attacks()                     -> [{id,title,phase,tier,summary,...}]
    get_attack(id)                     -> AttackModule | None
    run_attack(session, id, spec, ...) -> {ok, mode, out|error}

New observability helpers
-------------------------
    pack_status()        per-pack load results (ok/error/count/ids)
    registry_status()    totals, counts, duplicates, problems
    validate_registry()  list of wiring problems (empty == healthy)
    manifest()           full machine-readable capability manifest
    reload_registry()    force a fresh import of every pack
"""
from __future__ import annotations

from .base import AttackModule
from .registry import (
    PACK_ORDER,
    PACK_SPECS,
    get_attack,
    list_attacks,
    load,
    manifest,
    pack_status,
    registry_status,
    reload_registry,
    run_attack,
    validate_registry,
)

__all__ = [
    "AttackModule",
    "PACK_ORDER",
    "PACK_SPECS",
    "get_attack",
    "list_attacks",
    "load",
    "manifest",
    "pack_status",
    "registry_status",
    "reload_registry",
    "run_attack",
    "validate_registry",
]
