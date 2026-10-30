"""Engagement memory — what was tried/worked, persisted per session.

Consulted by surface ranking and chains to avoid re-firing dead ends
across runs. Stored as JSON in the session dir; keyed by
(vector, target, detail).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from modules.session import Session


def _path(session: Session) -> Path:
    d = session.dir("core")
    d.mkdir(parents=True, exist_ok=True)
    return d / "memory.json"


def load(session: Session) -> Dict[str, Any]:
    p = _path(session)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def remember(session: Session, vector: str, target: str, detail: str,
             outcome: str) -> Dict[str, Any]:
    """Record an attempt outcome: hit | miss | error | blocked."""
    mem = load(session)
    mem[f"{vector}||{target}||{detail}"] = {
        "outcome": outcome, "at": datetime.now().isoformat()}
    _path(session).write_text(json.dumps(mem, indent=2))
    return mem


def known_miss(session: Session, vector: str, target: str,
               detail: str = "", ttl_hours: float = 24.0) -> bool:
    """True if this exact vector recently failed here (skip it).

    Misses expire after ttl_hours so transient failures (dropped
    packets, WAF hiccups) don't permanently block a vector.
    """
    from datetime import datetime as _dt, timedelta
    mem = load(session)
    cutoff = _dt.now() - timedelta(hours=ttl_hours)

    def _fresh(v):
        if v.get("outcome") not in ("miss", "blocked"):
            return False
        try:
            return _dt.fromisoformat(v.get("at", "")) >= cutoff
        except Exception:
            return True

    if detail:
        return _fresh(mem.get(f"{vector}||{target}||{detail}", {}))
    return any(_fresh(v) for k, v in mem.items()
               if k.startswith(f"{vector}||{target}||"))


def summary(session: Session) -> Dict[str, Any]:
    mem = load(session)
    counts: Dict[str, int] = {}
    for v in mem.values():
        counts[v.get("outcome", "?")] = counts.get(v.get("outcome", "?"), 0) + 1
    return {"entries": len(mem), "by_outcome": counts}
