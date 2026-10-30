"""Proof bundles — hash-chained, tamper-evident POC packages.

Each bundle binds transcript + evidence + finding ids with sha256 links
(prev_hash chain), saved under session report/. Verifiers recompute the
chain with verify_bundle(). Reports link the bundle file.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from modules.session import Session


def _h(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def create_bundle(session: Session, chain_id: str,
                  transcript: List[Dict[str, Any]],
                  finding_ids: List[str]) -> Path:
    d = session.dir("report")
    d.mkdir(parents=True, exist_ok=True)
    prev = "GENESIS"
    entries = []
    for step in transcript:
        body = json.dumps({"step": step.get("step"), "ok": step.get("ok"),
                           "evidence": str(step.get("evidence"))[:500]},
                          sort_keys=True)
        h = _h(prev + body)
        entries.append({"step": step.get("step"), "ok": step.get("ok"),
                        "evidence": str(step.get("evidence"))[:500],
                        "prev": prev, "hash": h})
        prev = h
    bundle = {"chain": chain_id, "session": session.meta.session_id,
              "target": session.meta.target,
              "created": datetime.now().isoformat(),
              "findings": finding_ids, "entries": entries, "tip": prev}
    p = d / f"poc_{chain_id}_{session.meta.session_id}.json"
    p.write_text(json.dumps(bundle, indent=2))
    return p


def verify_bundle(path: str) -> Dict[str, Any]:
    """Recompute the hash chain. Returns {valid, steps}."""
    data = json.loads(Path(path).read_text())
    prev = "GENESIS"
    for e in data.get("entries", []):
        body = json.dumps({"step": e.get("step"), "ok": e.get("ok"),
                           "evidence": e.get("evidence")}, sort_keys=True)
        if _h(prev + body) != e.get("hash"):
            return {"valid": False, "failed_at": e.get("step")}
        prev = e["hash"]
    return {"valid": prev == data.get("tip"),
            "steps": len(data.get("entries", []))}
