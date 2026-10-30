"""Exfil ledger — append-only accounting of simulated exfiltrated artifacts."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.session import Session


def _ledger_path(session: Session) -> Path:
    d = session.dir("exfil")
    d.mkdir(parents=True, exist_ok=True)
    return d / "ledger.jsonl"


def record(session: Session, artifact: str, kind: str = "file",
           size_bytes: int = 0, channel: str = "https",
           note: str = "") -> Dict[str, Any]:
    """Record a simulated exfil event. Nothing leaves the machine."""
    entry = {"ts": datetime.now().isoformat(), "artifact": artifact,
             "kind": kind, "size_bytes": size_bytes,
             "channel": channel, "note": note}
    with open(_ledger_path(session), "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def list_entries(session: Session) -> List[Dict[str, Any]]:
    p = _ledger_path(session)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def summary(session: Session) -> Dict[str, Any]:
    entries = list_entries(session)
    by_channel: Dict[str, int] = {}
    total = 0
    for e in entries:
        by_channel[e.get("channel", "?")] = by_channel.get(e.get("channel", "?"), 0) + 1
        total += int(e.get("size_bytes", 0) or 0)
    return {"events": len(entries), "bytes": total, "by_channel": by_channel}
