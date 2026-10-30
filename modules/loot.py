"""Loot triage — parse, de-duplicate and rank captured credentials/secrets."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

PATTERNS = {
    "password": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*(\S{1,64})"),
    "api_key": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*(\S{8,128})"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "ntlm_hash": re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"),
    "bearer": re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+)"),
}

CROWN_JEWEL_HINTS = ("admin", "domain admin", "aws", "prod", "vault",
                     "backup", "dc01", "krbtgt")


def triage_text(text: str, source: str = "") -> List[Dict[str, Any]]:
    """Extract loot items from arbitrary text. Secrets are REDACTED in output."""
    items = []
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text or ""):
            secret = m.group(0)
            items.append({
                "kind": kind, "source": source,
                "preview": secret[:6] + "…[redacted]",
                "length": len(secret),
                "crown_jewel": any(h in text.lower() for h in CROWN_JEWEL_HINTS),
            })
    # de-dup by (kind, length, preview)
    seen, out = set(), []
    for it in items:
        key = (it["kind"], it["length"], it["preview"])
        if key not in seen:
            seen.add(key)
            out.append(it)
    return sorted(out, key=lambda i: (not i["crown_jewel"], i["kind"]))


def triage_session(session: Session,
                   logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """Triage loot across all session findings' evidence blobs."""
    if logger is None:
        logger = get_logger("loot")
    all_items: List[Dict[str, Any]] = []
    for f in session.get_findings():
        blob = f.evidence or ""
        if isinstance(blob, (dict, list)):
            import json
            blob = json.dumps(blob, default=str)
        all_items.extend(triage_text(str(blob), source=f.id))
    jewels = [i for i in all_items if i["crown_jewel"]]
    if all_items:
        session.add_finding(Finding(
            source="loot.triage",
            title=f"Loot triage: {len(all_items)} secrets "
                  f"({len(jewels)} crown jewels)",
            description="De-duplicated credential/secret inventory (redacted)",
            severity=SeverityLevel.CRITICAL if jewels else SeverityLevel.HIGH,
            host=session.meta.target, tags=["loot", "credentials"]))
    logger.success(f"loot: {len(all_items)} items, {len(jewels)} crown jewels")
    return {"items": all_items, "crown_jewels": jewels,
            "count": len(all_items)}
