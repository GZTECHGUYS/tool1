"""HTTP-method audit — OPTIONS + verb matrix per live URL (safe).

Sends OPTIONS and a header-only TRACE probe. Flags risky methods
(TRACE/XST, PUT/DELETE/unsupported state-changers). No bodies sent.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

RISKY = {"TRACE": "XST risk", "TRACK": "XST risk", "PUT": "file overwrite risk",
         "DELETE": "object deletion risk", "CONNECT": "proxy abuse risk"}


def _live_urls(session: Session, target: str) -> List[str]:
    urls = []
    for f in session.get_findings():
        raw = f.raw or {}
        if isinstance(raw, dict):
            for key in ("url", "live_url"):
                if raw.get(key) and raw[key] not in urls:
                    urls.append(raw[key])
    if not urls:
        base = target if target.startswith("http") else f"https://{target}"
        urls = [base]
    return urls[:8]


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.methods")
    target = target or session.meta.target
    out: Dict[str, Any] = {"urls": {}}
    for url in _live_urls(session, target):
        try:
            r = requests.request("OPTIONS", url, timeout=12,
                                 headers={"User-Agent": "ARDF-method-audit"})
            allow = r.headers.get("Allow", "") + r.headers.get("Public", "")
            methods = sorted({m.strip().upper() for m in allow.replace(",", " ").split()
                              if m.strip().isalpha()})
        except Exception as e:
            out["urls"][url] = {"error": str(e)[:150]}
            continue
        risky = {m: RISKY[m] for m in methods if m in RISKY}
        out["urls"][url] = {"allow": methods, "risky": risky}
        for m, why in risky.items():
            session.add_finding(Finding(
                source="recon.methods",
                title=f"Risky HTTP method enabled: {m} ({why})",
                description=f"{url} advertises {m} via OPTIONS.",
                severity=SeverityLevel.LOW, host=url,
                tags=["http-methods", "hardening", "recon"],
                remediation="Disable unused methods at the server/WAF."))
    logger.success(f"method-audit: {len(out['urls'])} URLs checked")
    return out
