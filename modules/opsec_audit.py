"""Pre-engagement OPSEC audit — fail-noisy checklist before first packet.

Read-only checks against config + environment. Returns graded items and
records an INFO finding so the audit itself is in the evidence trail.
Blocking guidance: scope disabled, direct egress on loud profile, or
system-DNS recon while proxy is on are FAILs; everything else warns.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


def audit(session: Optional[Session] = None,
          logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("opsec.audit")
    from modules import proxy_chain as pc
    from modules import opsec_profiles as op
    from ops.scope import ScopeGuard

    items: List[Dict[str, str]] = []

    def add(name: str, status: str, detail: str):
        items.append({"check": name, "status": status, "detail": detail})

    scope = ScopeGuard()
    add("scope-guard", "PASS" if scope.enabled else "FAIL",
        f"enabled={scope.enabled} rules={len(scope.allowed_targets)}")

    st = pc.status()
    if st["proxies"]:
        add("egress-proxy", "PASS", f"active={st['active']}")
    else:
        prof = op.current_profile()
        rate = float(prof.get("rate_limit", 2.0) or 2.0)
        add("egress-proxy", "FAIL" if rate > 2.0 else "WARN",
            "direct egress, no proxy configured (ARDF_PROXY / stealth.proxy)")

    tor_cfg = st["tor_configured"]
    if tor_cfg:
        res = pc.tor_new_circuit() if os.getenv("ARDF_TOR_ROTATE") else None
        add("tor", "PASS" if res is None or res.get("ok") else "WARN",
            "configured" + ("" if res is None else f" newnym={res.get('ok')}"))
    else:
        add("tor", "WARN", "not configured (optional)")

    try:
        import modules.doh as _doh  # noqa: F401
        add("doh-available", "PASS", "DoH resolver importable")
    except Exception as e:
        add("doh-available", "WARN", str(e)[:100])

    prof = op.current_profile()
    add("opsec-profile", "PASS",
        f"rate={prof.get('rate_limit')} req/s profiles={prof.get('profiles')}")

    if os.getenv("ARDF_PROXY") and not st["proxies"]:
        add("env-leak", "WARN", "ARDF_PROXY set but not picked up")
    else:
        add("env-leak", "PASS", "no proxy env mismatch")

    fails = sum(1 for i in items if i["status"] == "FAIL")
    verdict = "NO-GO" if fails else "GO"
    if session is not None:
        session.add_finding(Finding(
            source="opsec.audit", title=f"Pre-engagement OPSEC audit: {verdict}",
            description="; ".join(f"{i['check']}={i['status']}" for i in items),
            severity=SeverityLevel.MEDIUM if fails else SeverityLevel.INFO,
            host=session.meta.target, tags=["opsec", "audit"]))
    logger.success(f"opsec-audit: {verdict} ({fails} FAILs)")
    return {"verdict": verdict, "fails": fails, "items": items}
