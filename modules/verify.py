"""Verification loop — re-validate flagged findings, close the loop.

validate -> exploit -> re-validate. This module performs the last step:
it re-runs the matching validator for each un-verified finding and records
whether the issue is CONFIRMED (still present) or STALE (gone).
No new exploitation is performed — only the original validation checks.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


def _finding_url(f: Finding) -> str:
    raw = f.raw or {}
    if isinstance(raw, dict):
        for key in ("url", "live_url", "target_url"):
            if raw.get(key):
                return raw[key]
    if f.host and f.host.startswith("http"):
        return f.host
    return ""


def run_verify(session: Session, logger: Optional[ARDFLogger] = None,
               max_findings: int = 25) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("verify")
    logger.banner("VERIFICATION LOOP", style="bold green")

    candidates = [f for f in session.get_findings()
                  if "verified" not in f.tags and "verification" not in f.tags]
    confirmed, stale, skipped = 0, 0, 0

    for f in candidates[:max_findings]:
        tags = {t.lower() for t in f.tags}
        try:
            if tags & {"sqli", "injection"}:
                outcome = _recheck_sqli(s, f, logger)
            elif tags & {"auth", "bruteforce", "login"}:
                outcome = _recheck_auth(s, f, logger)
            else:
                skipped += 1
                continue
        except Exception as e:
            logger.warning(f"verify error on '{f.title[:40]}': {e}")
            skipped += 1
            continue
        _record(session, f, outcome)
        if outcome == "confirmed":
            confirmed += 1
        else:
            stale += 1

    logger.success(f"verify: {confirmed} confirmed, {stale} stale, "
                   f"{skipped} skipped")
    return {"confirmed": confirmed, "stale": stale, "skipped": skipped}


def _recheck_sqli(session: Session, f: Finding, logger) -> str:
    from modules.validate.sqli import SQLiValidator
    url = _finding_url(f)
    if not url:
        return "stale"
    res = SQLiValidator(session, logger).validate(url)
    return "confirmed" if res.get("vulnerable") else "stale"


def _recheck_auth(session: Session, f: Finding, logger) -> str:
    from modules.validate.auth import AuthValidator
    url = _finding_url(f) or f.host
    if not url:
        return "stale"
    res = AuthValidator(session, logger).validate(url)
    vulns = res.get("vulnerabilities") or res.get("findings") or []
    return "confirmed" if vulns else "stale"


def _record(session: Session, original: Finding, outcome: str) -> None:
    sev = SeverityLevel.HIGH if outcome == "confirmed" else SeverityLevel.INFO
    session.add_finding(Finding(
        source="verify.loop",
        title=f"Re-verification {outcome.upper()}: {original.title[:80]}",
        description=f"Original finding {original.id} re-checked: {outcome}",
        severity=sev, host=original.host,
        tags=["verification", "verified", outcome]))
    original.tags = sorted(set(original.tags) | {"verified"})
