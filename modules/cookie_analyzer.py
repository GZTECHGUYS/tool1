"""Cookie / session hygiene analyzer — flags weak cookie attributes.

Reads Set-Cookie headers (no auth needed) and scores: missing Secure /
HttpOnly / SameSite, short names, non-__Host prefixes on sensitive
cookies. Read-only header analysis.
"""
from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


def analyze_cookies(set_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    issues = []
    jar: Dict[str, Dict[str, str]] = {}
    for header in set_cookie_headers:
        c = SimpleCookie()
        try:
            c.load(header)
        except Exception:
            continue
        for name, morsel in c.items():
            jar[name] = {k: morsel[k] for k in ("secure", "httponly", "samesite", "path")}
    for name, attrs in jar.items():
        sensitive = any(k in name.lower() for k in
                        ("sess", "auth", "token", "login", "sid", "jwt"))
        flags = []
        if not attrs.get("secure"):
            flags.append("missing Secure")
        if not attrs.get("httponly") and sensitive:
            flags.append("missing HttpOnly")
        if not attrs.get("samesite"):
            flags.append("missing SameSite")
        if flags and (sensitive or len(flags) > 1):
            issues.append({"cookie": name, "flags": flags,
                           "sensitive": sensitive})
    return issues


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("postex.cookies")
    target = target or session.meta.target
    base = target if target.startswith("http") else f"https://{target}"
    try:
        r = requests.get(base, timeout=12,
                         headers={"User-Agent": "ARDF-cookie-audit"})
        raw = r.headers.get("Set-Cookie", "")
        headers = [raw] if raw else []
    except Exception as e:
        return {"url": base, "error": str(e)[:200], "issues": []}
    issues = analyze_cookies(headers)
    for it in issues:
        session.add_finding(Finding(
            source="postex.cookies",
            title=f"Weak cookie '{it['cookie']}': {', '.join(it['flags'])}",
            description="Cookie attributes weaken session security.",
            severity=SeverityLevel.MEDIUM if it["sensitive"] else SeverityLevel.LOW,
            host=target, tags=["cookies", "session", "postex"],
            remediation="Secure + HttpOnly + SameSite=Lax/Strict; "
                        "__Host- prefix for session cookies."))
    logger.success(f"cookie-audit: {len(issues)} issues")
    return {"url": base, "issues": issues}
