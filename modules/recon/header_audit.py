"""Security-header audit — missing headers mapped to hardening findings."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

EXPECTED = {
    "strict-transport-security": ("HSTS missing — downgrade attacks possible",
                                  SeverityLevel.MEDIUM),
    "content-security-policy": ("CSP missing — XSS impact amplified",
                                SeverityLevel.MEDIUM),
    "x-frame-options": ("Clickjacking protection missing", SeverityLevel.LOW),
    "x-content-type-options": ("MIME-sniffing protection missing", SeverityLevel.LOW),
    "referrer-policy": ("Referrer policy missing", SeverityLevel.INFO),
    "permissions-policy": ("Permissions policy missing", SeverityLevel.INFO),
}
LEAKY = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.headers")
    target = target or session.meta.target
    base = target if target.startswith("http") else f"https://{target}"
    try:
        r = requests.get(base, timeout=12,
                         headers={"User-Agent": "ARDF-header-audit"})
    except Exception as e:
        return {"url": base, "error": str(e)[:200]}
    headers = {k.lower(): v for k, v in r.headers.items()}
    missing, leaks = [], {}
    for name, (desc, sev) in EXPECTED.items():
        if name not in headers:
            missing.append(name)
            session.add_finding(Finding(
                source="recon.headers", title=desc,
                description=f"Header '{name}' absent on {base}",
                severity=sev, host=target,
                tags=["headers", "hardening", "recon"],
                remediation=f"Emit {name} header (see OWASP Secure Headers)."))
    for name in LEAKY:
        if name in headers:
            leaks[name] = headers[name][:80]
    if leaks:
        session.add_finding(Finding(
            source="recon.headers",
            title="Stack disclosure: " + ", ".join(
                f"{k}={v}" for k, v in leaks.items())[:120],
            description="Response headers leak technology/version.",
            severity=SeverityLevel.LOW, host=target,
            tags=["headers", "version-disclosure", "recon"]))
    logger.success(f"header-audit: {len(missing)} missing, {len(leaks)} leaks")
    return {"url": base, "missing": missing, "leaks": leaks}
