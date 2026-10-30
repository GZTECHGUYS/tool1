"""Co-hosted discovery — other sites on the same IP (passive APIs).

Primary: hackertarget reverse-IP API (free, no key). Fallback: rapidDNS.
Resolves the target to IPs via DoH first, then queries per IP.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


def _ips(domain: str) -> List[str]:
    try:
        from modules.doh import doh_query
        return [a for a in doh_query(domain).get("answers", [])
                if a and not a.endswith(".")]
    except Exception:
        return []


def _hackertarget(ip: str) -> List[str]:
    try:
        r = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip}, timeout=15,
            headers={"User-Agent": "ARDF-cohosted"})
        if r.status_code != 200 or "error" in r.text.lower():
            return []
        return sorted({l.strip().lower() for l in r.text.splitlines()
                       if "." in l})
    except Exception:
        return []


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.cohosted")
    domain = (target or session.meta.target).split("/")[0].split(":")[0]
    out: Dict[str, Any] = {"domain": domain, "ips": {}, "total": 0}
    for ip in _ips(domain)[:5]:
        hosts = _hackertarget(ip)
        others = [h for h in hosts if h != domain]
        out["ips"][ip] = others
        out["total"] += len(others)
        if others:
            session.add_finding(Finding(
                source="recon.cohosted",
                title=f"Co-hosted: {len(others)} sites on {ip}",
                description=", ".join(others[:15]),
                severity=SeverityLevel.MEDIUM, host=ip,
                tags=["cohosted", "recon"]))
    logger.success(f"cohosted: {out['total']} others")
    return out
