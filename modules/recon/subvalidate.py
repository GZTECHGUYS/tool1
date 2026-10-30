"""Subdomain validation — live-host inventory with titles and servers.

Takes every known subdomain, probes HTTP/S (status, title, server
header) and records a validated inventory. EyeWitness-style screenshots
need a browser; this is the lightweight classifier tier.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _collect(session: Session, domain: str) -> List[str]:
    hosts = set()
    for f in session.get_findings():
        raw = f.raw or {}
        if isinstance(raw, dict):
            for key in ("subdomains", "urls"):
                for h in raw.get(key, []) or []:
                    if isinstance(h, str):
                        hosts.add(h.split("/")[0].lower())
        if f.host:
            hosts.add(f.host.split("/")[0].lower())
    return sorted(h for h in hosts if h.endswith(domain))[:100]


def _probe(host: str) -> Optional[Dict[str, Any]]:
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=10,
                             headers={"User-Agent": "ARDF-subvalidate"},
                             verify=False)
            m = TITLE_RE.search(r.text or "")
            return {"host": host, "scheme": scheme,
                    "status": r.status_code,
                    "title": (m.group(1).strip()[:80] if m else ""),
                    "server": r.headers.get("Server", "")[:60]}
        except Exception:
            continue
    return None


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.subvalidate")
    domain = (target or session.meta.target).split("/")[0].split(":")[0]
    live = []
    for host in _collect(session, domain):
        info = _probe(host)
        if info:
            live.append(info)
    if live:
        session.add_finding(Finding(
            source="recon.subvalidate",
            title=f"Validated live hosts: {len(live)}",
            description=" | ".join(
                f"{h['host']} ({h['status']}) {h['title']}" for h in live[:10]),
            severity=SeverityLevel.INFO, host=domain,
            tags=["subdomain", "validated", "recon"],
            raw={"live_hosts": live}))
    logger.success(f"subvalidate: {len(live)} live")
    return {"domain": domain, "live": live}
