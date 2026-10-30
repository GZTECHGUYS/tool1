"""robots/sitemap/security.txt harvester — passive file enumeration."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

FILES = ["robots.txt", "sitemap.xml", "sitemap_index.xml",
         ".well-known/security.txt", ".well-known/change-password",
         "crossdomain.xml", "clientaccesspolicy.xml"]
DISALLOW_RE = re.compile(r"disallow:\s*(\S+)", re.IGNORECASE)


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.robots")
    target = target or session.meta.target
    base = (target if target.startswith("http") else f"https://{target}").rstrip("/") + "/"
    found: Dict[str, Any] = {}
    for name in FILES:
        url = urljoin(base, name)
        try:
            r = requests.get(url, timeout=10,
                             headers={"User-Agent": "ARDF-robots"})
            if r.status_code == 200 and len(r.content) > 10:
                found[name] = {"size": len(r.content)}
        except Exception:
            continue
    if "robots.txt" in found:
        try:
            body = requests.get(urljoin(base, "robots.txt"), timeout=10).text
            paths = sorted(set(DISALLOW_RE.findall(body)))[:30]
            found["robots.txt"]["disallow"] = paths
            if paths:
                session.add_finding(Finding(
                    source="recon.robots",
                    title=f"robots.txt hides {len(paths)} paths",
                    description="Disallowed paths are recon hints: " +
                                ", ".join(paths[:10]),
                    severity=SeverityLevel.INFO, host=target,
                    tags=["robots", "recon"]))
        except Exception:
            pass
    if found:
        session.add_finding(Finding(
            source="recon.robots",
            title="Discovery files exposed: " + ", ".join(sorted(found)),
            description="Sitemap/robots/policy files enumerate attack surface.",
            severity=SeverityLevel.INFO, host=target,
            tags=["robots", "recon"]))
    logger.success(f"robots: {sorted(found) or 'none found'}")
    return {"base": base, "files": found}
