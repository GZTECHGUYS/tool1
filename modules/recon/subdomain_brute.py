"""Subdomain brute via DoH — stealthy enumeration, no local DNS logs.

Small built-in label list resolved through DNS-over-HTTPS with jitter.
Wildcard detection via a random-label control query.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

LABELS = ["www", "mail", "ftp", "admin", "portal", "vpn", "remote", "test",
          "dev", "staging", "api", "app", "apps", "webapps", "owa", "erp",
          "crm", "intranet", "extranet", "reports", "backup", "ns1", "mx",
          "webmail", "owa", "portal2", "sso", "ldap", "db", "files"]


def run(session: Session, domain: str,
        logger: Optional[ARDFLogger] = None,
        labels: Optional[List[str]] = None,
        jitter: float = 0.4) -> Dict[str, Any]:
    from modules.doh import doh_query
    if logger is None:
        logger = get_logger("recon.subbrute")
    labels = labels or LABELS
    control = doh_query(f"ardf-{random.randint(10000, 99999)}.{domain}")
    wildcard = set(control.get("answers", []))
    found = []
    for label in labels:
        fqdn = f"{label}.{domain}"
        try:
            ans = doh_query(fqdn).get("answers", [])
        except Exception:
            continue
        real = [a for a in ans if a not in wildcard]
        if real:
            found.append({"host": fqdn, "records": real[:4]})
        time.sleep(jitter * (0.5 + random.random()))
    for entry in found:
        session.add_finding(Finding(
            source="recon.subbrute",
            title=f"Subdomain (DoH brute): {entry['host']}",
            description="Resolved via DNS-over-HTTPS label brute-force.",
            severity=SeverityLevel.INFO, host=entry["host"],
            tags=["subdomain", "recon"]))
    logger.success(f"subdomain-brute: {len(found)}/{len(labels)} hit")
    return {"domain": domain, "tried": len(labels), "found": found}
