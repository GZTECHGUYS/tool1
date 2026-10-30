"""Subdomain permutations — altdns-style mutation brute force via DoH.

Takes known subdomains, mutates labels (dev/test/stage/old/new/beta,
numeric suffixes, hyphen joins) and resolves via DNS-over-HTTPS.
Finds subdomains-of-subdomains without touching the target.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

PREFIXES = ["dev", "test", "stage", "staging", "old", "new", "beta",
            "alpha", "demo", "qa", "uat", "pre", "prod", "api", "admin",
            "internal", "private", "secure", "vpn", "mail2", "www2"]
SUFFIXES = ["01", "02", "1", "2", "old", "new", "bak", "test", "dev"]


def mutate(label: str) -> List[str]:
    out = set()
    for p in PREFIXES:
        out.add(f"{p}-{label}")
        out.add(f"{p}.{label}")
    for s in SUFFIXES:
        out.add(f"{label}-{s}")
        out.add(f"{label}{s}")
    parts = label.split("-")
    if len(parts) > 1:
        out.add("".join(parts))
    return sorted(out)


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None,
        jitter: float = 0.3) -> Dict[str, Any]:
    from modules.doh import doh_query
    if logger is None:
        logger = get_logger("recon.subpermute")
    domain = (target or session.meta.target).split("/")[0].split(":")[0]
    known = set()
    for f in session.get_findings():
        for blob in ((f.raw or {}).get("subdomains", []) if isinstance(f.raw, dict) else [],
                     [f.host] if f.host else []):
            for h in blob if isinstance(blob, list) else [blob]:
                if isinstance(h, str) and h.endswith(domain):
                    known.add(h.lower())
    if not known:
        known = {domain}
    found = []
    tried = 0
    for sub in sorted(known)[:20]:
        label = sub[:-(len(domain) + 1)] if sub != domain else ""
        cands = mutate(label) if label else [f"{p}.{domain}" for p in PREFIXES[:10]]
        for m in cands:
            fqdn = f"{m}.{domain}" if "." not in m or not m.endswith(domain) else m
            if not fqdn.endswith(domain):
                fqdn = f"{m}.{domain}"
            tried += 1
            try:
                ans = doh_query(fqdn).get("answers", [])
            except Exception:
                continue
            if ans:
                found.append({"host": fqdn, "records": ans[:3]})
            time.sleep(jitter * (0.5 + random.random()))
            if tried >= 200:
                break
        if tried >= 200:
            break
    for entry in found:
        session.add_finding(Finding(
            source="recon.subpermute",
            title=f"Permuted subdomain: {entry['host']}",
            description="Mutation brute-force via DoH (subdomain-of-subdomain).",
            severity=SeverityLevel.INFO, host=entry["host"],
            tags=["subdomain", "recon"]))
    logger.success(f"subpermute: {len(found)}/{tried} hit")
    return {"domain": domain, "tried": tried, "found": found}
