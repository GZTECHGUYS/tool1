"""ASN / net-range lookup — whole-infrastructure view via ARIN RDAP.

HTTPS JSON, no API key. Resolves domain to IPs (DoH), then maps each
IP to its announced range + org. Feeds scope expansion decisions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

RDAP = "https://rdap.arin.net/registry/ip/{ip}"


def lookup_ip(ip: str) -> Dict[str, Any]:
    try:
        r = requests.get(RDAP.format(ip=ip), timeout=15,
                         headers={"User-Agent": "ARDF-asn",
                                  "Accept": "application/json"})
        if r.status_code != 200:
            return {"ip": ip, "error": f"rdap {r.status_code}"}
        d = r.json()
        org = ""
        for ent in d.get("entities", []) or []:
            for v in (ent.get("vcardArray", []) or [None, []])[1] or []:
                if isinstance(v, list) and v and v[0] == "fn":
                    org = " ".join(str(x) for x in v[3:] if x)
        return {"ip": ip, "cidr": d.get("cidr0_cidrs", [{}])[0]
                if isinstance(d.get("cidr0_cidrs"), list) and d.get("cidr0_cidrs")
                else {},
                "name": d.get("name", ""), "org": org,
                "country": d.get("country", "")}
    except Exception as e:
        return {"ip": ip, "error": str(e)[:150]}


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    from modules.doh import doh_query
    if logger is None:
        logger = get_logger("recon.asn")
    domain = (target or session.meta.target).split("/")[0].split(":")[0]
    ips = [a for a in doh_query(domain).get("answers", []) if a and not a.endswith(".")][:5]
    ranges = [lookup_ip(ip) for ip in ips]
    for rec in ranges:
        if rec.get("error"):
            continue
        cidr = rec.get("cidr") or {}
        session.add_finding(Finding(
            source="recon.asn",
            title=f"Net range: {cidr.get('v4prefix', cidr.get('v6prefix', '?'))} "
                  f"({rec.get('org') or rec.get('name')})",
            description=f"IP {rec['ip']} announces here. Consider scope expansion.",
            severity=SeverityLevel.INFO, host=rec["ip"],
            tags=["asn", "netrange", "recon"]))
    logger.success(f"asn: {len([r for r in ranges if not r.get('error')])} ranges")
    return {"domain": domain, "ranges": ranges}
