"""WAF / CDN fingerprint — headers + behaviour probes, passive-first.

Identifies Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, Sucuri,
F5 BIG-IP and others from response headers, cookies and challenge
pages. Two benign probes max per host (one 404, one query append).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"],
    "Akamai": ["akamai", "ak_bmsc", "bm_sv"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "AWS WAF/CloudFront": ["x-amz-cf-id", "x-amzn-", "awselb"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Sucuri": ["x-sucuri", "sucuri"],
    "F5 BIG-IP": ["bigipserver", "f5_"],
    "Barracuda": ["barra_counter_session", "bnc"],
    "Fortinet": ["fortiwaf", "fgt"],
    "Citrix NetScaler": ["ns_af", "citrix"],
}


def fingerprint_headers(headers: Dict[str, str], cookies: str,
                        body: str = "") -> List[str]:
    blob = (" ".join(headers.keys()) + " " + " ".join(headers.values())
            + " " + cookies + " " + body[:2000]).lower()
    return [name for name, sigs in SIGNATURES.items()
            if any(s in blob for s in sigs)]


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.waf")
    target = target or session.meta.target
    base = target if target.startswith("http") else f"https://{target}"
    found: Dict[str, List[str]] = {}
    for probe in (base, base + "/ardf-waf-probe-404"):
        try:
            r = requests.get(probe, timeout=12,
                             headers={"User-Agent": "ARDF-waf-detect"})
            hits = fingerprint_headers(dict(r.headers),
                                       str(r.cookies), r.text)
            if hits:
                found[probe] = hits
        except Exception:
            continue
    detected = sorted({w for hits in found.values() for w in hits})
    if detected:
        session.add_finding(Finding(
            source="recon.waf",
            title=f"WAF/CDN detected: {', '.join(detected)}",
            description="Tune tamper set + OPSEC profile accordingly; "
                        "aggressive scanning will be flagged.",
            severity=SeverityLevel.INFO, host=target,
            tags=["waf", "cdn", "recon"]))
    else:
        session.add_finding(Finding(
            source="recon.waf", title="No WAF fingerprint matched",
            description="No known WAF/CDN signatures in headers/cookies.",
            severity=SeverityLevel.INFO, host=target,
            tags=["waf", "recon"]))
    logger.success(f"waf-detect: {detected or 'none'}")
    return {"waf": detected, "probes": list(found.keys())}
