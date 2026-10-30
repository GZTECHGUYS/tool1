"""API discovery — passive GET-only enumeration of API surfaces."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

WELL_KNOWN = [
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/docs", "/redoc",
    "/.well-known/security.txt", "/graphql",
]

_JS_URL = re.compile(r"""['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""")


def _targets(session: Session, target: str) -> List[str]:
    urls = []
    for f in session.get_findings():
        for tag in ("live_url", "url", "web"):
            pass
        raw = (f.raw or {})
        for key in ("url", "live_url"):
            if isinstance(raw, dict) and raw.get(key):
                urls.append(raw[key])
        if f.host and f.host.startswith("http"):
            urls.append(f.host)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    if not out:
        base = target if target.startswith("http") else f"https://{target}"
        out = [base]
    return out[:10]


def run_api_discovery(session: Session, target: str = "",
                      logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """GET-only API surface discovery. No exploitation, no fuzzing."""
    import requests
    if logger is None:
        logger = get_logger("recon.api")
    target = target or session.meta.target
    logger.banner("API DISCOVERY", style="bold cyan")

    found_specs, js_endpoints, checked = [], [], 0
    for base in _targets(session, target):
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in WELL_KNOWN:
            url = origin + path
            checked += 1
            try:
                r = requests.get(url, timeout=10,
                                 headers={"User-Agent": "ARDF-api-discovery"})
                if r.status_code == 200 and len(r.content) > 50:
                    found_specs.append(url)
            except Exception:
                continue
        try:
            r = requests.get(origin, timeout=10,
                             headers={"User-Agent": "ARDF-api-discovery"})
            for m in _JS_URL.finditer(r.text):
                js_endpoints.append(urljoin(origin, m.group(1)))
        except Exception:
            continue

    js_endpoints = sorted(set(js_endpoints))[:50]
    # v2 CT harvest (passive crt.sh subdomain source)
    ct_subs: List[str] = []
    try:
        from ops.v2 import ct_subdomains as _ct
        ct_subs = [s for s in _ct(target) if s][:25]
    except Exception:
        ct_subs = []
    if found_specs:
        session.add_finding(Finding(
            source="recon.api", title=f"API spec exposed: {found_specs[0]}",
            description=f"{len(found_specs)} spec/doc endpoints reachable (GET only)",
            severity=SeverityLevel.MEDIUM, host=target,
            tags=["api", "spec", "recon"],
            evidence=", ".join(found_specs[:5])))
    if js_endpoints:
        session.add_finding(Finding(
            source="recon.api",
            title=f"{len(js_endpoints)} JS bundles found (endpoint mining candidates)",
            description="JavaScript files that may hide API routes",
            severity=SeverityLevel.INFO, host=target,
            tags=["api", "js", "recon"],
            raw={"js_bundles": js_endpoints[:50]}))
    if ct_subs:
        session.add_finding(Finding(
            source="recon.api",
            title=f"{len(ct_subs)} CT subdomains (crt.sh)",
            description="Certificate-transparency subdomain harvest: " +
                        ", ".join(ct_subs[:10]),
            severity=SeverityLevel.INFO, host=target,
            tags=["subdomain", "ct", "recon"]))
    logger.success(f"API discovery: {len(found_specs)} specs, "
                   f"{len(js_endpoints)} JS files ({checked} checks)")
    return {"specs": found_specs, "js_bundles": js_endpoints,
            "ct_subdomains": ct_subs, "checked": checked}
