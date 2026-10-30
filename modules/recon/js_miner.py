"""JS endpoint miner — extracts routes from discovered JS bundles (offline).

Reads bundle URLs recorded by recon.api and mines them for API routes,
fetch/XHR targets and interesting strings. Pure GET + regex, no fuzzing.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

ROUTE_RES = [
    re.compile(r"""['"`](/(?:api|v\d|graphql|rest|ajax|endpoint)[^'"`\s]*)['"`]"""),
    re.compile(r"""fetch\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""(?:axios\.(?:get|post|put|delete)|ajax\(\s*['"`]([^'"`]+)['"`])"""),
    re.compile(r"""['"`](https?://[^'"`\s]+)['"`]"""),
]
SECRET_RES = [
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9\-._]{8,}['\"]"),
]


def _bundle_urls(session: Session) -> List[str]:
    urls = []
    for f in session.get_findings():
        raw = f.raw or {}
        blobs = []
        if isinstance(raw, dict):
            for key in ("js_bundles", "js_urls", "bundles"):
                if isinstance(raw.get(key), list):
                    blobs.extend(raw[key])
        if "JS bundles found" in f.title:
            import json as _j
            try:
                ev = _j.loads(f.evidence) if isinstance(f.evidence, str) and f.evidence.startswith("[") else []
                blobs.extend(ev if isinstance(ev, list) else [])
            except Exception:
                pass
        for u in blobs:
            if u not in urls:
                urls.append(u)
    return urls[:30]


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.jsminer")
    routes, secrets = set(), set()
    fetched = 0
    for bundle in _bundle_urls(session):
        try:
            r = requests.get(bundle, timeout=12,
                             headers={"User-Agent": "ARDF-js-miner"})
            fetched += 1
            text = r.text
        except Exception:
            continue
        for rx in ROUTE_RES:
            for m in rx.finditer(text):
                routes.add(m.group(1)[:200])
        for rx in SECRET_RES:
            if rx.search(text):
                secrets.add(bundle)
    routes = sorted(routes)[:200]
    if routes:
        session.add_finding(Finding(
            source="recon.jsminer",
            title=f"{len(routes)} hidden routes mined from JS",
            description="Sample: " + ", ".join(routes[:8]),
            severity=SeverityLevel.MEDIUM,
            host=target or session.meta.target,
            tags=["api", "js", "routes", "recon"]))
    if secrets:
        session.add_finding(Finding(
            source="recon.jsminer", title="Possible hardcoded secrets in JS",
            description=f"{len(secrets)} bundle(s) match secret patterns",
            severity=SeverityLevel.HIGH, host=target or session.meta.target,
            tags=["secret", "js", "recon"]))
    logger.success(f"js-miner: {fetched} bundles, {len(routes)} routes")
    return {"bundles": fetched, "routes": routes,
            "secret_bundles": sorted(secrets)}
