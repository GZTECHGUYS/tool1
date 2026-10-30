"""AuthZ mapper — builds the IDOR / access-control test matrix (no abuse).

Correlates identifier-bearing params (id, uuid, order, account, …)
across discovered URLs into a test matrix: which identities × objects
to compare. It does NOT fetch other users' objects — the matrix is a
plan for operator-approved manual testing.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

ID_HINTS = re.compile(
    r"(?i)^(id|uuid|guid|user_id|account|account_id|order|order_id|"
    r"invoice|doc|file_id|customer|client|profile|member)$|_(id|uuid)$")


def id_params(url: str) -> List[str]:
    try:
        return [n for n, _ in parse_qsl(urlparse(url).query)
                if ID_HINTS.search(n)]
    except Exception:
        return []


def run(session: Session, logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("postex.authz")
    matrix: List[Dict[str, Any]] = []
    seen = set()
    for f in session.get_findings():
        raw = f.raw or {}
        urls = []
        if isinstance(raw, dict):
            for k in ("url", "live_url"):
                if raw.get(k):
                    urls.append(raw[k])
        if f.host and f.host.startswith("http"):
            urls.append(f.host)
        for url in urls:
            for p in id_params(url):
                key = (url.split("?")[0], p)
                if key not in seen:
                    seen.add(key)
                    matrix.append({"endpoint": key[0], "param": p,
                                   "test": "compare low-priv vs high-priv "
                                           "object access; test sequential IDs"})
    if matrix:
        session.add_finding(Finding(
            source="postex.authz",
            title=f"{len(matrix)} IDOR test points mapped (plan only)",
            description="Endpoints taking object identifiers. No cross-user "
                        "access attempted — matrix is for approved testing.",
            severity=SeverityLevel.INFO,
            host=session.meta.target,
            tags=["idor", "authz", "postex"]))
    logger.success(f"authz-mapper: {len(matrix)} test points")
    return {"matrix": matrix[:100], "count": len(matrix)}
