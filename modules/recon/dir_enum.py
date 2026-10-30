"""Light directory enum — tiny built-in list, 404-filtered, jittered.

For when gobuster/dirb are absent or too loud. Baselines the 404 body
once, then reports only non-baseline hits. GET only, ~25 paths.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

PATHS = ["admin", "administrator", "login", "signin", "wp-admin", "server-status",
         "api", "api/v1", "graphql", ".git/HEAD", ".env", "backup.zip",
         "phpinfo.php", "info.php", "web.config", "robots.txt", "sitemap.xml",
         "console", "manager", "actuator", "health", "status", "debug",
         "test", "old", "bak"]


def run(session: Session, base_url: str,
        logger: Optional[ARDFLogger] = None,
        paths: Optional[List[str]] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.direnum")
    if isinstance(paths, str) and paths.startswith("payloaddb:"):
        try:
            from modules.payload_db import query
            paths = query(paths.split(":", 1)[1] or "directories",
                          limit=120) or None
        except Exception:
            paths = None
    paths = paths or PATHS
    ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ARDF-direnum"}

    def _get(p: str):
        return requests.get(urljoin(base_url.rstrip("/") + "/", p),
                            timeout=10, headers=ua, verify=False)

    try:
        miss = _get(f"ardf-404-{random.randint(10000, 99999)}")
        baseline = (miss.status_code, len(miss.content))
    except Exception as e:
        return {"base": base_url, "error": str(e)[:150], "hits": []}
    hits = []
    for p in paths:
        try:
            r = _get(p)
            if (r.status_code, len(r.content)) != baseline and r.status_code < 500:
                if r.status_code != 404 or len(r.content) != baseline[1]:
                    hits.append({"path": p, "status": r.status_code,
                                 "size": len(r.content)})
        except Exception:
            continue
        time.sleep(0.3 + random.random() * 0.5)
    for h in hits:
        session.add_finding(Finding(
            source="recon.direnum",
            title=f"Hidden path: /{h['path']} ({h['status']})",
            description="Non-baseline response on directory probe.",
            severity=SeverityLevel.MEDIUM if h["status"] < 400 else SeverityLevel.INFO,
            host=base_url, tags=["direnum", "recon"]))
    logger.success(f"dir-enum: {len(hits)}/{len(paths)} hits")
    return {"base": base_url, "hits": hits}
