"""Wayback harvester — historic URLs, robots and JS via CDX API.

Fully passive (web.archive.org only, target never touched). Pulls:
  - all archived URLs for domain* (params preserved for surface feed)
  - historic robots.txt snapshots
  - archived .js files (extra mining input for js_miner)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

CDX = ("https://web.archive.org/cdx/search/cdx"
       "?url={q}&output=json&fl=original,mimetype,statuscode"
       "&collapse=urlkey&limit={limit}")


def _cdx(query: str, limit: int = 2000) -> List[List[str]]:
    r = requests.get(CDX.format(q=quote(query, safe=""), limit=limit),
                     timeout=25, headers={"User-Agent": "ARDF-wayback"})
    if r.status_code != 200:
        return []
    try:
        rows = r.json()
    except Exception:
        return []
    return rows[1:] if rows and rows[0] == ["original", "mimetype",
                                           "statuscode"] else rows


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.wayback")
    target = (target or session.meta.target).split("/")[0].split(":")[0]
    logger.banner("WAYBACK HARVEST", style="bold cyan")

    rows = _cdx(f"{target}/*")
    urls = sorted({r[0] for r in rows if r and r[0].startswith("http")})
    with_params = sorted({u for u in urls if "?" in u})
    js_files = sorted({u for u in urls if u.split("?")[0].endswith(".js")})[:50]
    robots = sorted({u for u in urls if u.rstrip("/").endswith("robots.txt")})

    if urls:
        session.add_finding(Finding(
            source="recon.wayback",
            title=f"Wayback: {len(urls)} historic URLs "
                  f"({len(with_params)} with params)",
            description="Sample: " + ", ".join(with_params[:5] or urls[:5]),
            severity=SeverityLevel.MEDIUM, host=target,
            tags=["wayback", "urls", "recon"],
            raw={"urls": with_params[:100], "live_url": with_params[0]
                 if with_params else urls[0]}))
    if js_files:
        session.add_finding(Finding(
            source="recon.wayback",
            title=f"Wayback: {len(js_files)} historic JS files",
            description="Feed to js_miner for endpoint mining.",
            severity=SeverityLevel.INFO, host=target,
            tags=["wayback", "js", "recon"],
            raw={"js_bundles": js_files}))
    if robots:
        session.add_finding(Finding(
            source="recon.wayback",
            title=f"Wayback: {len(robots)} historic robots.txt",
            description="Old robots often leak removed paths: " +
                        robots[0][:150],
            severity=SeverityLevel.INFO, host=target,
            tags=["wayback", "robots", "recon"]))
    logger.success(f"wayback: {len(urls)} urls, {len(with_params)} params, "
                   f"{len(js_files)} js")
    return {"urls": len(urls), "with_params": with_params[:100],
            "js_files": js_files, "robots": robots[:10]}
