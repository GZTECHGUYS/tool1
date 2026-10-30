"""Dork-pack generator — per-target search-operator packs (offline).

Builds Google/Bing/GitHub dork lists for params, logins, filetypes,
juicy files and secret leaks. Offline text generation; run the dorks
in a browser (or wire a SERP API later). Saved to session + finding.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel


def build_pack(domain: str) -> Dict[str, List[str]]:
    d = domain.split("/")[0].split(":")[0]
    return {
        "parameters": [
            f"site:{d} inurl:.php?id=",
            f"site:{d} inurl:.aspx?id=",
            f"site:{d} inurl:.jsp?user=",
            f"site:{d} inurl:?q=",
            f"site:{d} inurl:.php?book=",
        ],
        "login_pages": [
            f"site:{d} inurl:login",
            f"site:{d} intext:login",
            f"site:{d} inurl:portal.php",
            f"site:{d} inurl:register.php",
            f"site:{d} inurl:admin",
        ],
        "filetypes": [
            f"site:{d} filetype:php",
            f"site:{d} filetype:aspx",
            f"site:{d} filetype:wsdl",
            f"site:{d} filetype:txt",
            f"site:{d} filetype:bak",
            f"site:{d} filetype:env",
        ],
        "juicy": [
            f"site:{d} intext:\"index of /\"",
            f"site:{d} ext:txt",
            f"site:{d} inurl:.php.txt",
            f"site:{d} intext:password",
        ],
        "github": [
            f"\"{d}\" password",
            f"\"{d}\" API_key",
            f"\"{d}\" api_key",
            f"\"dev.{d}\"",
            f"\"api.{d}\"",
        ],
        "subdomains": [
            f"site:{d} -site:www.{d}",
        ],
    }


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.dorks")
    target = (target or session.meta.target).split("/")[0].split(":")[0]
    pack = build_pack(target)
    d = session.dir("recon")
    d.mkdir(parents=True, exist_ok=True)
    total = 0
    for name, queries in pack.items():
        (d / f"dorks_{name}.txt").write_text("\n".join(queries) + "\n")
        total += len(queries)
    session.add_finding(Finding(
        source="recon.dorks",
        title=f"Dork pack: {total} queries in {len(pack)} categories",
        description="Run manually (Google/Bing/GitHub) or feed to SERP API. "
                    "Param dorks feed surface candidates.",
        severity=SeverityLevel.INFO, host=target,
        tags=["dorks", "recon"]))
    logger.success(f"dork-pack: {total} queries")
    return {"categories": sorted(pack), "total": total, "pack": pack}
