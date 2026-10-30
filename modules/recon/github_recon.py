"""GitHub recon — code-search for leaked secrets (token from config).

Uses api.github.com code search when GITHUB_TOKEN is configured;
without a token the API refuses code search, so the module degrades
to recording ready-to-run search URLs (dorkpack github set) as an
operator task. Never clones or exfiltrates repo contents.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests
import yaml
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

CONFIG = Path(__file__).parent.parent.parent / "config" / "ardf.yaml"

QUERIES = ["password", "API_key", "api_key", "secret", "passwd",
           "aws_secret", "private_key"]


def _token() -> str:
    if os.getenv("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        data = yaml.safe_load(CONFIG.read_text()) or {}
        tok = ((data.get("api_keys", {}) or {}).get("github", "")) or ""
        if tok.startswith("${") and tok.endswith("}"):
            return os.getenv(tok[2:-1], "")
        return tok
    except Exception:
        return ""


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.github")
    domain = (target or session.meta.target).split("/")[0].split(":")[0]
    token = _token()
    out: Dict[str, Any] = {"domain": domain, "authed": bool(token), "hits": []}
    if not token:
        urls = [f"https://github.com/search?q={quote_plus(f'\"{domain}\" {q}')}&type=code"
                for q in QUERIES]
        session.add_finding(Finding(
            source="recon.github",
            title="GitHub recon queued (no GITHUB_TOKEN)",
            description="Code search needs a token. Manual URLs ready: " +
                        urls[0][:100] + " …",
            severity=SeverityLevel.INFO, host=domain,
            tags=["github", "recon"],
            remediation="",
            ))
        out["manual_urls"] = urls
        logger.info("github: no token, manual URLs recorded")
        return out
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json",
               "User-Agent": "ARDF-github"}
    for q in QUERIES:
        try:
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": f"\"{domain}\" {q}", "per_page": 5},
                headers=headers, timeout=15)
            if r.status_code == 200:
                for item in r.json().get("items", [])[:5]:
                    out["hits"].append({
                        "repo": (item.get("repository") or {}).get("full_name"),
                        "path": item.get("path"),
                        "query": q})
        except Exception:
            continue
    if out["hits"]:
        session.add_finding(Finding(
            source="recon.github",
            title=f"GitHub code hits: {len(out['hits'])} files mention {domain}",
            description="Review each hit for secrets; rotate anything leaked.",
            severity=SeverityLevel.HIGH, host=domain,
            tags=["github", "secrets", "recon"]))
    logger.success(f"github: {len(out['hits'])} hits (authed)")
    return out
