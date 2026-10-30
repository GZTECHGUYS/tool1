"""Stateful same-origin crawler — link/form/JS harvest feeding surface.

Follows same-origin links to a bounded depth, collecting forms (with
inputs), URL params and script srcs. Session-cookie aware (keeps the
cookies the site sets). Respects scope (same registrable domain only).
"""
from __future__ import annotations

import re
import time
from collections import deque
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qsl

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

HREF_RE = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"'#]+)["']''',
                     re.IGNORECASE)
FORM_RE = re.compile(r"<form[^>]*>", re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]*name=["\']?([\w$-]+)', re.IGNORECASE)


def _registrable(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None,
        max_pages: int = 40, max_depth: int = 2) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.crawler")
    target = target or session.meta.target
    start = target if target.startswith("http") else f"https://{target}"
    scope = _registrable(urlparse(start).hostname or target)
    ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ARDF-crawler"}
    seen, forms, params, scripts = set(), [], set(), set()
    queue: deque = deque([(start, 0)])
    pages = 0
    sess = requests.Session()
    while queue and pages < max_pages:
        url, depth = queue.popleft()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        try:
            r = sess.get(url, timeout=12, headers=ua, verify=False)
            pages += 1
        except Exception:
            continue
        ctype = r.headers.get("Content-Type", "")
        if "html" not in ctype:
            continue
        text = r.text or ""
        for m in FORM_RE.finditer(text):
            tag = m.group(0)
            action = re.search(r'action=["\']?([^"\'\s>]+)',
                               tag, re.IGNORECASE)
            inputs = INPUT_RE.findall(text[m.start():m.start() + 2000])
            forms.append({"page": url,
                          "action": urljoin(url, action.group(1))
                          if action else url,
                          "inputs": sorted(set(inputs))[:12]})
        for m in HREF_RE.finditer(text):
            link = urljoin(url, m.group(1))
            p = urlparse(link)
            if _registrable(p.hostname or "") != scope:
                continue
            if p.path.endswith(".js"):
                scripts.add(link.split("?")[0])
            for n, _ in parse_qsl(p.query):
                params.add((link.split("?")[0], n))
            if (link, depth + 1) not in queue and link not in seen:
                queue.append((link, depth + 1))
        time.sleep(0.4)
    out = {"pages": pages, "forms": forms[:30],
           "params": sorted(params)[:100], "scripts": sorted(scripts)[:50]}
    if forms:
        session.add_finding(Finding(
            source="recon.crawler",
            title=f"Crawler: {len(forms)} forms on {pages} pages",
            description="; ".join(
                f"{f['action']} [{','.join(f['inputs'])}]" for f in forms[:6]),
            severity=SeverityLevel.MEDIUM, host=target,
            tags=["forms", "crawler", "recon"],
            raw={"forms": forms[:30]}))
    if params:
        session.add_finding(Finding(
            source="recon.crawler",
            title=f"Crawler: {len(params)} parameterized endpoints",
            description=", ".join(f"{u}?{n}" for u, n in list(params)[:8]),
            severity=SeverityLevel.MEDIUM, host=target,
            tags=["params", "crawler", "recon"],
            raw={"urls": [f"{u}?{n}=x" for u, n in list(params)[:50]]}))
    if scripts:
        session.add_finding(Finding(
            source="recon.crawler",
            title=f"Crawler: {len(scripts)} JS bundles",
            description="Feed to js_miner.",
            severity=SeverityLevel.INFO, host=target,
            tags=["js", "crawler", "recon"],
            raw={"js_bundles": sorted(scripts)}))
    logger.success(f"crawler: {pages} pages, {len(forms)} forms, "
                   f"{len(params)} params")
    return out
