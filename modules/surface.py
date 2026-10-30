"""Attack-surface builder — recon findings -> validator-ready candidates.

This is the recon→exploit bridge: it aggregates every testable input
discovered so far (URLs, params, forms, JS routes, login endpoints) into
a typed candidate queue, and can dispatch the matching validators.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl

from modules.logger import get_logger, ARDFLogger
from modules.session import Session

# candidate type -> validator module.Class (Tier-2, detection-only)
DISPATCH = {
    "param": "modules.validate.xss.XSSValidator",
    "sqli_param": "modules.validate.sqli.SQLiValidator",
    "login": "modules.validate.auth.AuthValidator",
    "upload": "modules.validate.lfi.LFIValidator",
    "redirect_param": "modules.validate.open_redirect.OpenRedirectValidator",
    "graphql": "modules.validate.graphql.GraphQLValidator",
    "api": "modules.validate.cors.CORSValidator",
}


def _params_of(url: str) -> List[str]:
    try:
        return [n for n, _ in parse_qsl(urlparse(url).query)]
    except Exception:
        return []


def build_candidates(session: Session) -> List[Dict[str, Any]]:
    """Assemble typed candidates from all session findings."""
    cands: List[Dict[str, Any]] = []
    seen = set()

    def add(ctype: str, url: str, detail: str = ""):
        key = (ctype, url, detail)
        if key not in seen:
            seen.add(key)
            cands.append({"type": ctype, "url": url, "detail": detail,
                          "validator": DISPATCH.get(ctype, "")})

    for f in session.get_findings():
        raw = f.raw or {}
        urls = []
        if isinstance(raw, dict):
            for k in ("url", "live_url", "target_url"):
                if raw.get(k):
                    urls.append(raw[k])
            for u in raw.get("urls", []) or []:  # wayback/crawler batches
                if isinstance(u, str) and u.startswith("http"):
                    urls.append(u)
            for entry in raw.get("live_hosts", []) or []:  # subvalidate
                if isinstance(entry, dict) and entry.get("host"):
                    urls.append("https://" + entry["host"])
            for form in raw.get("forms", []) or []:  # crawler forms
                if not isinstance(form, dict):
                    continue
                action = form.get("action", "")
                for name in form.get("inputs", []) or []:
                    if action.startswith("http"):
                        add("param", action + f"?{name}=x", name)
                        add("sqli_param", action + f"?{name}=x", name)
                joined = (action + " " + " ".join(
                    form.get("inputs", []) or [])).lower()
                if "login" in joined or "password" in joined:
                    add("login", action or session.meta.target,
                        "crawled login form")
        if f.host and f.host.startswith("http"):
            urls.append(f.host)
        for url in urls:
            for p in _params_of(url):
                add("param", url, p)
                add("sqli_param", url, p)
                if p.lower() in ("redirect", "next", "url", "return", "dest"):
                    add("redirect_param", url, p)
                if p.lower() in ("file", "path", "page", "include"):
                    add("upload", url, p)
        tags = {t.lower() for t in f.tags}
        if "login" in tags or "portal" in tags:
            add("login", f.host or session.meta.target, f.title[:60])
        if "graphql" in tags:
            add("graphql", f.host or session.meta.target, "")
        if "api" in tags:
            add("api", f.host or session.meta.target, "")
    return cands


def run_surface_validate(session: Session,
                         logger: Optional[ARDFLogger] = None,
                         limit: int = 20) -> Dict[str, Any]:
    """Dispatch matching validators across the candidate queue."""
    import importlib
    if logger is None:
        logger = get_logger("surface")
    cands = build_candidates(session)
    results: Dict[str, Any] = {"candidates": len(cands), "ran": 0,
                               "by_type": {}, "errors": []}
    for cand in cands[:limit]:
        ref = cand["validator"]
        if not ref:
            continue
        mod_name, cls_name = ref.rsplit(".", 1)
        try:
            cls = getattr(importlib.import_module(mod_name), cls_name)
            inst = cls(session, logger)
            if hasattr(inst, "test_url"):
                inst.test_url(cand["url"])
            elif hasattr(inst, "validate"):
                inst.validate(cand["url"])
            results["ran"] += 1
            t = cand["type"]
            results["by_type"][t] = results["by_type"].get(t, 0) + 1
        except Exception as e:
            results["errors"].append(f"{cand['type']}: {str(e)[:150]}")
    logger.success(f"surface-validate: {results['ran']}/{len(cands)} dispatched")
    return results
