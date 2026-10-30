"""Exploit actions engine — per-finding Validate / Exploit / DB-login.

Safety model (offensive framework, Tier discipline):
  validate  Tier-2, detection-only payloads, runs on operator click
            (the click IS the approval) and is audit-logged.
  exploit   Tier-3: requires confirm_text='CONFIRM' AND a prior
            VERIFIED finding (tags: verified + confirmed) for the same
            host/URL. Uses a SAFE payload subset (no stacked queries,
            no time-bombs, no writes) — proof of injectability only.
  db_login  Tier-3: NSE default-credential probe, 2 credentials max per
            service, stealth-paced. Requires confirm_text='CONFIRM'.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional


def finding_actions(finding) -> List[Dict[str, str]]:
    """Available actions for a finding, derived from its tags/source."""
    tags = {str(t).lower() for t in (finding.tags or [])}
    src = (finding.source or "").lower()
    acts = [{"action": "validate", "tier": 2,
             "label": "Re-validate (detection only)"}]
    if tags & {"sqli", "injection", "xss", "lfi", "ssti"} or \
            "validate" in src or "exploit" in src:
        acts.append({"action": "exploit", "tier": 3,
                     "label": "Proof-of-injectability (needs verified finding + CONFIRM)"})
    if tags & {"db", "exposed-port", "credentials"} or \
            any(p in (finding.title or "").lower()
                for p in ("1433", "5432", "3306", "6379", "27017")):
        acts.append({"action": "db_login", "tier": 3,
                     "label": "DB default-credential probe (2 creds, +CONFIRM)"})
    acts.append({"action": "verify", "tier": 1,
                 "label": "Mark for verify loop"})
    return acts


def _finding_url(finding) -> str:
    raw = finding.raw or {}
    if isinstance(raw, dict):
        for key in ("url", "live_url", "target_url"):
            if raw.get(key):
                return raw[key]
    if finding.host and finding.host.startswith("http"):
        return finding.host
    return ""


def run_validate(session, finding, logger) -> Dict[str, Any]:
    """Dispatch the matching validator's test against the finding's URL."""
    import importlib
    from modules.surface import DISPATCH
    tags = {str(t).lower() for t in (finding.tags or [])}
    url = _finding_url(finding) or finding.host
    if not url:
        return {"error": "finding has no URL/host"}
    order = ["sqli_param" if tags & {"sqli", "injection"} else None,
             "param" if tags & {"xss"} else None,
             "login" if tags & {"auth", "bruteforce"} else None,
             "upload" if tags & {"lfi"} else None,
             "redirect_param" if "open-redirect" in tags else None,
             "graphql" if "graphql" in tags else None,
             "api" if "cors" in tags else None]
    order = [o for o in order if o]
    if not order:
        order = ["param"]
    ref = DISPATCH[order[0]]
    mod_name, cls_name = ref.rsplit(".", 1)
    inst = getattr(importlib.import_module(mod_name), cls_name)(session, logger)
    if hasattr(inst, "test_url"):
        return {"validator": ref, **inst.test_url(url)}
    return {"validator": ref, **inst.validate(url)}


def _infer_vector(finding) -> Optional[str]:
    """Keyword inference of vector from title/evidence (fallback mapper)."""
    import re as _re

    blob = " ".join(str(x) for x in (finding.title, finding.evidence,
                                     finding.description)).lower()
    if _re.search(r"sql[ -]?(injection|inject|i)\b|sqli", blob):
        return "sqli_param"
    if "jwt" in blob or _re.search(r"eyJ[A-Za-z0-9_-]{8,}", blob):
        return "jwt_weak"
    if "cors" in blob:
        return "cors_site"
    if _re.search(r"\blfi\b|file inclusion|path traversal|traversal",
                  blob):
        return "lfi_param"
    if _re.search(r"\bxss\b|cross-site scripting|reflection", blob):
        return "xss_param"
    return None


def run_exploit(session, finding, confirm_text: str,
                logger) -> Dict[str, Any]:
    """Dispatch the precise chain for the finding's vector (Tier-3).

    DB ports -> db_* chain (banner -> blank -> 2 default creds -> stop).
    SQLi URL -> sqli_param chain (detect -> boolean confirm -> dbname).
    XSS/LFI/JWT/CORS -> their chains. Refuses when the vector is absent
    (no params, no token, unparsed port) instead of firing blind.
    """
    import re as _re
    from ops.chains import run_chain
    tags = {str(t).lower() for t in (finding.tags or [])}
    title = finding.title or ""
    host = (finding.host or "").split(":")[0].split("/")[0]
    url = _finding_url(finding) or (finding.host or "")

    def _go(chain_id: str, spec: Dict[str, Any]):
        return run_chain(session, chain_id, spec, confirm_text, logger)

    if tags & {"db", "exposed-port"} or _re.search(r"1433|5432|3306", title):
        m = _re.search(r"(\d{2,5})/tcp", title)
        port = int(m.group(1)) if m else 0
        slow = title.lower()
        if port == 5432 or "postgres" in slow:
            svc = "postgres"
        elif port == 3306 or ("mysql" in slow and "mssql" not in slow):
            svc = "mysql"
        elif port == 1433 or "mssql" in slow or "sql server" in slow:
            svc = "mssql"
        else:
            svc = ""
        chain = {"mssql": "db_mssql", "postgres": "db_postgres",
                 "mysql": "db_mysql"}.get(svc)
        if not chain or not port:
            return {"error": "cannot map finding to a DB chain",
                    "title": title[:120]}
        tgt = host or session.meta.target
        return _go(chain, {"host": tgt.split("/")[0], "port": port,
                           "service": svc, "target": tgt})
    if tags & {"sqli", "injection"}:
        if not url.startswith("http"):
            return {"error": "finding has no testable URL"}
        return _go("sqli_param", {"url": url,
                                  "target": session.meta.target})
    if "xss" in tags:
        if not url.startswith("http"):
            return {"error": "finding has no testable URL"}
        return _go("xss_param", {"url": url,
                                 "target": session.meta.target})
    if "lfi" in tags:
        if not url.startswith("http"):
            return {"error": "finding has no testable URL"}
        return _go("lfi_param", {"url": url,
                                 "target": session.meta.target})
    if "jwt" in tags:
        import re as _re2
        toks = _re2.findall(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                            f"{finding.evidence or ''} {finding.description or ''}")
        if not toks:
            return {"error": "no token in finding to attack"}
        return _go("jwt_weak", {"token": toks[0],
                                "target": session.meta.target})
    if "cors" in tags:
        if not url.startswith("http"):
            return {"error": "finding has no testable URL"}
        return _go("cors_site", {"url": url,
                                 "target": session.meta.target})

    # ── aggregate autoexploit (prove/assist) summary findings ──
    if tags & {"autoexploit", "prove", "assist"}:
        url = _finding_url(finding) or url
        inferred = _infer_vector(finding)
        url_chains = {"sqli_param", "xss_param", "lfi_param", "cors_site"}
        if inferred and not (inferred in url_chains
                             and not url.startswith("http")):
            return _go(inferred, {"url": url,
                                  "target": session.meta.target})
        # no URL / no vector keywords: re-fire the top-ranked live
        # candidate from the autoexploit ranking (this is the plan the
        # summary finding reports on), preferring the inferred vector
        try:
            from ops.autoexploit import rank as _rank

            ranked = _rank(session)
            choice = None
            if inferred:
                choice = next(
                    (c for c in ranked
                     if _CAND_CHAIN.get(c.get("type", "")) == inferred),
                    None)
            if choice is None:
                choice = next(
                    (c for c in ranked
                     if _CAND_CHAIN.get(c.get("type", ""), "")), None)
            if choice is None:
                from modules.surface import build_candidates

                choice = next(
                    (c for c in build_candidates(session)
                     if _CAND_CHAIN.get(c.get("type", ""), "")), None)
            if choice:
                chain = _CAND_CHAIN.get(choice.get("type", ""), "")
                logger.info(f"autoexploit summary -> refire {chain} on "
                            f"{choice.get('url', '')}")
                return _go(chain, {"url": choice.get("url", ""),
                                   "target": session.meta.target})
        except Exception as e:
            return {"error": f"cannot refire autoexploit chain: {e}"}
        return {"error": "no runnable candidates in this autoexploit "
                         "summary; exploit the individual Findings rows "
                         "(each vector finding has its own Exploit)",
                "tags": sorted(tags), "inferred": inferred}

    return {"error": "no exploit chain for these tags",
            "tags": sorted(tags)}


_CAND_CHAIN = {"sqli_param": "sqli_param", "upload": "lfi_param",
               "param": "xss_param"}


def run_db_login(session, host: str, port: int, service: str,
                 logger) -> Dict[str, Any]:
    """NSE default-credential probe: 2 credentials, stealth-paced."""
    from modules.db_access import probe as _probe
    return _probe(session, host, port, service, logger)
