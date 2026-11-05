"""P2 offensive pack — 10 modules.

Every module is scope-guarded. Modules that can produce a safe,
evidence-backed result do so for real; the rest remain explicit runbooks.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from .base import AttackModule, require_in_scope
from .net import base_url, host_of, http
from .p3_pack import _scan_text


def _finding(session: Session, title: str, severity: str, host: str = "",
             evidence: str = "", tags: Optional[List[str]] = None,
             raw: Optional[Dict[str, Any]] = None) -> Finding:
    sev = {"critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH,
           "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW,
           "info": SeverityLevel.INFO}.get(severity, SeverityLevel.INFO)
    f = Finding(source="attacks.p2", title=title[:180], host=host[:200],
                severity=sev, evidence=(evidence or "")[:3000],
                tags=["p2"] + list(tags or []), raw=raw or {})
    session.add_finding(f)
    return f


def _session_urls(session: Session, limit: int = 20) -> List[str]:
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


class CICDExploit(AttackModule):
    id = "cicd_pipeline"
    title = "CI/CD pipeline exploitation"
    tier = 3
    summary = ("GitHub Actions / GitLab runner abuse, exposed .git, "
               "runner takeover, artifact secret scraping.")
    confirm_word = "CONFIRM"

    PATHS = ["/.git/HEAD", "/.git/config", "/.gitlab-ci.yml",
             "/.github/workflows/main.yml", "/.github/workflows/ci.yml",
             "/.circleci/config.yml", "/Jenkinsfile", "/.travis.yml",
             "/azure-pipelines.yml"]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = base_url(session, spec)
        require_in_scope(host_of(target))
        return {"module": self.id, "mode": "plan", "target": target,
                "paths": self.PATHS}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = base_url(session, spec)
        host = host_of(target)
        require_in_scope(host)
        base = target.rstrip("/")
        hits: List[Dict[str, Any]] = []
        for path in self.PATHS:
            r = http(base + path, timeout=8, max_bytes=200_000,
                     allow_redirects=False)
            if not r.get("ok") or r.get("status") != 200:
                continue
            body = r.get("body", "")
            entry: Dict[str, Any] = {"path": path, "bytes": r.get("bytes")}
            if path.endswith("HEAD"):
                entry["git"] = body.strip().startswith("ref:")
            secrets = _scan_text(body, base + path)
            if secrets:
                entry["secrets"] = secrets
            hits.append(entry)
            if entry.get("git") or secrets:
                _finding(session, f"CI/CD exposure at {base + path}",
                         "high" if secrets else "medium", host=host,
                         evidence=json.dumps(entry)[:2000],
                         tags=["cicd", "git", "secrets"], raw=entry)
        logger.info(f"cicd {host}: {len(hits)} exposed path(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "hits": hits}


class CloudIAMPlanner(AttackModule):
    id = "cloud_iam_planner"
    title = "Cloud IAM escalation planner"
    tier = 2
    summary = ("AWS/GCP/Azure role-assumption graph builder -> least-path "
               "escalation chain from discovered identities.")
    confirm_word = "CONFIRM"

    ARN = re.compile(r"arn:(aws|aws-cn|aws-us-gov):[a-zA-Z0-9\-]+:[^:\s]*:"
                     r"\d{12}:[\w\-/+=,.@]+")
    GCP = re.compile(r"[\w.-]+@[\w.-]+\.iam\.gserviceaccount\.com")
    AZURE = re.compile(r"/subscriptions/[0-9a-f-]{36}", re.I)

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan", "target": target,
                "steps": ["collect identities from findings",
                          "build assume/impersonate graph",
                          "emit least-path escalation chain"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        blob = "\n".join(
            " ".join([f.title or "", f.evidence or "", f.description or "",
                      json.dumps(f.raw or {}, default=str)])
            for f in session.get_findings())
        arns = sorted(set(m.group(0) for m in self.ARN.finditer(blob)))
        gcp = sorted(set(self.GCP.findall(blob)))
        azure = sorted(set(self.AZURE.findall(blob)))
        nodes = ([{"type": "aws_role", "id": a} for a in arns] +
                 [{"type": "gcp_sa", "id": g} for g in gcp] +
                 [{"type": "azure_scope", "id": z} for z in azure])
        edges = [{"from": "discovered_principal", "to": n["id"],
                  "action": "assume/impersonate"} for n in nodes]
        if nodes:
            _finding(session, f"{len(nodes)} cloud identity/scope reference(s)",
                     "medium", host=target,
                     evidence="\n".join(n["id"] for n in nodes[:40]),
                     tags=["cloud", "iam", "graph"],
                     raw={"nodes": nodes[:100], "edges": edges[:100]})
        logger.info(f"cloud iam: {len(nodes)} node(s)")
        return {"module": self.id, "mode": "exec", "nodes": nodes,
                "edges": edges,
                "least_path": ("assume the most privileged discovered role "
                               "first; verify with a read-only STS call") if nodes else None}


class CloudStorageAudit(AttackModule):
    id = "cloud_storage_audit"
    title = "Cloud storage exposure audit"
    tier = 2
    summary = ("public buckets, leaked env/build artifacts, policy "
               "conflicts across S3/GCS/Azure.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        from modules.recon.s3_enum import run as s3_run

        out = s3_run(session, target)
        return {"module": self.id, "mode": "plan", "target": target,
                "s3_enum": out}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        from modules.recon.s3_enum import candidates, test_bucket

        hits = []
        for b in candidates(target)[:25]:
            r = test_bucket(b)
            if r.get("open") or r.get("status", 0) in (200, 301):
                hits.append(r)
        return {"module": self.id, "mode": "exec", "target": target,
                "hits": hits}


class GraphQLDeep(AttackModule):
    id = "graphql_deep"
    title = "GraphQL deep attack (introspect + schema dump)"
    tier = 2
    summary = ("Introspection audit and depth-limited schema extraction; "
               "extends modules/validate/graphql.")
    confirm_word = "APPROVE"

    QUERY = {"query": "{ __schema { types { name kind fields { name } } } }"}

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = base_url(session, spec)
        require_in_scope(host_of(target))
        return {"module": self.id, "mode": "plan", "target": target,
                "steps": ["try common GraphQL paths",
                          "POST introspection query",
                          "dump type/field names"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = base_url(session, spec)
        p = urlparse(target)
        host = p.hostname or host_of(target)
        require_in_scope(host)
        paths = [target] + [
            f"{p.scheme or 'https'}://{p.netloc}{s}"
            for s in ("/graphql", "/api/graphql", "/v1/graphql", "/gql")]
        tested, found = [], None
        for url in dict.fromkeys(paths):
            r = http(url, method="POST", timeout=8, max_bytes=300_000,
                     headers={"Content-Type": "application/json"},
                     data=json.dumps(self.QUERY).encode())
            tested.append(url)
            if not r.get("ok"):
                continue
            try:
                body = json.loads(r.get("body") or "{}")
            except Exception:
                continue
            schema = (body.get("data") or {}).get("__schema")
            if schema:
                types = [t.get("name") for t in schema.get("types", [])
                         if isinstance(t, dict)][:100]
                found = {"url": url, "types": types}
                _finding(session, f"GraphQL introspection exposed on {host}",
                         "medium", host=host, evidence=url,
                         tags=["graphql", "introspection"],
                         raw=found)
                break
        logger.info(f"graphql {host}: introspect={bool(found)}")
        return {"module": self.id, "mode": "exec", "tested": tested,
                "introspection": bool(found), **(found or {})}


class DNSAttack(AttackModule):
    id = "dns_attack"
    title = "DNS/zone attack module"
    tier = 3
    summary = ("AXFR zone transfer attempt, wildcard DNS detection and "
               "lame-delegation reporting.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        domain = host_of(spec.get("target") or session.meta.target)
        require_in_scope(domain)
        return {"module": self.id, "mode": "plan", "domain": domain,
                "steps": ["resolve NS set", "AXFR each NS",
                          "wildcard probe with random label"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        domain = host_of(spec.get("target") or session.meta.target)
        if domain.startswith("www."):
            domain = domain[4:]
        require_in_scope(domain)
        try:
            import dns.query
            import dns.resolver
            import dns.zone
        except ImportError:
            return {"module": self.id, "mode": "exec",
                    "status": "tool_missing",
                    "error": "dnspython not installed; pip install dnspython"}

        ns = []
        try:
            ns = [str(r).rstrip(".") for r in
                  dns.resolver.resolve(domain, "NS", lifetime=5)]
        except Exception:
            ns = []
        transfers = []
        for server in ns[:5]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(server, domain,
                                                   timeout=6, lifetime=10))
                names = sorted(str(n) for n in z.nodes.keys())[:100]
                transfers.append({"ns": server, "ok": True, "records": len(names),
                                  "names": names})
                _finding(session, f"DNS zone transfer allowed on {server}",
                         "high", host=server,
                         evidence="\n".join(names[:60]),
                         tags=["dns", "axfr"], raw=transfers[-1])
            except Exception as exc:
                transfers.append({"ns": server, "ok": False,
                                  "error": type(exc).__name__})
        wildcard = False
        try:
            probe = f"ardf-{hashlib.sha256(domain.encode()).hexdigest()[:12]}.{domain}"
            dns.resolver.resolve(probe, "A", lifetime=5)
            wildcard = True
        except Exception:
            wildcard = False
        if wildcard:
            _finding(session, f"Wildcard DNS on {domain}", "low", host=domain,
                     evidence="random label resolved to an address",
                     tags=["dns", "wildcard"])
        logger.info(f"dns attack {domain}: ns={len(ns)} "
                    f"axfr={sum(1 for t in transfers if t.get('ok'))} "
                    f"wildcard={wildcard}")
        return {"module": self.id, "mode": "exec", "domain": domain,
                "nameservers": ns, "transfers": transfers,
                "wildcard": wildcard}


class VPNAppliance(AttackModule):
    id = "vpn_appliance"
    title = "VPN/edge appliance matcher"
    tier = 2
    summary = ("Banner/fingerprint harvest for SonicWall/Citrix/Fortinet/"
               "Pulse/Ivanti edge appliances with a local CVE matrix.")
    confirm_word = "APPROVE"

    PRODUCTS = [
        ("sonicwall", "SonicWall", [("CVE-2024-40766", "SSL VPN access control")]),
        ("citrix", "Citrix", [("CVE-2023-3519", "NetScaler RCE")]),
        ("fortinet", "Fortinet", [("CVE-2023-27997", "FortiGate SSL VPN RCE")]),
        ("pulse", "Pulse Secure", [("CVE-2023-46805", "Ivanti auth bypass")]),
        ("ivanti", "Ivanti", [("CVE-2023-46805", "auth bypass")]),
        ("globalprotect", "Palo Alto", [("CVE-2024-3400", "GlobalProtect RCE")]),
    ]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = host_of(spec.get("target") or session.meta.target)
        require_in_scope(target)
        return {"module": self.id, "mode": "plan", "host": target,
                "steps": ["fetch 443/4443", "match product banner/body",
                          "map to local CVE matrix"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = host_of(spec.get("target") or session.meta.target)
        require_in_scope(target)
        probes = [f"https://{target}", f"https://{target}:4443",
                  f"http://{target}"]
        matches: List[Dict[str, Any]] = []
        for url in probes:
            r = http(url, timeout=8, max_bytes=300_000,
                     allow_redirects=False)
            if not r.get("ok"):
                continue
            hay = " ".join([r.get("headers", {}).get("server", ""),
                            r.get("body", "")[:20_000]]).lower()
            for needle, product, cves in self.PRODUCTS:
                if needle in hay:
                    m = re.search(rf"{needle}[^0-9]{{0,20}}(\d+\.\d+[\.\d]*)",
                                  hay)
                    entry = {"url": url, "product": product,
                             "version": m.group(1) if m else None,
                             "cves": [{"id": c, "note": n} for c, n in cves]}
                    matches.append(entry)
                    _finding(session, f"{product} edge appliance exposed on {target}",
                             "medium", host=target,
                             evidence=json.dumps(entry)[:2000],
                             tags=["vpn", "edge", "cve"], raw=entry)
        logger.info(f"vpn {target}: {len(matches)} product match(es)")
        return {"module": self.id, "mode": "exec", "host": target,
                "matches": matches}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


class SessionTokens(AttackModule):
    id = "session_tokens"
    title = "Session/token policy audit"
    tier = 2
    summary = ("Cookie attributes, session-id entropy and OAuth state/nonce "
               "validation across discovered responses.")
    confirm_word = "APPROVE"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan", "target": target,
                "urls": _session_urls(session, 8)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = base_url(session, spec)
        require_in_scope(host_of(base))
        urls = list(dict.fromkeys([base] + _session_urls(session, 8)))[:8]
        results: List[Dict[str, Any]] = []
        for url in urls:
            r = http(url, timeout=8, max_bytes=300_000)
            if not r.get("ok"):
                continue
            raw_cookies = [v for k, v in r.get("headers", {}).items()
                           if k == "set-cookie"]
            cookies = []
            for blob in raw_cookies:
                for part in re.split(r",(?=[^;]+=)", blob):
                    name = part.split("=", 1)[0].strip()
                    value = part.split("=", 1)[1].split(";", 1)[0].strip() \
                        if "=" in part else ""
                    cookies.append({"name": name, "value": value,
                                    "secure": "secure" in part.lower(),
                                    "httponly": "httponly" in part.lower(),
                                    "samesite": "samesite" in part.lower(),
                                    "entropy": round(_entropy(value), 2)})
            issues = []
            for c in cookies:
                if not c["secure"]:
                    issues.append(f"{c['name']}: missing Secure")
                if not c["httponly"]:
                    issues.append(f"{c['name']}: missing HttpOnly")
                if c["name"].lower() in ("session", "sessionid", "jsessionid",
                                         "phpsessid") and c["entropy"] < 3.5:
                    issues.append(f"{c['name']}: low entropy ({c['entropy']})")
            results.append({"url": url, "cookies": cookies, "issues": issues})
            if issues:
                _finding(session, f"Cookie policy issues on {host_of(url)}",
                         "medium", host=host_of(url),
                         evidence="; ".join(issues), tags=["cookies", "session"],
                         raw=results[-1])
        logger.info(f"session tokens: {len(results)} response(s) audited")
        return {"module": self.id, "mode": "exec", "results": results}


class FirmwareAudit(AttackModule):
    id = "firmware_audit"
    title = "Firmware/OTA imaging audit"
    tier = 3
    summary = ("Firmware URL discovery, bounded download + hash, and "
               "string scan for embedded keys. Lab/read-only mode.")
    confirm_word = "CONFIRM"

    RX = re.compile(r"https?://[^\s\"'<>]+\.(?:bin|img|fw|trx|chk|rom|tar\.gz)",
                    re.I)

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        blob = "\n".join([f.evidence or "" for f in session.get_findings()])
        return {"module": self.id, "mode": "plan", "target": target,
                "candidates": sorted(set(self.RX.findall(blob)))[:20]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        blob = "\n".join([f.evidence or "" for f in session.get_findings()]
                         + [json.dumps(f.raw or {}, default=str)
                            for f in session.get_findings()])
        urls = sorted(set(self.RX.findall(blob)))[:3]
        if not urls:
            return {"module": self.id, "mode": "exec",
                    "status": "no_candidates",
                    "note": "no firmware URLs found in session evidence"}
        results: List[Dict[str, Any]] = []
        for url in urls:
            try:
                import requests

                require_in_scope(host_of(url))
                resp = requests.get(url, timeout=25, verify=False, stream=True)
                raw = resp.raw.read(5_000_000, decode_content=True) or b""
                resp.close()
                text = raw.decode("utf-8", "ignore")
                digest = hashlib.sha256(raw).hexdigest()
                secrets = _scan_text(text, url)
                entry = {"url": url, "bytes": len(raw), "sha256": digest,
                         "secrets": secrets}
                results.append(entry)
                if secrets:
                    _finding(session,
                             f"Embedded secrets in firmware {host_of(url)}",
                             "high", host=host_of(url),
                             evidence=json.dumps(secrets)[:2000],
                             tags=["firmware", "secrets"], raw=entry)
            except PermissionError:
                raise
            except Exception as exc:
                results.append({"url": url, "error": str(exc)[:160]})
        logger.info(f"firmware: {len(results)} image(s) scanned")
        return {"module": self.id, "mode": "exec", "images": results}


class ExposedServices(AttackModule):
    id = "exposed_services"
    title = "Exposed service walker (Docker/Redis/Mongo/WinRM...)"
    tier = 2
    summary = ("banner capture + unauth read-only probe for high-signal "
               "management services outside db_access coverage.")

    SERVICES = {"6379": "redis", "2375": "docker", "2376": "docker-tls",
                "5985": "winrm", "9200": "elasticsearch", "27017": "mongo",
                "11211": "memcached", "4369": "epmd", "8500": "consul"}

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        hosts = sorted({f.host.split("/")[0] for f in session.get_findings()
                        if f.host})[:40]
        return {"module": self.id, "mode": "plan", "target": target,
                "host_count": len(hosts)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        base = target.split("/")[0] if "/" in target else target
        hosts = spec.get("targets") or [base] or [
            f.host.split("/")[0] for f in session.get_findings() if f.host]
        hosts = list(dict.fromkeys(h for h in hosts if h))[:30]
        for h in hosts:
            require_in_scope(h)
        found = []
        for h in hosts:
            for port, svc in self.SERVICES.items():
                sock = socket.socket()
                sock.settimeout(4)
                if sock.connect_ex((h, int(port))) != 0:
                    sock.close()
                    continue
                ev = ""
                try:
                    if svc == "redis":
                        sock.sendall(b"PING\r\n")
                        ev = (sock.recv(64) or b"").decode("utf-8", "ignore")
                    elif svc == "memcached":
                        sock.sendall(b"version\r\n")
                        ev = (sock.recv(64) or b"").decode("utf-8", "ignore")
                    else:
                        ev = f"port open {port}/{svc}"
                except Exception:
                    ev = f"port open {port}/{svc}"
                sock.close()
                found.append({"host": h, "port": port, "svc": svc,
                              "evidence": ev[:80]})
                session.add_finding(Finding(
                    source="attacks",
                    title=f"exposed service {svc} on {h}:{port}",
                    host=h, port=int(port),
                    severity=SeverityLevel.HIGH, evidence=ev[:200],
                    tags=["exposed_service", "p2", "executed"]))
        if found:
            session.save()
        return {"module": self.id, "mode": "exec", "scanned": hosts,
                "findings": found}


class LateralPlanner(AttackModule):
    id = "lateral_planner"
    title = "Lateral movement plan builder"
    tier = 3
    summary = ("Hash/credential inventory and RDP/WinRM/SMB/SSH adjacency "
               "graph from evidence; emits an operator-gated chain spec.")
    confirm_word = "CONFIRM"

    SERVICE_TAGS = {
        "smb": ("445", "smb"), "rdp": ("3389", "rdp"),
        "winrm": ("5985", "winrm"), "ssh": ("22", "ssh"),
        "ldap": ("389", "ldap"), "mssql": ("1433", "mssql"),
    }

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        return {"module": self.id, "mode": "plan", "target": target,
                "steps": ["collect credential evidence",
                          "build service adjacency graph",
                          "emit ops.chains execution spec"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        require_in_scope(target)
        hosts: Dict[str, set] = {}
        creds: List[Dict[str, Any]] = []
        for f in session.get_findings():
            host = str(f.host or "").split("/")[0]
            if host:
                hosts.setdefault(host, set())
            tags = {str(t).lower() for t in (f.tags or [])}
            blob = " ".join([f.title or "", f.evidence or "",
                             json.dumps(f.raw or {}, default=str)]).lower()
            for key, (port, label) in self.SERVICE_TAGS.items():
                if key in tags or port in blob or label in blob:
                    hosts.setdefault(host or target, set()).add(label)
            for marker in ("password", "hash", "ntlm", "ssh key", "token"):
                if marker in blob:
                    creds.append({"host": host or target, "kind": marker,
                                  "evidence": (f.title or "")[:120]})
                    break
        edges = [{"from": target, "to": h, "via": sorted(svcs)}
                 for h, svcs in hosts.items() if h and svcs]
        if edges:
            _finding(session, f"Lateral adjacency: {len(edges)} reachable host(s)",
                     "medium", host=target,
                     evidence=json.dumps(edges[:50], indent=1)[:2000],
                     tags=["lateral", "graph"], raw={"edges": edges[:100]})
        logger.info(f"lateral planner: {len(edges)} edge(s), "
                    f"{len(creds)} credential hint(s)")
        return {"module": self.id, "mode": "exec", "target": target,
                "edges": edges, "credentials": creds[:100],
                "chain_spec": {"target": target, "steps": [
                    {"needs": e["via"], "run": "ops.chains"} for e in edges[:10]]}}


PACK2 = [
    CICDExploit(),
    CloudIAMPlanner(),
    CloudStorageAudit(),
    GraphQLDeep(),
    DNSAttack(),
    VPNAppliance(),
    SessionTokens(),
    FirmwareAudit(),
    ExposedServices(),
    LateralPlanner(),
]

# P2 classes inherit P1 scaffolding where applicable; stamp the phase.
for _module in PACK2:
    _module.phase = "P2"
