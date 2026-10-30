"""P3 pack — posture, validation and planning modules.

Design rules
------------
* Every module is scope-guarded through ``require_in_scope``.
* Read-only checks are Tier-1; active probes are Tier-2; anything that
  changes state or needs operator judgement is a Tier-3 runbook.
* No module writes to a target. Findings contain redacted evidence only.
* Network helpers are deliberately small and bounded (timeouts, byte caps,
  request caps) so a bad target cannot stall the console.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from .base import AttackModule, require_in_scope
from .p1_pack import _RunbookModule

_SEV = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
       "ARDF/3.1 authorized-assessment")


def _base_url(session: Session, spec: Dict[str, Any]) -> str:
    raw = str(spec.get("target") or getattr(session.meta, "target", "") or "").strip()
    if not raw:
        raise ValueError("target is required")
    if "://" not in raw:
        scheme = str(spec.get("scheme") or "https").lower()
        raw = f"{scheme}://{raw}"
    return raw


def _host_of(raw: str) -> str:
    """Extract a bare hostname from a URL, ``host:port`` or bare host."""
    value = str(raw or "").strip()
    try:
        parsed = urlparse(value if "://" in value else "//" + value)
        if parsed.hostname:
            return parsed.hostname.lower()
    except Exception:
        pass
    # Bare IPv6 literal (no brackets), optionally scoped with %eth0.
    if value.count(":") > 1 and not value.startswith("["):
        return value.split("%", 1)[0].lower()
    # Fallback for malformed input: strip userinfo, path and port.
    return value.rsplit("@", 1)[-1].split("/")[0].split(":")[0].lower()


def _scope_allowed(raw: str) -> bool:
    """Non-raising scope check used to filter candidate URLs."""
    try:
        require_in_scope(_host_of(raw))
        return True
    except Exception:
        return False


def _http(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
          data: Optional[bytes] = None, timeout: int = 10,
          max_bytes: int = 1_000_000, allow_redirects: bool = True
          ) -> Dict[str, Any]:
    """Bounded HTTP helper. Network errors return a dict; scope violations
    deliberately raise so the caller reports a hard policy failure.

    Redirects are followed manually so every hop is re-checked against the
    engagement scope. This closes the obvious SSRF/scope pivot where an
    in-scope URL redirects to a third-party host.
    """
    import requests  # local import keeps module import cheap

    hdr = {"User-Agent": _UA, "Accept": "*/*"}
    hdr.update(headers or {})
    current = url
    current_data = data
    session = None
    r = None
    try:
        require_in_scope(_host_of(current))
        session = requests.Session()
        for _hop in range(5):
            r = session.request(method, current, headers=hdr, data=current_data,
                                timeout=timeout, allow_redirects=False,
                                verify=False, stream=True)
            if not allow_redirects or not r.is_redirect:
                break
            location = r.headers.get("location", "")
            if not location:
                break
            nxt = urljoin(current, location)
            if not nxt.startswith(("http://", "https://")):
                break
            require_in_scope(_host_of(nxt))
            # Match requests' redirect semantics closely enough for an
            # assessment probe: 303 always GETs, 301/302 convert non-GET.
            if r.status_code == 303 or (
                    r.status_code in (301, 302) and
                    str(method).upper() not in ("GET", "HEAD")):
                method, current_data = "GET", None
            r.close()
            current = nxt
        else:
            if r is not None:
                r.close()
            return {"ok": False, "error": "too many redirects",
                    "url": current}
        if r is None:
            return {"ok": False, "error": "no response", "url": current}
        encoding = r.encoding
        try:
            body = r.raw.read(max_bytes, decode_content=True) or b""
        except Exception:
            body = b""
        text = body.decode(encoding or "utf-8", "ignore")
        out = {"ok": True, "url": url, "final_url": current,
               "status": r.status_code,
               "headers": {str(k).lower(): str(v)
                           for k, v in r.headers.items()},
               "body": text, "bytes": len(body)}
        r.close()
        return out
    except PermissionError:
        # A scope violation is a hard policy stop, not a probe failure.
        raise
    except Exception as e:
        return {"ok": False, "error": str(e)[:240], "url": current}
    finally:
        if r is not None:
            try:
                r.close()
            except Exception:
                pass
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


def _finding(session: Session, title: str, severity: str, host: str = "",
             evidence: str = "", tags: Optional[List[str]] = None,
             description: str = "", remediation: str = "",
             raw: Optional[Dict[str, Any]] = None) -> Finding:
    f = Finding(source="attacks.p3", title=title[:180],
                description=description[:800], severity=_SEV.get(severity, SeverityLevel.INFO),
                host=host[:200], evidence=(evidence or "")[:3000],
                tags=["p3"] + list(tags or []), remediation=remediation[:800],
                raw=raw or {})
    session.add_finding(f)
    return f


def _plan(session: Session, spec: Dict[str, Any]) -> str:
    target = str(spec.get("target") or getattr(session.meta, "target", "") or "")
    require_in_scope(target)
    return target


# ── DNS helpers ──────────────────────────────────────────────

def _dns(name: str, rtype: str) -> List[str]:
    try:
        import dns.resolver

        ans = dns.resolver.resolve(name, rtype, lifetime=5)
        out = []
        for r in ans:
            if rtype == "TXT" and hasattr(r, "strings"):
                out.append(b"".join(r.strings).decode("utf-8", "ignore"))
            elif rtype == "MX" and hasattr(r, "exchange"):
                out.append(str(r.exchange).rstrip("."))
            elif rtype == "CAA" and hasattr(r, "value"):
                out.append(str(r.value))
            else:
                out.append(str(r).rstrip("."))
        return out
    except Exception:
        return []


def _txt(name: str) -> List[str]:
    return _dns(name, "TXT")


def _dns_ok(domain: str) -> Tuple[bool, str]:
    """Distinguish 'resolver reachable' from 'no egress'.

    Empty answers are valid (a domain may have no MX/CAA), but a timeout
    or a missing resolver must not be reported as a missing security
    record — that would be a false positive.
    """
    try:
        import dns.resolver

        try:
            dns.resolver.resolve(domain, "NS", lifetime=4)
            return True, ""
        except Exception as e:
            if type(e).__name__ == "NoAnswer":
                return True, ""
            if type(e).__name__ == "NXDOMAIN":
                return False, f"domain does not exist: {domain}"
            return False, f"{type(e).__name__}: {e}"
    except ImportError:
        return False, "dnspython is not installed (pip install dnspython)"


# ── TLS ──────────────────────────────────────────────────────

def _cert_name(cert: Dict[str, Any], field: str) -> str:
    parts = []
    for rdn in cert.get(field, ()) or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _decode_der(der: bytes) -> Dict[str, Any]:
    path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as fh:
            fh.write(der)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except Exception:
                pass


def _tls_probe(host: str, port: int, timeout: int = 8) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    verified = True
    cert: Dict[str, Any] = {}
    der = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
                version = ss.version()
                cipher = ss.cipher()
    except ssl.SSLCertVerificationError:
        verified = False
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True) or b""
                version = ss.version()
                cipher = ss.cipher()
        cert = _decode_der(der)
    return {"version": version, "cipher": cipher, "cert": cert,
            "verified": verified}


class TlsPosture(AttackModule):
    id = "tls_posture"
    title = "TLS / certificate posture audit"
    phase = "P3"
    tier = 1
    summary = ("Certificate expiry, issuer, self-signed detection, protocol "
               "version and cipher suite for the target endpoint.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        p = urlparse(_base_url(session, spec))
        return {"module": self.id, "mode": "plan", "target": target,
                "host": p.hostname, "port": spec.get("port") or p.port or 443}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        p = urlparse(_base_url(session, spec))
        host = p.hostname or _host_of(target)
        port = int(spec.get("port") or p.port or 443)
        require_in_scope(host)
        info = _tls_probe(host, port)
        cert = info.get("cert") or {}
        subject = _cert_name(cert, "subject")
        issuer = _cert_name(cert, "issuer")
        days = None
        not_after = cert.get("notAfter")
        if not_after:
            try:
                days = int((ssl.cert_time_to_seconds(not_after) - datetime.now(
                    timezone.utc).timestamp()) / 86400)
            except Exception:
                days = None
        version = info.get("version") or "unknown"
        self_signed = bool(subject and subject == issuer)
        issues = []
        if not info.get("verified"):
            issues.append("certificate chain not trusted")
        if self_signed:
            issues.append("self-signed certificate")
        if days is not None and days < 0:
            issues.append("certificate expired")
        elif days is not None and days < 30:
            issues.append(f"certificate expires in {days} day(s)")
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            issues.append(f"legacy protocol {version}")
        sev = "high" if any(("expired" in x or "legacy" in x)
                            for x in issues) else (
            "medium" if issues else "info")
        _finding(session, f"TLS posture {host}:{port}", sev, host=host,
                 evidence="; ".join(issues) or "certificate and protocol look healthy",
                 tags=["tls", "posture", "read-only"],
                 description=f"subject={subject}; issuer={issuer}; "
                             f"notAfter={not_after}; protocol={version}",
                 remediation="Renew certificates, disable TLS < 1.2, prefer "
                             "modern AEAD cipher suites and enable HSTS.",
                 raw={"subject": subject, "issuer": issuer, "days": days,
                      "version": version, "cipher": info.get("cipher"),
                      "verified": info.get("verified")})
        logger.info(f"tls posture {host}:{port}: {issues or 'ok'}")
        return {"module": self.id, "mode": "exec", "host": host, "port": port,
                "subject": subject, "issuer": issuer, "days_left": days,
                "version": version, "cipher": info.get("cipher"),
                "verified": info.get("verified"), "issues": issues}


# ── Email / DNS posture ─────────────────────────────────────

class EmailSecurityPosture(AttackModule):
    id = "email_security_posture"
    title = "SPF / DMARC / DKIM posture"
    phase = "P3"
    tier = 1
    summary = ("DNS-only email authentication audit: SPF all-mechanism, "
               "DMARC policy, common DKIM selectors.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        domain = _host_of(target)
        if domain.startswith("www."):
            domain = domain[4:]
        require_in_scope(domain)
        ok, err = _dns_ok(domain)
        if not ok:
            return {"module": self.id, "mode": "exec",
                    "error": f"DNS resolver unavailable: {err}"}
        txt = _txt(domain)
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        dmarc = _txt(f"_dmarc.{domain}")
        dmarc_rec = next((t for t in dmarc if "v=dmarc1" in t.lower()), "")
        selectors = ("default", "google", "selector1", "selector2", "s1",
                     "s2", "k1", "mail", "dkim")
        dkim = []
        for sel in selectors:
            if _txt(f"{sel}._domainkey.{domain}"):
                dkim.append(sel)
        issues = []
        if not spf:
            issues.append("no SPF record")
        elif len(spf) > 1:
            issues.append("multiple SPF records")
        else:
            low = spf[0].lower()
            if "+all" in low:
                issues.append("SPF permits all senders")
            elif "?all" in low:
                issues.append("SPF is neutral (?all)")
            elif "~all" in low:
                issues.append("SPF soft-fails (~all)")
        if not dmarc_rec:
            issues.append("no DMARC record")
        elif "p=none" in dmarc_rec.lower():
            issues.append("DMARC policy is p=none")
        elif "p=quarantine" in dmarc_rec.lower():
            issues.append("DMARC policy is quarantine")
        if not dkim:
            issues.append("no common DKIM selector found")
        sev = ("high" if any("no SPF" in x or "permits all" in x for x in issues)
               else "medium" if issues else "info")
        _finding(session, f"Email authentication posture {domain}", sev,
                 host=domain, evidence="; ".join(issues) or "SPF/DMARC/DKIM present",
                 tags=["email", "dns", "posture", "read-only"],
                 description=f"SPF={spf or 'none'}; DMARC={dmarc_rec or 'none'}; "
                             f"DKIM selectors={dkim or 'none'}",
                 remediation="Publish a single SPF record with -all (after "
                             "inventory), DMARC p=reject with rua reporting, "
                             "and rotate/select DKIM keys.",
                 raw={"spf": spf, "dmarc": dmarc_rec, "dkim": dkim})
        logger.info(f"email posture {domain}: {issues or 'ok'}")
        return {"module": self.id, "mode": "exec", "domain": domain,
                "spf": spf, "dmarc": dmarc_rec, "dkim": dkim,
                "issues": issues}


class DnsHygiene(AttackModule):
    id = "dns_hygiene"
    title = "DNS hygiene and DNSSEC audit"
    phase = "P3"
    tier = 1
    summary = ("NS redundancy, MX, CAA, DNSSEC DS and duplicate SPF checks "
               "using resolver queries only.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        domain = _host_of(target)
        if domain.startswith("www."):
            domain = domain[4:]
        require_in_scope(domain)
        ok, err = _dns_ok(domain)
        if not ok:
            return {"module": self.id, "mode": "exec",
                    "error": f"DNS resolver unavailable: {err}"}
        ns = _dns(domain, "NS")
        mx = _dns(domain, "MX")
        caa = _dns(domain, "CAA")
        ds = _dns(domain, "DS")
        txt = _txt(domain)
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        issues = []
        if len(ns) < 2:
            issues.append(f"only {len(ns)} NS record(s)")
        if not mx:
            issues.append("no MX record")
        if not caa:
            issues.append("no CAA record")
        if not ds:
            issues.append("DNSSEC not delegated (no DS)")
        if len(spf) > 1:
            issues.append("multiple SPF records")
        sev = "medium" if any("multiple SPF" in x or "only 0 NS" in x for x in issues) else (
            "low" if issues else "info")
        _finding(session, f"DNS hygiene {domain}", sev, host=domain,
                 evidence="; ".join(issues) or "DNS records look healthy",
                 tags=["dns", "hygiene", "read-only"],
                 description=f"NS={ns}; MX={mx}; CAA={caa}; DS={ds}",
                 remediation="Add a second nameserver, publish CAA, enable "
                             "DNSSEC, and keep exactly one SPF record.",
                 raw={"ns": ns, "mx": mx, "caa": caa, "ds": ds})
        logger.info(f"dns hygiene {domain}: {issues or 'ok'}")
        return {"module": self.id, "mode": "exec", "domain": domain,
                "ns": ns, "mx": mx, "caa": caa, "dnssec": bool(ds),
                "issues": issues}


# ── HTTP posture ─────────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing (downgrade risk)",
    "content-security-policy": "CSP missing (XSS blast radius)",
    "x-content-type-options": "X-Content-Type-Options missing",
    "x-frame-options": "X-Frame-Options missing (clickjacking)",
    "referrer-policy": "Referrer-Policy missing",
    "permissions-policy": "Permissions-Policy missing",
}


class HttpHeaderAudit(AttackModule):
    id = "http_header_audit"
    title = "Security header and cookie audit"
    phase = "P3"
    tier = 1
    summary = ("Single-request header/cookie review: HSTS, CSP, frame and "
               "MIME protections, disclosure headers, cookie flags.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        url = _base_url(session, spec)
        host = _host_of(url)
        require_in_scope(host)
        res = _http(url)
        if not res.get("ok"):
            return {"module": self.id, "mode": "exec", "error": res.get("error")}
        headers = res["headers"]
        missing = [k for k in _SECURITY_HEADERS if k not in headers]
        issues = [_SECURITY_HEADERS[k] for k in missing]
        hsts = headers.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if hsts and m and int(m.group(1)) < 31536000:
            issues.append(f"HSTS max-age too short ({m.group(1)})")
        csp = headers.get("content-security-policy", "")
        if "'unsafe-inline'" in csp.lower():
            issues.append("CSP allows 'unsafe-inline'")
        disclosed = [h for h in ("server", "x-powered-by", "x-aspnet-version")
                     if h in headers]
        if disclosed:
            issues.append("technology disclosure: " + ", ".join(disclosed))
        cookies = []
        for raw in (headers.get("set-cookie") or "").split("\n"):
            if raw.strip():
                cookies.append(raw.strip())
        try:
            from modules.cookie_analyzer import analyze_cookies

            cookie_issues = analyze_cookies(cookies)
            for c in cookie_issues:
                issues.append(f"cookie {c.get('cookie')}: {c.get('issue')}")
        except Exception:
            cookie_issues = []
        sev = "medium" if len(missing) >= 4 else ("low" if issues else "info")
        _finding(session, f"HTTP security posture {host}", sev, host=host,
                 evidence="; ".join(issues) or "security headers present",
                 tags=["http", "headers", "cookies", "read-only"],
                 description=f"status={res.get('status')}; missing={missing}; "
                             f"server={headers.get('server', '')}; "
                             f"powered_by={headers.get('x-powered-by', '')}",
                 remediation="Add the missing headers at the edge, use a "
                             "nonce-based CSP, and set Secure/HttpOnly/SameSite "
                             "on all session cookies.",
                 raw={"status": res.get("status"), "missing": missing,
                      "headers": {k: headers.get(k, "") for k in
                                  list(_SECURITY_HEADERS) + ["server",
                                                             "x-powered-by"]},
                      "cookies": cookie_issues})
        logger.info(f"http posture {host}: {len(issues)} issue(s)")
        return {"module": self.id, "mode": "exec", "url": res.get("url"),
                "status": res.get("status"), "missing": missing,
                "issues": issues, "cookies": cookie_issues}


# ── tokens / CORS ────────────────────────────────────────────

def _b64d(part: str) -> str:
    part += "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part.encode()).decode("utf-8", "ignore")


def _decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        head, payload, _sig = token.split(".")
        return {"header": json.loads(_b64d(head)),
                "payload": json.loads(_b64d(payload))}
    except Exception:
        return None


def _find_token(session: Session, spec: Dict[str, Any]) -> str:
    token = str(spec.get("token") or "").strip()
    if token:
        return token
    rx = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
    for f in session.get_findings():
        blob = " ".join(str(x) for x in (f.evidence, f.description,
                                         json.dumps(f.raw or {})))
        m = rx.search(blob)
        if m:
            return m.group(0)
    return ""


class JwtAudit(AttackModule):
    id = "jwt_audit"
    title = "JWT structure and claim audit"
    phase = "P3"
    tier = 2
    summary = ("Offline JWT review: alg=none, weak claim lifetime, missing "
               "exp/aud/iss, and untrusted jku/x5u headers.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "token_present": bool(_find_token(session, spec))}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        token = _find_token(session, spec)
        if not token:
            return {"module": self.id, "mode": "exec",
                    "error": "no JWT supplied (spec.token) or found in findings"}
        decoded = _decode_jwt(token)
        if not decoded:
            return {"module": self.id, "mode": "exec",
                    "error": "token is not a decodable JWT"}
        header, payload = decoded["header"], decoded["payload"]
        alg = str(header.get("alg", "")).lower()
        issues = []
        if alg in ("none", ""):
            issues.append("alg=none accepted candidate")
        if header.get("jku") or header.get("x5u"):
            issues.append("untrusted jku/x5u header present")
        now = int(datetime.now(timezone.utc).timestamp())
        exp = payload.get("exp")
        iat = payload.get("iat")
        if not isinstance(exp, (int, float)):
            issues.append("missing exp claim")
        else:
            if exp < now:
                issues.append("token already expired")
            elif exp - now > 60 * 60 * 24 * 30:
                issues.append("token lifetime exceeds 30 days")
        if not payload.get("aud"):
            issues.append("missing aud claim")
        if not payload.get("iss"):
            issues.append("missing iss claim")
        if alg.startswith("hs"):
            issues.append("symmetric HS* algorithm (secret reuse risk)")
        sev = "high" if any("alg=none" in x or "jku" in x for x in issues) else (
            "medium" if issues else "info")
        _finding(session, "JWT claim/structure audit", sev, host=_host_of(target),
                 evidence="; ".join(issues) or "JWT claims look healthy",
                 tags=["jwt", "token", "read-only"],
                 description=f"alg={alg}; header={header}; claims="
                             f"{ {k: payload.get(k) for k in ('iss','aud','exp','iat','sub')} }",
                 remediation="Pin the allowed algorithm, reject alg=none, "
                             "validate iss/aud/exp server-side, keep access "
                             "tokens short-lived and rotate signing keys.",
                 raw={"header": header,
                      "claims": {k: payload.get(k) for k in
                                 ("iss", "aud", "exp", "iat", "sub", "scope")}})
        logger.info(f"jwt audit: {issues or 'ok'}")
        return {"module": self.id, "mode": "exec", "alg": alg,
                "issues": issues, "header": header,
                "claims": {k: payload.get(k) for k in
                           ("iss", "aud", "exp", "iat", "sub", "scope")}}


class CorsOriginAudit(AttackModule):
    id = "cors_origin_audit"
    title = "CORS origin reflection audit"
    phase = "P3"
    tier = 2
    summary = ("Sends one canary Origin header and inspects ACAO/ACAC. "
               "Flags arbitrary-origin reflection and credentialed trust.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        url = _base_url(session, spec)
        host = _host_of(url)
        require_in_scope(host)
        origin = str(spec.get("origin") or "https://ardf-canary.invalid")
        res = _http(url, headers={"Origin": origin}, allow_redirects=False)
        if not res.get("ok"):
            return {"module": self.id, "mode": "exec", "error": res.get("error")}
        h = res["headers"]
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"
        reflected = bool(acao) and (acao == origin or acao == "*")
        issues = []
        if reflected and acac:
            issues.append(f"credentialed CORS trust for {acao}")
        elif reflected:
            issues.append(f"ACAO reflects {acao}")
        if acao == "null":
            issues.append("ACAO accepts null origin")
        sev = "high" if (reflected and acac) else (
            "medium" if issues else "info")
        _finding(session, f"CORS policy {host}", sev, host=host,
                 evidence="; ".join(issues) or "no permissive ACAO observed",
                 tags=["cors", "browser", "read-only"],
                 description=f"origin={origin}; ACAO={acao or 'absent'}; "
                             f"ACAC={acac}",
                 remediation="Use an explicit allowlist of trusted origins. "
                             "Never combine ACAO reflection with credentials.",
                 raw={"origin": origin, "acao": acao, "acac": acac,
                      "status": res.get("status")})
        logger.info(f"cors audit {host}: {issues or 'ok'}")
        return {"module": self.id, "mode": "exec", "origin": origin,
                "acao": acao, "acac": acac, "issues": issues}


# ── discovery / secrets / services ──────────────────────────

_ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin/", "/cpanel",
    "/webmail", "/login", "/signin", "/auth/login", "/api/admin",
    "/console", "/manager/html", "/.git/config", "/server-status",
]


class AdminPanelDiscovery(AttackModule):
    id = "admin_panel_discovery"
    title = "Admin / management panel discovery"
    phase = "P3"
    tier = 2
    summary = ("Bounded path probe for exposed admin consoles and .git "
               "config leaks (default 14 paths, 6s timeout each).")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec), "paths": _ADMIN_PATHS}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        p = urlparse(_base_url(session, spec))
        host = p.hostname or _host_of(target)
        require_in_scope(host)
        base = f"{p.scheme or 'https'}://{p.netloc or host}"
        limit = max(0, min(int(spec.get("max_paths", len(_ADMIN_PATHS))),
                           len(_ADMIN_PATHS)))
        hits = []
        for path in _ADMIN_PATHS[:limit]:
            res = _http(base + path, timeout=6, max_bytes=2048,
                        allow_redirects=False)
            if not res.get("ok"):
                continue
            status = res.get("status")
            loc = res.get("headers", {}).get("location", "")
            interesting = status in (200, 401, 403) or (
                status in (301, 302) and any(x in loc.lower() for x in
                                             ("login", "admin", "auth")))
            if interesting:
                hits.append({"path": path, "status": status, "location": loc})
        if hits:
            _finding(session, f"Management surface exposed on {host}",
                     "medium", host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["admin", "discovery", "exposed"],
                     description="One or more administrative/VCS paths answered "
                                 "on the public edge. Validate the 200s and "
                                 "confirm auth, MFA and source restrictions.",
                     remediation="Restrict admin paths by source IP / SSO, "
                                 "require MFA, and remove exposed VCS files.",
                     raw={"hits": hits})
        logger.info(f"admin discovery {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "base": base,
                "hits": hits, "tested": limit}


_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_live", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(
        r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]")),
]


def _scan_text(text: str, source: str = "") -> List[Dict[str, str]]:
    hits = []
    seen = set()
    for name, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            raw = m.group(0)
            if name == "generic_api_key" and m.groups():
                raw = m.group(1)
            # A generic rule often repeats a token already found by a
            # provider-specific rule; keep the higher-signal hit only.
            if raw in seen:
                continue
            seen.add(raw)
            if len(raw) > 12:
                redacted = raw[:6] + "…" + raw[-4:]
            else:
                redacted = "…"
            hits.append({"type": name, "value": redacted,
                         "source": source[:200]})
            if len(hits) >= 25:
                return hits
    return hits


def _urls_from_findings(session: Session) -> List[str]:
    urls = []
    for f in session.get_findings():
        raw = f.raw if isinstance(f.raw, dict) else {}
        for key in ("url", "live_url", "target_url", "urls", "js_urls"):
            val = raw.get(key)
            if isinstance(val, str) and val.startswith("http"):
                urls.append(val)
            elif isinstance(val, (list, tuple)):
                urls += [x for x in val if isinstance(x, str) and
                         x.startswith("http")]
        if isinstance(f.host, str) and f.host.startswith("http"):
            urls.append(f.host)
    # Findings can contain third-party URLs (CDNs, SaaS). Never turn those
    # into probes just because they appeared in the session graph.
    return [u for u in dict.fromkeys(urls) if _scope_allowed(u)][:20]


class SecretLeakScan(AttackModule):
    id = "secret_leak_scan"
    title = "Client-side secret leak scan"
    phase = "P3"
    tier = 1
    summary = ("Fetches up to 12 discovered pages/JS assets and looks for "
               "cloud keys, tokens and private keys. Evidence is redacted.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        urls = _urls_from_findings(session) or [_base_url(session, spec)]
        return {"module": self.id, "mode": "plan", "target": target,
                "candidate_urls": urls[:12]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        base = _base_url(session, spec)
        require_in_scope(_host_of(base))
        candidates = list(spec.get("urls") or _urls_from_findings(session))
        if base not in candidates:
            candidates.insert(0, base)
        candidates = list(dict.fromkeys(candidates))
        hits, scanned, skipped = [], [], []
        for url in candidates:
            if len(scanned) >= 12:
                break
            if not str(url).startswith("http"):
                continue
            if not _scope_allowed(url):
                skipped.append(url)
                continue
            res = _http(url, max_bytes=750_000, timeout=10)
            if not res.get("ok"):
                continue
            scanned.append(url)
            body = res.get("body", "")
            hits += _scan_text(body, url)
            if "text/html" in res.get("headers", {}).get("content-type", ""):
                p = urlparse(url)
                for src in re.findall(
                        r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.I):
                    if src.startswith("http"):
                        candidates.append(src)
                    elif src.startswith("/"):
                        candidates.append(f"{p.scheme}://{p.netloc}{src}")
                candidates = list(dict.fromkeys(candidates))
            if len(hits) >= 25:
                break
        if hits:
            _finding(session, f"Client-side secret exposure on {_host_of(base)}",
                     "high", host=_host_of(base),
                     evidence=json.dumps(hits, indent=1)[:3000],
                     tags=["secrets", "javascript", "exposure"],
                     description="Public client assets contain credential-like "
                                 "strings. Values are redacted in evidence.",
                     remediation="Move secrets server-side, rotate exposed "
                                 "keys, and add secret scanning to CI.",
                     raw={"hits": hits, "scanned": scanned})
        logger.info(f"secret scan {base}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "scanned": scanned,
                "hits": hits, "skipped_out_of_scope": skipped}


def _port_open(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


class SmbSigningAudit(AttackModule):
    id = "smb_signing_audit"
    title = "SMB signing / dialect audit"
    phase = "P3"
    tier = 2
    summary = ("Checks tcp/445 and, when nmap is present, runs the "
               "smb2-security-mode NSE script. Flags signing-not-required.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec), "port": 445}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        host = _host_of(target)
        port = int(spec.get("port", 445))
        require_in_scope(host)
        if not _port_open(host, port):
            return {"module": self.id, "mode": "exec", "host": host,
                    "port": port, "open": False}
        out = ""
        if os.name != "nt":
            import shutil

            if shutil.which("nmap"):
                try:
                    proc = subprocess.run(
                        ["nmap", "-p", str(port), "--script",
                         "smb2-security-mode", "-T2", "--open", host],
                        capture_output=True, text=True, timeout=60)
                    out = proc.stdout[-3000:]
                except Exception as e:
                    out = f"nmap error: {e}"
        low = out.lower()
        if "signing enabled but not required" in low or \
                "signing is not required" in low or \
                "message signing enabled but not required" in low:
            sev, msg = "high", "SMB signing is not required"
        elif "signing is required" in low:
            sev, msg = "info", "SMB signing is required"
        else:
            sev, msg = "medium", "tcp/445 open; signing state unconfirmed"
        _finding(session, f"SMB posture {host}:{port}", sev, host=host,
                 evidence=(msg + "\n" + out)[:3000],
                 tags=["smb", "signing", "lateral"],
                 description="SMB signing state determines whether relay "
                             "attacks can succeed against this host.",
                 remediation="Require SMB signing (and SMB encryption where "
                             "supported) via GPO / smb.conf.",
                 raw={"host": host, "port": port, "nmap": out[:1500]})
        logger.info(f"smb audit {host}: {msg}")
        return {"module": self.id, "mode": "exec", "host": host, "port": port,
                "open": True, "verdict": msg, "nmap": out[-1500:]}


class SshPostureAudit(AttackModule):
    id = "ssh_posture_audit"
    title = "SSH banner and version posture"
    phase = "P3"
    tier = 1
    summary = ("Reads the SSH banner and flags old OpenSSH families. "
               "No authentication or credential attempts.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec), "port": 22}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        host = _host_of(target)
        port = int(spec.get("port", 22))
        require_in_scope(host)
        banner = ""
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                banner = sock.recv(256).decode("utf-8", "ignore").strip()
        except Exception as e:
            return {"module": self.id, "mode": "exec", "host": host,
                    "port": port, "open": False, "error": str(e)[:160]}
        m = re.search(r"OpenSSH[_-]([\d.]+)", banner, re.I)
        old = False
        if m:
            try:
                old = tuple(int(x) for x in m.group(1).split(".")[:2]) < (7, 4)
            except Exception:
                old = False
        sev = "medium" if old else "info"
        _finding(session, f"SSH posture {host}:{port}", sev, host=host,
                 evidence=banner,
                 tags=["ssh", "banner", "read-only"],
                 description="Banner-only assessment; no authentication "
                             "attempts were made.",
                 remediation="Disable password auth, require modern KEX/ciphers, "
                             "and keep OpenSSH patched.",
                 raw={"banner": banner, "old_family": old})
        logger.info(f"ssh posture {host}: {banner[:80]}")
        return {"module": self.id, "mode": "exec", "host": host, "port": port,
                "open": True, "banner": banner, "old_family": old}


_GRAPHQL_QUERY = {"query": "{ __schema { types { name } } }"}


class GraphqlIntrospectionAudit(AttackModule):
    id = "graphql_introspection_audit"
    title = "GraphQL introspection exposure"
    phase = "P3"
    tier = 2
    summary = ("POSTs a depth-limited introspection query to common GraphQL "
               "paths and reports whether the schema is public.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = _plan(session, spec)
        base = _base_url(session, spec).rstrip("/")
        p = urlparse(base)
        host = p.hostname or _host_of(target)
        require_in_scope(host)
        paths = [spec.get("url")] if spec.get("url") else []
        for suffix in ("/graphql", "/api/graphql", "/v1/graphql", "/gql"):
            paths.append(f"{p.scheme or 'https'}://{p.netloc}{suffix}")
        paths = [x for x in paths if x and _scope_allowed(x)]
        for url in paths:
            res = _http(url, method="POST",
                        headers={"Content-Type": "application/json"},
                        data=json.dumps(_GRAPHQL_QUERY).encode(),
                        timeout=8, max_bytes=200_000)
            if not res.get("ok"):
                continue
            try:
                body = json.loads(res.get("body") or "{}")
            except Exception:
                continue
            schema = (body.get("data") or {}).get("__schema")
            if schema:
                types = [t.get("name") for t in schema.get("types", [])
                         if isinstance(t, dict)][:60]
                _finding(session, f"GraphQL introspection exposed on {host}",
                         "medium", host=host, evidence=url,
                         tags=["graphql", "introspection", "exposure"],
                         description=f"{len(types)} schema types returned",
                         remediation="Disable introspection in production or "
                                     "restrict it to trusted roles.",
                         raw={"url": url, "types": types})
                return {"module": self.id, "mode": "exec", "url": url,
                        "introspection": True, "types": len(types)}
        return {"module": self.id, "mode": "exec", "introspection": False,
                "tested": [x for x in paths if x]}


# ── Tier-3 runbooks ─────────────────────────────────────────

class RequestSmugglingPlan(_RunbookModule):
    id = "request_smuggling_plan"
    title = "HTTP request smuggling assessment plan"
    phase = "P3"
    tier = 3
    summary = ("CL.TE / TE.CL / TE.TE differential plan for front-end/back-end "
               "pairs, with strict stop-on-detect and canary-only probes.")
    steps = [
        "fingerprint front-end/back-end pair (headers, server, timing)",
        "send paired canary requests to measure desync differential",
        "confirm only with a harmless timing or status canary, never poison users",
        "record affected route, pair, and mitigation (normalise both headers)",
    ]


class CachePoisonPlan(_RunbookModule):
    id = "cache_poison_plan"
    title = "Web cache poisoning assessment plan"
    phase = "P3"
    tier = 3
    summary = ("Unkeyed-header / parameter discovery, cache-key analysis and "
               "canary poisoning with immediate purge instructions.")
    steps = [
        "identify cache layer (age, x-cache, cf-cache-status) and TTL",
        "enumerate unkeyed inputs already present in reflected responses",
        "poison with a canary host/path only against your own test key",
        "verify cache key, then purge; write a detector rule for the header",
    ]


class ApiBolaPlan(_RunbookModule):
    id = "api_bola_plan"
    title = "API BOLA / IDOR verification plan"
    phase = "P3"
    tier = 3
    summary = ("Two-account differential plan for object-level authorization, "
               "using owned test accounts and read-only object fetches.")
    steps = [
        "map object identifiers (numeric, uuid, slug) from captured traffic",
        "fetch the same object with account B using account A's identifier",
        "compare status + body shape, redact PII in evidence",
        "repeat for write methods only after explicit written authorisation",
    ]


class CloudMetadataPlan(_RunbookModule):
    id = "cloud_metadata_plan"
    title = "Cloud metadata / SSRF escalation plan"
    phase = "P3"
    tier = 3
    summary = ("Read-only IMDSv1/v2 and GCP/Azure metadata reachability plan "
               "for a confirmed SSRF endpoint; no credential exfiltration.")
    steps = [
        "confirm SSRF with a canary URL and record egress behaviour",
        "test IMDSv1 169.254.169.254/latest/meta-data/ role name only",
        "check IMDSv2 token requirement and Azure/GCP equivalents",
        "report reachability + role name, then stop (no token theft)",
    ]


class AdcsEscPlan(_RunbookModule):
    id = "adcs_esc_plan"
    title = "AD CS ESC1-ESC8 assessment plan"
    phase = "P3"
    tier = 3
    summary = ("Certificate-template audit plan (enrollee-supplied subject, "
               "client auth EKU, approval missing) for in-scope enterprise CAs.")
    steps = [
        "enumerate CAs and templates with certipy/ldap (read-only)",
        "flag ESC1/ESC2/ESC3/ESC8 conditions in template ACLs",
        "request a certificate only for an owned test principal",
        "document template fix (manager approval, EKU restriction, ACL)",
    ]


class SupplyChainPlan(_RunbookModule):
    id = "supply_chain_plan"
    title = "Dependency / supply-chain review plan"
    phase = "P3"
    tier = 3
    summary = ("Typosquat, dependency-confusion and CI token exposure review "
               "for package manifests already discovered in scope.")
    steps = [
        "collect package.json/requirements.txt/gemfile.lock from surface",
        "match internal package names against public registries",
        "check CI publish tokens and artifact signing posture",
        "report takeover candidates with owner-only remediation",
    ]


PACK3 = [
    TlsPosture(),
    EmailSecurityPosture(),
    DnsHygiene(),
    HttpHeaderAudit(),
    JwtAudit(),
    CorsOriginAudit(),
    AdminPanelDiscovery(),
    SecretLeakScan(),
    SmbSigningAudit(),
    SshPostureAudit(),
    GraphqlIntrospectionAudit(),
    RequestSmugglingPlan(),
    CachePoisonPlan(),
    ApiBolaPlan(),
    CloudMetadataPlan(),
    AdcsEscPlan(),
    SupplyChainPlan(),
]
