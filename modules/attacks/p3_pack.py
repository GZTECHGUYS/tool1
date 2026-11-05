"""P3 pack — posture, validation and planning modules.

Design rules
------------
* Every module is scope-guarded through ``require_in_scope``.
* Read-only checks are Tier-1; active probes are Tier-2; anything that
  changes state or needs operator judgement is a Tier-3 assessment
  (CONFIRM-gated).
* No module writes to a target. Findings contain redacted evidence only.
* Network helpers are deliberately small and bounded (timeouts, byte caps,
  request caps) so a bad target cannot stall the console.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import (parse_qsl, quote, urlencode, urljoin, urlparse)

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from .base import AttackModule, require_in_scope

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
        _plan(session, spec)
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
        _plan(session, spec)
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
        _plan(session, spec)
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


# ── injection / redirect validation ─────────────────────────

_REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return",
                    "returnUrl", "continue", "dest", "destination", "target",
                    "r", "u", "to", "redir", "out"]
_SSRF_PARAMS = ["url", "uri", "dest", "destination", "redirect", "redirect_uri",
                "proxy", "fetch", "image", "avatar", "callback", "webhook",
                "feed", "host", "path", "src", "link"]
_TRAVERSAL_PARAMS = ["file", "path", "page", "template", "download", "doc",
                     "view", "name", "include", "lang", "load", "read"]
_SSTI_PARAMS = ["q", "search", "name", "template", "message", "title", "lang",
                "page", "input", "comment", "subject", "text"]
_CANARY = "https://ardf-canary.invalid/probe"


def _with_param(base: str, param: str, value: str) -> str:
    """Replace/append one query parameter without duplicating its key."""
    parsed = urlparse(base)
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != param]
    query.append((param, value))
    return parsed._replace(query=urlencode(query, quote_via=quote)).geturl()


def _body_has(body: str, *needles: str) -> bool:
    low = (body or "").lower()
    return any(n.lower() in low for n in needles)


class OpenRedirectAudit(AttackModule):
    id = "open_redirect_audit"
    title = "Open redirect validation"
    phase = "P3"
    tier = 2
    summary = ("Injects a canary URL into common redirect parameters and "
               "checks Location/body reflection without following hops.")

    PARAMS = _REDIRECT_PARAMS

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "params": [str(p) for p in
                           (spec.get("params") or self.PARAMS)][:20]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        params = [str(p) for p in (spec.get("params") or self.PARAMS)][:20]
        canary = str(spec.get("canary") or _CANARY)
        marker = _host_of(canary)
        hits: List[Dict[str, Any]] = []
        for param in params:
            url = _with_param(base, param, canary)
            res = _http(url, timeout=8, max_bytes=64_000,
                        allow_redirects=False)
            if not res.get("ok"):
                continue
            location = str(res.get("headers", {}).get("location", ""))
            body = res.get("body", "")
            if marker and (marker in location or marker in body):
                hits.append({"param": param, "status": res.get("status"),
                             "location": location[:300]})
        if hits:
            _finding(session, f"Open redirect candidate on {host}", "medium",
                     host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["redirect", "open-redirect", "validation"],
                     description="A redirect parameter accepted an off-site "
                                 "canary value and reflected it.",
                     remediation="Allow-list redirect destinations or resolve "
                                 "them to relative paths before redirecting.",
                     raw={"hits": hits, "canary": canary})
        logger.info(f"open redirect {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "hits": hits, "tested": params}


class SsrfCanaryAudit(AttackModule):
    id = "ssrf_canary_audit"
    title = "SSRF canary validation"
    phase = "P3"
    tier = 2
    summary = ("Injects a harmless canary URL into fetch-style parameters "
               "and detects reflection or server-side fetch behaviour.")

    PARAMS = _SSRF_PARAMS

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "params": [str(p) for p in
                           (spec.get("params") or self.PARAMS)][:20],
                "canary": str(spec.get("canary") or _CANARY)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        params = [str(p) for p in (spec.get("params") or self.PARAMS)][:20]
        canary = str(spec.get("canary") or _CANARY)
        marker = _host_of(canary)
        baseline = _http(base, timeout=8, max_bytes=200_000)
        base_body = baseline.get("body", "") if baseline.get("ok") else ""
        hits: List[Dict[str, Any]] = []
        for param in params:
            url = _with_param(base, param, canary)
            res = _http(url, timeout=10, max_bytes=400_000,
                        allow_redirects=False)
            if not res.get("ok"):
                continue
            body = res.get("body", "")
            location = str(res.get("headers", {}).get("location", ""))
            reflected = bool(marker) and (marker in body or marker in location)
            if reflected and marker not in base_body:
                hits.append({"param": param, "status": res.get("status"),
                             "evidence": "canary reflected",
                             "location": location[:200]})
        if hits:
            _finding(session, f"SSRF candidate on {host}", "medium", host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["ssrf", "validation"],
                     description="A fetch-style parameter echoed or acted on "
                                 "an attacker-supplied URL canary.",
                     remediation="Allow-list outbound destinations and block "
                                 "link-local/private ranges at the egress.",
                     raw={"hits": hits, "canary": canary})
        logger.info(f"ssrf canary {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "hits": hits, "tested": params, "canary": canary}


class PathTraversalAudit(AttackModule):
    id = "path_traversal_audit"
    title = "Path traversal validation"
    phase = "P3"
    tier = 2
    summary = ("Sends encoded traversal payloads into file/path parameters "
               "and looks for /etc/passwd or win.ini content signatures.")

    PARAMS = _TRAVERSAL_PARAMS
    PAYLOADS = [
        ("plain", "../../../../etc/passwd"),
        ("url", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("double", "..%252f..%252f..%252f..%252fetc%252fpasswd"),
        ("windows", "..\\..\\..\\..\\windows\\win.ini"),
    ]
    SIGNATURES = ["root:x:0:0:", "[extensions]", "[fonts]"]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "params": [str(p) for p in
                           (spec.get("params") or self.PARAMS)][:15],
                "payloads": [p[0] for p in self.PAYLOADS]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        params = [str(p) for p in (spec.get("params") or self.PARAMS)][:15]
        hits: List[Dict[str, Any]] = []
        for param in params:
            for label, payload in self.PAYLOADS:
                url = _with_param(base, param, payload)
                res = _http(url, timeout=8, max_bytes=200_000,
                            allow_redirects=False)
                if not res.get("ok"):
                    continue
                body = res.get("body", "")
                if any(sig in body for sig in self.SIGNATURES):
                    hits.append({"param": param, "payload": label,
                                 "status": res.get("status")})
                    break
        if hits:
            _finding(session, f"Path traversal candidate on {host}", "high",
                     host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["traversal", "lfi", "validation"],
                     description="A file/path parameter returned local file "
                                 "content for a traversal payload.",
                     remediation="Resolve user input against a fixed base "
                                 "directory and reject path separators.",
                     raw={"hits": hits})
        logger.info(f"traversal {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "hits": hits, "tested_params": params}


class SstiCanaryAudit(AttackModule):
    id = "ssti_canary_audit"
    title = "Server-side template injection canary"
    phase = "P3"
    tier = 2
    summary = ("Injects arithmetic template canaries ({{7*7}}, ${7*7}, "
               "<%= 7*7 %>) and flags evaluated output not present at baseline.")

    PARAMS = _SSTI_PARAMS
    PAYLOADS = [
        ("jinja", "{{7*7}}", "49"),
        ("freemarker", "${7*7}", "49"),
        ("erb", "<%= 7*7 %>", "49"),
        ("ruby", "#{7*7}", "49"),
        ("twig", "{{7*'7'}}", "7777777"),
    ]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "params": [str(p) for p in
                           (spec.get("params") or self.PARAMS)][:15],
                "payloads": [p[0] for p in self.PAYLOADS]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        params = [str(p) for p in (spec.get("params") or self.PARAMS)][:15]
        baseline = _http(base, timeout=8, max_bytes=200_000)
        base_body = baseline.get("body", "") if baseline.get("ok") else ""
        hits: List[Dict[str, Any]] = []
        for param in params:
            for label, payload, marker in self.PAYLOADS:
                url = _with_param(base, param, payload)
                res = _http(url, timeout=8, max_bytes=200_000,
                            allow_redirects=False)
                if not res.get("ok"):
                    continue
                body = res.get("body", "")
                if marker in body and marker not in base_body:
                    hits.append({"param": param, "engine": label,
                                 "marker": marker, "status": res.get("status")})
                    break
        if hits:
            _finding(session, f"SSTI candidate on {host}", "high", host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["ssti", "template", "validation"],
                     description="Template expression was evaluated server-side "
                                 "rather than reflected literally.",
                     remediation="Do not build templates from user input; use "
                                 "a sandboxed renderer and strict contexts.",
                     raw={"hits": hits})
        logger.info(f"ssti {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "hits": hits, "tested_params": params}


class NosqlInjectionAudit(AttackModule):
    id = "nosql_injection_audit"
    title = "NoSQL injection validation"
    phase = "P3"
    tier = 2
    summary = ("Sends JSON operator payloads ($ne/$gt) to a login-style "
               "endpoint and compares against a known-bad baseline.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "endpoint": str(spec.get("url") or _base_url(session, spec)),
                "user_field": str(spec.get("user_field") or "username"),
                "pass_field": str(spec.get("pass_field") or "password")}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        endpoint = str(spec.get("url") or base)
        ufield = str(spec.get("user_field") or "username")
        pfield = str(spec.get("pass_field") or "password")
        headers = {"Content-Type": "application/json"}
        baseline_body = json.dumps({ufield: "ardf_nx_9f3", pfield: "ardf_bad_9f3"})
        baseline = _http(endpoint, method="POST", headers=headers,
                         data=baseline_body.encode(), timeout=8,
                         max_bytes=200_000, allow_redirects=False)
        base_status = int(baseline.get("status") or 0)
        base_text = (baseline.get("body", "") if baseline.get("ok") else "").lower()
        base_denied = base_status >= 400 or _body_has(
            base_text, "invalid", "unauthorized", "incorrect", "failed",
            "denied", "bad credentials")
        payloads = [
            ("$ne", {ufield: {"$ne": None}, pfield: {"$ne": None}}),
            ("$gt", {ufield: {"$gt": ""}, pfield: {"$gt": ""}}),
        ]
        hits: List[Dict[str, Any]] = []
        for label, doc in payloads:
            res = _http(endpoint, method="POST", headers=headers,
                        data=json.dumps(doc).encode(), timeout=8,
                        max_bytes=200_000, allow_redirects=False)
            if not res.get("ok"):
                continue
            status = int(res.get("status") or 0)
            text = (res.get("body", "") or "").lower()
            denied = status >= 400 or _body_has(
                text, "invalid", "unauthorized", "incorrect", "failed",
                "denied", "bad credentials")
            success_marker = _body_has(text, "token", "session", "welcome",
                                       "dashboard", "logout", "success")
            if base_denied and (not denied or success_marker):
                hits.append({"operator": label, "status": status,
                             "baseline_status": base_status,
                             "success_marker": success_marker})
        if hits:
            _finding(session, f"NoSQL injection candidate on {host}", "high",
                     host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["nosql", "injection", "auth-bypass"],
                     description="Operator payloads bypassed the invalid-login "
                                 "response shape.",
                     remediation="Cast credentials to strings and reject object "
                                 "values before building the query.",
                     raw={"hits": hits, "endpoint": endpoint})
        logger.info(f"nosql {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "endpoint": endpoint,
                "hits": hits, "baseline_status": base_status}


class XxeAudit(AttackModule):
    id = "xxe_audit"
    title = "XXE validation"
    phase = "P3"
    tier = 2
    summary = ("Posts a DOCTYPE external-entity document to an XML endpoint "
               "and checks whether a local file entity is resolved.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "endpoint": str(spec.get("url") or _base_url(session, spec)),
                "entity": str(spec.get("xxe_file") or "file:///etc/passwd")}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        endpoint = str(spec.get("url") or base)
        entity = str(spec.get("xxe_file") or "file:///etc/passwd")
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{entity}">]>'
            "<r><data>&xxe;</data></r>")
        res = _http(endpoint, method="POST",
                    headers={"Content-Type": "application/xml"},
                    data=payload.encode(), timeout=10, max_bytes=300_000,
                    allow_redirects=False)
        if not res.get("ok"):
            return {"module": self.id, "mode": "exec", "endpoint": endpoint,
                    "error": res.get("error")}
        body = res.get("body", "")
        signatures = ["root:x:0:0:", "[extensions]", "[fonts]",
                      "for 16-bit app support"]
        resolved = any(sig in body for sig in signatures)
        if resolved:
            _finding(session, f"XXE file disclosure on {host}", "high",
                     host=host,
                     evidence=f"entity={entity}\nstatus={res.get('status')}",
                     tags=["xxe", "xml", "file-read"],
                     description="The XML parser resolved an external entity "
                                 "and returned local file content.",
                     remediation="Disable DTDs/external entities in the XML "
                                 "parser and reject DOCTYPE input.",
                     raw={"endpoint": endpoint, "entity": entity,
                          "status": res.get("status")})
        logger.info(f"xxe {host}: resolved={resolved}")
        return {"module": self.id, "mode": "exec", "endpoint": endpoint,
                "resolved": resolved, "status": res.get("status"),
                "entity": entity}


class HostHeaderAudit(AttackModule):
    id = "host_header_audit"
    title = "Host header injection audit"
    phase = "P3"
    tier = 2
    summary = ("Replays the target with canary Host/X-Forwarded-Host values "
               "and flags reflection in Location, cookies or the body.")

    HEADERS = ["Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host"]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "headers": [str(h) for h in
                            (spec.get("headers") or self.HEADERS)][:8]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        canary = str(spec.get("canary") or "ardf-canary.invalid")
        headers = [str(h) for h in
                   (spec.get("headers") or self.HEADERS)][:8]
        hits: List[Dict[str, Any]] = []
        for header in headers:
            res = _http(base, headers={header: canary}, timeout=8,
                        max_bytes=200_000, allow_redirects=False)
            if not res.get("ok"):
                continue
            location = str(res.get("headers", {}).get("location", ""))
            cookie = str(res.get("headers", {}).get("set-cookie", ""))
            body = res.get("body", "")
            if canary in location or canary in cookie or canary in body:
                hits.append({"header": header, "status": res.get("status"),
                             "in": ("location" if canary in location else
                                    "cookie" if canary in cookie else "body")})
        if hits:
            _finding(session, f"Host header injection on {host}", "medium",
                     host=host,
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["host-header", "injection", "cache"],
                     description="An attacker-controlled Host-family header "
                                 "was reflected into a response artifact.",
                     remediation="Validate Host against an allow-list and "
                                 "never use it to build absolute URLs.",
                     raw={"hits": hits, "canary": canary})
        logger.info(f"host header {host}: {len(hits)} hit(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "hits": hits, "canary": canary}


class HttpMethodAudit(AttackModule):
    id = "http_method_audit"
    title = "HTTP method exposure audit"
    phase = "P3"
    tier = 1
    summary = ("Reads OPTIONS Allow and tests TRACE echo; flags dangerous "
               "verbs exposed without an obvious gateway control.")

    DANGEROUS = {"PUT", "DELETE", "TRACE", "PATCH", "CONNECT"}

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        options = _http(base, method="OPTIONS", timeout=8, max_bytes=64_000,
                        allow_redirects=False)
        allow: List[str] = []
        if options.get("ok"):
            raw = str(options.get("headers", {}).get("allow", ""))
            allow = sorted({v.strip().upper() for v in raw.split(",") if v.strip()})
        trace = _http(base, method="TRACE", timeout=8, max_bytes=64_000,
                      allow_redirects=False)
        trace_body = trace.get("body", "") if trace.get("ok") else ""
        trace_echo = (int(trace.get("status") or 0) == 200 and
                      ("TRACE /" in trace_body or "Max-Forwards" in trace_body))
        dangerous = sorted(set(allow) & self.DANGEROUS)
        issues = []
        if trace_echo:
            issues.append("TRACE reflected the request")
        if dangerous:
            issues.append("Allow advertises " + ", ".join(dangerous))
        if issues:
            _finding(session, f"HTTP method exposure on {host}",
                     "medium" if trace_echo else "low", host=host,
                     evidence="; ".join(issues) + f"\nallow={allow}",
                     tags=["http", "methods", "read-only"],
                     description="Dangerous HTTP verbs are exposed or TRACE "
                                 "is enabled.",
                     remediation="Disable TRACE and restrict write verbs at "
                                 "the edge unless explicitly required.",
                     raw={"allow": allow, "trace_echo": trace_echo,
                          "trace_status": trace.get("status")})
        logger.info(f"http methods {host}: allow={allow} trace={trace_echo}")
        return {"module": self.id, "mode": "exec", "target": base,
                "allow": allow, "trace_echo": trace_echo,
                "dangerous": dangerous}


def _ws_handshake(host: str, port: int, path: str, origin: str = "",
                  use_tls: bool = False, timeout: int = 6) -> Dict[str, Any]:
    """Minimal RFC6455 upgrade probe with handshake verification."""
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            sock = ssl._create_unverified_context().wrap_socket(
                sock, server_hostname=host)
        sock.sendall(request)
        raw = sock.recv(4096) or b""
        text = raw.decode("iso-8859-1", "ignore")
        match = re.match(r"HTTP/\d\.\d\s+(\d{3})", text)
        status = int(match.group(1)) if match else 0
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest()).decode()
        return {"status": status,
                "accepted": status == 101 and expected in text,
                "headers": text.split("\r\n\r\n", 1)[0][:2000]}
    except Exception as exc:
        return {"status": 0, "accepted": False,
                "error": f"{type(exc).__name__}: {exc}"[:200]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


class WebsocketOriginAudit(AttackModule):
    id = "websocket_origin_audit"
    title = "WebSocket origin validation audit"
    phase = "P3"
    tier = 2
    summary = ("Performs a bounded WebSocket upgrade with an untrusted Origin "
               "and verifies the 101 handshake, flagging missing origin checks.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        parsed = urlparse(_base_url(session, spec))
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "host": parsed.hostname or _host_of(_plan(session, spec)),
                "path": str(spec.get("ws_path") or "/"),
                "origin": str(spec.get("origin") or _CANARY)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        raw = str(spec.get("ws_url") or _base_url(session, spec))
        parsed = urlparse(raw if "://" in raw else f"wss://{raw}")
        host = (parsed.hostname or _host_of(raw)).lower()
        require_in_scope(host)
        use_tls = (parsed.scheme or "wss").lower() in ("wss", "https", "tls")
        port = int(parsed.port or (443 if use_tls else 80))
        path = str(spec.get("ws_path") or parsed.path or "/")
        if parsed.query:
            path = f"{path}?{parsed.query}"
        origin = str(spec.get("origin") or _CANARY)
        evil = _ws_handshake(host, port, path, origin=origin, use_tls=use_tls)
        no_origin = _ws_handshake(host, port, path, origin="", use_tls=use_tls)
        accepted = bool(evil.get("accepted"))
        if accepted:
            _finding(session, f"WebSocket accepts untrusted Origin on {host}",
                     "medium", host=host,
                     evidence=f"origin={origin}\npath={path}\n"
                              f"status={evil.get('status')}",
                     tags=["websocket", "cswsh", "origin"],
                     description="The upgrade completed with an Origin that "
                                 "does not belong to the target.",
                     remediation="Validate the Origin header against an "
                                 "allow-list during the WebSocket handshake.",
                     raw={"origin": origin, "path": path,
                          "status": evil.get("status")})
        logger.info(f"websocket origin {host}: accepted={accepted}")
        return {"module": self.id, "mode": "exec", "host": host, "port": port,
                "path": path, "origin": origin,
                "untrusted_origin_accepted": accepted,
                "no_origin_accepted": bool(no_origin.get("accepted")),
                "status": evil.get("status"),
                "error": evil.get("error", "")}


class RateLimitAudit(AttackModule):
    id = "rate_limit_audit"
    title = "Rate-limit / abuse-control audit"
    phase = "P3"
    tier = 2
    summary = ("Sends a short bounded burst and records whether 429/503, "
               "Retry-After or rate-limit headers appear.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "requests": max(2, min(int(spec.get("requests") or 12), 25))}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        count = max(2, min(int(spec.get("requests") or 12), 25))
        statuses: List[int] = []
        throttled = False
        headers_seen: Dict[str, str] = {}
        for _ in range(count):
            res = _http(base, timeout=6, max_bytes=32_000,
                        allow_redirects=False)
            if not res.get("ok"):
                continue
            status = int(res.get("status") or 0)
            statuses.append(status)
            hdrs = res.get("headers", {})
            for key in ("retry-after", "x-ratelimit-limit",
                        "x-ratelimit-remaining", "ratelimit-limit",
                        "ratelimit-remaining"):
                if key in hdrs:
                    headers_seen[key] = hdrs[key]
            if status in (429, 503) or "retry-after" in hdrs:
                throttled = True
        if statuses and not throttled:
            _finding(session, f"No rate-limit response observed on {host}",
                     "low", host=host,
                     evidence=f"{len(statuses)} requests; statuses="
                              f"{sorted(set(statuses))}",
                     tags=["rate-limit", "abuse-control", "read-only"],
                     description="A short burst produced no 429/503 or "
                                 "rate-limit headers.",
                     remediation="Add per-identity and per-IP rate limits at "
                                 "the edge and return 429 with Retry-After.",
                     raw={"statuses": statuses, "headers": headers_seen})
        logger.info(f"rate limit {host}: throttled={throttled} "
                    f"statuses={sorted(set(statuses))}")
        return {"module": self.id, "mode": "exec", "target": base,
                "requests": len(statuses), "throttled": throttled,
                "statuses": statuses, "headers": headers_seen}


# ── Tier-3 runbooks ─────────────────────────────────────────

def _raw_http(host: str, port: int, payload: bytes, *, tls: bool = False,
              timeout: float = 6.0, max_bytes: int = 65536
              ) -> Dict[str, Any]:
    """Bounded raw-socket HTTP exchange for framing differentials.

    Only one request is ever written. A read timeout is reported as a
    signal (the peer may be waiting for more bytes), never retried.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            sock = ssl._create_unverified_context().wrap_socket(
                sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        chunks, total = [], 0
        while total < max_bytes:
            try:
                data = sock.recv(min(8192, max_bytes - total))
            except socket.timeout:
                return {"ok": False, "status": 0, "timed_out": True,
                        "error": "read timeout"}
            if not data:
                break
            chunks.append(data)
            total += len(data)
        raw = b"".join(chunks)
        head = raw.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "ignore")
        match = re.match(r"HTTP/\d\.\d\s+(\d{3})", head)
        return {"ok": True, "status": int(match.group(1)) if match else 0,
                "timed_out": False, "head": head[:2000],
                "bytes": len(raw)}
    except Exception as exc:
        return {"ok": False, "status": 0, "timed_out": False,
                "error": f"{type(exc).__name__}: {exc}"[:200]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _run_tool(argv: List[str], timeout: int = 45) -> Dict[str, Any]:
    """Bounded argv-based helper for the read-only LDAP path."""
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, errors="replace")
    return {"rc": proc.returncode, "stdout": proc.stdout or "",
            "stderr": proc.stderr or ""}


def _levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein (OSA), so an adjacent transposition costs 1."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous_previous = None
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            current[j] = min(current[j - 1] + 1, previous[j] + 1,
                             previous[j - 1] + cost)
            if (i > 1 and j > 1 and ca == b[j - 2] and
                    a[i - 2] == cb and previous_previous is not None):
                current[j] = min(current[j], previous_previous[j - 2] + 1)
        previous_previous, previous = previous, current
    return previous[-1]


class RequestSmugglingPlan(AttackModule):
    id = "request_smuggling_plan"
    title = "HTTP request smuggling framing check"
    phase = "P3"
    tier = 3
    summary = ("CL.TE / TE.CL / TE.TE framing differential using a single "
               "canary request per probe; no second request is smuggled.")

    PROBES = ("cl.te", "te.cl", "te.invalid", "te.obfuscated")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        parsed = urlparse(_base_url(session, spec))
        host = parsed.hostname or _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "host": host,
                "path": parsed.path or "/", "probes": list(self.PROBES),
                "notes": "canary framing only; no smuggled prefix or "
                         "poisoned cache entry"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        parsed = urlparse(base)
        host = (parsed.hostname or _host_of(base)).lower()
        require_in_scope(host)
        tls = (parsed.scheme or "https").lower() in ("https", "tls", "wss")
        port = int(parsed.port or (443 if tls else 80))
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host_header = parsed.netloc or host
        timeout = float(spec.get("timeout") or 6)

        def _request(extra: List[str], body: bytes) -> bytes:
            lines = [f"POST {path} HTTP/1.1", f"Host: {host_header}",
                     f"User-Agent: {_UA}", "Connection: close",
                     "Content-Type: application/x-www-form-urlencoded"]
            lines += extra
            return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

        baseline = _raw_http(host, port,
                             _request(["Content-Length: 3"], b"a=1"),
                             tls=tls, timeout=timeout)
        if not baseline.get("ok"):
            return {"module": self.id, "mode": "exec", "host": host,
                    "status": "unreachable",
                    "error": baseline.get("error")}

        probes = [
            ("cl.te", ["Content-Length: 6", "Transfer-Encoding: chunked"],
             b"0\r\n\r\n"),
            ("te.cl", ["Content-Length: 6", "Transfer-Encoding: chunked"],
             b"0\r\n\r\nX"),
            ("te.invalid", ["Content-Length: 3", "Transfer-Encoding: chunked"],
             b"ZZZ"),
            ("te.obfuscated", ["Transfer-Encoding: chunked",
                               "Transfer-Encoding: identity",
                               "Content-Length: 3"], b"a=1"),
        ]
        results: List[Dict[str, Any]] = []
        possible: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        for label, headers, body in probes:
            res = _raw_http(host, port, _request(headers, body),
                            tls=tls, timeout=timeout)
            entry = {"probe": label, "status": res.get("status"),
                     "timed_out": bool(res.get("timed_out")),
                     "error": res.get("error", "")}
            results.append(entry)
            if entry["timed_out"]:
                possible.append(entry)
            elif res.get("status") in (400, 501, 505):
                rejected.append(entry)
            elif res.get("ok") and res.get("status") != baseline.get("status"):
                possible.append(entry)
        if possible:
            _finding(session, f"HTTP framing differential on {host}", "medium",
                     host=host,
                     evidence=json.dumps({"baseline": baseline.get("status"),
                                          "probes": possible}, indent=1)[:2000],
                     tags=["request-smuggling", "framing", "differential"],
                     description="At least one conflicting framing probe timed "
                                 "out or answered differently from the "
                                 "baseline. This is a candidate, not a "
                                 "confirmed smuggle; no second request was "
                                 "sent.",
                     remediation="Normalise Content-Length/Transfer-Encoding "
                                 "at the edge, reject ambiguous framing, and "
                                 "keep one HTTP parser end to end.",
                     raw={"baseline": baseline.get("status"),
                          "possible": possible, "rejected": rejected})
        logger.info(f"smuggling framing {host}: possible={len(possible)} "
                    f"rejected={len(rejected)}")
        return {"module": self.id, "mode": "exec", "host": host, "port": port,
                "tls": tls, "baseline_status": baseline.get("status"),
                "probes": results, "possible_desync": possible,
                "rejected_conflicts": rejected}


class CachePoisonPlan(AttackModule):
    id = "cache_poison_plan"
    title = "Web cache poisoning validation"
    phase = "P3"
    tier = 3
    summary = ("Reflects canary values through common unkeyed headers on a "
               "unique cache-buster URL, then checks whether the response was "
               "cached. Other users' cache entries are never touched.")

    HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
               "X-Host", "X-Original-URL", "X-Rewrite-URL"]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "headers": [str(h) for h in
                            (spec.get("headers") or self.HEADERS)][:10],
                "notes": "each probe uses a fresh unique query key so only "
                         "the assessor's own cache entry can be affected"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        host = _host_of(base)
        require_in_scope(host)
        headers = [str(h) for h in
                   (spec.get("headers") or self.HEADERS)][:10]
        baseline = _http(base, timeout=8, max_bytes=200_000,
                         allow_redirects=False)
        cache_layer = {}
        if baseline.get("ok"):
            cache_layer = {k: v for k, v in baseline.get("headers", {}).items()
                           if k in ("x-cache", "cf-cache-status", "age",
                                    "x-served-by", "x-cache-hits",
                                    "cache-control", "akamai-grn")}
        hits: List[Dict[str, Any]] = []
        for header in headers:
            token = os.urandom(6).hex()
            url = _with_param(base, "_ardf", f"cb{token}")
            canary = f"ardf-{token}.invalid"
            res = _http(url, headers={header: canary}, timeout=8,
                        max_bytes=300_000, allow_redirects=False)
            if not res.get("ok"):
                continue
            body = res.get("body", "")
            location = str(res.get("headers", {}).get("location", ""))
            reflected = canary in body or canary in location
            if not reflected:
                continue
            confirm = _http(url, timeout=8, max_bytes=300_000,
                            allow_redirects=False)
            cached_hit = False
            still_present = False
            if confirm.get("ok"):
                cached_hit = any(
                    "hit" in str(confirm.get("headers", {}).get(k, "")).lower()
                    for k in ("x-cache", "cf-cache-status", "x-cache-hits"))
                still_present = (canary in confirm.get("body", "") or
                                 canary in str(confirm.get("headers", {})
                                               .get("location", "")))
            hits.append({"header": header, "status": res.get("status"),
                         "reflected_in": ("location" if canary in location
                                          else "body"),
                         "cache_buster": f"_ardf=cb{token}",
                         "cached_hit": cached_hit,
                         "still_present": still_present})
        if hits:
            cached = any(h["cached_hit"] and h["still_present"] for h in hits)
            _finding(session, f"Cache poisoning candidate on {host}",
                     "high" if cached else "medium", host=host,
                     evidence=json.dumps({"cache_layer": cache_layer,
                                          "hits": hits}, indent=1)[:2000],
                     tags=["cache-poisoning", "unkeyed-header", "validation"],
                     description="An unkeyed header was reflected on a unique "
                                 "cache-buster URL"
                                 + (" and the poisoned response was served "
                                    "from cache." if cached else
                                    "."),
                     remediation="Include the header in the cache key or "
                                 "strip it at the edge; purge the unique test "
                                 "key after validation.",
                     raw={"cache_layer": cache_layer, "hits": hits})
        logger.info(f"cache poison {host}: {len(hits)} reflected, "
                    f"cached={sum(1 for h in hits if h['cached_hit'])}")
        return {"module": self.id, "mode": "exec", "target": base,
                "cache_layer": cache_layer, "hits": hits,
                "cached_confirmation": any(h["cached_hit"] and h["still_present"]
                                           for h in hits)}


class ApiBolaPlan(AttackModule):
    id = "api_bola_plan"
    title = "API BOLA / IDOR differential"
    phase = "P3"
    tier = 3
    summary = ("Two-token read-only differential: fetch the same object as "
               "owner A, other user B and unauthenticated, then compare "
               "status/body fingerprints. Tokens never enter evidence.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        urls = []
        if spec.get("object_url"):
            urls.append(str(spec["object_url"]))
        urls += [str(u) for u in (spec.get("object_urls") or [])]
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "object_urls": len(urls),
                "required": ["token_a", "token_b", "object_url or "
                             "object_urls"]}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        require_in_scope(_host_of(base))
        object_url = str(spec.get("object_url") or spec.get("url") or "").strip()
        urls = [str(u) for u in (spec.get("object_urls") or []) if u]
        ids = [str(i) for i in (spec.get("ids") or []) if str(i)]
        if object_url and "{id}" in object_url and ids:
            urls += [object_url.replace("{id}", i) for i in ids]
        elif object_url:
            urls.insert(0, object_url)
        urls = [u for u in dict.fromkeys(urls) if _scope_allowed(u)][:20]
        token_a = str(spec.get("token_a") or spec.get("token") or "").strip()
        token_b = str(spec.get("token_b") or "").strip()
        missing = []
        if not urls:
            missing.append("object_url or object_urls")
        if not token_a:
            missing.append("token_a")
        if not token_b:
            missing.append("token_b")
        if missing:
            return {"module": self.id, "mode": "exec",
                    "status": "input_required", "missing": missing,
                    "note": "BOLA verification needs two owned accounts and "
                            "at least one object URL; no request was sent."}
        auth_header = str(spec.get("auth_header") or "Authorization")
        prefix = str(spec.get("auth_prefix") or "Bearer ")

        def _auth(token: str) -> Dict[str, str]:
            return {auth_header: f"{prefix}{token}"}

        def _sig(text: str) -> Dict[str, Any]:
            raw = (text or "").encode("utf-8", "ignore")
            return {"bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest()}

        results: List[Dict[str, Any]] = []
        for url in urls:
            owner = _http(url, headers=_auth(token_a), timeout=10,
                          max_bytes=300_000, allow_redirects=False)
            other = _http(url, headers=_auth(token_b), timeout=10,
                          max_bytes=300_000, allow_redirects=False)
            anon = _http(url, timeout=10, max_bytes=300_000,
                         allow_redirects=False)
            a_ok = owner.get("ok") and int(owner.get("status") or 0) == 200
            b_ok = other.get("ok") and int(other.get("status") or 0) == 200
            same = False
            if a_ok and b_ok:
                sa, sb = _sig(owner.get("body", "")), _sig(other.get("body", ""))
                same = (sa["sha256"] == sb["sha256"] or
                        (sa["bytes"] and abs(sa["bytes"] - sb["bytes"]) <=
                         max(32, int(sa["bytes"] * 0.05))))
            anon_ok = (anon.get("ok") and int(anon.get("status") or 0) == 200
                       and "login" not in str(
                           anon.get("headers", {}).get("location", "")).lower())
            entry = {"url": url,
                     "owner_status": owner.get("status"),
                     "other_status": other.get("status"),
                     "anon_status": anon.get("status"),
                     "same_object": same, "anon_ok": anon_ok,
                     "owner_sig": _sig(owner.get("body", "")) if a_ok else None,
                     "other_sig": _sig(other.get("body", "")) if b_ok else None}
            results.append(entry)
            if same:
                _finding(session, f"BOLA/IDOR candidate at {_host_of(url)}",
                         "high", host=_host_of(url),
                         evidence=json.dumps(entry, indent=1)[:2000],
                         tags=["api", "bola", "idor", "authorization"],
                         description="Account B received the same object "
                                     "fingerprint as the owner account.",
                         remediation="Enforce object-level authorization on "
                                     "every read and write, keyed to the "
                                     "authenticated subject.",
                         raw=entry)
            elif anon_ok:
                _finding(session, f"Unauthenticated object access at "
                                  f"{_host_of(url)}", "medium",
                         host=_host_of(url),
                         evidence=json.dumps(entry, indent=1)[:2000],
                         tags=["api", "bola", "unauthenticated"],
                         description="The object URL returned 200 without an "
                                     "Authorization header.",
                         remediation="Require authentication and object-level "
                                     "authorization before returning data.",
                         raw=entry)
        logger.info(f"bola {_host_of(base)}: {len(results)} object(s), "
                    f"{sum(1 for r in results if r['same_object'])} shared")
        return {"module": self.id, "mode": "exec", "target": base,
                "tested": len(results), "results": results}


class CloudMetadataPlan(AttackModule):
    id = "cloud_metadata_plan"
    title = "Cloud metadata reachability via SSRF"
    phase = "P3"
    tier = 3
    summary = ("Injects metadata root URLs through a confirmed SSRF parameter "
               "and reports reachability. Only directory/root listings are "
               "requested; credentials are never fetched.")

    ENDPOINTS = [
        ("aws_imdsv1", "http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "placement/", "security-credentials"]),
        ("aws_iam", "http://169.254.169.254/latest/meta-data/iam/"
                    "security-credentials/", ["security-credentials"]),
        ("gcp", "http://metadata.google.internal/computeMetadata/v1/",
         ["project/", "instance/", "computemetadata"]),
        ("azure", "http://169.254.169.254/metadata/instance?"
                  "api-version=2021-02-01",
         ["azenvironment", "vmid", "location"]),
    ]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "endpoints": [name for name, _, _ in self.ENDPOINTS],
                "required": ["ssrf_url (or url)", "ssrf_param (or param)"],
                "notes": "stops at the role directory; no token theft"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        ssrf_url = str(spec.get("ssrf_url") or spec.get("url") or "").strip()
        param = str(spec.get("ssrf_param") or spec.get("param") or "").strip()
        if not ssrf_url or not param:
            return {"module": self.id, "mode": "exec",
                    "status": "input_required",
                    "missing": [m for m, v in
                                (("ssrf_url", ssrf_url), ("ssrf_param", param))
                                if not v],
                    "note": "point this at a confirmed SSRF parameter; no "
                            "request was sent."}
        require_in_scope(_host_of(ssrf_url))
        hits: List[Dict[str, Any]] = []
        for name, endpoint, markers in self.ENDPOINTS:
            url = _with_param(ssrf_url, param, endpoint)
            res = _http(url, timeout=10, max_bytes=200_000,
                        allow_redirects=False)
            if not res.get("ok"):
                continue
            body = (res.get("body") or "").lower()
            matched = [m for m in markers if m in body]
            if matched:
                hits.append({"endpoint": name, "markers": matched,
                             "status": res.get("status")})
        if hits:
            _finding(session, f"Cloud metadata reachable via SSRF on "
                              f"{_host_of(ssrf_url)}", "high",
                     host=_host_of(ssrf_url),
                     evidence=json.dumps(hits, indent=1)[:2000],
                     tags=["cloud", "metadata", "ssrf", "imds"],
                     description="The SSRF parameter reached a cloud metadata "
                                 "root/directory listing. Credentials were "
                                 "not requested.",
                     remediation="Require IMDSv2, block 169.254.169.254 at "
                                 "the egress, and allow-list outbound URLs.",
                     raw={"hits": hits})
        logger.info(f"cloud metadata {_host_of(ssrf_url)}: "
                    f"{len(hits)} reachable")
        return {"module": self.id, "mode": "exec", "target": ssrf_url,
                "param": param, "hits": hits,
                "reachable": bool(hits)}


def _ldif_blocks(text: str) -> List[Dict[str, List[str]]]:
    rows: List[Dict[str, List[str]]] = []
    current: Dict[str, List[str]] = {}
    for line in (text or "").splitlines():
        if line.startswith("dn:"):
            if current:
                rows.append(current)
            current = {"dn": [line[3:].strip()]}
        elif ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            current.setdefault(key.strip().lower(), []).append(value.strip())
    if current:
        rows.append(current)
    return rows


def _flag_int(value: str) -> Optional[int]:
    raw = str(value or "").strip().lower()
    try:
        return int(raw, 16) if raw.startswith("0x") else int(raw)
    except ValueError:
        return None


class AdcsEscPlan(AttackModule):
    id = "adcs_esc_plan"
    title = "AD CS ESC1-ESC8 assessment"
    phase = "P3"
    tier = 3
    summary = ("Probes web enrollment endpoints (ESC8 signal) and, when "
               "read-only LDAP bind material is supplied, audits certificate "
               "template flags for ESC1/ESC2/ESC3 conditions.")

    WEB_PATHS = ["/certsrv/", "/certsrv/Default.asp",
                 "/certsrv/certfnsh.asp", "/CertSrv/",
                 "/certsrv/mscep/mscep.dll", "/certsrv/mscep_admin/"]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        host = _host_of(_plan(session, spec))
        return {"module": self.id, "mode": "plan", "host": host,
                "web_paths": self.WEB_PATHS,
                "optional": ["ldap_url", "base_dn", "bind_dn", "bind_pw"],
                "notes": "LDAP template audit is read-only and only runs "
                         "when bind material is supplied"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        parsed = urlparse(base)
        host = (parsed.hostname or _host_of(base)).lower()
        require_in_scope(host)
        root = f"{parsed.scheme or 'https'}://{parsed.netloc or host}"
        web: List[Dict[str, Any]] = []
        for path in self.WEB_PATHS:
            res = _http(root + path, timeout=8, max_bytes=200_000,
                        allow_redirects=False)
            if not res.get("ok"):
                continue
            body = (res.get("body") or "").lower()
            headers = res.get("headers", {})
            interesting = int(res.get("status") or 0) in (200, 401, 403) and (
                "certsrv" in body or "certificate services" in body or
                "mscep" in body or "microsoft" in body)
            ntlm = "ntlm" in str(headers.get("www-authenticate", "")).lower()
            if interesting or ntlm:
                web.append({"path": path, "status": res.get("status"),
                            "esc8_candidate": bool(interesting and ntlm),
                            "ntlm": ntlm})
        if any(w["esc8_candidate"] for w in web):
            _finding(session, f"AD CS web enrollment with NTLM on {host}",
                     "high", host=host,
                     evidence=json.dumps(web, indent=1)[:2000],
                     tags=["adcs", "esc8", "ntlm", "relay"],
                     description="Web enrollment answered and advertises NTLM, "
                                 "the ESC8 relay precondition.",
                     remediation="Enable EPA/HTTPS-only enrollment and disable "
                                 "NTLM on the CA web endpoints.",
                     raw={"web": web})
        elif web:
            _finding(session, f"AD CS web enrollment exposed on {host}",
                     "medium", host=host,
                     evidence=json.dumps(web, indent=1)[:2000],
                     tags=["adcs", "web-enrollment", "exposure"],
                     description="Certificate Services web endpoints are "
                                 "reachable from the assessed surface.",
                     remediation="Restrict enrollment to managed networks and "
                                 "require strong authentication.",
                     raw={"web": web})

        ldap_result: Dict[str, Any] = {"used": False, "templates": [],
                                       "candidates": [], "note": ""}
        ldap_url = str(spec.get("ldap_url") or f"ldap://{host}:389")
        require_in_scope(_host_of(ldap_url))
        ldap = shutil.which("ldapsearch")
        if not ldap:
            ldap_result["note"] = ("ldapsearch not found; install ldap-utils "
                                   "for the template audit")
        else:
            bind_dn = str(spec.get("bind_dn") or spec.get("username") or "")
            bind_pw = str(spec.get("bind_pw") or spec.get("password") or "")
            base_dn = str(spec.get("base_dn") or "")
            pw_file = None
            bind_args: List[str] = []
            try:
                if bind_dn:
                    bind_args = ["-D", bind_dn]
                    if bind_pw:
                        handle = tempfile.NamedTemporaryFile(
                            mode="w", delete=False)
                        handle.write(bind_pw)
                        handle.close()
                        pw_file = handle.name
                        bind_args += ["-y", pw_file]
                if not base_dn:
                    root_res = _run_tool(
                        [ldap, "-x", "-H", ldap_url] + bind_args +
                        ["-s", "base", "-b", "", "defaultNamingContext",
                         "-LLL"], timeout=30)
                    match = re.search(r"defaultNamingContext:\s*(\S+)",
                                      root_res["stdout"], re.I)
                    base_dn = match.group(1) if match else ""
                if base_dn:
                    template_base = ("CN=Certificate Templates,"
                                     "CN=Public Key Services,CN=Services,"
                                     + base_dn)
                    proc = _run_tool(
                        [ldap, "-x", "-H", ldap_url] + bind_args +
                        ["-b", template_base,
                         "(objectClass=pKICertificateTemplate)", "cn",
                         "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage",
                         "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                         "-LLL", "-o", "ldif-wrap=no"], timeout=60)
                    templates, candidates = [], []
                    for block in _ldif_blocks(proc["stdout"]):
                        name = (block.get("cn") or [""])[0]
                        if not name:
                            continue
                        name_flag = _flag_int(
                            (block.get("mspki-certificate-name-flag") or
                             [""])[0])
                        enroll_flag = _flag_int(
                            (block.get("mspki-enrollment-flag") or [""])[0])
                        ra_sig = _flag_int(
                            (block.get("mspki-ra-signature") or [""])[0])
                        eku = " ".join(block.get("pkiextendedkeyusage") or
                                       []).lower()
                        client_auth = "1.3.6.1.5.5.7.3.2" in eku
                        any_eku = "2.5.29.37.0" in eku
                        agent = "1.3.6.1.4.1.311.20.2.1" in eku
                        needs_approval = bool(enroll_flag and enroll_flag & 2)
                        esc1 = bool(name_flag and name_flag & 1 and
                                    (client_auth or any_eku) and
                                    not needs_approval and
                                    (ra_sig in (None, 0)))
                        esc2 = bool((any_eku or not eku) and
                                    not needs_approval)
                        esc3 = bool(agent and not needs_approval)
                        entry = {"template": name,
                                 "esc1": esc1, "esc2": esc2, "esc3": esc3,
                                 "client_auth": client_auth,
                                 "needs_approval": needs_approval}
                        templates.append(entry)
                        if esc1 or esc2 or esc3:
                            candidates.append(entry)
                    ldap_result = {"used": True, "base_dn": base_dn,
                                   "templates": templates[:200],
                                   "candidates": candidates[:100],
                                   "note": "" if proc["rc"] == 0 else
                                           proc["stderr"][-300:]}
                    if candidates:
                        _finding(session,
                                 f"{len(candidates)} AD CS template candidate(s) "
                                 f"on {host}", "high", host=host,
                                 evidence=json.dumps(candidates[:30],
                                                      indent=1)[:2000],
                                 tags=["adcs", "esc1", "esc2", "esc3",
                                       "templates"],
                                 description="Template flags match one or more "
                                             "ESC conditions. Validate with an "
                                             "owned test principal before "
                                             "requesting anything.",
                                 remediation="Require manager approval, "
                                             "remove enrollee-supplied subject, "
                                             "and restrict client-auth EKUs.",
                                 raw={"candidates": candidates[:100]})
            except subprocess.TimeoutExpired:
                ldap_result["note"] = "ldapsearch timed out"
            except Exception as exc:
                ldap_result["note"] = f"{type(exc).__name__}: {exc}"[:300]
            finally:
                if pw_file:
                    try:
                        os.unlink(pw_file)
                    except OSError:
                        pass
        logger.info(f"adcs {host}: web={len(web)} "
                    f"templates={len(ldap_result['templates'])} "
                    f"candidates={len(ldap_result['candidates'])}")
        return {"module": self.id, "mode": "exec", "host": host,
                "web": web, "ldap": ldap_result}


_POPULAR_PACKAGES = {
    "requests", "urllib3", "flask", "django", "numpy", "pandas", "react",
    "lodash", "express", "axios", "chalk", "commander", "boto3",
    "cryptography", "setuptools", "pip", "npm", "debug", "colors",
    "event-stream", "serialize-javascript", "log4j-core", "spring-core",
    "jackson-databind", "commons-io",
}


def _collect_deps(name: str, text: str) -> Dict[str, Any]:
    deps: List[Tuple[str, str, str]] = []
    scripts: List[str] = []
    if name.endswith(("package.json", "composer.json")):
        try:
            doc = json.loads(text)
        except Exception:
            doc = {}
        if isinstance(doc, dict):
            for key in ("dependencies", "devDependencies", "peerDependencies",
                        "optionalDependencies", "require", "require-dev"):
                block = doc.get(key)
                if isinstance(block, dict):
                    for dep, version in block.items():
                        deps.append((str(dep), str(version), key))
            scr = doc.get("scripts")
            if isinstance(scr, dict):
                scripts = [f"{k}: {v}" for k, v in scr.items()]
    elif name.endswith("requirements.txt"):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            deps.append((re.split(r"[<>=!~ \[;]", line, 1)[0], line,
                         "requirements"))
    elif name.endswith("go.mod"):
        in_block = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_block = True
                continue
            if in_block and stripped == ")":
                in_block = False
                continue
            match = re.match(r"^(?:require\s+)?([\w./\-]+)\s+(v[\w.\-+]+)",
                             stripped)
            if match and (in_block or stripped.startswith("require")):
                deps.append((match.group(1), match.group(2), "go"))
    elif name.endswith("pom.xml"):
        for block in re.findall(r"<dependency>(.*?)</dependency>", text,
                                re.S):
            gid = re.search(r"<groupId>(.*?)</groupId>", block)
            aid = re.search(r"<artifactId>(.*?)</artifactId>", block)
            ver = re.search(r"<version>(.*?)</version>", block)
            if aid:
                deps.append((f"{gid.group(1) if gid else ''}:"
                             f"{aid.group(1)}",
                             ver.group(1) if ver else "", "maven"))
    elif name.endswith("Gemfile.lock"):
        for line in text.splitlines():
            match = re.match(r"^\s{4}([\w.\-]+)\s+\(([^)]+)\)", line)
            if match:
                deps.append((match.group(1), match.group(2), "gem"))
    return {"deps": deps, "scripts": scripts}


def _supply_issues(name: str, text: str,
                   parsed: Dict[str, Any]) -> List[Tuple[str, str]]:
    issues: List[Tuple[str, str]] = []
    for dep, version, kind in parsed["deps"]:
        if version in ("*", "latest", "") or (
                version.startswith(">=") and "<" not in version):
            issues.append(("unpinned", f"{kind}:{dep} {version}"))
        if version.startswith(("http://", "git://")):
            issues.append(("insecure_source", f"{kind}:{dep} {version}"))
    for script in parsed["scripts"]:
        low = script.lower()
        if any(marker in low for marker in
               ("curl ", "wget ", "bash -c", "node -e", "eval(",
                "powershell", "chmod +x")):
            issues.append(("dangerous_script", script[:200]))
    for dep, _version, _kind in parsed["deps"]:
        base_name = dep.rsplit("/", 1)[-1].lower()
        if len(base_name) < 5 or base_name in _POPULAR_PACKAGES:
            continue
        for popular in _POPULAR_PACKAGES:
            if len(popular) >= 5 and _levenshtein(base_name, popular) == 1:
                issues.append(("typosquat_candidate",
                               f"{dep} ~ {popular}"))
                break
    for secret in _scan_text(text, name):
        issues.append(("secret", f"{secret.get('type')} "
                                 f"{secret.get('value')}"))
    return issues


class SupplyChainPlan(AttackModule):
    id = "supply_chain_plan"
    title = "Dependency / supply-chain review"
    phase = "P3"
    tier = 3
    summary = ("Fetches in-scope manifests, then flags unpinned/insecure "
               "sources, dangerous install scripts, typosquat candidates and "
               "committed secrets. Read-only static analysis.")

    DEFAULT_PATHS = ["/package.json", "/requirements.txt", "/composer.json",
                     "/composer.lock", "/Gemfile.lock", "/go.mod", "/pom.xml",
                     "/yarn.lock", "/pnpm-lock.yaml"]

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        return {"module": self.id, "mode": "plan",
                "target": _plan(session, spec),
                "paths": [str(p) for p in
                          (spec.get("paths") or self.DEFAULT_PATHS)][:12],
                "notes": "read-only manifest fetch; no registry upload or "
                         "package installation"}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        base = _base_url(session, spec)
        require_in_scope(_host_of(base))
        urls = [str(u) for u in (spec.get("manifests") or
                                 spec.get("urls") or []) if u]
        if not urls:
            parsed = urlparse(base)
            root = f"{parsed.scheme or 'https'}://{parsed.netloc or _host_of(base)}"
            paths = spec.get("paths") or self.DEFAULT_PATHS
            urls = [root + str(p) for p in paths]
        urls = [u for u in dict.fromkeys(urls) if _scope_allowed(u)][:20]
        manifests, all_issues = [], []
        for url in urls:
            res = _http(url, timeout=10, max_bytes=2_000_000,
                        allow_redirects=False)
            if not res.get("ok") or int(res.get("status") or 0) != 200:
                continue
            text = res.get("body") or ""
            stripped = text.lstrip().lower()
            if stripped.startswith(("<!doctype", "<html", "{", "[")) and not (
                    url.endswith(".json")):
                continue
            name = urlparse(url).path.rsplit("/", 1)[-1].lower()
            if not name.endswith((".json", ".txt", ".lock", ".mod", ".xml",
                                  ".yaml", ".yml")):
                continue
            parsed_manifest = _collect_deps(name, text)
            issues = _supply_issues(name, text, parsed_manifest)
            entry = {"manifest": name, "url": url,
                     "dependencies": len(parsed_manifest["deps"]),
                     "scripts": len(parsed_manifest["scripts"]),
                     "issues": [{"kind": k, "detail": d}
                                for k, d in issues[:50]]}
            manifests.append(entry)
            all_issues += [{"manifest": name, "kind": k, "detail": d}
                           for k, d in issues]
            if issues:
                kinds = {k for k, _ in issues}
                sev = ("high" if kinds & {"secret", "dangerous_script"}
                       else "medium" if "insecure_source" in kinds else "low")
                _finding(session, f"Supply-chain issues in {name}", sev,
                         host=_host_of(url),
                         evidence=json.dumps(entry["issues"],
                                             indent=1)[:2000],
                         tags=["supply-chain", "dependencies", "manifest"],
                         description="Static review of a discovered "
                                     "dependency manifest.",
                         remediation="Pin versions, use HTTPS registry "
                                     "sources, review install scripts, and "
                                     "rotate any committed secrets.",
                         raw=entry)
        logger.info(f"supply chain {_host_of(base)}: "
                    f"{len(manifests)} manifest(s), "
                    f"{len(all_issues)} issue(s)")
        return {"module": self.id, "mode": "exec", "target": base,
                "manifests": manifests, "issue_count": len(all_issues)}


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
    OpenRedirectAudit(),
    SsrfCanaryAudit(),
    PathTraversalAudit(),
    SstiCanaryAudit(),
    NosqlInjectionAudit(),
    XxeAudit(),
    HostHeaderAudit(),
    HttpMethodAudit(),
    WebsocketOriginAudit(),
    RateLimitAudit(),
    RequestSmugglingPlan(),
    CachePoisonPlan(),
    ApiBolaPlan(),
    CloudMetadataPlan(),
    AdcsEscPlan(),
    SupplyChainPlan(),
]
