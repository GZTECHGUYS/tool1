"""Shared, bounded network helpers for the attack packs.

This module exists so P1/P2 can reuse the same scope-checked HTTP/probe
primitives as P3/P4 without importing a sibling pack (which would create
a circular import: P3 imports P1, P4 imports P3).

Every helper is deliberately small and bounded. Scope violations always
raise a hard ``PermissionError`` — they are never downgraded to a probe
failure.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .base import require_in_scope

_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
       "ARDF/3.1 authorized-assessment")


def host_of(raw: str) -> str:
    """Extract a bare hostname from a URL, ``host:port`` or bare host."""
    value = str(raw or "").strip()
    try:
        parsed = urlparse(value if "://" in value else "//" + value)
        if parsed.hostname:
            return parsed.hostname.lower()
    except Exception:
        pass
    if value.count(":") > 1 and not value.startswith("["):
        return value.split("%", 1)[0].lower()
    return value.rsplit("@", 1)[-1].split("/")[0].split(":")[0].lower()


def base_url(session, spec: Dict[str, Any]) -> str:
    """Build an absolute URL from the spec/session target."""
    raw = str(spec.get("target") or getattr(session.meta, "target", "") or "").strip()
    if not raw:
        raise ValueError("target is required")
    if "://" not in raw:
        scheme = str(spec.get("scheme") or "https").lower()
        raw = f"{scheme}://{raw}"
    return raw


def scope_ok(*targets: str) -> bool:
    """Non-raising scope check used to filter candidate URLs/hosts."""
    try:
        for t in targets:
            require_in_scope(host_of(t) if "://" in str(t) else str(t))
        return True
    except Exception:
        return False


def http(url: str, method: str = "GET",
         headers: Optional[Dict[str, str]] = None,
         data: Optional[bytes] = None, timeout: int = 10,
         max_bytes: int = 1_000_000, allow_redirects: bool = True
         ) -> Dict[str, Any]:
    """Bounded HTTP request with per-hop scope re-validation."""
    import requests  # local import keeps module import cheap

    hdr = {"User-Agent": _UA, "Accept": "*/*"}
    hdr.update(headers or {})
    current = url
    current_data = data
    sess = None
    r = None
    try:
        require_in_scope(host_of(current))
        sess = requests.Session()
        for _hop in range(5):
            r = sess.request(method, current, headers=hdr, data=current_data,
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
            require_in_scope(host_of(nxt))
            if r.status_code == 303 or (
                    r.status_code in (301, 302) and
                    str(method).upper() not in ("GET", "HEAD")):
                method, current_data = "GET", None
            r.close()
            current = nxt
        else:
            if r is not None:
                r.close()
            return {"ok": False, "error": "too many redirects", "url": current}
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
        raise
    except Exception as e:
        return {"ok": False, "error": str(e)[:240], "url": current}
    finally:
        if r is not None:
            try:
                r.close()
            except Exception:
                pass
        if sess is not None:
            try:
                sess.close()
            except Exception:
                pass


def port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def need(*names: str, fix: str) -> str:
    """First available binary, or an honest, actionable error."""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    raise RuntimeError(f"required tool '{names[0]}' not found on PATH; {fix}")


def run_cmd(argv: List[str], timeout: int = 120) -> Dict[str, Any]:
    """Bounded argv-based subprocess (never shell=True)."""
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, errors="replace")
    return {"rc": proc.returncode,
            "stdout": (proc.stdout or "")[-20000:],
            "stderr": (proc.stderr or "")[-4000:]}
