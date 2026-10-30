"""JWT weak-secret audit — offline HMAC crack of captured tokens.

Tries a small built-in secret list against HS256/HS384/HS512 tokens
found in session findings (or supplied directly). Fully offline; flags
`none`-algorithm tokens immediately. No network, no brute-force service.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

SECRETS = ["secret", "password", "123456", "admin", "jwt", "key",
           "changeme", "test", "qwerty", "letmein", "s3cret"]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _pad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def crack(token: str, secrets: Optional[List[str]] = None) -> Dict[str, Any]:
    """Return {weak:bool, secret?, alg?} — pure offline crypto."""
    try:
        header_b, _, sig_b = token.strip().split(".")
        header = json.loads(_pad(header_b))
    except Exception:
        return {"weak": False, "error": "not a jwt"}
    alg = header.get("alg", "")
    if alg.lower() == "none":
        return {"weak": True, "alg": "none", "secret": None}
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return {"weak": False, "alg": alg}
    signing = f"{header_b}.{token.strip().split('.')[1]}".encode()
    for secret in secrets or SECRETS:
        mac = hmac.new(secret.encode(), signing, digest).digest()
        if hmac.compare_digest(_b64url(mac), sig_b):
            return {"weak": True, "alg": alg, "secret": secret}
    return {"weak": False, "alg": alg}


def _tokens_in(session: Session) -> List[str]:
    import re
    out = []
    rx = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    for f in session.get_findings():
        for blob in (f.evidence or "", f.description or ""):
            out.extend(rx.findall(str(blob)))
    return sorted(set(out))[:20]


def run(session: Session, logger: Optional[ARDFLogger] = None,
        tokens: Optional[List[str]] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("validate.jwtcrack")
    tokens = tokens or _tokens_in(session)
    weak = []
    for t in tokens:
        r = crack(t)
        if r.get("weak"):
            weak.append({"token": t[:24] + "…", **r})
    for w in weak:
        session.add_finding(Finding(
            source="validate.jwtcrack",
            title=f"Weak JWT ({w.get('alg')})" +
                  (f": secret '{w['secret']}'" if w.get("secret") else ": alg=none"),
            description="Token forgeable offline. Rotate secret; enforce "
                        "strong random keys; reject alg=none.",
            severity=SeverityLevel.CRITICAL, host=session.meta.target,
            tags=["jwt", "credentials"]))
    logger.success(f"jwt-crack: {len(weak)}/{len(tokens)} weak")
    return {"tested": len(tokens), "weak": weak}
