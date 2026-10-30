"""Payload repo catalog — the 10 web-payload sources + local clone status."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

REPOS = [
    {"dir": "patt", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
     "covers": "XSS SQLi SSTI XXE SSRF LFI deserialization WAF-bypass", "size": "large"},
    {"dir": "seclists", "url": "https://github.com/danielmiessler/SecLists",
     "covers": "fuzzing passwords usernames discovery shells", "size": "large"},
    {"dir": "fuzzdb", "url": "https://github.com/fuzzdb-project/fuzzdb",
     "covers": "attack patterns: sqli xss traversal format-string", "size": "small"},
    {"dir": "foospidy", "url": "https://github.com/foospidy/payloads",
     "covers": "curated web attack payloads", "size": "small"},
    {"dir": "xss", "url": "https://github.com/7ioSecurity/XSS-Payloads",
     "covers": "xss vectors filter evasions", "size": "small"},
    {"dir": "tiny-xss", "url": "https://github.com/terjanq/Tiny-XSS-Payloads",
     "covers": "minimal xss vectors", "size": "tiny"},
    {"dir": "watt", "url": "https://github.com/iamshafayat/WordlistsAllTheThings",
     "covers": "lfi ssrf crlf redirect 403-bypass jwt api", "size": "medium"},
    {"dir": "intruder", "url": "https://github.com/patuuh/Payloads-and-wordlists",
     "covers": "burp intruder sets: xss xxe ldap sql xpath ssti log4j", "size": "small"},
    {"dir": "secpayloads", "url": "https://github.com/ogh-bnz/SecPayloads",
     "covers": "idor htmli dorks wp", "size": "small"},
    {"dir": "sec2025", "url": "https://github.com/0ff-set/SecLists-2025-advanced",
     "covers": "2025 packs: graphql smuggling ssrf-internals", "size": "small"},
]


def _bases() -> List[Path]:
    cands = [os.getenv("ARDF_PAYLOADS", ""),
             str(Path(__file__).parent.parent / "payloads"),
             str(Path.home() / ".ardf" / "payloads"),
             "/opt/ardf/payloads"]
    return [Path(c) for c in cands if c and Path(c).is_dir()]


def catalog(root: str = "") -> List[Dict[str, Any]]:
    """Repo list annotated with local clone presence."""
    bases = [Path(root)] if root else _bases()
    out = []
    for r in REPOS:
        hit, files = None, 0
        for base in bases:
            d = base / r["dir"]
            if d.is_dir():
                hit = d
                break
        if hit is not None:
            # top-level entries only: rglob over multi-GB clones stalls
            try:
                files = sum(1 for _ in hit.iterdir())
            except Exception:
                files = 0
        out.append({**r, "cloned": hit is not None, "files": files})
    return out
