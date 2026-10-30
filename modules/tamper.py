"""Tamper kit — benign payload encodings to slip past naive WAF rules.

All transforms preserve detection semantics (reflection / error / math
evaluation). Used by web validators; also browsable in the dashboard.
No exploit code — encodings only.
"""
from __future__ import annotations

import random
import urllib.parse
from typing import Callable, Dict, List


def case_swap(payload: str) -> str:
    return "".join(c.upper() if c.islower() and random.random() < 0.5
                   else c.lower() if c.isupper() and random.random() < 0.5
                   else c for c in payload)


def inline_comments(payload: str) -> str:
    return payload.replace(" ", "/**/")


def space_to_plus(payload: str) -> str:
    return payload.replace(" ", "+")


def double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def unicode_encode(payload: str) -> str:
    return "".join(f"%u{ord(c):04x}" if c.isalpha() else c for c in payload)


def null_byte(payload: str) -> str:
    return payload + "%00"


TAMPERS: Dict[str, Callable[[str], str]] = {
    "case_swap": case_swap,
    "inline_comments": inline_comments,
    "space_to_plus": space_to_plus,
    "double_url_encode": double_url_encode,
    "unicode_encode": unicode_encode,
    "null_byte": null_byte,
}


def apply(payload: str, names: List[str]) -> List[str]:
    """Return [original, *tampered variants]. Unknown names ignored."""
    out = [payload]
    for name in names or []:
        fn = TAMPERS.get(name)
        if fn:
            try:
                out.append(fn(payload))
            except Exception:
                continue
    return out


def catalog() -> List[Dict[str, str]]:
    return [{"name": n, "use": f.__doc__ or ""} for n, f in TAMPERS.items()]
