"""Response differ — nonce-aware comparison killing false differentials.

Strips per-request volatile material (CSRF tokens, viewstates, timestamps,
nonces, session ids) before comparing, so boolean/reflection oracles only
fire on REAL application differences. Used by every validator via web_base.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

_PATTERNS = [
    r'value="[A-Za-z0-9_\-+/=]{20,}"',          # hidden input tokens
    r"value='[A-Za-z0-9_\-+/=]{20,}'",
    r"__[A-Z_]+\"?\s*[:=]\s*\"?[A-Za-z0-9_\-+/=]{16,}",  # __VIEWSTATE etc
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\"'<\s]*",  # timestamps
    r"\b[0-9a-f]{32,}\b",                        # hex nonces/hashes
    r"Fri, \d{2} \w{3} \d{4} [\d:]+ GMT",        # http dates in body
]
_RES = [re.compile(p) for p in _PATTERNS]


def normalize(text: str) -> str:
    out = text or ""
    for rx in _RES:
        out = rx.sub("", out)
    return out


def differs(a: str, b: str) -> Dict[str, Any]:
    """Compare after normalization. Returns {different, len_a, len_b}."""
    na, nb = normalize(a), normalize(b)
    return {"different": na != nb, "len_a": len(na), "len_b": len(nb)}


def reflection_points(html: str, marker: str) -> List[str]:
    """Contexts where marker appears (post-normalization positions)."""
    contexts = []
    for m in re.finditer(re.escape(marker), html or ""):
        before = html[max(0, m.start() - 100):m.start()]
        if "<!--" in before.split("-->")[-1]:
            contexts.append("comment")
        elif re.search(r"<[^>]*$", before):
            contexts.append("tag")
        else:
            contexts.append("body")
    return contexts
