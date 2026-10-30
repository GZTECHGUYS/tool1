"""DNS-over-HTTPS resolver — keep recon names out of local resolver logs.

Queries Cloudflare / Google DoH JSON endpoints over HTTPS (optionally
via the proxy chain). Falls back to an error dict — never to plaintext
system DNS — so callers know exactly what leaked where.
"""
from __future__ import annotations

from typing import Any, Dict, List

import requests

PROVIDERS = [
    "https://cloudflare-dns.com/dns-query?name={q}&type={t}",
    "https://dns.google/resolve?name={q}&type={t}",
]


def doh_query(name: str, rtype: str = "A", timeout: int = 10,
              proxy: str = "") -> Dict[str, Any]:
    """Resolve via DoH. Returns {answers:[...], provider} or {error}."""
    session = requests.Session()
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    errors = []
    for tpl in PROVIDERS:
        try:
            r = session.get(tpl.format(q=name, t=rtype), timeout=timeout,
                            headers={"Accept": "application/dns-json"})
            data = r.json()
            answers = [a.get("data", "") for a in data.get("Answer", [])]
            if answers:
                return {"name": name, "type": rtype, "answers": answers,
                        "provider": tpl.split("/")[2]}
            errors.append(f"{tpl.split('/')[2]}: no answers")
        except Exception as e:
            errors.append(f"{tpl.split('/')[2]}: {str(e)[:100]}")
    return {"name": name, "type": rtype, "answers": [], "errors": errors}


def resolve_many(names: List[str], rtype: str = "A",
                 proxy: str = "") -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for n in names[:50]:
        out[n] = doh_query(n, rtype, proxy=proxy).get("answers", [])
    return out
