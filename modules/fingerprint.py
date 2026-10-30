"""HTTP fingerprint rotation — vary the client signature per request.

Rotates User-Agent (from config stealth list), Accept-Language, and
header casing/order profiles so bulk requests don't share one static
fingerprint. Complements (not replaces) proxy egress.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

CONFIG_PATH = Path(__file__).parent.parent / "config" / "ardf.yaml"

FALLBACK_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.7",
         "de-DE,de;q=0.9,en;q=0.6"]

PROFILES = ("chrome_win", "firefox_linux", "safari_mac", "edge_win")


def _ua_pool() -> List[str]:
    if HAVE_YAML and CONFIG_PATH.exists():
        try:
            data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            pool = ((data.get("stealth", {}) or {})
                    .get("user_agents", []) or [])
            if pool:
                return pool
        except Exception:
            pass
    return FALLBACK_UAS


def headers_for(profile: str = "") -> Dict[str, str]:
    """A rotated, browser-plausible header set."""
    uas = _ua_pool()
    profile = profile or random.choice(PROFILES)
    if "firefox" in profile:
        ua = next((u for u in uas if "Firefox/" in u or " rv:" in u), uas[0])
        sec_ua = None
    elif "safari" in profile:
        ua = next((u for u in uas if "Safari" in u and "Chrome" not in u),
                  uas[-1] if len(uas) > 2 else uas[0])
        sec_ua = None
    else:
        ua = next((u for u in uas if "Chrome" in u), uas[0])
        sec_ua = '"Chromium";v="120", "Not(A:Brand";v="24"'
    h: Dict[str, str] = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(LANGS),
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
    }
    if sec_ua:
        h["Sec-Ch-Ua"] = sec_ua
    # slight order/casing variance defeats naive header-hash fingerprinting
    items = list(h.items())
    random.shuffle(items)
    return dict(items)


def rotate_ua() -> str:
    return random.choice(_ua_pool())


def catalog() -> Dict[str, Any]:
    return {"profiles": list(PROFILES), "languages": LANGS,
            "ua_pool_size": len(_ua_pool())}
