"""Shared base for web validators — session wiring, stealth HTTP, reports."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]


class WebValidator:
    """Base class: stealth GET/POST, candidate targets, finding+report I/O."""

    source = "validate.web"
    out_name = "web"

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger(self.source)
        self.out_dir = session.dir("validate") / self.out_name
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)
        self.timeout = 12

    # ── HTTP (stealth-paced) ──────────────────────────────

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        try:
            from modules.fingerprint import headers_for
            h = headers_for()
        except Exception:
            h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ARDF-validate"}
        if extra:
            h.update(extra)
        return h

    def _get(self, url: str, params: Optional[Dict] = None,
             headers: Optional[Dict] = None):
        try:
            from modules.rateboss import take
            take()
        except Exception:
            self.stealth.sleep(0.4)
        r = requests.get(url, params=params, headers=self._headers(headers),
                         timeout=self.timeout, verify=False)
        self._watch(r, url)
        return r

    def _post(self, url: str, data: Optional[Dict] = None,
              headers: Optional[Dict] = None):
        try:
            from modules.rateboss import take
            take()
        except Exception:
            self.stealth.sleep(0.4)
        r = requests.post(url, data=data, headers=self._headers(headers),
                          timeout=self.timeout, verify=False)
        self._watch(r, url)
        return r

    @staticmethod
    def differential(a: str, b: str) -> Dict[str, Any]:
        """Nonce-aware response comparison (see modules.diffengine)."""
        from modules.diffengine import differs
        return differs(a, b)

    @staticmethod
    def _watch(r, url: str) -> None:
        """Feed response signals to counter-detection (are THEY flagging us?)."""
        try:
            from modules.counterdetect import get_watch
            w = get_watch()
            w.record(getattr(r, "status_code", 0), url,
                     getattr(r, "text", "") or "")
            if w.hostile >= 4 and w.hostile % 4 == 0:
                get_logger("counterdetect").warning(
                    "counterdetect: " + w.advise()["advice"])
        except Exception:
            pass

    # ── candidate target collection ───────────────────────

    def _base(self, target: str) -> str:
        return target if target.startswith("http") else f"https://{target}"

    def candidate_urls(self, target: str, limit: int = 15) -> List[str]:
        """Live URLs from session findings, else the bare target."""
        urls: List[str] = []
        for f in self.session.get_findings():
            raw = f.raw or {}
            if isinstance(raw, dict):
                for key in ("url", "live_url", "target_url"):
                    if raw.get(key) and raw[key] not in urls:
                        urls.append(raw[key])
            if f.host and f.host.startswith("http") and f.host not in urls:
                urls.append(f.host)
        if not urls:
            urls = [self._base(target)]
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out[:limit]

    # ── output helpers ────────────────────────────────────

    def add_finding(self, title: str, url: str, severity: SeverityLevel,
                    tags: List[str], description: str = "",
                    evidence: str = "", remediation: str = "") -> None:
        self.session.add_finding(Finding(
            source=self.source, title=title,
            description=description or title, severity=severity, host=url,
            tags=tags, evidence=evidence, remediation=remediation))

    def save(self, name: str, results: Dict[str, Any]) -> Path:
        p = self.out_dir / f"{name}.json"
        p.write_text(json.dumps(results, indent=2, default=str))
        return p

    @staticmethod
    def marker(n: int = 8) -> str:
        import random
        import string
        return "ardf" + "".join(random.choice(string.ascii_lowercase)
                                for _ in range(n))
