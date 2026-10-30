"""Reflected XSS validation — benign marker reflection + context detection.

Sends a unique inert marker (no script execution). Flags a finding only
when the exact marker reflects, with the HTML context recorded
(attribute / tag / script / comment) for manual follow-up.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from modules.logger import ARDFLogger
from modules.session import Session, SeverityLevel
from modules.validate.web_base import WebValidator


class XSSValidator(WebValidator):
    source = "validate.xss"
    out_name = "xss"

    PROBE_HINTS = ["q", "query", "search", "s", "keyword", "name", "message",
                   "comment", "text", "title", "redirect", "url", "lang"]

    def _context(self, html: str, marker: str) -> str:
        idx = html.find(marker)
        if idx < 0:
            return "none"
        before, after = html[max(0, idx - 120):idx], html[idx:idx + 120]
        if "<!--" in before.split("-->")[-1]:
            return "comment"
        if "<script" in before.split("<")[-1] or "</script>" in after[:40]:
            return "script"
        if re.search(r"<[^>]*$", before):
            return "tag-attribute" if "=" in before.split("<")[-1] else "tag"
        return "html-body"

    def test_url(self, url: str) -> Dict[str, Any]:
        marker = self.marker()
        parts = urlparse(url)
        params = dict(parse_qsl(parts.query))
        tested = params.keys() or ["q"]
        hits = []
        for name in list(tested)[:8]:
            probe = dict(params)
            probe[name] = f"prefix{marker}suffix"
            target = urlunparse(parts._replace(query=urlencode(probe)))
            try:
                r = self._get(target)
                if marker in r.text:
                    hits.append({"param": name,
                                 "context": self._context(r.text, marker)})
            except Exception:
                continue
        return {"url": url, "hits": hits}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"XSS VALIDATION: {target}", style="bold red")
        results: Dict[str, Any] = {"target": target, "tested": [], "vulnerable": []}
        for url in self.candidate_urls(target):
            try:
                res = self.test_url(url)
            except Exception as e:
                res = {"url": url, "error": str(e)[:200], "hits": []}
            results["tested"].append(res)
            for hit in res.get("hits", []):
                results["vulnerable"].append({"url": url, **hit})
                self.add_finding(
                    f"Reflected input: param '{hit['param']}' reflects ({hit['context']})",
                    url, SeverityLevel.MEDIUM, ["xss", "reflected", "injection"],
                    f"Benign marker reflected in {hit['context']} context — "
                    "confirm exploitability manually with an inert proof payload.",
                    evidence=f"param={hit['param']} context={hit['context']}",
                    remediation="Context-aware output encoding + CSP. "
                                "Validate input on server side.")
        self.save("xss_report", results)
        self.logger.success(f"XSS: {len(results['tested'])} URLs, "
                            f"{len(results['vulnerable'])} reflections")
        return results
