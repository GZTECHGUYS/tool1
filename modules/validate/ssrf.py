"""SSRF candidate mapping — identifies fetch-likely params, no callbacks.

Blind SSRF confirmation needs an out-of-band listener, which this module
never assumes. It flags params whose names/values look fetchable
(url, redirect, path, dest, …) as candidates, and supports an operator
-supplied callback URL for manual confirmation.
"""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qsl

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class SSRFValidator(WebValidator):
    source = "validate.ssrf"
    out_name = "ssrf"

    CANDIDATE_NAMES = {"url", "uri", "link", "src", "source", "redirect",
                       "next", "dest", "destination", "path", "file", "page",
                       "feed", "fetch", "proxy", "callback", "webhook",
                       "image", "img", "avatar", "logo", "pdf", "doc"}

    def test_url(self, url: str, callback: str = "") -> Dict[str, Any]:
        params = dict(parse_qsl(urlparse(url).query))
        candidates = [n for n in params
                      if n.lower() in self.CANDIDATE_NAMES
                      or str(params[n]).startswith(("http", "/", "file:"))]
        return {"url": url, "candidates": candidates,
                "callback_offered": bool(callback)}

    def validate(self, url: str, callback: str = "") -> Dict[str, Any]:
        return self.test_url(url, callback)

    def run(self, target: str, callback: str = "") -> Dict[str, Any]:
        self.logger.banner(f"SSRF MAPPING: {target}", style="bold red")
        results: Dict[str, Any] = {"target": target, "tested": [], "candidates": []}
        for url in self.candidate_urls(target):
            res = self.test_url(url, callback)
            results["tested"].append(res)
            for name in res["candidates"]:
                results["candidates"].append({"url": url, "param": name})
                self.add_finding(
                    f"SSRF candidate: param '{name}' looks server-fetchable",
                    url, SeverityLevel.MEDIUM, ["ssrf", "candidate"],
                    "Parameter name/value suggests server-side fetching. "
                    "Confirm manually with a collaborator/callback URL; "
                    "block metadata endpoints (169.254.169.254) regardless.",
                    evidence=f"param={name}",
                    remediation="Allow-list fetch domains. Deny metadata IP. "
                                "Require auth for fetch features.")
        self.save("ssrf_report", results)
        self.logger.success(f"SSRF: {len(results['tested'])} URLs, "
                            f"{len(results['candidates'])} candidates")
        return results
