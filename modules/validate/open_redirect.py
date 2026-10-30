"""Open-redirect validation — 30x Location reflection against safe hosts.

Uses example.com / ardf-probe.invalid as redirect targets (never attacker
infrastructure), so a positive only proves reflection, never delivers
victims anywhere.
"""
from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class OpenRedirectValidator(WebValidator):
    source = "validate.redirect"
    out_name = "redirect"

    PARAMS = {"redirect", "next", "url", "return", "returnto", "return_url",
              "continue", "dest", "destination", "target", "to", "go", "r"}
    SAFE_HOSTS = ["https://example.com/", "https://ardf-probe.invalid/"]

    def test_url(self, url: str) -> Dict[str, Any]:
        parts = urlparse(url)
        params = dict(parse_qsl(parts.query))
        names = [n for n in params if n.lower() in self.PARAMS] or (
            list(params.keys())[:3])
        hits = []
        for name in names:
            for safe in self.SAFE_HOSTS:
                trial = dict(params)
                trial[name] = safe
                target = urlunparse(parts._replace(query=urlencode(trial)))
                try:
                    r = self._get(target)
                    loc = r.headers.get("Location", "")
                    if "example.com" in loc or "ardf-probe.invalid" in loc:
                        hits.append({"param": name, "location": loc[:120]})
                        break
                    if r.status_code in (301, 302, 303, 307, 308) and safe in r.text:
                        hits.append({"param": name, "location": "body-reflect"})
                        break
                except Exception:
                    continue
        return {"url": url, "hits": hits}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"OPEN-REDIRECT VALIDATION: {target}", style="bold red")
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
                    f"Open redirect: param '{hit['param']}' follows off-site",
                    url, SeverityLevel.MEDIUM, ["open-redirect", "phishing-aid"],
                    "Unvalidated redirect enables phishing. Proven with "
                    "benign example.com target only.",
                    evidence=f"param={hit['param']}",
                    remediation="Allow-list redirect targets. Use indirect "
                                "reference map (e.g. ?next=dashboard).")
        self.save("redirect_report", results)
        self.logger.success(f"Redirect: {len(results['tested'])} URLs, "
                            f"{len(results['vulnerable'])} hits")
        return results
