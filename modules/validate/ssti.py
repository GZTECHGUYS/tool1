"""SSTI validation — safe arithmetic evaluation probes only.

Sends template math (`7*7`) variants per engine. Flags only when the
computed value (49) renders — pure detection, no object access, no RCE.
"""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class SSTIValidator(WebValidator):
    source = "validate.ssti"
    out_name = "ssti"

    PROBES = [
        ("jinja2/twig", "{{7*7}}", "49"),
        ("smarty", "{7*7}", "49"),
        ("freemarker", "${7*7}", "49"),
        ("erb", "<%= 7*7 %>", "49"),
        ("polyglot", "{{7*'7'}}", "49"),
    ]

    def test_url(self, url: str) -> Dict[str, Any]:
        parts = urlparse(url)
        params = dict(parse_qsl(parts.query))
        names = list(params.keys())[:6] or ["q"]
        hits = []
        for engine, probe, expect in self.PROBES:
            for name in names:
                trial = dict(params)
                trial[name] = probe
                target = urlunparse(parts._replace(query=urlencode(trial)))
                try:
                    r = self._get(target)
                    if expect in r.text and probe not in r.text:
                        hits.append({"param": name, "engine": engine})
                        break
                except Exception:
                    continue
        return {"url": url, "hits": hits}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"SSTI VALIDATION: {target}", style="bold red")
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
                    f"SSTI ({hit['engine']}): param '{hit['param']}' evaluates templates",
                    url, SeverityLevel.CRITICAL, ["ssti", "injection", "rce-risk"],
                    "Arithmetic template evaluated server-side. Treat as "
                    "potential RCE — confirm manually in a sandbox.",
                    evidence=f"param={hit['param']} engine={hit['engine']}",
                    remediation="Never render user input as template. "
                                "Use logic-less templates + sandbox.")
        self.save("ssti_report", results)
        self.logger.success(f"SSTI: {len(results['tested'])} URLs, "
                            f"{len(results['vulnerable'])} hits")
        return results
