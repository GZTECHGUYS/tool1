"""Host-header audit — reflection / poisoning indicators, no reset abuse.

Checks whether attacker-controlled Host / X-Forwarded-Host is reflected
(cache-poisoning indicator) and whether absolute URLs are built from it.
Never triggers password-reset emails or state-changing flows.
"""
from __future__ import annotations

from typing import Any, Dict

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class HostHeaderValidator(WebValidator):
    source = "validate.hostheader"
    out_name = "hostheader"

    EVIL = "ardf-evil.invalid"

    def test_url(self, url: str) -> Dict[str, Any]:
        try:
            base = self._get(url)
        except Exception as e:
            return {"url": url, "error": str(e)[:200], "reflected": False}
        try:
            evil = self._get(url, headers={"Host": self.EVIL,
                                           "X-Forwarded-Host": self.EVIL})
        except Exception as e:
            return {"url": url, "error": str(e)[:200], "reflected": False}
        reflected = self.EVIL in evil.text and self.EVIL not in base.text
        return {"url": url, "reflected": reflected,
                "status_evil": evil.status_code, "status_base": base.status_code}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"HOST-HEADER AUDIT: {target}", style="bold red")
        results: Dict[str, Any] = {"target": target, "tested": [], "reflected": []}
        for url in self.candidate_urls(target, limit=8):
            res = self.test_url(url)
            results["tested"].append(res)
            if res.get("reflected"):
                results["reflected"].append(res)
                self.add_finding(
                    "Host header reflected (cache-poisoning indicator)",
                    url, SeverityLevel.MEDIUM, ["host-header", "cache-poison"],
                    "Attacker Host value renders in responses — poisonable "
                    "through shared caches. No reset/state flows triggered.",
                    evidence="Host: ardf-evil.invalid reflected",
                    remediation="Validate Host against allow-list. Use "
                                "relative URLs / configured canonical host.")
        self.save("hostheader_report", results)
        self.logger.success(f"Host-header: {len(results['tested'])} URLs, "
                            f"{len(results['reflected'])} reflections")
        return results
