"""CORS misconfiguration test — evil-origin reflection check, no exfil.

Sends `Origin: https://ardf-evil.invalid` and inspects ACAO/ACAC.
Never reads authenticated responses — header analysis only.
"""
from __future__ import annotations

from typing import Any, Dict

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class CORSValidator(WebValidator):
    source = "validate.cors"
    out_name = "cors"

    EVIL = "https://ardf-evil.invalid"

    def test_url(self, url: str) -> Dict[str, Any]:
        try:
            r = self._get(url, headers={"Origin": self.EVIL})
        except Exception as e:
            return {"url": url, "error": str(e)[:200], "misconfigured": False}
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        reflected = acao == self.EVIL
        wildcard = acao == "*"
        return {"url": url, "acao": acao, "acac": acac,
                "misconfigured": bool(reflected or (wildcard and acac.lower() == "true")),
                "reflected": reflected, "wildcard_with_creds": bool(wildcard and acac)}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"CORS VALIDATION: {target}", style="bold red")
        results: Dict[str, Any] = {"target": target, "tested": [], "misconfigured": []}
        for url in self.candidate_urls(target):
            res = self.test_url(url)
            results["tested"].append(res)
            if res.get("misconfigured"):
                results["misconfigured"].append(res)
                self.add_finding(
                    f"CORS misconfig: {res.get('acao')} "
                    f"(credentials={res.get('acac') or 'off'})",
                    url, SeverityLevel.MEDIUM, ["cors", "misconfig"],
                    "Arbitrary origins can read responses; with credentials "
                    "this enables session riding. Header analysis only — "
                    "no authenticated data touched.",
                    evidence=f"ACAO={res.get('acao')} ACAC={res.get('acac')}",
                    remediation="Mirror a strict allow-list of origins. "
                                "Never combine ACAO:* with credentials.")
        self.save("cors_report", results)
        self.logger.success(f"CORS: {len(results['tested'])} URLs, "
                            f"{len(results['misconfigured'])} misconfigured")
        return results
