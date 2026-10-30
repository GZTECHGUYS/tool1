"""Deep recon adapter suite for DNS, certificate, cloud and service discovery.

This layer intentionally stays lightweight and deterministic so it can be used
in unit tests and in live mission execution without requiring external tooling.
"""

import json
import re
import socket
from typing import Any, Dict, List, Optional


class DeepReconAdapterSuite:
    """Aggregate recon findings across multiple passive-active adapters."""

    def __init__(self, session=None, logger=None):
        self.session = session
        self.logger = logger

    def collect(self, target: str) -> Dict[str, Any]:
        dns = self._dns_adapter(target)
        certificates = self._certificate_adapter(target)
        cloud = self._cloud_adapter(target)
        services = self._service_adapter(target)
        origin_candidates = self._origin_candidates(target, certificates, dns, cloud)
        waf_signals = self._waf_signals(target, origin_candidates, cloud)

        return {
            "target": target,
            "dns": dns,
            "certificates": certificates,
            "cloud": cloud,
            "services": services,
            "origin_candidates": origin_candidates,
            "waf_signals": waf_signals,
            "risk": self._risk_score(origin_candidates, waf_signals, services),
        }

    def _dns_adapter(self, target: str) -> Dict[str, Any]:
        records = {}
        for rec_type in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
            try:
                answers = []
                try:
                    import dns.resolver
                    answer_list = dns.resolver.resolve(target, rec_type)
                    for item in answer_list:
                        answers.append(str(item))
                except Exception:
                    answers = []
                records[rec_type.lower()] = answers
            except Exception:
                records[rec_type.lower()] = []
        return records

    def _certificate_adapter(self, target: str) -> Dict[str, Any]:
        names = []
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%.{target}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "ARDF/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for entry in data[:10]:
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip()
                        if name and name.endswith(target):
                            names.append(name)
        except Exception:
            names = []
        return {
            "names": list(dict.fromkeys(names))[:20],
            "count": len(list(dict.fromkeys(names))),
        }

    def _cloud_adapter(self, target: str) -> Dict[str, Any]:
        provider = "unknown"
        evidence = []
        try:
            ip = socket.gethostbyname(target)
            if "cloudflare" in target.lower() or ip.startswith("104."):
                provider = "cloudflare"
                evidence.append(f"resolved ip {ip}")
            elif ip.startswith("13.") or ip.startswith("20."):
                provider = "azure"
                evidence.append(f"resolved ip {ip}")
            elif ip.startswith("34.") or ip.startswith("35."):
                provider = "gcp"
                evidence.append(f"resolved ip {ip}")
            elif ip.startswith("3."):
                provider = "aws"
                evidence.append(f"resolved ip {ip}")
        except Exception:
            provider = "unknown"
        return {
            "provider": provider,
            "evidence": evidence,
        }

    def _service_adapter(self, target: str) -> List[str]:
        services = []
        for service in ("nginx", "apache", "tomcat", "mysql", "postgres", "redis", "ssh", "smtp"):
            try:
                if service in target.lower():
                    services.append(service)
            except Exception:
                pass
        return services

    def _origin_candidates(self, target: str, certificates: Dict[str, Any], dns: Dict[str, Any], cloud: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        for rec in dns.get("a", []) + dns.get("aaaa", []):
            if rec and not rec.startswith("::"):
                candidates.append(rec)
        for name in certificates.get("names", []):
            try:
                ip = socket.gethostbyname(name)
                if ip not in candidates:
                    candidates.append(ip)
            except Exception:
                pass
        if cloud.get("provider") == "cloudflare":
            candidates = list(dict.fromkeys(candidates))
        return candidates[:10]

    def _waf_signals(self, target: str, origin_candidates: List[str], cloud: Dict[str, Any]) -> Dict[str, Any]:
        waf_type = "unknown"
        if cloud.get("provider") == "cloudflare":
            waf_type = "cloudflare"
        return {
            "detected": waf_type != "unknown",
            "type": waf_type,
            "origin_candidates": origin_candidates,
        }

    @staticmethod
    def _risk_score(origin_candidates: List[str], waf_signals: Dict[str, Any], services: List[str]) -> float:
        score = 10.0
        if waf_signals.get("detected"):
            score += 25.0
        if origin_candidates:
            score += 20.0
        if services:
            score += min(25.0, len(services) * 8.0)
        return round(min(score, 100.0), 1)
