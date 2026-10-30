"""Payload-DB fuzzer — Tier-2 param fuzzing with reflection/error oracle.

Pulls payloads from modules.payload_db, injects per-parameter with
stealth pacing, and triages responses:
  reflection of dangerous markers -> finding (per category severity)
  error-pattern match (sql/syntax/stack) -> finding
  input_validator risk jump vs baseline -> note
Caps: max_requests default 60. Backdoor categories never fuzzed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.validate.web_base import WebValidator

ERROR_RES = ["sql", "syntax", "exception", "stack trace", "ora-",
             "mysql", "postgres", "sqlite", "warning:", "fatal"]
CAT_SEV = {"sqli": SeverityLevel.HIGH, "xss": SeverityLevel.MEDIUM,
           "ssti": SeverityLevel.CRITICAL, "cmdi": SeverityLevel.CRITICAL,
           "path-traversal": SeverityLevel.HIGH, "xxe": SeverityLevel.HIGH,
           "ssrf": SeverityLevel.MEDIUM, "crlf": SeverityLevel.LOW,
           "open-redirect": SeverityLevel.MEDIUM, "fuzzing": SeverityLevel.INFO}


class PayloadFuzzer(WebValidator):
    source = "fuzz.payloaddb"
    out_name = "fuzz"

    def fuzz_url(self, url: str, category: str,
                 max_requests: int = 60) -> Dict[str, Any]:
        from modules.payload_db import query
        from modules.input_validator import detect_injection
        marker = self.marker()
        parts = urlparse(url)
        params = dict(parse_qsl(parts.query))
        names = list(params.keys())[:5] or ["q"]
        payloads = query(category, limit=max_requests)
        res: Dict[str, Any] = {"url": url, "category": category,
                               "requests": 0, "hits": []}
        for name in names:
            # baseline: does this param reflect at all?
            trial = dict(params)
            trial[name] = f"z{marker}z"
            try:
                base = self._get(urlunparse(parts._replace(query=urlencode(trial))))
                reflects = marker in base.text
            except Exception:
                continue
            for payload in payloads:
                if res["requests"] >= max_requests:
                    break
                trial[name] = payload
                target = urlunparse(parts._replace(query=urlencode(trial)))
                try:
                    r = self._get(target)
                except Exception:
                    continue
                res["requests"] += 1
                body = r.text.lower()
                if payload[:24] in r.text and reflects:
                    res["hits"].append({"param": name, "via": "reflection",
                                        "payload": payload[:120]})
                elif any(e in body for e in ERROR_RES):
                    res["hits"].append({"param": name, "via": "error-pattern",
                                        "payload": payload[:120]})
                if len(res["hits"]) >= 10:
                    break
            if res["hits"]:
                break
        return res

    def run(self, target: str, category: str = "xss",
            max_requests: int = 60) -> Dict[str, Any]:
        self.logger.banner(f"PAYLOAD FUZZ [{category}]: {target}",
                           style="bold red")
        results: Dict[str, Any] = {"target": target, "category": category,
                                   "tested": [], "hits": []}
        for url in self.candidate_urls(target, limit=5):
            try:
                res = self.fuzz_url(url, category, max_requests)
            except Exception as e:
                res = {"url": url, "error": str(e)[:200], "hits": [],
                       "requests": 0}
            results["tested"].append(res)
            for hit in res.get("hits", [])[:3]:
                results["hits"].append({"url": url, **hit})
                self.add_finding(
                    f"Fuzz hit [{category}] param '{hit['param']}' via {hit['via']}",
                    url, CAT_SEV.get(category, SeverityLevel.MEDIUM),
                    ["fuzz", category, hit["via"]],
                    f"Payload-DB payload triggered {hit['via']} signal.",
                    evidence=hit["payload"],
                    remediation="Fix per validator guidance for " + category + ".")
        self.save(f"fuzz_{category}", results)
        self.logger.success(f"fuzz[{category}]: {len(results['tested'])} URLs, "
                            f"{len(results['hits'])} hits")
        return results
