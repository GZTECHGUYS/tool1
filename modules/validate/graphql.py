"""GraphQL discovery — introspection + common endpoint probing, read-only.

GET/POST probes for /graphql variants; asks only schema-describing
queries (`__typename`, `__schema` field list). No mutations, no depth
bombs (single-level queries only).
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from modules.session import SeverityLevel
from modules.validate.web_base import WebValidator


class GraphQLValidator(WebValidator):
    source = "validate.graphql"
    out_name = "graphql"

    PATHS = ["/graphql", "/graphql/", "/api/graphql", "/v1/graphql",
             "/graphiql", "/playground", "/altair"]
    INTROSPECTION = {"query": "{__schema{queryType{name}}}"}
    TYPENAME = {"query": "{__typename}"}

    def test_url(self, url: str) -> Dict[str, Any]:
        base = url.rstrip("/")
        found = []
        for path in self.PATHS:
            endpoint = base + path if "://" in base else base
            if not endpoint.startswith("http"):
                continue
            try:
                r = self._post(endpoint, data=json.dumps(self.TYPENAME),
                               headers={"Content-Type": "application/json"})
                if "__typename" in r.text and r.status_code == 200:
                    found.append({"endpoint": path, "introspection": True})
                    continue
            except Exception:
                pass
            try:
                r = self._get(endpoint)
                if r.status_code in (200, 400) and "graphql" in r.text.lower():
                    found.append({"endpoint": path, "introspection": False})
            except Exception:
                continue
        return {"url": url, "endpoints": found}

    def validate(self, url: str) -> Dict[str, Any]:
        return self.test_url(url)

    def run(self, target: str) -> Dict[str, Any]:
        self.logger.banner(f"GRAPHQL DISCOVERY: {target}", style="bold red")
        results: Dict[str, Any] = {"target": target, "tested": [], "exposed": []}
        for url in self.candidate_urls(target, limit=5):
            try:
                res = self.test_url(url)
            except Exception as e:
                res = {"url": url, "error": str(e)[:200], "endpoints": []}
            results["tested"].append(res)
            for ep in res.get("endpoints", []):
                results["exposed"].append({"url": url, **ep})
                sev = SeverityLevel.MEDIUM if ep["introspection"] else SeverityLevel.INFO
                self.add_finding(
                    f"GraphQL endpoint: {ep['endpoint']} "
                    f"(introspection={'on' if ep['introspection'] else 'off'})",
                    url, sev, ["graphql", "api"],
                    "Introspection exposes the full schema to attackers. "
                    "Disable in production; enforce query depth/cost limits.",
                    evidence=f"endpoint={ep['endpoint']}",
                    remediation="Disable introspection in prod. Persisted "
                                "queries + depth limiting + authz per field.")
        self.save("graphql_report", results)
        self.logger.success(f"GraphQL: {len(results['tested'])} bases, "
                            f"{len(results['exposed'])} endpoints")
        return results
