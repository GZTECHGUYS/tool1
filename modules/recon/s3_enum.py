"""S3 bucket tester — name generation + anonymous ListBucket check.

Builds candidate bucket names from the target, then performs
unauthenticated GETs only. A `ListBucketResult` XML response means
public listing — recorded as HIGH. Never attempts PUT/write.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

SUFFIXES = ["", "-backup", "-backups", "-data", "-assets", "-static",
            "-media", "-files", "-prod", "-dev", "-test", "-staging",
            "-uploads", "-downloads", "-private", "-public", "-www",
            "-app", "-web", "-logs", "-archive"]


def candidates(domain: str) -> List[str]:
    base = domain.split(".")[0].lower()
    parts = re.sub(r"[^a-z0-9-]", "", domain.lower().replace(".", "-"))
    names = {f"{base}{s}" for s in SUFFIXES}
    names.add(parts)
    names.add(f"{parts}-backup")
    return sorted(names)[:25]


def test_bucket(name: str, timeout: int = 10) -> Dict[str, Any]:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "ARDF-s3enum"})
    except Exception as e:
        return {"bucket": name, "error": str(e)[:120]}
    body = r.text or ""
    if "ListBucketResult" in body:
        keys = re.findall(r"<Key>([^<]{1,80})", body)
        return {"bucket": name, "public_list": True, "keys": keys[:10]}
    if r.status_code == 403:
        return {"bucket": name, "public_list": False, "exists": True}
    if r.status_code == 404:
        return {"bucket": name, "public_list": False, "exists": False}
    return {"bucket": name, "public_list": False,
            "status": r.status_code}


def run(session: Session, target: str = "",
        logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("recon.s3")
    domain = (target or session.meta.target).split("/")[0].split(":")[0]
    exposed = []
    for name in candidates(domain):
        res = test_bucket(name)
        if res.get("public_list"):
            exposed.append(res)
            session.add_finding(Finding(
                source="recon.s3",
                title=f"PUBLIC S3 bucket listing: {name}",
                description="Anonymous ListBucket succeeds. Sample keys: " +
                            ", ".join(res.get("keys", [])[:5]),
                severity=SeverityLevel.HIGH, host=name,
                tags=["s3", "bucket", "cloud", "recon"],
                remediation="Block public access (account + bucket policy). "
                            "Audit for secrets in listed objects."))
    logger.success(f"s3: {len(exposed)} public listings")
    return {"domain": domain, "tested": len(candidates(domain)),
            "exposed": exposed}
