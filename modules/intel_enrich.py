"""Intel auto-enrichment — CVE + OSINT enrichment on demand per finding."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session


def enrich_finding(session: Session, finding_id: str,
                   logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """Enrich a single finding: CVE records via NVD + tag-based OSINT hints."""
    from modules.intel import get_engine
    if logger is None:
        logger = get_logger("intel.enrich")
    findings = session.get_findings()
    target = next((f for f in findings if f.id == finding_id), None)
    if target is None:
        raise ValueError(f"finding not found: {finding_id}")
    engine = get_engine()
    cves = engine.enrich_cves([target], logger, with_ai=False)
    hints = _osint_hints(target)
    if hints and "osint_enriched" not in target.tags:
        target.tags = sorted(set(target.tags) | {"osint_enriched"})
    logger.success(f"enriched {finding_id}: {len(cves)} CVE refs, "
                   f"{len(hints)} OSINT hints")
    return {"finding_id": finding_id, "cves": cves, "osint_hints": hints}


def auto_enrich(session: Session, logger: Optional[ARDFLogger] = None,
                max_findings: int = 30) -> Dict[str, Any]:
    """Enrich all high/critical findings lacking enrichment (D22)."""
    if logger is None:
        logger = get_logger("intel.enrich")
    from modules.session import SeverityLevel
    hot = [f for f in session.get_findings()
           if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
           and "osint_enriched" not in f.tags][:max_findings]
    done, errors = 0, 0
    for f in hot:
        try:
            enrich_finding(session, f.id, logger)
            done += 1
        except Exception as e:
            logger.warning(f"enrich failed for {f.id}: {e}")
            errors += 1
    return {"enriched": done, "errors": errors, "candidates": len(hot)}


def _osint_hints(finding) -> List[Dict[str, Any]]:
    hints = []
    tags = {t.lower() for t in finding.tags}
    if "subdomain" in tags:
        hints.append({"type": "dns_history",
                      "hint": "check SecurityTrails/crt.sh for origin IP"})
    if "s3" in tags or "bucket" in tags:
        hints.append({"type": "bucket_enum",
                      "hint": "test ListBucket + common prefixes"})
    if "cloud" in tags:
        hints.append({"type": "cloud_billing",
                      "hint": "enumerate sibling regions/accounts"})
    if finding.cve:
        hints.append({"type": "exploit_db",
                      "hint": f"search Exploit-DB for {finding.cve}"})
    return hints
