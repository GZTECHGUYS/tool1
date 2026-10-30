"""Executive PDF export + remediation lifecycle tracking."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, SeverityLevel


# ── PDF (reportlab, optional dep with graceful fallback) ─────

def build_pdf(session: Session, logger: Optional[ARDFLogger] = None,
              filename: str = "") -> Path:
    """Executive summary PDF: counts, top findings, kill-chain coverage."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
    except ImportError as e:
        raise RuntimeError(
            "reportlab not installed: "
            "sudo apt-get install -y python3-reportlab "
            "(or pip install reportlab)") from e
    if logger is None:
        logger = get_logger("report.pdf")

    findings = session.get_findings()
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    out = session.dir("report") / (filename or
          f"ardf_executive_{session.meta.session_id}.pdf")
    c = canvas.Canvas(str(out), pagesize=A4)
    w, h = A4
    y = h - 20 * mm
    c.setFont("Helvetica-Bold", 18)
    c.drawString(20 * mm, y, "ARDF Executive Summary")
    y -= 10 * mm
    c.setFont("Helvetica", 11)
    for line in (f"Target: {session.meta.target}",
                 f"Session: {session.meta.session_id}",
                 f"Generated: {datetime.now().isoformat(timespec='seconds')}",
                 f"Findings: {len(findings)}",
                 "By severity: " + (", ".join(
                     f"{k}={v}" for k, v in sorted(by_sev.items()))
                     if by_sev else "none")):
        c.drawString(20 * mm, y, line[:110])
        y -= 7 * mm
    y -= 3 * mm
    c.setFont("Helvetica-Bold", 13)
    c.drawString(20 * mm, y, "Top findings")
    y -= 8 * mm
    c.setFont("Helvetica", 10)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = sorted(findings, key=lambda f: order.get(f.severity.value, 9))[:20]
    for f in top:
        if y < 25 * mm:
            c.showPage()
            y = h - 20 * mm
            c.setFont("Helvetica", 10)
        c.drawString(20 * mm, y, f"[{f.severity.value.upper()}] {f.title[:90]}")
        y -= 6 * mm
    c.save()
    logger.success(f"Executive PDF saved -> {out}")
    return out


# ── Remediation lifecycle (open / fixed / retested / accepted) ─

STATES = ("open", "fixed", "retested", "accepted")


def _rem_path(session: Session) -> Path:
    d = session.dir("report")
    d.mkdir(parents=True, exist_ok=True)
    return d / "remediation.json"


def get_status(session: Session) -> Dict[str, Dict[str, Any]]:
    p = _rem_path(session)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def set_state(session: Session, finding_id: str, state: str,
              note: str = "", user: str = "?") -> Dict[str, Any]:
    if state not in STATES:
        raise ValueError(f"state must be one of {STATES}")
    data = get_status(session)
    data[finding_id] = {"state": state, "note": note, "user": user,
                        "updated": datetime.now().isoformat()}
    _rem_path(session).write_text(json.dumps(data, indent=2))
    return data[finding_id]


def remediation_summary(session: Session) -> Dict[str, Any]:
    data = get_status(session)
    counts = {s: 0 for s in STATES}
    for rec in data.values():
        counts[rec.get("state", "open")] = counts.get(rec.get("state"), 0) + 1
    total = len(session.get_findings())
    tracked = len(data)
    return {"total_findings": total, "tracked": tracked,
            "untracked_open": max(total - tracked, 0), "by_state": counts}
