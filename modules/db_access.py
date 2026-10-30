"""DB access probe — NSE default-credential check, minimal footprint.

Runs nmap --script ms-sql-brute / pgsql-brute / mysql-brute with at most
2 credentials per service, single-threaded timing (T2), one attempt each.
Tier-3: the caller (dashboard route / actions engine) enforces CONFIRM.
Any valid credential is recorded REDACTED immediately.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel

SCRIPTS = {"mssql": "ms-sql-brute", "postgres": "pgsql-brute",
           "mysql": "mysql-brute"}
DEFAULT_CREDS = [("postgres", "postgres"), ("sa", "")]


def probe(session: Session, host: str, port: int, service: str,
          logger: Optional[ARDFLogger] = None,
          creds: Optional[List[tuple]] = None) -> Dict[str, Any]:
    if logger is None:
        logger = get_logger("dbaccess")
    script = SCRIPTS.get(service.lower())
    if not script:
        return {"error": f"unsupported service: {service}",
                "supported": sorted(SCRIPTS)}
    if shutil.which("nmap") is None:
        return {"error": "nmap not installed"}
    creds = (creds or DEFAULT_CREDS)[:2]  # hard cap: 2 credentials
    userdb = ",".join(u for u, _ in creds)
    passdb = ",".join(p if p else " " for _, p in creds)
    cmd = ["nmap", "-p", str(port), "--script", script,
           "--script-args", f"userdb={userdb},passdb={passdb},unpwdb.timelimit=60s",
           "-T2", "--open", host]
    logger.info(f"db-probe: {service} {host}:{port} ({len(creds)} creds, T2)")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"host": host, "port": port, "service": service,
                "valid": [], "timeout": True}
    out = proc.stdout
    valid = []
    for m in re.finditer(r"(?i)(valid credentials|login:\s*\S+|user:\s*\S+)[^\n]{0,80}", out):
        line = m.group(0)
        if "postgres" in line.lower() or "sa" in line.lower():
            valid.append("REDACTED-valid-login")
    valid = sorted(set(valid))
    if valid:
        session.add_finding(Finding(
            source="exploit.db",
            title=f"DB ACCESS: valid default credentials on {service} {host}:{port}",
            description="Default credentials accepted. Rotate immediately; "
                        "restrict DB to app-tier security group.",
            severity=SeverityLevel.CRITICAL, host=f"{host}:{port}",
            tags=["db", "credentials", "exploited-proof"],
            remediation="Rotate credentials; firewall DB ports; audit logins."))
        logger.success(f"DB ACCESS proven on {service} {host}:{port}")
    else:
        session.add_finding(Finding(
            source="exploit.db",
            title=f"DB probe clean: no default creds on {service} {host}:{port}",
            description="2 default credentials tested, none accepted.",
            severity=SeverityLevel.INFO, host=f"{host}:{port}",
            tags=["db", "hardening"]))
    return {"host": host, "port": port, "service": service,
            "creds_tested": len(creds), "valid": valid}
