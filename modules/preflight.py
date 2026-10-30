"""Pre-flight checks — what's installed, what's missing, how to fix it."""
from __future__ import annotations

import importlib
import shutil
from pathlib import Path
from typing import Any, Dict, List

# tool -> (binary, apt package, used for)
TOOLS = [
    ("nmap", "nmap", "port scanning / service discovery"),
    ("sqlmap", "sqlmap", "SQL injection automation"),
    ("hydra", "hydra", "password brute-forcing"),
    ("gobuster", "gobuster", "directory / DNS enumeration"),
    ("dirb", "dirb", "web content discovery"),
    ("nikto", "nikto", "web server scanning"),
    ("masscan", "masscan", "fast port scanning"),
    ("amass", "amass", "subdomain enumeration"),
    ("subfinder", "subfinder", "passive subdomain discovery"),
    ("nuclei", "nuclei", "vulnerability scanning"),
    ("john", "john", "hash cracking"),
    ("hashcat", "hashcat", "GPU hash cracking"),
    ("msfconsole", "metasploit-framework", "exploitation framework"),
    ("bloodhound", "bloodhound", "AD attack-path analysis"),
    ("responder", "responder", "LLMNR/NBT-NS poisoning"),
    ("secretsdump.py", "python3-impacket", "AD credential dumping (impacket)"),
]

PY_DEPS = [
    ("flask", "flask", "dashboard"),
    ("flask_cors", "flask-cors", "dashboard CORS"),
    ("yaml", "pyyaml", "config / playbooks"),
    ("rich", "rich", "CLI output"),
    ("aiohttp", "aiohttp", "async networking"),
    ("reportlab", "reportlab", "PDF reports"),
    ("argon2", "argon2-cffi", "dashboard auth"),
    ("requests", "requests", "HTTP intel"),
    ("dns", "dnspython", "DNS recon"),
]


def check() -> Dict[str, Any]:
    tools: List[Dict[str, Any]] = []
    for binary, apt, purpose in TOOLS:
        found = shutil.which(binary) is not None
        tools.append({"tool": binary, "installed": found,
                      "purpose": purpose,
                      "fix": None if found else f"sudo apt-get install -y {apt}"})
    pydeps: List[Dict[str, Any]] = []
    for mod, pip, purpose in PY_DEPS:
        try:
            importlib.import_module(mod)
            ok = True
        except ImportError:
            ok = False
        pydeps.append({"package": pip, "installed": ok, "purpose": purpose,
                       "fix": None if ok else f"python3 -m pip install {pip}"})
    missing_tools = [t["tool"] for t in tools if not t["installed"]]
    missing_py = [p["package"] for p in pydeps if not p["installed"]]
    # v2 registry coverage (wires ardf_v2_auto_tool_discovery into preflight)
    try:
        from ops.v2 import tool_coverage as _v2cov
        v2cov = _v2cov()
    except Exception:
        v2cov = {"count": 0, "tools": [], "installed": 0}
    ready = not missing_tools and not missing_py
    return {
        "ready": ready,
        "tools": tools,
        "python": pydeps,
        "v2_coverage": v2cov,
        "missing_tools": missing_tools,
        "missing_python": missing_py,
        "setup_hint": ("sudo ./setup.sh" if (missing_tools or missing_py)
                       else "all dependencies satisfied"),
    }
