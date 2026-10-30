"""Payload profiles — named per-OS/arch payload presets for delivery.

Profiles describe WHAT to build (type, arch, staging, evasion). Actual
generation still goes through ardf_v2_payload_delivery / Metasploit so
this module stays a planner-friendly catalogue, not a malware factory.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

PAYLOAD_PROFILES: Dict[str, Dict[str, Any]] = {
    "windows_x64_staged": {
        "os": "windows", "arch": "x64", "staging": "staged",
        "channel": "https", "evasion": ["obfuscate", "sleep-mask"],
        "use": "general Windows foothold with small initial stager",
    },
    "windows_x64_stageless": {
        "os": "windows", "arch": "x64", "staging": "stageless",
        "channel": "https", "evasion": ["obfuscate"],
        "use": "single-shot delivery where staging callbacks are blocked",
    },
    "linux_x64_stageless": {
        "os": "linux", "arch": "x64", "staging": "stageless",
        "channel": "https", "evasion": [],
        "use": "Linux servers, cron/systemd persistence",
    },
    "fileless_powershell": {
        "os": "windows", "arch": "x64", "staging": "fileless",
        "channel": "dns", "evasion": ["amsi-bypass", "etw-bypass"],
        "use": "memory-only execution, minimal disk footprint",
    },
    "web_shell_php": {
        "os": "any", "arch": "any", "staging": "none",
        "channel": "https", "evasion": ["polyglot-name"],
        "use": "post-upload persistence after file-upload bypass",
    },
}


def list_profiles() -> List[Dict[str, Any]]:
    return [{"name": n, **p} for n, p in PAYLOAD_PROFILES.items()]


def build_profile(name: str, lhost: str = "", lport: int = 443,
                  extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a concrete build spec for a profile (no generation)."""
    if name not in PAYLOAD_PROFILES:
        raise ValueError(f"Unknown payload profile: {name}. "
                         f"Available: {sorted(PAYLOAD_PROFILES)}")
    spec = {"profile": name, "lhost": lhost, "lport": lport,
            **PAYLOAD_PROFILES[name]}
    if extra:
        spec.update(extra)
    return spec
