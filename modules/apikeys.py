"""API key storage & resolution for third-party intel services.

Resolution order (first hit wins):

1. environment variable (e.g. ``SHODAN_API_KEY``)
2. ``config/api_keys.yaml`` — written by the dashboard Settings tab,
   chmod 0600, gitignored
3. ``config/ardf.yaml`` ``api_keys:`` block — only if the value is a real
   string, not an unresolved ``${ENV_VAR}`` placeholder

Keys are NEVER handed to the dashboard in plaintext: ``status()`` returns
masked values plus the source each key resolved from.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

# logical key -> environment variable (matches config/ardf.yaml)
KEYS: Dict[str, str] = {
    "shodan": "SHODAN_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VT_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "censys_id": "CENSYS_API_ID",
    "censys_secret": "CENSYS_API_SECRET",
    "c99": "C99_API_KEY",
    "github": "GITHUB_TOKEN",
    "hunter": "HUNTER_API_KEY",        # optional
    "greynoise": "GREYNOISE_API_KEY",  # optional
}

ROOT = Path(__file__).parent.parent
KEYS_FILE = ROOT / "config" / "api_keys.yaml"
ARDF_YAML = ROOT / "config" / "ardf.yaml"


def _is_placeholder(value: Any) -> bool:
    """True for empty values and unresolved ``${VAR}`` templates."""
    return not value or (isinstance(value, str) and value.startswith("${"))


def _file_values() -> Dict[str, str]:
    if not KEYS_FILE.exists():
        return {}
    try:
        data = yaml.safe_load(KEYS_FILE.read_text()) or {}
        return {k: str(v).strip() for k, v in (data or {}).items()
                if v is not None and str(v).strip()}
    except Exception:
        return {}


def _config_values() -> Dict[str, str]:
    """Values from ardf.yaml's api_keys block (placeholders stripped)."""
    if not ARDF_YAML.exists():
        return {}
    try:
        data = yaml.safe_load(ARDF_YAML.read_text()) or {}
        ak = data.get("api_keys") or {}
        out: Dict[str, str] = {}
        for name in KEYS:
            if name.startswith("censys_"):
                v = (ak.get("censys") or {}).get(name.split("_", 1)[1])
            else:
                v = ak.get(name)
            if not _is_placeholder(v):
                out[name] = str(v).strip()
        return out
    except Exception:
        return {}


def get_key(name: str) -> str:
    """Resolve a key: env var -> api_keys.yaml -> ardf.yaml value."""
    if name not in KEYS:
        return ""
    v = os.environ.get(KEYS[name], "").strip()
    if v:
        return v
    v = _file_values().get(name, "")
    if v:
        return v
    return _config_values().get(name, "")


def source_of(name: str) -> str:
    """Where a key would resolve from: env | file | config | unset."""
    if name not in KEYS:
        return "unknown"
    if os.environ.get(KEYS[name], "").strip():
        return "env"
    if _file_values().get(name):
        return "file"
    if _config_values().get(name):
        return "config"
    return "unset"


def set_key(name: str, value: str) -> None:
    """Persist a key to config/api_keys.yaml (0600)."""
    if name not in KEYS:
        raise KeyError(f"unknown api key {name!r}; valid: {sorted(KEYS)}")
    values = _file_values()
    value = (value or "").strip()
    if value:
        values[name] = value
    else:
        values.pop(name, None)
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEYS_FILE.write_text(
        yaml.safe_dump(values, default_flow_style=False, sort_keys=True))
    os.chmod(KEYS_FILE, 0o600)


def delete_key(name: str) -> bool:
    """Remove a key from api_keys.yaml (env/config sources stay)."""
    if name not in KEYS:
        raise KeyError(f"unknown api key {name!r}; valid: {sorted(KEYS)}")
    values = _file_values()
    if name not in values:
        return False
    values.pop(name)
    if values:
        KEYS_FILE.write_text(
            yaml.safe_dump(values, default_flow_style=False, sort_keys=True))
    else:
        KEYS_FILE.unlink(missing_ok=True)
    os.chmod(KEYS_FILE, 0o600) if KEYS_FILE.exists() else None
    return True


def mask(value: str) -> str:
    """Show enough to recognise a key, never enough to use it."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def status() -> List[Dict[str, Any]]:
    """Dashboard-safe key inventory: masked value + resolution source."""
    out = []
    for name in KEYS:
        v = get_key(name)
        out.append({
            "name": name,
            "env_var": KEYS[name],
            "configured": bool(v),
            "source": source_of(name),
            "masked": mask(v),
        })
    return out


def apply_to_environ() -> int:
    """Export resolved keys into os.environ for existing consumers.

    Several recon modules read env vars directly (e.g. SHODAN_API_KEY);
    this bridges keys stored in api_keys.yaml/ardf.yaml into that path.
    Returns the number of variables set.
    """
    set_count = 0
    for name in KEYS:
        if os.environ.get(KEYS[name], "").strip():
            continue
        v = get_key(name)
        if v:
            os.environ[KEYS[name]] = v
            set_count += 1
    return set_count
