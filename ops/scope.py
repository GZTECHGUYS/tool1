"""Scope guardrail — refuse out-of-scope targets before anything runs."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import List, Tuple

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

CONFIG_PATH = Path(__file__).parent.parent / "config" / "ardf.yaml"


class ScopeViolation(PermissionError):
    """Raised when a target is outside the authorised scope."""


def _save_scope_config(enabled: bool, allowed: List[str],
                       path: Path = CONFIG_PATH) -> None:
    """Surgical rewrite of ONLY the scope block (comments preserved)."""
    lines = path.read_text().splitlines()
    out, i, n = [], 0, len(lines)
    replaced = False
    while i < n:
        if lines[i].strip() == "scope:" and not replaced:
            replaced = True
            out.append("scope:")
            out.append(f"  enabled: {'true' if enabled else 'false'}"
                       "            # set true for engagements")
            out.append("  allowed_targets:")
            for t in allowed:
                out.append(f'    - "{t}"')
            i += 1
            # skip the old block: blank lines and indented lines belong
            # to it; stop at the next top-level key or comment header
            while i < n and (not lines[i].strip() or
                             lines[i].startswith((" ", "\t"))):
                i += 1
            continue
        out.append(lines[i])
        i += 1
    if not replaced:
        out.append("scope:")
        out.append(f"  enabled: {'true' if enabled else 'false'}")
        out.append("  allowed_targets:")
        for t in allowed:
            out.append(f'    - "{t}"')
    path.write_text("\n".join(out) + "\n")


def _load_scope_config(path: Path = CONFIG_PATH) -> dict:
    if HAVE_YAML and path.exists():
        try:
            data = yaml.safe_load(path.read_text()) or {}
            return data.get("scope", {}) or {}
        except Exception:
            return {}
    return {}


class ScopeGuard:
    """Authorised-target allowlist enforcement."""

    def __init__(self, enabled: bool = False, allowed_targets: List[str] = None,
                 config_path: Path = CONFIG_PATH):
        self._path = config_path
        if allowed_targets is None and config_path.exists():
            cfg = _load_scope_config(config_path)
            enabled = cfg.get("enabled", enabled)
            allowed_targets = cfg.get("allowed_targets") or []
        self.enabled = enabled
        self.allowed_targets = allowed_targets or []

    def validate(self, target: str) -> Tuple[bool, str]:
        """Return (ok, reason). Strips scheme/port before matching."""
        host = (target or "").strip().lower()
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0].split("@")[-1]
        if not host:
            return False, "empty target"
        if not re.fullmatch(r"[a-z0-9._-]+", host) or ".." in host:
            fixed = host.replace(",", ".").replace(" ", "").replace("|", "")
            return False, (
                f"target '{host}' is NOT a valid hostname (illegal "
                f"characters — looks like a typo, did you mean '{fixed}'?). "
                "Re-type it in the target field (dots, not commas)."
            )
        if not self.enabled:
            return True, "scope guard disabled (scope.enabled=false)"
        for entry in self.allowed_targets:
            e = entry.strip().lower()
            if not e:
                continue
            if "/" in e:  # CIDR
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(e, strict=False):
                        return True, f"matched CIDR {entry}"
                except ValueError:
                    continue
            elif e.startswith("."):  # domain suffix
                if host == e[1:] or host.endswith(e):
                    return True, f"matched suffix {entry}"
            else:  # exact host/IP
                if host == e:
                    return True, f"matched {entry}"
        labels = host.split(".")
        root_tip = "." + ".".join(labels[-2:]) if len(labels) > 2 else f".{host}"
        return False, (
            f"target '{host}' is OUT OF SCOPE "
            f"({len(self.allowed_targets)} allowlist entries). "
            "Add it first: Dashboard -> Scope -> 'Add target', "
            "or edit scope.allowed_targets in config/ardf.yaml "
            f"(tip: add '{host}' exactly, or '{root_tip}' "
            "with a dot to cover all subdomains)."
        )

    def require(self, target: str) -> None:
        ok, reason = self.validate(target)
        if not ok:
            raise ScopeViolation(reason)

    def reload(self) -> None:
        cfg = _load_scope_config(self._path)
        self.enabled = cfg.get("enabled", False)
        self.allowed_targets = cfg.get("allowed_targets") or []

    def set_enabled(self, enabled: bool) -> Dict[str, Any]:
        _save_scope_config(bool(enabled), list(self.allowed_targets),
                           self._path)
        self.reload()
        return {"enabled": self.enabled,
                "allowed_targets": self.allowed_targets}

    def add_target(self, entry: str) -> Dict[str, Any]:
        entry = (entry or "").strip()
        if not entry:
            raise ValueError("empty target")
        if entry not in self.allowed_targets:
            self.allowed_targets.append(entry)
        _save_scope_config(self.enabled, list(self.allowed_targets),
                           self._path)
        self.reload()
        return {"enabled": self.enabled,
                "allowed_targets": self.allowed_targets}

    def remove_target(self, entry: str) -> Dict[str, Any]:
        self.allowed_targets = [t for t in self.allowed_targets
                                if t != (entry or '').strip()]
        _save_scope_config(self.enabled, list(self.allowed_targets),
                           self._path)
        self.reload()
        return {"enabled": self.enabled,
                "allowed_targets": self.allowed_targets}
