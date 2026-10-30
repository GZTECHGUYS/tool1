"""Dashboard authentication — config users (argon2) + audit trail."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    HAVE_ARGON2 = True
except ImportError:
    HAVE_ARGON2 = False

CONFIG_PATH = Path(__file__).parent.parent / "config" / "ardf.yaml"
AUDIT_PATH = Path(__file__).parent.parent / "logs" / "dashboard_audit.jsonl"


class AuthManager:
    """Username/password auth with expiring tokens and an audit log."""

    DEFAULT_USER = "admin"
    DEFAULT_PASS = "changeme"

    def __init__(self, config_path: Path = CONFIG_PATH,
                 audit_path: Path = AUDIT_PATH,
                 token_hours: int = 8):
        self.config_path = config_path
        self.audit_path = audit_path
        self.token_hours = token_hours
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self._ph = PasswordHasher() if HAVE_ARGON2 else None

    # ── users ──────────────────────────────────────────────

    def _config_users(self) -> List[Dict[str, str]]:
        if HAVE_YAML and self.config_path.exists():
            try:
                data = yaml.safe_load(self.config_path.read_text()) or {}
                users = (data.get("dashboard", {}) or {}).get("users", []) or []
                return [u for u in users if u.get("name") and u.get("hash")]
            except Exception:
                return []
        return []

    def using_defaults(self) -> bool:
        return len(self._config_users()) == 0

    def verify(self, username: str, password: str) -> bool:
        for u in self._config_users():
            if u["name"] == username:
                if self._ph is None:
                    return False
                try:
                    self._ph.verify(u["hash"], password)
                    return True
                except Exception:
                    return False
        # fallback default account (warned about in UI)
        return username == self.DEFAULT_USER and password == self.DEFAULT_PASS

    # ── tokens ─────────────────────────────────────────────

    def issue(self, username: str) -> Dict[str, str]:
        token = secrets.token_hex(24)
        expires = datetime.now() + timedelta(hours=self.token_hours)
        self.tokens[token] = {"user": username, "expires": expires.isoformat()}
        self.audit("login", username, "success")
        return {"token": token, "expires": expires.isoformat(), "user": username}

    def check(self, token: str) -> Optional[str]:
        """Return username if token valid, else None."""
        rec = self.tokens.get(token or "")
        if not rec:
            return None
        if datetime.now() > datetime.fromisoformat(rec["expires"]):
            self.tokens.pop(token, None)
            return None
        return rec["user"]

    def revoke(self, token: str) -> None:
        user = (self.tokens.pop(token, {}) or {}).get("user", "?")
        self.audit("logout", user, "success")

    # ── audit ──────────────────────────────────────────────

    def audit(self, action: str, user: str, result: str,
              detail: str = "") -> None:
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, "a") as f:
                f.write(json.dumps({
                    "ts": datetime.now().isoformat(),
                    "action": action, "user": user,
                    "result": result, "detail": detail,
                }) + "\n")
        except Exception:
            pass

    def recent_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        try:
            lines = self.audit_path.read_text().splitlines()[-limit:]
            return [json.loads(l) for l in lines if l.strip()]
        except Exception:
            return []
