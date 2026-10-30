"""OPSEC profiles — one knob for rate/jitter/proxy behaviour.

quiet  : 0.5 req/s, high jitter, Tor/proxy required, passive-only bias
normal : 2   req/s, medium jitter, proxy if configured
loud   : 10  req/s, low jitter, direct (lab use)
"""
from __future__ import annotations

from typing import Any, Dict

from modules.logger import get_logger
from modules.stealth import StealthConfig, get_stealth_engine


class OpsecProfile:
    """Plain class (not a dataclass: dataclasses break under the v3
    spec-based loader, which execs modules without a sys.modules entry)."""

    def __init__(self, name: str, rate_limit: float, jitter: float,
                 require_proxy: bool, description: str):
        self.name = name
        self.rate_limit = rate_limit
        self.jitter = jitter
        self.require_proxy = require_proxy
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "rate_limit": self.rate_limit,
                "jitter": self.jitter, "require_proxy": self.require_proxy,
                "description": self.description}


PROFILES: Dict[str, OpsecProfile] = {
    "quiet": OpsecProfile("quiet", 0.5, 2.0, True,
                          "Low-and-slow; minimal detection surface"),
    "normal": OpsecProfile("normal", 2.0, 0.5, False,
                           "Default authorised-assessment pace"),
    "loud": OpsecProfile("loud", 10.0, 0.1, False,
                         "Lab/time-boxed assessments only"),
}


def apply_profile(name: str) -> OpsecProfile:
    """Apply a profile to the global stealth engine. Returns the profile."""
    if name not in PROFILES:
        raise ValueError(f"Unknown OPSEC profile: {name}. "
                         f"Available: {sorted(PROFILES)}")
    profile = PROFILES[name]
    engine = get_stealth_engine()
    engine.config.rate_limit = profile.rate_limit
    try:
        from modules.rateboss import configure
        configure(profile.rate_limit)  # global bucket follows profile
    except Exception:
        pass
    try:
        engine.config.jitter = profile.jitter
    except AttributeError:
        pass
    get_logger("opsec").info(
        f"OPSEC profile '{name}': {profile.rate_limit} req/s, "
        f"jitter={profile.jitter}s")
    return profile


def current_profile() -> Dict[str, Any]:
    engine = get_stealth_engine()
    return {"rate_limit": engine.config.rate_limit,
            "profiles": sorted(PROFILES)}
