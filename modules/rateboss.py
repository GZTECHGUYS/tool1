"""Global throttle — single token-bucket choke point for all HTTP.

Every stealth-sensitive request path (validators, fuzzer, crawler,
recon) should take tokens here. OPSEC profiles set the rate; the
bucket enforces it globally so parallel modules can't overshoot.
Thread-safe. In-memory (per-process).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict

_lock = threading.Lock()
_tokens = 10.0
_last = time.monotonic()
_rate = 2.0  # tokens/sec — mirrored from OPSEC profile


def configure(rate_per_sec: float) -> None:
    global _rate
    with _lock:
        _rate = max(float(rate_per_sec), 0.1)


def current_rate() -> float:
    with _lock:
        return _rate


def take(n: float = 1.0, block: bool = True,
         timeout: float = 30.0) -> bool:
    """Take n tokens, sleeping until available (or timeout when blocking)."""
    global _tokens, _last
    deadline = time.monotonic() + timeout
    while True:
        with _lock:
            now = time.monotonic()
            _tokens = min(10.0, _tokens + (now - _last) * _rate)
            _last = now
            if _tokens >= n:
                _tokens -= n
                return True
            deficit = n - _tokens
        if not block or time.monotonic() >= deadline:
            return False
        time.sleep(min(deficit / _rate, 0.5))


def status() -> Dict[str, Any]:
    with _lock:
        return {"rate_per_sec": _rate, "tokens": round(_tokens, 2)}
