"""Internal process-wide event bus feeding the ops console SSE stream.

Everything is defensive: publish() must never break a caller. Subscribers
get (id, type, data) dicts; history allows reconnecting SSE clients to
replay events since a given id (Last-Event-ID semantics).
"""
from __future__ import annotations

import itertools
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional

_LOCK = threading.Lock()
_HISTORY: Deque[Dict[str, Any]] = deque(maxlen=500)
_COUNTER = itertools.count(1)
_SUBS: List[Any] = []  # callables: fn(event)


def _snapshot() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(_HISTORY)


def publish(event_type: str, data: Optional[Dict[str, Any]] = None,
            session_id: str = "") -> Dict[str, Any]:
    """Publish an event. Never raises; returns the stored event (or a stub)."""
    event = {
        "id": 0,
        "type": str(event_type),
        "session_id": session_id or "",
        "data": data if isinstance(data, dict) else {},
    }
    try:
        with _LOCK:
            event["id"] = next(_COUNTER)
            _HISTORY.append(dict(event))
            subs = list(_SUBS)
        for fn in subs:
            try:
                fn(event)
            except Exception:
                pass
    except Exception:
        pass
    return event


def subscribe(callback) -> None:
    """Register a live callback. Returns nothing; call unsubscribe to stop."""
    if not callable(callback):
        return
    with _LOCK:
        if callback not in _SUBS:
            _SUBS.append(callback)


def unsubscribe(callback) -> None:
    try:
        with _LOCK:
            if callback in _SUBS:
                _SUBS.remove(callback)
    except Exception:
        pass


def since(event_id: int) -> List[Dict[str, Any]]:
    """Events with id > event_id, oldest first."""
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = 0
    return [dict(e) for e in _snapshot() if e.get("id", 0) > event_id]


def stats() -> Dict[str, Any]:
    with _LOCK:
        return {"history": len(_HISTORY), "subscribers": len(_SUBS),
                "last_id": _HISTORY[-1]["id"] if _HISTORY else 0}
