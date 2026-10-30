"""Unified proxy chain — one source of truth for egress routing.

Reads (in priority order): explicit arg > ARDF_PROXY env >
config network.proxies[] > config stealth.proxy{enabled,address}.
Provides rotation, Tor NEWNYM signalling (raw control-protocol, no stem
dependency), and reachability status. http_client consults this module
when no explicit proxy is passed.
"""
from __future__ import annotations

import os
import random
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

CONFIG_PATH = Path(__file__).parent.parent / "config" / "ardf.yaml"


def _cfg() -> Dict[str, Any]:
    if HAVE_YAML and CONFIG_PATH.exists():
        try:
            return yaml.safe_load(CONFIG_PATH.read_text()) or {}
        except Exception:
            return {}
    return {}


def configured_proxies() -> List[str]:
    """All configured egress proxies, highest priority first."""
    out: List[str] = []
    env = os.environ.get("ARDF_PROXY", "").strip()
    if env:
        out.append(env)
    cfg = _cfg()
    net = cfg.get("network", {}) or {}
    for p in net.get("proxies", []) or []:
        if p and p not in out:
            out.append(p)
    sp = (cfg.get("stealth", {}) or {}).get("proxy", {}) or {}
    if sp.get("enabled") and sp.get("address"):
        addr = sp["address"]
        typ = (sp.get("type", "") or "").lower()
        scheme = {"socks5": "socks5h", "http": "http",
                  "https": "https"}.get(typ, "")
        proxy = f"{scheme}://{addr}" if scheme and "://" not in addr else addr
        if proxy not in out:
            out.append(proxy)
    return out


def current_proxy() -> Optional[str]:
    """The proxy in effect right now (None = direct)."""
    proxies = configured_proxies()
    if not proxies:
        return None
    cfg = _cfg()
    rotate = ((cfg.get("network", {}) or {}).get("rotate_proxies", False)
              or ((cfg.get("stealth", {}) or {}).get("proxy", {}) or {})
              .get("rotate", False))
    if rotate and len(proxies) > 1:
        return random.choice(proxies)
    return proxies[0]


def tor_control_port() -> int:
    cfg = _cfg()
    try:
        return int(((cfg.get("stealth", {}) or {}).get("tor", {}) or {})
                   .get("control_port", 9051))
    except (TypeError, ValueError):
        return 9051


def tor_new_circuit(password: str = "") -> Dict[str, Any]:
    """SIGNAL NEWNYM over the Tor control port (plaintext protocol)."""
    port = tor_control_port()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except Exception as e:
        return {"ok": False, "error": f"tor control unreachable :{port}: {e}"}
    try:
        f = s.makefile("rw")
        if password:
            f.write(f'AUTHENTICATE "{password}"\r\n')
        else:
            f.write("AUTHENTICATE\r\n")
        f.flush()
        auth = f.readline()
        if not auth.startswith("250"):
            return {"ok": False, "error": f"tor auth refused: {auth.strip()[:80]}"}
        f.write("SIGNAL NEWNYM\r\n")
        f.flush()
        resp = f.readline()
        ok = resp.startswith("250")
        return {"ok": ok, "response": resp.strip()[:80]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:150]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def status() -> Dict[str, Any]:
    """Egress posture snapshot (no traffic sent except optional check)."""
    proxies = configured_proxies()
    cfg = _cfg()
    sp = (cfg.get("stealth", {}) or {}).get("proxy", {}) or {}
    tor = (cfg.get("stealth", {}) or {}).get("tor", {}) or {}
    return {"direct_allowed": not proxies,
            "proxies": proxies,
            "active": current_proxy(),
            "tor_configured": bool(tor.get("enabled")),
            "tor_control_port": tor_control_port(),
            "stealth_proxy_enabled": bool(sp.get("enabled"))}


def egress_verify(timeout: int = 12) -> Dict[str, Any]:
    """Prove egress routing: compare direct IP vs proxied IP.

    Sends two tiny api.ipify.org lookups (direct + via active proxy).
    masked_proxied=True means the target never sees the operator IP.
    """
    import requests
    out: Dict[str, Any] = {"direct_ip": None, "proxied_ip": None,
                           "masked": False, "proxy": current_proxy()}
    try:
        out["direct_ip"] = requests.get(
            "https://api.ipify.org?format=json",
            timeout=timeout).json().get("ip")
    except Exception as e:
        out["direct_error"] = str(e)[:120]
    if out["proxy"]:
        try:
            s = requests.Session()
            s.proxies.update({"http": out["proxy"], "https": out["proxy"]})
            out["proxied_ip"] = s.get(
                "https://api.ipify.org?format=json",
                timeout=timeout).json().get("ip")
        except Exception as e:
            out["proxy_error"] = str(e)[:120]
    if out["direct_ip"] and out["proxied_ip"]:
        out["masked"] = out["direct_ip"] != out["proxied_ip"]
    return out
