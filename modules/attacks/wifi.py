"""Linux Wi-Fi assessment helpers for authorized physical engagements.

Nothing in this module runs unless the caller supplies an explicit
authorization reference and a wireless interface. PMKID capture additionally
requires the target BSSID to appear in an explicit allow-list.

Design rules
------------
* argv-based subprocess calls only, bounded by timeouts, output is capped.
* passive survey (``iw scan``) needs no monitor mode and never transmits.
* PMKID capture (``hcxdumptool``) requires a monitor-mode interface and a
  single allow-listed BSSID; no deauth or broadcast capture is performed.
* missing hardware/tooling is an honest, actionable error.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import hashlib
import math
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "ardf.yaml"

_BSSID_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ─────────────────────────────────────────────────────────────
# config / authorization
# ─────────────────────────────────────────────────────────────

def wifi_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Return the ``wifi:`` config block (empty dict when absent)."""
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    section = data.get("wifi") if isinstance(data, dict) else {}
    return section if isinstance(section, dict) else {}


def enabled(cfg: Optional[Dict[str, Any]] = None) -> bool:
    cfg = cfg if cfg is not None else wifi_config()
    return bool(cfg.get("enabled", True))


def authorization_ref(spec: Dict[str, Any],
                      cfg: Optional[Dict[str, Any]] = None) -> str:
    """First non-empty authorization reference (spec > env > config)."""
    cfg = cfg if cfg is not None else wifi_config()
    for value in (spec.get("authorization_ref"), spec.get("authorization"),
                  os.getenv("ARDF_WIFI_AUTH"), cfg.get("authorization_ref")):
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def normalize_bssid(value: Any) -> str:
    raw = str(value or "").strip().upper().replace("-", ":")
    return raw if _BSSID_RE.match(raw) else ""


def _list_setting(spec: Dict[str, Any], spec_key: str, cfg_key: str,
                  cfg: Dict[str, Any]) -> List[str]:
    if spec_key in spec:
        values = spec.get(spec_key) or []
    else:
        values = cfg.get(cfg_key) or []
    if isinstance(values, str):
        values = [values]
    return [str(v).strip() for v in values if str(v).strip()]


def allowed_bssids(spec: Dict[str, Any],
                   cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    cfg = cfg if cfg is not None else wifi_config()
    out = []
    for value in _list_setting(spec, "allowed_bssids", "allowed_bssids", cfg):
        bssid = normalize_bssid(value)
        if bssid:
            out.append(bssid)
    return sorted(set(out))


def allowed_ssids(spec: Dict[str, Any],
                  cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    cfg = cfg if cfg is not None else wifi_config()
    return sorted(set(_list_setting(spec, "allowed_ssids", "allowed_ssids", cfg)))


# ─────────────────────────────────────────────────────────────
# subprocess / interface discovery
# ─────────────────────────────────────────────────────────────

def _run(argv: List[str], timeout: int = 60) -> Dict[str, Any]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, errors="replace")
        return {"rc": proc.returncode, "stdout": proc.stdout or "",
                "stderr": proc.stderr or "", "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "timeout": True,
                "stderr": f"timeout after {timeout}s"}
    except FileNotFoundError as exc:
        return {"rc": 127, "stdout": "", "stderr": str(exc),
                "timeout": False}
    except OSError as exc:
        return {"rc": 126, "stdout": "", "timeout": False,
                "stderr": f"{type(exc).__name__}: {exc}"}


def _sysfs_wireless() -> List[str]:
    """Detect wireless interfaces without iw/nmcli (sysfs or procfs)."""
    names: List[str] = []
    base = Path("/sys/class/net")
    try:
        if base.is_dir():
            for entry in base.iterdir():
                if ((entry / "wireless").exists() or
                        (entry / "phy80211").exists()):
                    names.append(entry.name)
    except OSError:
        pass
    if not names:
        try:
            proc = Path("/proc/net/wireless")
            if proc.exists():
                for line in proc.read_text(encoding="utf-8").splitlines()[2:]:
                    match = re.match(r"\s*([\w.:-]+):", line)
                    if match:
                        names.append(match.group(1))
        except OSError:
            pass
    return sorted(set(names))


def list_interfaces() -> List[Dict[str, Any]]:
    """Enumerate wireless interfaces via ``iw dev`` then ``nmcli``."""
    rows: List[Dict[str, Any]] = []
    iw = shutil.which("iw")
    if iw:
        res = _run([iw, "dev"], timeout=10)
        current: Optional[Dict[str, Any]] = None
        for line in res["stdout"].splitlines():
            text = line.strip()
            if text.startswith("Interface "):
                if current:
                    rows.append(current)
                current = {"name": text.split(None, 1)[1].strip()}
            elif current is not None and text.startswith("type "):
                current["type"] = text.split(None, 1)[1].strip()
            elif current is not None and text.startswith("addr "):
                current["mac"] = text.split(None, 1)[1].strip().upper()
            elif current is not None and text.startswith("channel "):
                parts = text.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    current["channel"] = int(parts[1])
        if current:
            rows.append(current)
        if rows:
            return rows
    nmcli = shutil.which("nmcli")
    if nmcli:
        res = _run([nmcli, "-t", "-f", "DEVICE,TYPE", "device"], timeout=10)
        for line in res["stdout"].splitlines():
            parts = _split_escaped(line)
            if len(parts) >= 2 and parts[1].strip().lower() == "wifi":
                rows.append({"name": parts[0].strip(), "type": "managed"})
    if not rows and shutil.which("termux-wifi-scaninfo"):
        rows.append({"name": "termux-wifi", "type": "managed",
                     "tool": "termux-wifi-scaninfo"})
    if not rows:
        rows = [{"name": name, "type": "managed", "tool": "sysfs"}
                for name in _sysfs_wireless()]
    return rows


def interface_info(iface: str) -> Dict[str, Any]:
    iw = shutil.which("iw")
    if not iw or not iface:
        return {}
    res = _run([iw, "dev", iface, "info"], timeout=10)
    info: Dict[str, Any] = {}
    for line in res["stdout"].splitlines():
        text = line.strip()
        if text.startswith("type "):
            info["type"] = text.split(None, 1)[1].strip()
        elif text.startswith("addr "):
            info["mac"] = text.split(None, 1)[1].strip().upper()
        elif text.startswith("channel "):
            parts = text.split()
            if len(parts) >= 2 and parts[1].isdigit():
                info["channel"] = int(parts[1])
    return info


def monitor_capable(iface: str) -> Tuple[bool, str]:
    """True when the adapter advertises monitor mode; reason otherwise."""
    if iface.lower().startswith("termux"):
        return False, ("Android/Termux does not expose monitor mode; use a "
                       "Linux host with a monitor-capable adapter")
    iw = shutil.which("iw")
    if not iw:
        return False, "iw not installed; apt install iw"
    target = iface
    phy_name = Path(f"/sys/class/net/{iface}/phy80211/name")
    try:
        if phy_name.exists():
            target = phy_name.read_text(encoding="utf-8").strip() or iface
    except OSError:
        target = iface
    argv = ([iw, "phy", target, "info"] if target != iface
            else [iw, "list"])
    res = _run(argv, timeout=10)
    if re.search(r"^\s*\*\s*monitor\s*$", res["stdout"], re.MULTILINE):
        return True, ""
    return False, "adapter does not advertise monitor mode"


def resolve_interface(spec: Dict[str, Any],
                      cfg: Optional[Dict[str, Any]] = None,
                      require_monitor: bool = False) -> str:
    cfg = cfg if cfg is not None else wifi_config()
    explicit = str(spec.get("interface") or spec.get("wifi_interface") or
                   cfg.get("interface") or "").strip()
    if explicit:
        return explicit
    interfaces = list_interfaces()
    if require_monitor:
        for row in interfaces:
            if str(row.get("type", "")).lower() == "monitor":
                return str(row["name"])
        return ""
    for row in interfaces:
        if str(row.get("type", "")).lower() in (
                "managed", "monitor", "ap", "station", "mesh"):
            return str(row["name"])
    return ""


# ─────────────────────────────────────────────────────────────
# passive survey
# ─────────────────────────────────────────────────────────────

def _freq_to_channel(freq: int) -> int:
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def _parse_iw_scan(text: str) -> List[Dict[str, Any]]:
    aps: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in (text or "").splitlines():
        match = re.match(r"^BSS\s+([0-9a-fA-F:]{17})", line.strip())
        if match:
            if current:
                aps.append(current)
            current = {"bssid": match.group(1).upper(), "ssid": "",
                       "frequency": 0, "channel": 0, "signal": None,
                       "security": [], "wps": False, "wpa3": False,
                       "hidden": False}
            continue
        if current is None:
            continue
        text_line = line.strip()
        if text_line.startswith("freq:"):
            try:
                current["frequency"] = int(float(
                    text_line.split(":", 1)[1].split()[0]))
                current["channel"] = _freq_to_channel(current["frequency"])
            except (IndexError, ValueError):
                pass
        elif text_line.startswith("signal:"):
            sig = re.search(r"(-?\d+(?:\.\d+)?)", text_line)
            if sig:
                current["signal"] = float(sig.group(1))
        elif text_line.startswith("SSID:"):
            current["ssid"] = text_line.split(":", 1)[1].strip()
        elif text_line.startswith("RSN:"):
            if "WPA2" not in current["security"]:
                current["security"].append("WPA2")
        elif text_line.startswith("WPA:"):
            if "WPA" not in current["security"]:
                current["security"].append("WPA")
        elif text_line.startswith("WEP:"):
            if "WEP" not in current["security"]:
                current["security"].append("WEP")
        elif text_line.startswith("WPS:"):
            current["wps"] = True
        elif (text_line.startswith("Authentication suites:") and
              "SAE" in text_line.upper()):
            current["wpa3"] = True
            if "WPA3" not in current["security"]:
                current["security"].append("WPA3")
    if current:
        aps.append(current)
    for ap in aps:
        if not ap["security"]:
            ap["security"] = ["OPEN"]
        ap["hidden"] = not bool(ap.get("ssid"))
    return aps


def _split_escaped(line: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    i = 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def _parse_nmcli(text: str) -> List[Dict[str, Any]]:
    aps: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        parts = _split_escaped(line)
        if len(parts) < 5:
            continue
        bssid = normalize_bssid(parts[0])
        if not bssid:
            continue
        security_text = parts[4].upper()
        security: List[str] = []
        if "WPA3" in security_text:
            security.append("WPA3")
        if "WPA2" in security_text:
            security.append("WPA2")
        if ("WPA1" in security_text or
                ("WPA" in security_text and "WPA2" not in security_text and
                 "WPA3" not in security_text)):
            security.append("WPA")
        if "WEP" in security_text:
            security.append("WEP")
        if not security:
            security = ["OPEN"]
        try:
            channel = int(parts[2])
        except ValueError:
            channel = 0
        try:
            signal = int(parts[3])
        except ValueError:
            signal = None
        aps.append({"bssid": bssid, "ssid": parts[1].strip(),
                    "frequency": 0, "channel": channel, "signal": signal,
                    "security": security, "wps": "WPS" in security_text,
                    "wpa3": "WPA3" in security_text,
                    "hidden": not bool(parts[1].strip())})
    return aps


def _parse_termux(text: str) -> List[Dict[str, Any]]:
    """Parse ``termux-wifi-scaninfo`` JSON (Android/Termux fallback)."""
    try:
        doc = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(doc, list):
        return []
    aps: List[Dict[str, Any]] = []
    for item in doc:
        if not isinstance(item, dict):
            continue
        bssid = normalize_bssid(item.get("bssid"))
        if not bssid:
            continue
        capabilities = str(item.get("capabilities") or "").upper()
        security: List[str] = []
        if "SAE" in capabilities or "WPA3" in capabilities:
            security.append("WPA3")
        if "WPA2" in capabilities or "RSN" in capabilities:
            security.append("WPA2")
        if "WPA1" in capabilities or (
                "WPA" in capabilities and "WPA2" not in capabilities and
                "WPA3" not in capabilities):
            security.append("WPA")
        if "WEP" in capabilities:
            security.append("WEP")
        if not security:
            security = ["OPEN"]
        try:
            frequency = int(float(item.get("frequency") or 0))
        except (TypeError, ValueError):
            frequency = 0
        try:
            signal = float(item.get("rssi"))
        except (TypeError, ValueError):
            signal = None
        ssid = str(item.get("ssid") or "").strip()
        if ssid.lower() in ("<hidden>", "<unknown ssid>", "0x"):
            ssid = ""
        aps.append({"bssid": bssid, "ssid": ssid,
                    "frequency": frequency,
                    "channel": _freq_to_channel(frequency),
                    "signal": signal, "security": security,
                    "wps": "WPS" in capabilities,
                    "wpa3": "WPA3" in security or "SAE" in capabilities,
                    "hidden": not bool(ssid)})
    return aps


def _termux_scan(path: str, timeout: int) -> Dict[str, Any]:
    res = _run([path], timeout=timeout)
    if res["timeout"]:
        return {"ok": False, "aps": [], "tool": "termux-wifi-scaninfo",
                "error": f"scan timed out after {timeout}s"}
    if res["rc"] != 0:
        hint = ("termux-wifi-scaninfo failed; install the Termux:API app, "
                "the termux-api package, grant location permission and "
                "enable Wi-Fi")
        detail = (res["stderr"] or "").strip()[-300:]
        return {"ok": False, "aps": [], "tool": "termux-wifi-scaninfo",
                "error": f"{hint}: {detail}" if detail else hint}
    return {"ok": True, "tool": "termux-wifi-scaninfo",
            "aps": _parse_termux(res["stdout"])}


def passive_scan(iface: str, timeout: int = 45) -> Dict[str, Any]:
    """Read-only scan; never changes the interface state.

    Order: Termux radio -> ``iw`` -> ``nmcli`` -> Termux fallback. An empty
    but successful scan is a valid result (``aps=[]``), not an error.
    """
    if not iface:
        return {"ok": False, "aps": [],
                "error": "no wireless interface supplied"}
    termux = shutil.which("termux-wifi-scaninfo")
    if iface.lower().startswith("termux"):
        if not termux:
            return {"ok": False, "aps": [], "tool": "",
                    "error": "termux-wifi-scaninfo not found; install "
                             "termux-api (pkg install termux-api)"}
        return _termux_scan(termux, timeout)

    nmcli_error = ""
    iw = shutil.which("iw")
    if iw:
        info = interface_info(iface)
        if str(info.get("type", "")).lower() == "monitor":
            return {"ok": False, "aps": [], "tool": "iw",
                    "error": f"{iface} is in monitor mode; use a managed "
                             f"interface for a survey"}
        res = _run([iw, "dev", iface, "scan"], timeout=timeout)
        if res["rc"] == 0:
            return {"ok": True, "tool": "iw",
                    "aps": _parse_iw_scan(res["stdout"])}
        stderr = res["stderr"].lower()
        if ("permission" in stderr or "not permitted" in stderr or
                "operation not permitted" in stderr):
            return {"ok": False, "aps": [], "tool": "iw",
                    "error": "iw scan needs root/CAP_NET_ADMIN"}
        nmcli_error = res["stderr"][-300:]
    nmcli = shutil.which("nmcli")
    if nmcli:
        res = _run([nmcli, "-t", "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
                    "device", "wifi", "list", "ifname", iface],
                   timeout=timeout)
        if res["rc"] == 0:
            return {"ok": True, "tool": "nmcli",
                    "aps": _parse_nmcli(res["stdout"])}
        nmcli_error = res["stderr"][-300:]
    if termux:
        return _termux_scan(termux, timeout)
    return {"ok": False, "aps": [], "tool": "",
            "error": nmcli_error or
                     "no supported scanner found; install iw, nmcli or "
                     "termux-api"}


# ─────────────────────────────────────────────────────────────
# security posture
# ─────────────────────────────────────────────────────────────

def _raise_severity(current: str, new: str) -> str:
    return new if _SEV_RANK.get(new, 0) > _SEV_RANK.get(current, 0) else current


def assess_ap(ap: Dict[str, Any], allow_bssids: List[str],
              allow_ssids: List[str]) -> Tuple[str, List[str]]:
    """Return (severity, issues) for one observed access point."""
    issues: List[str] = []
    severity = "info"
    security = {str(s).upper() for s in (ap.get("security") or [])}
    bssid = str(ap.get("bssid") or "").upper()
    ssid = str(ap.get("ssid") or "")
    if "OPEN" in security or not security:
        issues.append("open network (no encryption)")
        severity = _raise_severity(severity, "high")
    if "WEP" in security:
        issues.append("WEP encryption")
        severity = _raise_severity(severity, "high")
    if "WPA" in security and "WPA2" not in security and "WPA3" not in security:
        issues.append("WPA1/TKIP only")
        severity = _raise_severity(severity, "medium")
    if ap.get("wps"):
        issues.append("WPS enabled")
        severity = _raise_severity(severity, "medium")
    if ap.get("hidden"):
        issues.append("hidden SSID")
        severity = _raise_severity(severity, "low")
    if allow_bssids and bssid in allow_bssids and not issues:
        issues.append("authorized AP; no weak-security signal")
    if (allow_ssids and ssid in allow_ssids and
            bssid not in allow_bssids):
        issues.append("evil-twin candidate: expected SSID on unlisted BSSID")
        severity = _raise_severity(severity, "high")
    return severity, issues


# ─────────────────────────────────────────────────────────────
# live tracing / distance estimation
# ─────────────────────────────────────────────────────────────

_TRACE_LOCK = threading.Lock()
_TRACE_STATE: Dict[str, Dict[str, Any]] = {}
_TRACE_LAST: Dict[str, Any] = {}

DISTANCE_CLASSES = [
    (1.0, "immediate"),
    (5.0, "near"),
    (15.0, "room"),
    (30.0, "adjacent"),
]


def _cfg_number(cfg: Dict[str, Any], key: str, default: float) -> float:
    try:
        value = cfg.get(key, default)
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def estimate_distance(rssi: Any, reference_rssi: float = -40.0,
                      path_loss: float = 2.7) -> Optional[float]:
    """Log-distance path-loss estimate in metres (None for bad RSSI).

    ``reference_rssi`` is the expected RSSI at one metre. This is an
    estimate only: walls, antenna orientation and transmit power all move
    the true distance. The dashboard labels it as such.
    """
    try:
        value = float(rssi)
    except (TypeError, ValueError):
        return None
    if value == 0:
        return None
    # Positive dBm values are not valid Wi-Fi RSSI; also avoid zero-division.
    path_loss = max(1.0, float(path_loss or 2.7))
    exponent = (float(reference_rssi) - value) / (10.0 * path_loss)
    meters = 10.0 ** exponent
    return round(max(0.3, min(meters, 500.0)), 2)


def distance_band(meters: Optional[float]) -> str:
    if meters is None:
        return "unknown"
    for limit, label in DISTANCE_CLASSES:
        if meters < limit:
            return label
    return "far"


def bssid_angle(bssid: str) -> float:
    """Deterministic bearing from the BSSID (same device -> same spot)."""
    raw = str(bssid or "").strip().upper()
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return float(int(digest[:8], 16) % 360)


def map_position(distance_m: Optional[float], angle_deg: float,
                 max_range_m: float = 50.0) -> Dict[str, float]:
    """Return x/y percentages inside the radar circle."""
    range_m = max(1.0, float(max_range_m or 50.0))
    distance = 0.0 if distance_m is None else max(0.0, float(distance_m))
    radius = math.sqrt(min(distance / range_m, 1.0)) * 42.0
    radians = math.radians(float(angle_deg or 0.0))
    return {
        "x": round(50.0 + radius * math.cos(radians), 2),
        "y": round(50.0 + radius * math.sin(radians), 2),
    }


def classify_device(ap: Dict[str, Any],
                    allow_bssids: Optional[List[str]] = None,
                    allow_ssids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Label an observed radio as authorized, evil-twin or foreign."""
    allow_bssids = allow_bssids or []
    allow_ssids = allow_ssids or []
    bssid = normalize_bssid(ap.get("bssid"))
    ssid = str(ap.get("ssid") or "")
    if bssid and bssid in allow_bssids:
        return {"kind": "authorized", "foreign": False,
                "reason": "BSSID is in the authorized allow-list"}
    if ssid and allow_ssids and ssid in allow_ssids:
        return {"kind": "evil_twin", "foreign": True,
                "reason": "expected SSID on an unlisted BSSID"}
    if not allow_bssids and not allow_ssids:
        reason = "unlisted device (no allow-list configured)"
    else:
        reason = "BSSID and SSID are not in the authorized allow-lists"
    return {"kind": "foreign", "foreign": True, "reason": reason}


def trace_devices(aps: List[Dict[str, Any]],
                  allow_bssids: Optional[List[str]] = None,
                  allow_ssids: Optional[List[str]] = None,
                  cfg: Optional[Dict[str, Any]] = None,
                  now: Optional[str] = None) -> List[Dict[str, Any]]:
    """Enrich survey rows with distance, bearing, map position and tracking."""
    cfg = cfg if cfg is not None else wifi_config()
    allow_bssids = allow_bssids or []
    allow_ssids = allow_ssids or []
    reference = _cfg_number(cfg, "rssi_at_1m", -40.0)
    path_loss = _cfg_number(cfg, "path_loss_exponent", 2.7)
    map_range = _cfg_number(cfg, "map_range_m", 50.0)
    stamp = now or datetime.now(timezone.utc).isoformat()
    out: List[Dict[str, Any]] = []

    for ap in aps or []:
        bssid = normalize_bssid(ap.get("bssid"))
        if not bssid:
            continue
        rssi = ap.get("signal", ap.get("rssi"))
        distance = estimate_distance(rssi, reference, path_loss)
        angle = bssid_angle(bssid)
        position = map_position(distance, angle, map_range)
        severity, issues = assess_ap(ap, allow_bssids, allow_ssids)
        kind = classify_device(ap, allow_bssids, allow_ssids)
        with _TRACE_LOCK:
            record = _TRACE_STATE.get(bssid) or {
                "first_seen": stamp, "seen_count": 0}
            record["last_seen"] = stamp
            record["seen_count"] = int(record.get("seen_count", 0)) + 1
            _TRACE_STATE[bssid] = record
            first_seen = record["first_seen"]
            seen_count = record["seen_count"]
        entry = dict(ap)
        entry.update({
            "bssid": bssid,
            "ssid": str(ap.get("ssid") or ""),
            "channel": ap.get("channel") or 0,
            "frequency": ap.get("frequency"),
            "rssi": rssi,
            "security": list(ap.get("security") or []),
            "severity": severity,
            "issues": issues,
            "kind": kind["kind"],
            "foreign": bool(kind["foreign"]),
            "kind_reason": kind["reason"],
            "distance_m": distance,
            "distance_band": distance_band(distance),
            "angle_deg": angle,
            "map": position,
            "first_seen": first_seen,
            "last_seen": stamp,
            "seen_count": seen_count,
        })
        out.append(entry)

    out.sort(key=lambda row: (not row["foreign"],
                              -_SEV_RANK.get(row["severity"], 0),
                              row["distance_m"] if row["distance_m"] is not None
                              else 999.0,
                              row["bssid"]))
    return out


def summarize_devices(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_kind: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for device in devices or []:
        kind = str(device.get("kind") or "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        severity = str(device.get("severity") or "info")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    foreign = sum(1 for d in (devices or []) if d.get("foreign"))
    nearest = None
    for device in devices or []:
        if device.get("distance_m") is None:
            continue
        if nearest is None or device["distance_m"] < nearest["distance_m"]:
            nearest = {"bssid": device.get("bssid"),
                       "ssid": device.get("ssid"),
                       "distance_m": device.get("distance_m")}
    return {"total": len(devices or []), "foreign": foreign,
            "authorized": by_kind.get("authorized", 0),
            "by_kind": by_kind, "by_severity": by_severity,
            "nearest": nearest}


def trace_scan(spec: Optional[Dict[str, Any]] = None,
               cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Authorized read-only scan + trace snapshot for the dashboard.

    Authorization is checked here as well as in the attack module; the
    dashboard must not be a quiet way around the engagement reference.
    """
    spec = spec or {}
    cfg = cfg if cfg is not None else wifi_config()
    if not enabled(cfg):
        return {"ok": False, "status": "disabled", "devices": [],
                "error": "wifi.enabled is false in config/ardf.yaml"}
    auth = authorization_ref(spec, cfg)
    if not auth:
        return {"ok": False, "status": "authorization_required",
                "devices": [], "missing": ["authorization_ref"],
                "error": "set wifi.authorization_ref, ARDF_WIFI_AUTH or an "
                         "authorization_ref in the request; no radio action "
                         "was taken"}
    iface = resolve_interface(spec, cfg)
    if not iface:
        return {"ok": False, "status": "hardware_required", "devices": [],
                "missing": ["interface"], "interfaces": list_interfaces(),
                "error": "plug in a wireless adapter or set wifi.interface"}
    timeout = _bounded_int(spec.get("scan_timeout") or
                           cfg.get("scan_timeout") or 20, 20, 5, 180)
    scan = passive_scan(iface, timeout=timeout)
    if not scan.get("ok"):
        return {"ok": False, "status": "scan_failed", "interface": iface,
                "tool": scan.get("tool", ""), "devices": [],
                "error": scan.get("error", "scan failed")}
    limit = _bounded_int(spec.get("max_aps") or cfg.get("max_aps") or 250,
                         250, 1, 500)
    allow_bssids = allowed_bssids(spec, cfg)
    allow_ssids = allowed_ssids(spec, cfg)
    devices = trace_devices((scan.get("aps") or [])[:limit],
                            allow_bssids, allow_ssids, cfg)
    summary = summarize_devices(devices)
    snapshot = {
        "ok": True, "status": "tracked", "interface": iface,
        "tool": scan.get("tool", ""), "authorization_ref": auth,
        "allowed_bssids": allow_bssids, "allowed_ssids": allow_ssids,
        "devices": devices, "summary": summary,
        "map_range_m": _cfg_number(cfg, "map_range_m", 50.0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with _TRACE_LOCK:
        _TRACE_LAST.clear()
        _TRACE_LAST.update(snapshot)
    try:
        from ops.events import publish
        publish("wifi.trace", {
            "interface": iface,
            "devices": summary.get("total", 0),
            "foreign": summary.get("foreign", 0),
            "nearest": summary.get("nearest"),
        })
    except Exception:
        pass
    return snapshot


def trace_state(limit: int = 100) -> Dict[str, Any]:
    """Return the last trace snapshot (devices capped by ``limit``)."""
    with _TRACE_LOCK:
        if not _TRACE_LAST:
            snapshot = {}
        else:
            try:
                snapshot = json.loads(json.dumps(_TRACE_LAST))
            except (TypeError, ValueError):
                snapshot = dict(_TRACE_LAST)
    if not snapshot:
        return {"ok": False, "status": "idle", "devices": [],
                "summary": summarize_devices([])}
    snapshot["devices"] = (snapshot.get("devices") or [])[:max(1, limit)]
    return snapshot


def reset_tracking() -> None:
    with _TRACE_LOCK:
        _TRACE_STATE.clear()
        _TRACE_LAST.clear()


# ─────────────────────────────────────────────────────────────
# PMKID capture (targeted, allow-listed)
# ─────────────────────────────────────────────────────────────

def pmkid_capture(iface: str, bssid: str, duration: int = 60,
                  outdir: Optional[str] = None) -> Dict[str, Any]:
    """Capture PMKID for one authorized BSSID, then convert to 22000."""
    bssid = normalize_bssid(bssid)
    if not bssid:
        return {"status": "error", "error": "invalid BSSID"}
    tool = shutil.which("hcxdumptool")
    conv = shutil.which("hcxpcapngtool")
    missing = [name for name, path in
               (("hcxdumptool", tool), ("hcxpcapngtool", conv)) if not path]
    if missing:
        return {"status": "tool_missing", "missing": missing,
                "error": f"missing {', '.join(missing)}; "
                         "apt install hcxdumptool hcxtools"}
    duration = max(5, min(int(duration), 600))
    outdir = outdir or tempfile.mkdtemp(prefix="ardf-wifi-")
    base = Path(outdir)
    base.mkdir(parents=True, exist_ok=True)
    pcap = str(base / "capture.pcapng")
    hash_file = str(base / "hashes.22000")
    filter_file = str(base / "ap-filter.txt")
    (base / "ap-filter.txt").write_text(bssid + "\n", encoding="utf-8")
    argv = [tool, "-i", iface, "-o", pcap, f"--tot={duration}",
            "--filterlist_ap", filter_file, "--filtermode", "2"]
    run = _run(argv, timeout=duration + 45)
    if run["rc"] != 0 and any(marker in run["stderr"].lower() for marker in
                              ("unrecognized option", "unknown option",
                               "invalid option")):
        return {"status": "tool_incompatible",
                "bssid": bssid, "pcap": pcap,
                "error": "hcxdumptool rejected the BSSID filter options; "
                         "upgrade hcxdumptool. No unfiltered capture was "
                         "attempted.",
                "stderr": run["stderr"][-400:]}
    if not Path(pcap).exists() or Path(pcap).stat().st_size == 0:
        return {"status": "no_capture", "pcap": pcap,
                "hash_file": hash_file, "rc": run["rc"],
                "stderr": run["stderr"][-400:],
                "error": "capture file is empty"}
    conv_run = _run([conv, "-o", hash_file, pcap], timeout=90)
    try:
        lines = [line.strip() for line in
                 Path(hash_file).read_text(encoding="utf-8",
                                           errors="replace").splitlines()
                 if line.strip()]
    except OSError:
        lines = []
    return {"status": "captured" if lines else "no_pmkid",
            "bssid": bssid, "pmkid_count": len(lines),
            "pcap": pcap, "hash_file": hash_file,
            "outdir": str(base), "rc": run["rc"],
            "convert_rc": conv_run["rc"],
            "stderr": (run["stderr"] or conv_run["stderr"])[-400:]}
