"""Tests for the live Wi-Fi kit and its P1 wiring.

No radio, no external binaries: every hardware/tool boundary is mocked at
the ``modules.attacks.wifi`` module.
"""
from __future__ import annotations

import datetime as _dt
import json

import modules.session as sm
from modules import attacks
from modules.attacks import wifi
from modules.session import Mode, Session, SessionMeta, SessionStatus


def _sess(tmp_path, target="127.0.0.1"):
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None
    now = _dt.datetime.now().isoformat()
    return Session(SessionMeta(
        session_id="wifi", name="wifi", target=target, mode=Mode.RED,
        status=SessionStatus.CREATED, created_at=now, updated_at=now))


def _log():
    from modules.logger import get_logger
    return get_logger("test.wifi")


def _run(session, **spec):
    return attacks.get_attack("wifi_adjacency").execute(
        session, {"target": "127.0.0.1", "mode": "exec", **spec}, _log())


# ─────────────────────────────────────────────────────────────
# Parsers and posture
# ─────────────────────────────────────────────────────────────

IW_SCAN = """\
BSS aa:bb:cc:dd:ee:01(on wlan0)
\tfreq: 2412
\tsignal: -42.00 dBm
\tSSID: CorpWiFi
\tRSN:
\t\tAuthentication suites: PSK
\tWPS: * Version: 1.0

BSS aa:bb:cc:dd:ee:02(on wlan0)
\tfreq: 5180
\tsignal: -71.00 dBm
\tSSID:
\tWEP:
"""


def test_parse_iw_scan_security_and_channel():
    aps = wifi._parse_iw_scan(IW_SCAN)
    assert [ap["bssid"] for ap in aps] == [
        "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
    assert aps[0]["ssid"] == "CorpWiFi"
    assert aps[0]["channel"] == 1
    assert aps[0]["security"] == ["WPA2"]
    assert aps[0]["wps"] is True
    assert aps[1]["channel"] == 36
    assert aps[1]["security"] == ["WEP"]
    assert aps[1]["hidden"] is True


def test_parse_nmcli_escaped_fields():
    text = ("AA\\:BB\\:CC\\:DD\\:EE\\:03:Corp Guest:6:61:WPA2 WPA3\n"
            "AA\\:BB\\:CC\\:DD\\:EE\\:04::11:40:WPA2\n")
    aps = wifi._parse_nmcli(text)
    assert aps[0]["bssid"] == "AA:BB:CC:DD:EE:03"
    assert aps[0]["ssid"] == "Corp Guest"
    assert aps[0]["channel"] == 6
    assert aps[0]["wpa3"] is True
    assert aps[1]["hidden"] is True


def test_assess_ap_flags_open_wep_and_evil_twin():
    allow_bssids = ["AA:BB:CC:DD:EE:02"]
    allow_ssids = ["CorpWiFi"]

    open_ap = {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "CorpWiFi",
               "security": ["OPEN"], "wps": False, "hidden": False}
    severity, issues = wifi.assess_ap(open_ap, allow_bssids, allow_ssids)
    assert severity == "high"
    assert any("open network" in issue for issue in issues)
    assert any("evil-twin" in issue for issue in issues)

    wep_ap = {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "Other",
              "security": ["WEP"], "wps": False, "hidden": False}
    severity, issues = wifi.assess_ap(wep_ap, allow_bssids, allow_ssids)
    assert severity == "high"
    assert "WEP encryption" in issues


def test_assess_ap_marks_authorized_ap_clean():
    severity, issues = wifi.assess_ap(
        {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "CorpWiFi",
         "security": ["WPA2"], "wps": False, "hidden": False},
        ["AA:BB:CC:DD:EE:02"], ["CorpWiFi"])
    assert severity == "info"
    assert issues == ["authorized AP; no weak-security signal"]


TERMUX_SCAN = json.dumps([
    {"bssid": "aa:bb:cc:dd:ee:05", "ssid": "CorpWiFi",
     "frequency": 2412, "rssi": -44,
     "capabilities": "[WPA2-PSK-CCMP][ESS]"},
    {"bssid": "aa:bb:cc:dd:ee:06", "ssid": "",
     "frequency": 5180, "rssi": -70,
     "capabilities": "[ESS]"},
])


def test_parse_termux_scaninfo():
    aps = wifi._parse_termux(TERMUX_SCAN)
    assert aps[0]["bssid"] == "AA:BB:CC:DD:EE:05"
    assert aps[0]["channel"] == 1
    assert aps[0]["security"] == ["WPA2"]
    assert aps[1]["security"] == ["OPEN"]
    assert aps[1]["hidden"] is True


def test_termux_radio_is_used_when_no_linux_tools(monkeypatch):
    monkeypatch.setattr(
        wifi.shutil, "which",
        lambda name: "/data/usr/bin/termux-wifi-scaninfo"
        if name == "termux-wifi-scaninfo" else None)
    monkeypatch.setattr(wifi, "_run", lambda argv, timeout=0: {
        "rc": 0, "stdout": TERMUX_SCAN, "stderr": "", "timeout": False})
    out = wifi.passive_scan("termux-wifi")
    assert out["ok"] is True
    assert out["tool"] == "termux-wifi-scaninfo"
    assert len(out["aps"]) == 2


def test_termux_failure_is_actionable(monkeypatch):
    monkeypatch.setattr(wifi, "_run", lambda argv, timeout=0: {
        "rc": 1, "stdout": "", "timeout": False,
        "stderr": "location permission denied"})
    out = wifi._termux_scan("/usr/bin/termux-wifi-scaninfo", 10)
    assert out["ok"] is False
    assert "Termux:API" in out["error"]
    assert "location permission" in out["error"]


def test_iw_success_with_no_aps_is_not_an_error(monkeypatch):
    monkeypatch.setattr(wifi.shutil, "which",
                        lambda name: "/usr/bin/iw" if name == "iw" else None)
    monkeypatch.setattr(wifi, "_run", lambda argv, timeout=0: {
        "rc": 0, "stdout": "", "stderr": "", "timeout": False})
    out = wifi.passive_scan("wlan0")
    assert out["ok"] is True
    assert out["aps"] == []


def test_sysfs_interface_discovery_without_tools(monkeypatch):
    monkeypatch.setattr(wifi.shutil, "which", lambda name: None)
    monkeypatch.setattr(wifi, "_sysfs_wireless", lambda: ["wlan0"])
    assert wifi.list_interfaces() == [
        {"name": "wlan0", "type": "managed", "tool": "sysfs"}]


def test_survey_refuses_monitor_mode_interface(monkeypatch):
    monkeypatch.setattr(wifi.shutil, "which",
                        lambda name: "/usr/bin/iw" if name == "iw" else None)
    monkeypatch.setattr(wifi, "interface_info",
                        lambda iface: {"type": "monitor"})
    out = wifi.passive_scan("wlan0mon")
    assert out["ok"] is False
    assert "managed interface" in out["error"]


def test_pmkid_never_falls_back_to_unfiltered_capture(monkeypatch):
    monkeypatch.setattr(wifi.shutil, "which",
                        lambda name: f"/usr/bin/{name}")
    calls = []

    def fake_run(argv, timeout=0):
        calls.append(argv)
        return {"rc": 1, "stdout": "", "timeout": False,
                "stderr": "unrecognized option '--filterlist_ap'"}

    monkeypatch.setattr(wifi, "_run", fake_run)
    out = wifi.pmkid_capture("wlan0mon", "AA:BB:CC:DD:EE:03")
    assert out["status"] == "tool_incompatible"
    assert len(calls) == 1
    assert "--filterlist_ap" in calls[0]
    assert "unfiltered" in out["error"].lower()


# ─────────────────────────────────────────────────────────────
# Module wiring / gates
# ─────────────────────────────────────────────────────────────

def test_wifi_is_registered_as_implemented():
    row = [r for r in attacks.list_attacks()
           if r["id"] == "wifi_adjacency"][0]
    assert row["status"] == "implemented"
    assert row["tier"] == 3


def test_disabled_kit_takes_no_action(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": False})
    out = _run(_sess(tmp_path))
    assert out["status"] == "disabled"


def test_requires_authorization_reference(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref", lambda spec, cfg: "")
    out = _run(_sess(tmp_path))
    assert out["status"] == "authorization_required"
    assert out["missing"] == ["authorization_ref"]


def test_requires_interface(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "")
    monkeypatch.setattr(wifi, "list_interfaces", lambda: [])
    out = _run(_sess(tmp_path))
    assert out["status"] == "hardware_required"
    assert out["missing"] == ["interface"]


def test_survey_reports_rogue_ap_and_authorized_ap(tmp_path, monkeypatch):
    cfg = {"enabled": True,
           "allowed_bssids": ["AA:BB:CC:DD:EE:02"],
           "allowed_ssids": ["CorpWiFi"]}
    monkeypatch.setattr(wifi, "wifi_config", lambda: cfg)
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "wlan0")
    monkeypatch.setattr(wifi, "passive_scan", lambda iface, timeout=45: {
        "ok": True, "tool": "iw", "aps": [
            {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "CorpWiFi",
             "security": ["OPEN"], "wps": False, "hidden": False,
             "channel": 1, "signal": -40.0},
            {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "CorpWiFi",
             "security": ["WPA2"], "wps": False, "hidden": False,
             "channel": 6, "signal": -55.0},
        ]})
    s = _sess(tmp_path)
    out = _run(s, action="survey")
    assert out["status"] == "surveyed"
    assert out["ap_count"] == 2
    assert out["flagged"] == 1
    finding = s.get_findings()[-1]
    assert finding.severity.name == "HIGH"
    assert "evil-twin" in finding.evidence
    assert "wifi" in finding.tags


def test_survey_failure_is_reported_not_hidden(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "wlan0")
    monkeypatch.setattr(wifi, "passive_scan", lambda iface, timeout=45: {
        "ok": False, "aps": [], "tool": "iw",
        "error": "iw scan needs root/CAP_NET_ADMIN"})
    out = _run(_sess(tmp_path), action="survey")
    assert out["status"] == "scan_failed"
    assert "CAP_NET_ADMIN" in out["scan"]["error"]


def test_pmkid_needs_explicit_bssid_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "wlan0mon")
    monkeypatch.setattr(wifi, "allowed_bssids", lambda spec, cfg: [])
    out = _run(_sess(tmp_path), action="pmkid",
               bssid="AA:BB:CC:DD:EE:03")
    assert out["capture"]["status"] == "authorization_required"


def test_pmkid_rejects_unlisted_bssid(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "wlan0mon")
    monkeypatch.setattr(wifi, "allowed_bssids",
                        lambda spec, cfg: ["AA:BB:CC:DD:EE:02"])
    out = _run(_sess(tmp_path), action="pmkid",
               bssid="AA:BB:CC:DD:EE:03")
    assert out["capture"]["status"] == "not_allowed"


def test_pmkid_capture_writes_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "wlan0mon")
    monkeypatch.setattr(wifi, "allowed_bssids",
                        lambda spec, cfg: ["AA:BB:CC:DD:EE:03"])
    monkeypatch.setattr(wifi, "monitor_capable", lambda iface: (True, ""))
    monkeypatch.setattr(wifi, "pmkid_capture", lambda iface, bssid, **kw: {
        "status": "captured", "bssid": bssid, "pmkid_count": 2,
        "hash_file": "/tmp/hashes.22000", "pcap": "/tmp/capture.pcapng"})
    s = _sess(tmp_path)
    out = _run(s, action="pmkid", bssid="aa-bb-cc-dd-ee-03")
    assert out["status"] == "captured"
    assert out["capture"]["pmkid_count"] == 2
    finding = s.get_findings()[-1]
    assert finding.severity.name == "HIGH"
    assert finding.host == "AA:BB:CC:DD:EE:03"
    assert "pmkid" in finding.tags


def test_pmkid_refuses_adapter_without_monitor_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi, "wifi_config", lambda: {"enabled": True})
    monkeypatch.setattr(wifi, "authorization_ref",
                        lambda spec, cfg: "ENG-2026-11")
    monkeypatch.setattr(wifi, "resolve_interface",
                        lambda spec, cfg: "wlan0")
    monkeypatch.setattr(wifi, "allowed_bssids",
                        lambda spec, cfg: ["AA:BB:CC:DD:EE:03"])
    monkeypatch.setattr(wifi, "monitor_capable",
                        lambda iface: (False, "adapter does not advertise "
                                              "monitor mode"))
    out = _run(_sess(tmp_path), action="pmkid",
               bssid="AA:BB:CC:DD:EE:03")
    assert out["capture"]["status"] == "hardware_required"
    assert "monitor mode" in out["capture"]["error"]


def test_pmkid_tool_missing_is_actionable(tmp_path, monkeypatch):
    monkeypatch.setattr(wifi.shutil, "which", lambda name: None)
    out = wifi.pmkid_capture("wlan0mon", "AA:BB:CC:DD:EE:03")
    assert out["status"] == "tool_missing"
    assert set(out["missing"]) == {"hcxdumptool", "hcxpcapngtool"}
    assert "apt install" in out["error"]


def test_bounded_subprocess_timeout(monkeypatch):
    import subprocess as _sp

    def boom(*a, **kw):
        raise _sp.TimeoutExpired(cmd="iw", timeout=5)

    monkeypatch.setattr(wifi.subprocess, "run", boom)
    out = wifi._run(["iw", "dev"], timeout=5)
    assert out["rc"] == 124
    assert out["timeout"] is True
