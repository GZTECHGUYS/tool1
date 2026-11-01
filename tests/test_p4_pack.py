"""Smoke tests for the P4 attack pack (modules/attacks/p4_pack.py).

No network and no external binaries: tool-backed paths are exercised via
missing-tool honesty checks, and protocol logic via monkeypatched _http.
"""
from __future__ import annotations

import base64
import json

import pytest

import modules.session as sm
from modules import attacks
from modules.attacks import p4_pack
from modules.session import (Mode, Session, SessionMeta, SessionStatus,
                             SeverityLevel)

P4_IDS = ["nmap_service_scan", "nuclei_scan", "gobuster_content_enum",
          "smb_share_enum", "kerberos_asrep_roast", "ldap_ad_enum",
          "jwt_active_check", "git_exposure_check", "endpoint_diff_fuzzer",
          "vhost_bruteforce", "cert_transparency"]


def _sess(tmp_path, target="127.0.0.1"):
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None
    import datetime as _dt
    now = _dt.datetime.now().isoformat()
    s = Session(SessionMeta(session_id="p4", name="p4", target=target,
                            mode=Mode.RED, status=SessionStatus.CREATED,
                            created_at=now, updated_at=now))
    return s


def _spec(target, **kw):
    return {"target": target, **kw}


def test_pack_registered():
    p4 = {a["id"]: a for a in attacks.list_attacks() if a["phase"] == "P4"}
    assert set(p4) == set(P4_IDS)
    for a in p4.values():
        assert a["tier"] in (1, 2)
        assert a["summary"]


def test_plan_mode_offline(tmp_path):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path)
    for mid in P4_IDS:
        mod = attacks.get_attack(mid)
        target = ("http://127.0.0.1" if mid in (
            "nuclei_scan", "gobuster_content_enum", "jwt_active_check",
            "git_exposure_check", "endpoint_diff_fuzzer",
            "vhost_bruteforce") else "127.0.0.1")
        out = mod.plan(s, _spec(target), log)
        assert out["mode"] == "plan"
        assert out["module"] == mid


def test_tier_gate_blocks_exec(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    # keep the tier-1 module off the network when the gate lets it through
    monkeypatch.setattr(p4_pack, "_http",
                        lambda *a, **k: {"ok": False, "error": "offline"})
    for mid in P4_IDS:
        r = attacks.run_attack(s, mid, _spec("127.0.0.1", mode="exec"))
        if attacks.get_attack(mid).tier >= 2:
            assert r["ok"] is False
            # registry nests the gate message under "out"
            err = r.get("error") or (r.get("out") or {}).get("error", "")
            word = "CONFIRM" if attacks.get_attack(mid).tier >= 3 else "APPROVE"
            assert word in err
        else:
            # tier-1 passes the gate (no confirm needed)
            assert r["ok"] is True


def test_scope_violation_is_hard_stop(tmp_path):
    s = _sess(tmp_path)
    r = attacks.run_attack(s, "nmap_service_scan",
                           _spec("evil.not-in-scope.test", mode="plan"))
    assert r["ok"] is False
    assert "SCOPE" in r["error"]


def test_missing_tool_is_honest_error(tmp_path, monkeypatch):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path)
    monkeypatch.setattr(p4_pack.shutil, "which", lambda n: None)
    for mid, snippet in [("nuclei_scan", "apt install nuclei"),
                         ("nmap_service_scan", "apt install nmap"),
                         ("gobuster_content_enum", "apt install gobuster")]:
        mod = attacks.get_attack(mid)
        with pytest.raises(RuntimeError) as e:
            mod.execute(s, _spec("http://127.0.0.1", mode="exec"), log)
        assert snippet in str(e.value)


def test_smb_closed_port_returns_honest_result(tmp_path, monkeypatch):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path)
    monkeypatch.setattr(p4_pack, "_port_open", lambda h, p: False)
    out = attacks.get_attack("smb_share_enum").execute(
        s, _spec("127.0.0.1", mode="exec"), log)
    assert out["open"] is False


def _mk_jwt(header, payload, sig="sig"):
    enc = lambda o: base64.urlsafe_b64encode(
        json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.{sig}"


def test_jwt_bypass_detected(tmp_path, monkeypatch):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path)
    good = _mk_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"})
    calls = []

    def fake_http(url, method="GET", headers=None, **kw):
        jwt = (headers or {}).get("Authorization", "").replace("Bearer ", "")
        head = json.loads(base64.urlsafe_b64decode(
            jwt.split(".")[0] + "=" * (-len(jwt.split(".")[0]) % 4)))
        calls.append(head.get("alg"))
        # server accepts alg=none (the vulnerability under test)
        if head.get("alg") == "none":
            return {"ok": True, "status": 200, "headers": {}, "body": ""}
        return {"ok": True, "status": 401, "headers": {}, "body": ""}

    monkeypatch.setattr(p4_pack, "_http", fake_http)
    out = attacks.get_attack("jwt_active_check").execute(
        s, _spec("http://127.0.0.1", mode="exec", url="http://127.0.0.1/api",
                  jwt=good), log)
    assert out["bypass"] is True
    assert any(a["kind"] == "alg=none" for a in out["accepted"])
    latest = s.get_findings()[-1]
    assert latest.severity == SeverityLevel.CRITICAL
    assert "none" in calls


def test_jwt_requires_inputs(tmp_path):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path)
    out = attacks.get_attack("jwt_active_check").execute(
        s, _spec("http://127.0.0.1", mode="exec"), log)
    assert out["status"] == "error"
    assert "spec['jwt']" in out["error"]


def test_cert_transparency_parses_rows(tmp_path, monkeypatch):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path, target="www.knutsford.edu.gh")
    rows = [{"name_value": "www.knutsford.edu.gh\n*.dev.knutsford.edu.gh"},
            {"name_value": "other.net"}]  # other.net must be filtered out

    def fake_http(url, **kw):
        assert "crt.sh" in url and "knutsford.edu.gh" in url
        return {"ok": True, "status": 200, "headers": {},
                "body": json.dumps(rows)}

    monkeypatch.setattr(p4_pack, "_http", fake_http)
    out = attacks.get_attack("cert_transparency").execute(
        s, _spec("www.knutsford.edu.gh", mode="exec"), log)
    assert out["count"] == 2
    assert out["hostnames"] == ["dev.knutsford.edu.gh",
                                "www.knutsford.edu.gh"]


def test_endpoint_diff_flags_reactor(tmp_path, monkeypatch):
    from modules.logger import get_logger
    log = get_logger("test")
    s = _sess(tmp_path)

    def fake_http(url, **kw):
        if "debug=" in url:
            return {"ok": True, "status": 500, "headers": {},
                    "body": "x" * 500, "bytes": 500}
        return {"ok": True, "status": 200, "headers": {},
                "body": "ok", "bytes": 2}

    monkeypatch.setattr(p4_pack, "_http", fake_http)
    out = attacks.get_attack("endpoint_diff_fuzzer").execute(
        s, _spec("http://127.0.0.1", mode="exec", params=["debug", "id"]),
        log)
    assert out["tested"] == 2
    assert [d["param"] for d in out["diffs"]] == ["debug"]
