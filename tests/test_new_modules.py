"""Tests for the recon+/validators/tamper/surface upgrade (offline only)."""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.session import Session, SessionMeta, SessionStatus, Mode, Finding, SeverityLevel
import modules.session as sm


def _sess(tmp_path, name="newmod"):
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None
    now = datetime.now().isoformat()
    s = Session(SessionMeta(session_id=name, name=name, target="example.com",
                            mode=Mode.RED, status=SessionStatus.CREATED,
                            created_at=now, updated_at=now))
    s.save()
    return s


class TestTamper:
    def test_variants_differ(self):
        from modules.tamper import apply, catalog
        out = apply("' OR 1=1--", ["inline_comments", "double_url_encode"])
        assert len(out) == 3 and out[0] == "' OR 1=1--"
        assert "/**/" in out[1] and "%" in out[2]
        assert len(catalog()) == 6

    def test_unknown_ignored(self):
        from modules.tamper import apply
        assert apply("x", ["nope"]) == ["x"]


class TestSurface:
    def test_build_candidates(self, tmp_path):
        from modules.surface import build_candidates, DISPATCH
        s = _sess(tmp_path)
        s.add_finding(Finding(source="recon", title="u",
                              severity=SeverityLevel.INFO,
                              host="http://t/?id=1&next=/x",
                              tags=["url"]))
        s.add_finding(Finding(source="recon", title="login",
                              severity=SeverityLevel.INFO, host="http://t/login",
                              tags=["login"]))
        cands = build_candidates(s)
        types = {c["type"] for c in cands}
        assert {"param", "sqli_param", "redirect_param", "login"} <= types
        for c in cands:
            assert c["validator"] == DISPATCH[c["type"]]
            __import__("importlib").import_module(
                c["validator"].rsplit(".", 1)[0])

    def test_empty_session(self, tmp_path):
        from modules.surface import build_candidates
        assert build_candidates(_sess(tmp_path)) == []


class TestPureValidators:
    def test_xss_contexts(self, tmp_path):
        from modules.validate.xss import XSSValidator
        v = XSSValidator(_sess(tmp_path))
        assert v._context('<input value="X">', "X") == "tag-attribute"
        assert v._context("<p>X</p>", "X") == "html-body"
        assert v._context("<!-- X -->", "X") == "comment"
        assert v._context("nope", "X") == "none"

    def test_ssrf_pure(self, tmp_path):
        from modules.validate.ssrf import SSRFValidator
        r = SSRFValidator(_sess(tmp_path)).test_url("http://t/?url=http://x&name=y")
        assert r["candidates"] == ["url"]

    def test_authz_ids(self):
        from modules.authz_mapper import id_params
        assert id_params("http://t/?id=1&user_id=2&foo=bar") == ["id", "user_id"]

    def test_cookies(self):
        from modules.cookie_analyzer import analyze_cookies
        out = analyze_cookies(["sessid=abc; Path=/"])
        assert out and out[0]["cookie"] == "sessid"
        assert analyze_cookies(["a=b; Secure; HttpOnly; SameSite=Lax"]) == []


class TestCatalogs:
    def test_payload_repos(self):
        from modules.payload_repos import catalog, REPOS
        assert len(REPOS) == 10
        rows = catalog(root="/nonexistent-ardf-test")
        assert len(rows) == 10 and all(r["cloned"] is False for r in rows)

    def test_waf_signatures(self):
        from modules.recon.waf_detect import fingerprint_headers
        assert "Cloudflare" in fingerprint_headers({"cf-ray": "x"}, "")
        assert fingerprint_headers({"server": "nginx"}, "") == []

    def test_v2_toolkit_wired(self):
        from ops.v2 import toolkit_catalog
        cat = toolkit_catalog()
        assert cat["classes_ok"] >= 30 and not cat["failed"]


class TestStealthKit:
    def test_proxy_env_priority(self, tmp_path, monkeypatch):
        from modules import proxy_chain as pc
        monkeypatch.setenv("ARDF_PROXY", "http://127.0.0.1:8080")
        assert pc.configured_proxies()[0] == "http://127.0.0.1:8080"
        assert pc.current_proxy() == "http://127.0.0.1:8080"

    def test_tor_unreachable_fast(self):
        from modules.proxy_chain import tor_new_circuit
        r = tor_new_circuit()
        assert r["ok"] is False and "error" in r

    def test_fingerprint_rotates(self):
        from modules.fingerprint import headers_for, catalog
        a, b = headers_for("chrome_win"), headers_for("firefox_linux")
        assert a["User-Agent"] != b["User-Agent"]
        assert len(catalog()["profiles"]) == 4

    def test_track_cover_generates(self, tmp_path):
        from modules.track_cover import generate, local_checklist
        s = _sess(tmp_path, "tc")
        out = generate(s, ["linux", "web"])
        assert set(out["scripts"]) == {"cover_linux.sh", "cover_web.txt"}
        assert (s.dir("exfil") / "cover_linux.sh").exists()
        assert len(local_checklist()) >= 4

    def test_opsec_audit_structure(self):
        from modules.opsec_audit import audit
        rep = audit(None)
        assert rep["verdict"] in ("GO", "NO-GO")
        assert isinstance(rep["fails"], int)
        assert any(i["check"] == "scope-guard" for i in rep["items"])


class TestPayloadDB:
    def test_stats(self):
        from modules.payload_db import stats
        s = stats()
        assert s["total_files"] >= 400
        cats = {c["category"] for c in s["categories"]}
        assert {"xss", "sqli", "fuzzing", "directories"} <= cats

    def test_query_dedup_cap(self):
        from modules.payload_db import query
        out = query("xss", limit=30)
        assert 0 < len(out) <= 30 and len(set(out)) == len(out)

    def test_no_backdoors(self):
        from modules.payload_db import query
        import re
        rx = re.compile(r"(backdoor|webshell|c99|r57)", re.IGNORECASE)
        for cat in ("cmdi", "fuzzing", "xss", "sqli"):
            for p in query(cat, limit=300):
                assert not rx.search(p), p[:80]

    def test_export_and_wordlist(self, tmp_path):
        from modules.payload_db import export, wordlist, brute_pair
        dest = str(tmp_path / "w.txt")
        export("open-redirect", dest, limit=20)
        assert len(open(dest).read().splitlines()) > 0
        assert wordlist("passwords") is not None
        bp = brute_pair()
        assert "users" in bp and "passwords" in bp

    def test_ardf2_wired(self, tmp_path):
        from modules.input_validator import detect_injection
        from modules.counterdetect import get_watch
        from modules.recon.port_fingerprint import identify_service
        assert detect_injection("admin' OR '1'='1")["injection_detected"] is True
        assert detect_injection("hello world")["injection_detected"] is False
        assert identify_service("SSH-2.0-OpenSSH", 22)[0] == "SSH"
        w = get_watch()
        w.record(429, "http://t/", "captcha challenge")
        assert w.advise()["level"] in ("high", "critical")


class TestReconBoss:
    def test_dorkpack(self, tmp_path):
        from modules.recon.dorkpack import build_pack, run
        pack = build_pack("example.com")
        assert "parameters" in pack and "github" in pack
        out = run(_sess(tmp_path, "dork"), "example.com")
        assert out["total"] > 15

    def test_subpermute_mutations(self):
        from modules.recon.subpermute import mutate
        m = mutate("portal")
        assert "dev-portal" in m and "portal-01" in m

    def test_s3_candidates(self):
        from modules.recon.s3_enum import candidates
        c = candidates("example.com")
        assert "example" in c and any("backup" in x for x in c)

    def test_github_no_token_path(self, tmp_path, monkeypatch):
        from modules.recon.github_recon import run
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        out = run(_sess(tmp_path, "gh"), "example.com")
        assert "manual_urls" in out or "hits" in out

    def test_boss_playbook_loads(self):
        from playbook.loader import PlaybookLoader
        from playbook.executor import PlaybookExecutor
        from modules.session import Session, SessionMeta, SessionStatus, Mode
        from datetime import datetime
        now = datetime.now().isoformat()
        s = Session(SessionMeta(session_id="pb", name="pb",
                                target="example.com", mode=Mode.RED,
                                status=SessionStatus.CREATED,
                                created_at=now, updated_at=now))
        pb = PlaybookLoader().load("recon_boss")
        assert len(pb["phases"]) == 11
        plan = PlaybookExecutor(s).build_plan(pb)
        assert plan is not None and len(plan["tasks"]) == 11


class TestHighGrade:
    def test_diffengine_nonce(self):
        from modules.diffengine import differs, reflection_points
        a = '<input value="CfDJ8LUBmEVgz3pIouCkU2TPsEt_xyz1234567890">'
        b = '<input value="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">'
        assert differs(a, b)["different"] is False
        assert differs("<p>hi</p>", "<p>bye</p>")["different"] is True
        assert reflection_points("<p>MARK</p>", "MARK") == ["body"]

    def test_rateboss_throttle(self):
        from modules import rateboss
        rateboss.configure(50.0)
        assert rateboss.take(5, block=False) is True
        assert rateboss.current_rate() == 50.0
        rateboss.configure(2.0)

    def test_memory_ttl(self, tmp_path):
        from modules import memory
        s = _sess(tmp_path, "mem")
        memory.remember(s, "xss", "http://t/?q=1", "", "miss")
        assert memory.known_miss(s, "xss", "http://t/?q=1") is True
        assert memory.summary(s)["by_outcome"]["miss"] == 1

    def test_poc_chain(self, tmp_path):
        from modules.poc import create_bundle, verify_bundle
        s = _sess(tmp_path, "poc")
        p = create_bundle(s, "demo",
                          [{"step": "a", "ok": True, "evidence": "e1"},
                           {"step": "b", "ok": False, "evidence": "e2"}],
                          ["f1"])
        assert verify_bundle(str(p)) == {"valid": True, "steps": 2}

    def test_crawler_signature(self):
        import inspect
        from modules.recon.crawler import run
        assert "max_pages" in inspect.signature(run).parameters

    def test_boss_playbook_11(self):
        from playbook.loader import PlaybookLoader
        pb = PlaybookLoader().load("recon_boss")
        assert len(pb["phases"]) == 11
