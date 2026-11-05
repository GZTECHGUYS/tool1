"""Wiring tests for the P1–P4 attack registry.

These are completeness tests: every pack must load, every expected module
must be registered exactly once, metadata must be valid, the tier gate must
be exact-match, and ``--attack-doctor`` must report a healthy registry.
"""
from __future__ import annotations

import datetime as _dt

import pytest

import modules.attacks as attacks
import modules.session as sm
from modules.session import Mode, Session, SessionMeta, SessionStatus

P1_IDS = {
    "subdomain_takeover", "ad_enum_builder", "mfa_sso_chain", "container_k8s",
    "deserial_factory", "ssh_key_reuse", "wifi_adjacency", "c2_macro_chain",
    "password_spray", "persistence_check",
}
P2_IDS = {
    "cicd_pipeline", "cloud_iam_planner", "cloud_storage_audit",
    "graphql_deep", "dns_attack", "vpn_appliance", "session_tokens",
    "firmware_audit", "exposed_services", "lateral_planner",
}
P3_IDS = {
    "tls_posture", "email_security_posture", "dns_hygiene", "http_header_audit",
    "jwt_audit", "cors_origin_audit", "admin_panel_discovery",
    "secret_leak_scan", "smb_signing_audit", "ssh_posture_audit",
    "graphql_introspection_audit", "open_redirect_audit",
    "ssrf_canary_audit", "path_traversal_audit", "ssti_canary_audit",
    "nosql_injection_audit", "xxe_audit", "host_header_audit",
    "http_method_audit", "websocket_origin_audit", "rate_limit_audit",
    "request_smuggling_plan", "cache_poison_plan", "api_bola_plan",
    "cloud_metadata_plan", "adcs_esc_plan", "supply_chain_plan",
}
P4_IDS = {
    "nmap_service_scan", "nuclei_scan", "gobuster_content_enum",
    "smb_share_enum", "kerberos_asrep_roast", "ldap_ad_enum",
    "jwt_active_check", "git_exposure_check", "endpoint_diff_fuzzer",
    "vhost_bruteforce", "cert_transparency", "ffuf_content_enum",
    "subfinder_enum", "httpx_probe", "naabu_port_scan", "katana_crawl",
    "dalfox_xss", "nikto_scan", "nxc_smb_enum", "bloodhound_ingest",
    "hashcat_crack",
}

EXPECTED = {"P1": P1_IDS, "P2": P2_IDS, "P3": P3_IDS, "P4": P4_IDS}


def _session(tmp_path, target="127.0.0.1"):
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None
    now = _dt.datetime.now().isoformat()
    return Session(SessionMeta(
        session_id="registry", name="registry", target=target,
        mode=Mode.RED, status=SessionStatus.CREATED,
        created_at=now, updated_at=now))


# ─────────────────────────────────────────────────────────────
# Completeness
# ─────────────────────────────────────────────────────────────

def test_every_pack_registers_its_full_inventory():
    rows = attacks.list_attacks()
    by_phase = {}
    for row in rows:
        by_phase.setdefault(row["phase"], set()).add(row["id"])
    assert set(by_phase) == set(EXPECTED)
    for phase, expected in EXPECTED.items():
        assert by_phase[phase] == expected, (
            f"{phase} mismatch: missing={expected - by_phase[phase]}, "
            f"extra={by_phase[phase] - expected}")


def test_registry_has_no_duplicates_and_no_problems():
    status = attacks.registry_status()
    assert status["duplicates"] == {}
    assert status["problems"] == []
    assert status["total"] == sum(len(v) for v in EXPECTED.values())
    for pack in status["packs"]:
        assert pack["ok"] is True
        assert pack["count"] == len(EXPECTED[pack["name"]])
        assert pack["error"] == ""


def test_every_module_is_discoverable_and_metadata_is_valid():
    for phase, ids in EXPECTED.items():
        for mid in ids:
            mod = attacks.get_attack(mid)
            assert mod is not None, f"{mid} is not registered"
            assert mod.id == mid
            assert mod.title and mod.summary
            assert mod.phase == phase
            assert int(mod.tier) in (1, 2, 3)
            assert callable(mod.plan) and callable(mod.execute)


def test_no_module_is_left_as_a_bare_scaffold():
    rows = attacks.list_attacks()
    scaffolds = [r["id"] for r in rows if r["status"] == "scaffold"]
    assert scaffolds == [], f"unwired modules: {scaffolds}"


def test_by_phase_counts_match_inventories():
    status = attacks.registry_status()
    assert status["by_phase"] == {p: len(ids) for p, ids in EXPECTED.items()}
    assert status["by_status"]["implemented"] + \
        status["by_status"]["runbook"] == status["total"]


# ─────────────────────────────────────────────────────────────
# Planning (offline)
# ─────────────────────────────────────────────────────────────

def test_all_modules_plan_offline(tmp_path, monkeypatch):
    from modules.logger import get_logger
    from modules.attacks import takeover

    # Keep the two plan() implementations with network I/O offline.
    monkeypatch.setattr(takeover, "_dangle_candidates", lambda *a, **k: [])
    import modules.recon.s3_enum as s3
    monkeypatch.setattr(s3, "run", lambda *a, **k: {})

    log = get_logger("test.registry")
    s = _session(tmp_path)
    for row in attacks.list_attacks():
        target = ("http://127.0.0.1" if row["phase"] in ("P3", "P4")
                  else "127.0.0.1")
        spec = {"target": target, "mode": "plan"}
        out = attacks.run_attack(s, row["id"], spec, log)
        assert out["ok"] is True, f"{row['id']} plan failed: {out.get('error')}"
        assert out["mode"] == "plan"
        assert out["out"]["module"] == row["id"]


# ─────────────────────────────────────────────────────────────
# Tier gate
# ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("tier,text,allowed", [
    (1, "", True),
    (2, "APPROVE", True),
    (2, "CONFIRM", True),
    (2, "NOT APPROVE", False),
    (2, "NOTCONFIRM", False),
    (2, "", False),
    (3, "CONFIRM", True),
    (3, "NOT CONFIRM", False),
    (3, "NOTCONFIRM", False),
    (3, "APPROVE", False),
])
def test_gate_is_exact_match(tier, text, allowed):
    from modules.attacks.registry import _gate_error

    class _Fake:
        id = "fake"
        title = "Fake"

    _Fake.tier = tier
    err = _gate_error(_Fake(), {"confirm_text": text})
    assert (err is None) is allowed


def test_tier2_exec_rejects_substring_confirm(tmp_path, monkeypatch):
    s = _session(tmp_path)
    calls = {"n": 0}

    class _Fake:
        id = "fake_tier2"
        title = "Fake Tier 2"
        phase = "P2"
        tier = 2

        def plan(self, *a, **k):
            return {"module": self.id, "mode": "plan"}

        def execute(self, *a, **k):
            calls["n"] += 1
            return {"module": self.id, "mode": "exec"}

    monkeypatch.setattr(attacks.registry, "_MODULES", {"fake_tier2": _Fake()})
    out = attacks.run_attack(s, "fake_tier2",
                             {"target": "127.0.0.1", "mode": "exec",
                              "confirm_text": "NOT APPROVE"})
    assert out["ok"] is False
    assert calls["n"] == 0


# ─────────────────────────────────────────────────────────────
# Dispatch errors
# ─────────────────────────────────────────────────────────────

def test_unknown_attack_is_structured_error(tmp_path):
    s = _session(tmp_path)
    out = attacks.run_attack(s, "does_not_exist",
                             {"target": "127.0.0.1", "mode": "plan"})
    assert out["ok"] is False
    assert "unknown attack" in out["error"]


def test_out_of_scope_target_is_hard_stop(tmp_path):
    s = _session(tmp_path)
    out = attacks.run_attack(s, "nmap_service_scan",
                             {"target": "definitely-not-in-scope.example.net",
                              "mode": "plan"})
    assert out["ok"] is False
    assert "SCOPE" in out["error"]


def test_manifest_covers_every_module():
    manifest = attacks.manifest()
    assert len(manifest) == sum(len(v) for v in EXPECTED.values())
    for row in manifest:
        assert row["class"] and row["module"].startswith("modules.attacks")


# ─────────────────────────────────────────────────────────────
# Dashboard wiring
# ─────────────────────────────────────────────────────────────

def test_dashboard_exposes_attack_routes():
    pytest.importorskip("flask")
    from ardf_v3_dashboard_api import ARDFv3DashboardAPI

    class _Framework:
        endpoints = type("_E", (), {
            "endpoints": {},
            "get_categories": lambda self: {},
        })()

        def get_modules(self):
            return {}

        def get_framework_state(self):
            return {}

    api = ARDFv3DashboardAPI(_Framework())
    rules = {str(r.rule) for r in api.app.url_map.iter_rules()}
    assert "/api/v3/attacks" in rules
    assert "/api/v3/attacks/run" in rules
    assert "/api/v3/attacks/status" in rules
