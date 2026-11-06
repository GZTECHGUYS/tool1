"""Framework loading + dashboard telemetry / model / Wi-Fi route tests."""
from __future__ import annotations

import importlib.util

import pytest


# ─────────────────────────────────────────────────────────────
# Framework module loading
# ─────────────────────────────────────────────────────────────

def test_load_all_modules_is_sequential_and_uses_unique_names(tmp_path):
    (tmp_path / "alpha.py").write_text(
        "NAME = __name__\nVALUE = 1\n", encoding="utf-8")
    (tmp_path / "beta.py").write_text(
        "NAME = __name__\nVALUE = 2\n", encoding="utf-8")

    from ardf_v3_framework import ARDFv3Framework

    fw = ARDFv3Framework(str(tmp_path))
    results = fw.load_all_modules()
    assert results == {"core.alpha": True, "core.beta": True}
    assert fw.state["modules_loaded"] == 2
    assert fw.state["modules_failed"] == 0

    names = {mod.NAME for mod in fw.modules.values()}
    assert names == {"_ardf_discovered_core_alpha",
                     "_ardf_discovered_core_beta"}
    # A module importing by bare stem no longer shadows a real package.
    assert all(name.startswith("_ardf_discovered_") for name in names)
    fw.executor.shutdown(wait=False)


def test_cloud_suite_imports_without_boto3():
    # boto3 is optional; importing the module must not fail when it is absent.
    import cloud_compromise_suite as suite
    assert hasattr(suite, "AWSCompromise")
    if importlib.util.find_spec("boto3") is None:
        assert suite.boto3 is None


# ─────────────────────────────────────────────────────────────
# Dashboard routes
# ─────────────────────────────────────────────────────────────

class _Endpoints:
    endpoints = {"GET /api/v3/ping": {"path": "/api/v3/ping"}}

    def get_categories(self):
        return {"core": ["GET /api/v3/ping"]}


class _Framework:
    endpoints = _Endpoints()

    def get_framework_state(self):
        return {
            "initialized": True,
            "modules_loaded": 190,
            "modules_failed": 3,
            "modules_info": {
                "core.alpha": {"status": "loaded", "category": "core"},
                "core.beta": {"status": "failed", "category": "core"},
            },
            "start_time": "2026-11-05T00:00:00",
        }

    def get_modules(self):
        return {}


def _api(monkeypatch):
    pytest.importorskip("flask")
    from ardf_v3_dashboard_api import ARDFv3DashboardAPI
    import ai.local_model as local_model
    import modules.preflight as preflight
    import modules.session as session
    import modules.attacks as attacks
    import ops.events as events

    class _Manager:
        def list_sessions(self):
            return [{
                "session_id": "s1", "status": "running",
                "findings_count": 0, "risk_score": 0,
                "updated_at": "2026-11-05T00:00:00",
            }]

        def load(self, session_id):
            raise AssertionError("no findings should be loaded for count=0")

    monkeypatch.setattr(session, "get_manager", lambda: _Manager())
    monkeypatch.setattr(preflight, "check", lambda: {"ready": True})
    monkeypatch.setattr(local_model, "model_status", lambda role="tactical": {
        "ollama_running": True, "available": ["qwen2.5:0.5b"],
        "count": 1, "installed": True,
    })
    monkeypatch.setattr(attacks, "list_attacks", lambda: [
        {"id": "a", "phase": "P1"}, {"id": "b", "phase": "P2"}])
    monkeypatch.setattr(events, "stats", lambda: {
        "history": 3, "subscribers": 1, "last_id": 7})
    monkeypatch.setattr(events, "since", lambda event_id: [
        {"id": 7, "type": "test", "data": {}}])

    api = ARDFv3DashboardAPI(_Framework())
    token = api.ops_auth.issue("tester")["token"]
    return api, {"Authorization": "Bearer " + token}


def test_telemetry_reports_loaded_modules_and_models(monkeypatch):
    api, headers = _api(monkeypatch)
    client = api.app.test_client()
    resp = client.get("/api/v3/dashboard/telemetry", headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["modules"]["loaded"] == 190
    assert data["modules"]["failed"] == 3
    assert data["modules"]["total"] == 193
    assert data["sessions"]["total"] == 1
    assert data["ai_models"]["count"] == 1
    assert data["attacks"]["total"] == 2
    assert data["endpoints"]["api_routes"] == 1
    assert data["stream"]["last_id"] == 7
    assert data["preflight_ready"] is True
    assert data["recent_events"]


def test_dashboard_exposes_telemetry_model_and_wifi_routes(monkeypatch):
    api, headers = _api(monkeypatch)
    rules = {str(rule) for rule in api.app.url_map.iter_rules()}
    for route in ("/api/v3/dashboard/telemetry", "/api/v3/models/status",
                  "/api/v3/models/start", "/api/v3/wifi/status",
                  "/api/v3/wifi/trace", "/api/v3/wifi/devices"):
        assert route in rules

    client = api.app.test_client()
    assert client.get("/api/v3/dashboard/telemetry").status_code == 401
    assert client.get("/api/v3/models/status", headers=headers).status_code == 200


def test_wifi_trace_route_does_not_bypass_authorization(monkeypatch):
    api, headers = _api(monkeypatch)
    import modules.attacks.wifi as wifi

    monkeypatch.setattr(wifi, "trace_scan", lambda spec: {
        "ok": False, "status": "authorization_required",
        "devices": [], "error": "authorization ref required"})
    client = api.app.test_client()
    resp = client.post("/api/v3/wifi/trace", json={}, headers=headers)
    assert resp.status_code == 403
    assert resp.get_json()["status"] == "authorization_required"


def test_model_status_reports_offline_cleanly(monkeypatch):
    from ai.local_model import ModelManager

    manager = ModelManager()
    monkeypatch.setattr(manager, "ollama_running", lambda: False)
    status = manager.status()
    assert status["ollama_running"] is False
    assert status["count"] == 0
    assert "ollama pull" in status["hint"]


def test_model_status_lists_installed_models(monkeypatch):
    from ai.local_model import ModelManager

    manager = ModelManager()
    monkeypatch.setattr(manager, "ollama_running", lambda: True)
    monkeypatch.setattr(manager, "list_models",
                        lambda force_refresh=False: ["qwen2.5:0.5b"])
    status = manager.status("tactical")
    assert status["count"] == 1
    assert status["best_for_role"] == "qwen2.5:0.5b"
