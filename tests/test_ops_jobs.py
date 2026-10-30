"""Ops job runner tests — offline playbook with an approval gate.

Uses a tmp report-only playbook (no network, no target contact) to prove:
scope check -> session -> plan -> gate pause -> approve -> execute -> done.
"""
import time

import pytest

import modules.session as sm


PB = """\
name: ops_test
version: "1.0"
mode: red
phases:
  - id: p1
    name: gated_report
    module: modules.report
    function: generate_report
    confirmation: true
    confirmation_message: "Approve report build?"
  - id: p2
    name: open_report
    module: modules.report
    function: generate_report
"""


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    sm._manager = None  # drop cached manager (root binds at construction)
    (tmp_path / "config" / "playbooks").mkdir(parents=True)
    pb = tmp_path / "pb.yaml"
    pb.write_text(PB)
    return pb


def _wait_for(cond, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.5)
    return False


class TestOpsJobs:
    def test_gate_pause_approve_complete(self, isolated):
        from ops.jobs import JobManager
        from ops.scope import ScopeGuard
        jm = JobManager(scope=ScopeGuard(enabled=False))
        job = jm.create_job(playbook=str(isolated), target="127.0.0.1",
                            user="test")
        assert _wait_for(
            lambda: jm.jobs[job["id"]]["status"] == "waiting_approval"), \
            "job never paused at gate"
        pending = jm.list_approvals()
        assert len(pending) == 1 and pending[0]["tier"] == 2
        out = jm.decide(pending[0]["id"], True, user="test")
        assert out["status"] == "approved"
        assert _wait_for(
            lambda: jm.jobs[job["id"]]["status"] == "complete", timeout=120), \
            "job never completed"
        tasks = {t["name"]: t["status"] for t in jm.jobs[job["id"]]["tasks"]}
        assert tasks.get("gated_report") == "done"
        assert tasks.get("open_report") == "done"

    def test_scope_violation_blocks_job(self, tmp_path):
        from ops.jobs import JobManager
        from ops.scope import ScopeGuard, ScopeViolation
        jm = JobManager(scope=ScopeGuard(
            enabled=True, allowed_targets=["10.0.0.0/8"]))
        with pytest.raises(ScopeViolation):
            jm.create_job(playbook="full", target="evil.example.com")

    def test_tier3_needs_confirm_text(self, isolated):
        from ops.jobs import JobManager
        from ops.scope import ScopeGuard
        jm = JobManager(scope=ScopeGuard(enabled=False))
        job = jm.create_job(playbook=str(isolated), target="127.0.0.1")
        assert _wait_for(
            lambda: jm.jobs[job["id"]]["status"] == "waiting_approval")
        ap = jm.list_approvals()[0]
        # tier-2 passes without confirm text
        assert jm.decide(ap["id"], True)["status"] == "approved"
