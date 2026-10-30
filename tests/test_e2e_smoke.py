"""E2E smoke test — full offline pipeline, no network, no targets.

Session -> findings -> attack paths -> kill chain -> loot triage ->
PDF -> remediation -> scope guard -> preflight. Proves CLI-adjacent
wiring works end-to-end after refactors.
"""
from datetime import datetime

from modules.session import Session, SessionMeta, SessionStatus, Mode
from modules.session import Finding, SeverityLevel


def _make_session(tmp_path, name="e2e_smoke"):
    import modules.session as sm
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    now = datetime.now().isoformat()
    meta = SessionMeta(
        session_id=name, name=name, target="127.0.0.1",
        mode=Mode.FULL, status=SessionStatus.CREATED,
        created_at=now, updated_at=now,
    )
    s = Session(meta)
    s.save()
    return s


class TestE2EPipeline:
    def test_full_offline_pipeline(self, tmp_path):
        from graph.attack_path import AttackPathBuilder
        from graph.kill_chain_mapper import KillChainMapper
        from modules import loot, exfil_ledger, pdf_report
        from modules import preflight
        from ops.scope import ScopeGuard

        s = _make_session(tmp_path)
        s.add_finding(Finding(
            source="recon.passive", title="Subdomain found",
            severity=SeverityLevel.INFO, host="127.0.0.1",
            tags=["subdomain", "passive"]))
        s.add_finding(Finding(
            source="exploit.web", title="SQL Injection confirmed",
            severity=SeverityLevel.CRITICAL, host="127.0.0.1",
            tags=["sqli", "confirmed"],
            evidence="password: s3cr3t password: s3cr3t"))

        # attack paths + kill chain
        paths = AttackPathBuilder(s).build_all()
        assert any("Web Application" in p.name for p in paths)
        kc = KillChainMapper(s).map()
        assert kc["total_mapped"] >= 2

        # loot + exfil ledger
        triage = loot.triage_session(s)
        assert triage["count"] >= 1
        exfil_ledger.record(s, "loot.txt", kind="loot",
                            size_bytes=128, channel="https")
        assert exfil_ledger.summary(s)["events"] == 1

        # PDF + remediation
        pdf = pdf_report.build_pdf(s)
        assert pdf.exists() and pdf.stat().st_size > 500
        pdf_report.set_state(s, s.get_findings()[0].id, "fixed",
                             note="smoke", user="test")
        summ = pdf_report.remediation_summary(s)
        assert summ["by_state"]["fixed"] == 1

        # scope + preflight
        guard = ScopeGuard(enabled=True, allowed_targets=["127.0.0.1"])
        assert guard.validate("127.0.0.1")[0] is True
        assert guard.validate("evil.example.com")[0] is False
        rep = preflight.check()
        assert "tools" in rep and "python" in rep

    def test_ops_modules_import(self):
        import ops.jobs, ops.auth, ops.c2  # noqa: F401
        import modules.verify, modules.payloads  # noqa: F401
        import modules.opsec_profiles, modules.intel_enrich  # noqa: F401
        from modules.payloads import build_profile
        spec = build_profile("linux_x64_stageless", lhost="10.0.0.1")
        assert spec["os"] == "linux"
        from modules.opsec_profiles import apply_profile
        assert apply_profile("normal").name == "normal"
