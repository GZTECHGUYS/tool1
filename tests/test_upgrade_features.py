import json
from pathlib import Path

from modules.session import Session, SessionMode
from modules.recon.adapters import DeepReconAdapterSuite
from modules.workflow import build_bypass_decision
from modules.exploit import classify_exploit, validate_exploit_target
from playbook.validator import PlaybookValidator


def _make_session(target: str = "example.com"):
    return Session(target, SessionMode.RED)


def test_deep_recon_artifacts_include_dns_cert_cloud_service():
    session = _make_session()
    suite = DeepReconAdapterSuite(session)
    result = suite.collect("example.com")

    assert set(["dns", "certificates", "cloud", "services", "origin_candidates", "waf_signals"]).issubset(result)
    assert isinstance(result["dns"], dict)
    assert isinstance(result["services"], list)
    assert isinstance(result["origin_candidates"], list)


def test_bypass_decision_tree_prefers_origin_candidates():
    decision = build_bypass_decision({
        "waf_type": "cloudflare",
        "origin_candidates": ["93.184.216.34"],
        "live_urls": ["https://example.com"],
    })

    assert decision["decision"] == "direct_origin"
    assert decision["origin_candidates"] == ["93.184.216.34"]
    assert "direct attack" in decision["reason"].lower()


def test_exploit_validation_requires_classification_before_execution():
    classification = classify_exploit("https://example.com", [], {}, {})
    assert classification["category"] in {"web", "network", "credential", "unknown"}

    validation = validate_exploit_target("https://example.com", {"category": "unknown"}, {})
    assert validation["allowed"] is False
    assert "classification" in validation["reason"].lower()


def test_playbook_validator_accepts_richer_yaml_fields():
    playbook = {
        "name": "full_offensive_phase",
        "version": "1.0",
        "mode": "red",
        "phases": [
            {
                "id": "phase_01",
                "name": "dns_recon",
                "module": "modules.recon",
                "function": "run_recon",
                "depends_on": [],
                "confirmation": True,
                "confirm_msg": "Will query live DNS and certificate sources.",
                "on_failure": "continue",
                "timeout_minutes": 30,
                "tags": ["dns", "recon"],
            }
        ],
    }

    valid, errors, warnings = PlaybookValidator().validate(playbook)
    assert valid is True
    assert errors == []
