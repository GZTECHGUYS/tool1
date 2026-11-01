"""Smoke tests for modules.apikeys (Settings-tab key resolver)."""
from __future__ import annotations

import os
import stat

import pytest

from modules import apikeys


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    """Point the resolver at temp files; keep env clean for our keys."""
    monkeypatch.setattr(apikeys, "KEYS_FILE", tmp_path / "api_keys.yaml")
    monkeypatch.setattr(apikeys, "ARDF_YAML", tmp_path / "ardf.yaml")
    (tmp_path / "ardf.yaml").write_text(
        "api_keys:\n"
        "  shodan: \"${SHODAN_API_KEY}\"\n"
        "  c99: \"real-config-value\"\n"
        "  censys:\n"
        "    id: \"${CENSYS_API_ID}\"\n"
        "    secret: \"censys-real-secret\"\n")
    for env in apikeys.KEYS.values():
        monkeypatch.delenv(env, raising=False)
    return tmp_path


def test_env_beats_file_and_config(isolated, monkeypatch):
    apikeys.set_key("shodan", "file-level-key")
    monkeypatch.setenv("SHODAN_API_KEY", "env-level-key")
    assert apikeys.get_key("shodan") == "env-level-key"
    assert apikeys.source_of("shodan") == "env"


def test_file_beats_config(isolated):
    apikeys.set_key("shodan", "file-level-key")
    assert apikeys.get_key("shodan") == "file-level-key"
    assert apikeys.source_of("shodan") == "file"


def test_config_value_used_when_not_placeholder(isolated):
    # c99 is a real value in ardf.yaml; shodan is a ${...} placeholder
    assert apikeys.get_key("c99") == "real-config-value"
    assert apikeys.source_of("c99") == "config"
    assert apikeys.get_key("shodan") == ""
    assert apikeys.source_of("shodan") == "unset"


def test_censys_nested_config(isolated):
    assert apikeys.get_key("censys_secret") == "censys-real-secret"
    assert apikeys.get_key("censys_id") == ""


def test_file_permissions_0600(isolated):
    apikeys.set_key("virustotal", "vt-secret")
    mode = stat.S_IMODE(os.stat(apikeys.KEYS_FILE).st_mode)
    assert mode == 0o600


def test_status_is_masked(isolated, monkeypatch):
    apikeys.set_key("virustotal", "0123456789abcdef")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-env-value")
    entries = {e["name"]: e for e in apikeys.status()}
    assert entries["virustotal"]["masked"] == "0123…cdef"
    assert "0123456789abcdef" not in str(entries)
    assert entries["shodan"]["source"] == "env"
    assert entries["greynoise"]["configured"] is False


def test_delete_removes_only_file_copy(isolated, monkeypatch):
    apikeys.set_key("github", "tok-file")
    monkeypatch.setenv("GITHUB_TOKEN", "tok-env")
    # env still wins after file delete; file copy gone
    apikeys.delete_key("github")
    assert apikeys._file_values() == {}
    monkeypatch.delenv("GITHUB_TOKEN")
    assert apikeys.get_key("github") == ""


def test_unknown_key_rejected(isolated):
    with pytest.raises(KeyError):
        apikeys.set_key("not-a-key", "x")
    with pytest.raises(KeyError):
        apikeys.delete_key("not-a-key")
    assert apikeys.get_key("not-a-key") == ""


def test_apply_to_environ(isolated):
    apikeys.set_key("securitytrails", "st-key")
    n = apikeys.apply_to_environ()
    assert n >= 1
    assert os.environ.get("SECURITYTRAILS_API_KEY") == "st-key"
    # second call is a no-op (already exported)
    assert apikeys.apply_to_environ() == 0
