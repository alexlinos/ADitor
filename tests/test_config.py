"""Tests for configuration module."""

import json

import pytest

from aditor.config.loader import load_config
from aditor.config.models import ActiveDirectoryConfig, Config

AD = {
    "server": "ldap://test.local:389",
    "domain": "test.local",
    "base_dn": "DC=test,DC=local",
    "bind_dn": "CN=admin,DC=test,DC=local",
    "password": "password123",
}


def write(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data,
                    encoding="utf-8")
    return str(path)


def test_load_config_from_file(tmp_path):
    config = load_config(write(tmp_path, {"active_directory": AD}))
    assert isinstance(config, Config)
    assert config.active_directory.server == "ldap://test.local:389"
    assert config.active_directory.domain == "test.local"


def test_load_config_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AD_MCP_CONFIG", write(tmp_path, {"active_directory": AD}))
    assert load_config().active_directory.base_dn == "DC=test,DC=local"


def test_the_password_placeholder_is_expanded_from_the_environment(
        tmp_path, monkeypatch):
    monkeypatch.setenv("AD_MCP_PASSWORD", "from-env")
    path = write(tmp_path, {"active_directory": dict(
        AD, password="${AD_MCP_PASSWORD}")})
    assert load_config(path).active_directory.password == "from-env"


def test_legacy_blocks_and_unknown_keys_are_ignored(tmp_path):
    # Configs written before the MCP removal still carry these.
    path = write(tmp_path, {
        "_comment": "written by the app",
        "active_directory": dict(AD, use_ssl=True, ssl_port=636),
        "organizational_units": {"users_ou": "OU=Users,DC=test,DC=local"},
        "logging": {"level": "INFO"},
        "security": {"require_secure_connection": True},
        "performance": {"connection_pool_size": 10, "max_retries": 1},
    })
    config = load_config(path)
    assert config.performance.max_retries == 1


def test_invalid_server_url():
    with pytest.raises(ValueError, match="Server must start with ldap:// or ldaps://"):
        ActiveDirectoryConfig(**dict(AD, server="http://invalid.com"))


def test_missing_config_file():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.json")


def test_invalid_json(tmp_path):
    with pytest.raises(json.JSONDecodeError):
        load_config(write(tmp_path, "invalid json content"))


def test_missing_required_fields(tmp_path):
    path = write(tmp_path, {"active_directory": {"server": "ldap://test.local"}})
    with pytest.raises(ValueError, match="invalid configuration"):
        load_config(path)


def test_a_config_without_an_active_directory_block_is_refused(tmp_path):
    with pytest.raises(ValueError, match="active_directory"):
        load_config(write(tmp_path, {"security": {}}))


def test_non_positive_retries_are_refused(tmp_path):
    path = write(tmp_path, {"active_directory": AD,
                            "performance": {"max_retries": 0}})
    with pytest.raises(ValueError, match="positive"):
        load_config(path)


def test_default_values(tmp_path):
    config = load_config(write(tmp_path, {"active_directory": AD}))
    assert config.security.enable_tls is True
    assert config.security.validate_certificate is True
    assert config.performance.max_retries == 3
    assert config.active_directory.timeout == 30
