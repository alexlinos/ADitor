"""Tests for the app's persisted settings.

The load-bearing assertion here is that the config file the app writes contains
the ``${AD_MCP_PASSWORD}`` placeholder and never the password, and that a
credential store which cannot take the secret means **nothing is written at
all** — not the secret, not the rest, not a fallback file.

Everything runs against ``tmp_path``. No real settings directory is read or
written.
"""

import json
import stat
import sys
from pathlib import Path

import pytest

from aditor.app.credentials import (
    CONFIG_PASSWORD_PLACEHOLDER,
    CredentialRef,
    CredentialStore,
    CredentialStoreError,
    CredentialStoreUnavailable,
)
from aditor.app.settings import (
    APP_DIR_NAME,
    CONFIG_FILENAME,
    ConnectionSettings,
    PersistRefused,
    build_config_document,
    config_path,
    load_password,
    load_settings,
    persist_connection,
    settings_dir,
)
from aditor.config.loader import load_config

PASSWORD = "N0t-A-Real-Password-9f3ac1"
BASE_DN = "DC=test,DC=local"
BIND_DN = f"CN=svc-aditor,OU=Service Accounts,{BASE_DN}"


def a_connection(**overrides) -> ConnectionSettings:
    values = {
        "server": "ldaps://dc01.test.local:636",
        "domain": "test.local",
        "base_dn": BASE_DN,
        "bind_dn": BIND_DN,
        "validate_certificate": True,
    }
    values.update(overrides)
    return ConnectionSettings(**values)


class FakeStore(CredentialStore):
    """An in-memory stand-in. Never touches a real credential store."""

    name = "Fake Store"
    where = "nowhere real"

    def __init__(self, available=True, fail_with=None):
        self._available = available
        self._fail_with = fail_with
        self.items = {}

    def available(self):
        return self._available

    def set_password(self, ref, password):
        self.require()
        if self._fail_with:
            raise self._fail_with
        self.items[ref.target] = password

    def get_password(self, ref):
        self.require()
        if self._fail_with:
            raise self._fail_with
        return self.items.get(ref.target)

    def delete_password(self, ref):
        self.require()
        return self.items.pop(ref.target, None) is not None


# --------------------------------------------------------------------------- #
# Where the settings live
# --------------------------------------------------------------------------- #

class TestSettingsDir:
    def test_windows_uses_appdata(self):
        path = settings_dir("win32", {"APPDATA": r"C:\Users\admin\AppData\Roaming"})
        assert path == Path(r"C:\Users\admin\AppData\Roaming") / APP_DIR_NAME

    def test_windows_falls_back_to_localappdata(self):
        path = settings_dir("win32", {"LOCALAPPDATA": r"C:\Users\admin\AppData\Local"})
        assert path.name == APP_DIR_NAME

    def test_macos_uses_application_support(self):
        path = settings_dir("darwin", {"HOME": "/Users/admin"})
        assert path == Path("/Users/admin/Library/Application Support") / APP_DIR_NAME

    def test_other_platforms_use_xdg(self):
        path = settings_dir("linux", {"XDG_CONFIG_HOME": "/home/a/.config"})
        assert path == Path("/home/a/.config/aditor")

    def test_it_is_not_inside_the_repository(self):
        # Snapshots and settings hold directory content; the repo is the one
        # place they must not default into.
        assert "ADMCP" not in str(settings_dir("win32", {"APPDATA": "C:/x"}))


# --------------------------------------------------------------------------- #
# The document — the password property, asserted without touching a disk
# --------------------------------------------------------------------------- #

class TestConfigDocument:
    def test_the_password_field_is_the_placeholder(self):
        document = build_config_document(a_connection())
        assert document["active_directory"]["password"] == \
            CONFIG_PASSWORD_PLACEHOLDER

    def test_the_password_appears_nowhere_in_the_serialised_document(self):
        # The whole document as text, because a password could be hiding in a
        # comment or a nested block rather than in the obvious field.
        text = json.dumps(build_config_document(a_connection()))
        assert PASSWORD not in text

    def test_it_carries_the_settings_the_form_collected(self):
        document = build_config_document(a_connection())
        active = document["active_directory"]
        assert active["server"] == "ldaps://dc01.test.local:636"
        assert active["domain"] == "test.local"
        assert active["base_dn"] == BASE_DN
        assert active["bind_dn"] == BIND_DN

    def test_certificate_validation_is_carried_through(self):
        assert build_config_document(
            a_connection(validate_certificate=False)
        )["security"]["validate_certificate"] is False

    def test_no_log_file_is_configured(self):
        # A log file is one more artifact that would need proving free of the
        # password, and the app has nowhere to display it.
        assert "logging" not in build_config_document(a_connection())

    def test_one_bind_attempt_not_three(self):
        # Three retries against a wrong password walks a real bind account
        # toward the domain's lockout threshold.
        assert build_config_document(
            a_connection())["performance"]["max_retries"] == 1

    def test_the_headless_server_can_load_what_the_app_writes(self, tmp_path,
                                                              monkeypatch):
        # The point of writing the server's own format: starting the server
        # must not need a translation step that can disagree with the app.
        path = tmp_path / CONFIG_FILENAME
        path.write_text(json.dumps(build_config_document(a_connection())))
        monkeypatch.setenv("AD_MCP_PASSWORD", PASSWORD)
        config = load_config(str(path))
        assert config.active_directory.base_dn == BASE_DN
        # The loader expands the placeholder from the environment, which is the
        # mechanism that keeps the secret off disk.
        assert config.active_directory.password == PASSWORD

    def test_the_placeholder_stays_unexpanded_without_the_variable(
            self, tmp_path, monkeypatch):
        path = tmp_path / CONFIG_FILENAME
        path.write_text(json.dumps(build_config_document(a_connection())))
        monkeypatch.delenv("AD_MCP_PASSWORD", raising=False)
        config = load_config(str(path))
        assert config.active_directory.password == CONFIG_PASSWORD_PLACEHOLDER


# --------------------------------------------------------------------------- #
# Persisting — both halves or neither
# --------------------------------------------------------------------------- #

class TestPersistConnection:
    def test_a_good_save_stores_the_secret_and_writes_the_file(self, tmp_path):
        store = FakeStore()
        result = persist_connection(a_connection(), PASSWORD, tmp_path, store)
        assert result.config_path == tmp_path / CONFIG_FILENAME
        assert store.items[CredentialRef(account=BIND_DN).target] == PASSWORD
        assert result.config_path.is_file()

    def test_the_written_file_does_not_contain_the_password(self, tmp_path):
        persist_connection(a_connection(), PASSWORD, tmp_path, FakeStore())
        text = (tmp_path / CONFIG_FILENAME).read_text(encoding="utf-8")
        assert PASSWORD not in text
        assert CONFIG_PASSWORD_PLACEHOLDER in text

    @pytest.mark.skipif(sys.platform.startswith("win"),
                        reason="POSIX file modes")
    def test_the_file_is_owner_only(self, tmp_path):
        persist_connection(a_connection(), PASSWORD, tmp_path, FakeStore())
        mode = stat.S_IMODE((tmp_path / CONFIG_FILENAME).stat().st_mode)
        assert mode == 0o600

    def test_an_unavailable_store_writes_nothing_at_all(self, tmp_path):
        store = FakeStore(available=False)
        with pytest.raises(PersistRefused) as caught:
            persist_connection(a_connection(), PASSWORD, tmp_path, store)
        # The refusal, and the absence of *any* file, is the whole point: a
        # config pointing at a credential that does not exist would send the
        # operator debugging an authentication failure.
        assert "Nothing has been saved" in str(caught.value)
        assert list(tmp_path.iterdir()) == []

    def test_a_store_error_writes_nothing_and_says_there_is_no_fallback(
            self, tmp_path):
        store = FakeStore(fail_with=CredentialStoreError("keychain is locked"))
        with pytest.raises(PersistRefused) as caught:
            persist_connection(a_connection(), PASSWORD, tmp_path, store)
        message = str(caught.value)
        assert "keychain is locked" in message
        assert "does not write the password to a file" in message
        assert list(tmp_path.iterdir()) == []

    def test_the_secret_is_stored_before_the_file_is_written(self, tmp_path):
        # Ordering matters: the store is the half that can fail for reasons the
        # operator has to act on, so it goes first.
        order = []

        class OrderedStore(FakeStore):
            def set_password(self, ref, password):
                order.append("store")
                super().set_password(ref, password)

        store = OrderedStore()
        persist_connection(a_connection(), PASSWORD, tmp_path, store)
        order.append("file" if (tmp_path / CONFIG_FILENAME).is_file() else "?")
        assert order == ["store", "file"]

    def test_missing_fields_are_all_named(self, tmp_path):
        with pytest.raises(PersistRefused) as caught:
            persist_connection(
                a_connection(domain="", base_dn=""), PASSWORD, tmp_path,
                FakeStore())
        message = str(caught.value)
        assert "Domain" in message and "Base DN" in message
        assert list(tmp_path.iterdir()) == []

    def test_no_password_is_a_refusal_not_an_empty_save(self, tmp_path):
        with pytest.raises(PersistRefused, match="without a password"):
            persist_connection(a_connection(), "", tmp_path, FakeStore())
        assert list(tmp_path.iterdir()) == []


class TestLoadSettings:
    def test_a_round_trip(self, tmp_path):
        persist_connection(a_connection(validate_certificate=False), PASSWORD,
                           tmp_path, FakeStore())
        loaded = load_settings(tmp_path).connection
        assert loaded.server == "ldaps://dc01.test.local:636"
        assert loaded.base_dn == BASE_DN
        assert loaded.bind_dn == BIND_DN
        assert loaded.validate_certificate is False

    def test_a_missing_file_gives_empty_defaults(self, tmp_path):
        settings = load_settings(tmp_path / "nope").connection
        assert settings.server == ""
        assert settings.missing_fields()

    def test_a_corrupt_file_gives_defaults_rather_than_a_traceback(self,
                                                                  tmp_path):
        config_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
        config_path(tmp_path).write_text("{ this is not json")
        assert load_settings(tmp_path).connection.server == ""

    def test_a_json_array_gives_defaults(self, tmp_path):
        config_path(tmp_path).write_text("[]")
        assert load_settings(tmp_path).connection.server == ""


class TestSnapshotDir:
    def test_an_explicit_directory_is_used(self, tmp_path):
        settings = a_connection(snapshot_dir=str(tmp_path / "scans"))
        assert settings.resolved_snapshot_dir() == tmp_path / "scans"

    def test_a_relative_directory_resolves_against_the_working_directory(self):
        settings = a_connection(snapshot_dir="scans")
        assert settings.resolved_snapshot_dir().is_absolute()

    def test_the_default_sits_under_the_app_directory(self):
        assert a_connection().resolved_snapshot_dir().name == "snapshots"


class TestLoadPassword:
    def test_it_comes_back_from_the_store(self, tmp_path):
        store = FakeStore()
        persist_connection(a_connection(), PASSWORD, tmp_path, store)
        assert load_password(a_connection(), store) == PASSWORD

    def test_an_unavailable_store_yields_none_rather_than_raising(self):
        assert load_password(a_connection(), FakeStore(available=False)) is None

    def test_an_unreadable_store_raises_so_it_is_not_read_as_empty(self):
        store = FakeStore(fail_with=CredentialStoreError("locked"))
        with pytest.raises(CredentialStoreError):
            load_password(a_connection(), store)

    def test_no_bind_account_means_no_lookup(self):
        assert load_password(a_connection(bind_dn=""), FakeStore()) is None

    def test_an_unavailable_store_is_not_asked(self):
        class Exploding(FakeStore):
            def get_password(self, ref):
                raise CredentialStoreUnavailable("should not be called")

        assert load_password(a_connection(),
                             Exploding(available=False)) is None
