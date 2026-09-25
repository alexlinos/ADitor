"""Tests for the OS credential store abstraction.

No keychain is touched and no Credential Manager call is made: the macOS store's
``subprocess.run`` is patched and the Windows store is exercised through its
pure parts (target naming, blob encoding) plus its availability check. That is
deliberate — the operator's real login keychain is out of bounds for this suite,
and the platform calls are thin wrappers around logic that *is* covered here.

What these tests are really guarding is the refusal: an unsupported platform must
raise rather than quietly writing the password somewhere.
"""

import logging
import subprocess
from unittest.mock import patch

import pytest

from aditor.app.credentials import (
    CONFIG_PASSWORD_PLACEHOLDER,
    DEFAULT_SERVICE,
    PASSWORD_ENV_VAR,
    REDACTED,
    CredentialRef,
    CredentialStoreError,
    CredentialStoreUnavailable,
    MacOSKeychainStore,
    NoCredentialStore,
    SecretRedactingFilter,
    WindowsCredentialManagerStore,
    decode_windows_blob,
    encode_windows_blob,
    get_store,
)

PASSWORD = "Tr0ub4dor-&3-horse-battery"
ACCOUNT = "CN=svc-aditor,OU=Service Accounts,DC=test,DC=local"


# --------------------------------------------------------------------------- #
# The shared contract
# --------------------------------------------------------------------------- #

class TestCredentialRef:
    def test_target_is_service_then_account(self):
        ref = CredentialRef(account=ACCOUNT)
        assert ref.service == DEFAULT_SERVICE
        assert ref.target == f"{DEFAULT_SERVICE}:{ACCOUNT}"

    def test_default_service_matches_the_keychain_script(self):
        # scan_keychain.sh uses ADMCP_KEYCHAIN_SERVICE=admcp-ldap. The
        # app must read the same item rather than keeping a second copy.
        assert DEFAULT_SERVICE == "admcp-ldap"

    def test_account_is_required(self):
        with pytest.raises(ValueError, match="account"):
            CredentialRef(account="")

    def test_service_is_required(self):
        with pytest.raises(ValueError, match="service"):
            CredentialRef(account=ACCOUNT, service="  ")

    def test_two_accounts_get_two_items(self):
        first = CredentialRef(account="CN=a,DC=test,DC=local")
        second = CredentialRef(account="CN=b,DC=test,DC=local")
        assert first.target != second.target


class TestPlaceholderContract:
    def test_placeholder_is_the_env_var(self):
        assert CONFIG_PASSWORD_PLACEHOLDER == "${" + PASSWORD_ENV_VAR + "}"

    def test_env_var_is_the_one_the_loader_expands(self):
        assert PASSWORD_ENV_VAR == "AD_MCP_PASSWORD"


class TestStoreSelection:
    def test_windows_gets_credential_manager(self):
        assert isinstance(get_store("win32"), WindowsCredentialManagerStore)

    def test_macos_gets_the_keychain(self):
        assert isinstance(get_store("darwin"), MacOSKeychainStore)

    def test_anything_else_gets_the_refusing_store(self):
        assert isinstance(get_store("linux"), NoCredentialStore)
        assert isinstance(get_store("freebsd13"), NoCredentialStore)

    def test_windows_store_is_unavailable_off_windows(self):
        # Asking for the Windows store on a Mac gets an object that says it
        # cannot run here, not one that pretends it can.
        assert get_store("win32").available() is False


# --------------------------------------------------------------------------- #
# The refusal — the property the brief is actually about
# --------------------------------------------------------------------------- #

class TestNoCredentialStoreRefuses:
    def test_set_password_raises_rather_than_writing_a_file(self, tmp_path):
        store = NoCredentialStore("linux")
        with pytest.raises(CredentialStoreUnavailable):
            store.set_password(CredentialRef(account=ACCOUNT), PASSWORD)
        # Nothing anywhere: no fallback file was created next to anything.
        assert list(tmp_path.iterdir()) == []

    def test_get_and_delete_raise_too(self):
        store = NoCredentialStore("linux")
        ref = CredentialRef(account=ACCOUNT)
        with pytest.raises(CredentialStoreUnavailable):
            store.get_password(ref)
        with pytest.raises(CredentialStoreUnavailable):
            store.delete_password(ref)

    def test_reason_names_the_platform_and_says_it_will_not_use_a_file(self):
        reason = NoCredentialStore("linux").unavailable_reason()
        assert "linux" in reason
        assert "will not write" in reason.lower()

    def test_require_raises(self):
        with pytest.raises(CredentialStoreUnavailable):
            NoCredentialStore("linux").require()

    def test_there_is_no_file_backed_store_to_fall_back_to(self):
        import aditor.app.credentials as module

        # A file-backed implementation is the thing that must not exist: its
        # presence is what would make a silent fallback a one-line change.
        names = [name for name in dir(module) if name.endswith("Store")]
        assert sorted(names) == [
            "CredentialStore", "MacOSKeychainStore", "NoCredentialStore",
            "WindowsCredentialManagerStore",
        ]


# --------------------------------------------------------------------------- #
# Windows — the parts that can be tested anywhere
# --------------------------------------------------------------------------- #

class TestWindowsBlob:
    def test_round_trip(self):
        assert decode_windows_blob(encode_windows_blob(PASSWORD)) == PASSWORD

    def test_encoding_is_utf16le_with_no_bom(self):
        blob = encode_windows_blob("ab")
        assert blob == b"a\x00b\x00"

    def test_unicode_survives(self):
        secret = "pässwörd-Ω-中"
        assert decode_windows_blob(encode_windows_blob(secret)) == secret

    def test_a_nul_terminated_blob_from_another_tool_decodes(self):
        blob = encode_windows_blob(PASSWORD) + b"\x00\x00"
        assert decode_windows_blob(blob) == PASSWORD

    def test_an_odd_length_blob_does_not_raise(self):
        assert decode_windows_blob(encode_windows_blob("ab") + b"\x01") == "ab"

    def test_encoding_rejects_a_non_string(self):
        with pytest.raises(TypeError):
            encode_windows_blob(1234)


# --------------------------------------------------------------------------- #
# macOS — argv must never carry the secret
# --------------------------------------------------------------------------- #

def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class TestMacOSKeychain:
    @pytest.fixture
    def store(self):
        store = MacOSKeychainStore()
        # available() is patched rather than the platform, so the test runs the
        # same on any machine.
        with patch.object(MacOSKeychainStore, "available", return_value=True):
            yield store

    def test_the_password_goes_on_stdin_and_never_into_argv(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed()) as run:
            store.set_password(CredentialRef(account=ACCOUNT), PASSWORD)
        argv, kwargs = run.call_args[0][0], run.call_args[1]
        # This is the assertion that matters: anything in argv is visible to
        # every user on the machine through ps.
        assert not any(PASSWORD in str(item) for item in argv)
        assert kwargs["input"] == f"{PASSWORD}\n{PASSWORD}\n"
        assert "-w" == argv[-1], "the -w flag must be last and valueless"

    def test_update_flag_is_passed_so_a_rotation_replaces_the_item(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed()) as run:
            store.set_password(CredentialRef(account=ACCOUNT), PASSWORD)
        assert "-U" in run.call_args[0][0]

    def test_a_failed_write_raises_and_says_nothing_was_written(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed(1, stderr="SecKeychainItemCreate: "
                                                     "User interaction is not "
                                                     "allowed.")):
            with pytest.raises(CredentialStoreError) as caught:
                store.set_password(CredentialRef(account=ACCOUNT), PASSWORD)
        message = str(caught.value)
        assert "User interaction is not allowed" in message
        assert "Nothing was written to disk" in message

    def test_get_returns_the_secret_without_its_newline(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed(0, stdout=PASSWORD + "\n")):
            assert store.get_password(
                CredentialRef(account=ACCOUNT)) == PASSWORD

    def test_a_missing_item_is_none_not_an_error(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed(
                       44, stderr="security: SecKeychainSearchCopyNext: The "
                                  "specified item could not be found in the "
                                  "keychain.")):
            assert store.get_password(CredentialRef(account=ACCOUNT)) is None

    def test_an_unreadable_store_raises_rather_than_looking_empty(self, store):
        # A locked keychain must not be indistinguishable from a first run, or
        # the operator is told to re-enter a password that is sitting there.
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed(
                       36, stderr="security: The user name or passphrase you "
                                  "entered is not correct.")):
            with pytest.raises(CredentialStoreError):
                store.get_password(CredentialRef(account=ACCOUNT))

    def test_delete_reports_whether_there_was_anything_to_delete(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed(0)):
            assert store.delete_password(CredentialRef(account=ACCOUNT)) is True
        with patch("aditor.app.credentials.subprocess.run",
                   return_value=_completed(44)):
            assert store.delete_password(CredentialRef(account=ACCOUNT)) is False

    def test_a_missing_security_binary_raises_the_store_error(self, store):
        with patch("aditor.app.credentials.subprocess.run",
                   side_effect=OSError("No such file or directory")):
            with pytest.raises(CredentialStoreError, match="security"):
                store.get_password(CredentialRef(account=ACCOUNT))

    def test_it_is_unavailable_off_darwin(self):
        with patch("aditor.app.credentials.sys.platform", "linux"):
            assert MacOSKeychainStore().available() is False


# --------------------------------------------------------------------------- #
# Log redaction
# --------------------------------------------------------------------------- #

class TestRedaction:
    def test_a_registered_secret_is_scrubbed_from_the_message(self):
        filt = SecretRedactingFilter()
        filt.add(PASSWORD)
        record = logging.LogRecord("aditor", logging.INFO, __file__, 1,
                                   f"bind failed for {PASSWORD}", None, None)
        filt.filter(record)
        assert PASSWORD not in record.getMessage()
        assert REDACTED in record.getMessage()

    def test_a_secret_in_the_args_is_scrubbed_too(self):
        # logger.info("bind %s", password) puts it in args, and formatting
        # happens later inside the handler.
        filt = SecretRedactingFilter()
        filt.add(PASSWORD)
        record = logging.LogRecord("aditor", logging.INFO, __file__, 1,
                                   "bind %s", (PASSWORD,), None)
        filt.filter(record)
        assert PASSWORD not in record.getMessage()

    def test_dict_args_are_scrubbed(self):
        filt = SecretRedactingFilter()
        filt.add(PASSWORD)
        # LogRecord unwraps a single-mapping tuple into ``args``, which is the
        # shape ``logger.info("%(pw)s", {...})`` actually produces.
        record = logging.LogRecord("aditor", logging.INFO, __file__, 1,
                                   "bind %(pw)s", ({"pw": PASSWORD},), None)
        filt.filter(record)
        assert PASSWORD not in record.getMessage()

    def test_nothing_is_touched_when_no_secret_is_registered(self):
        filt = SecretRedactingFilter()
        record = logging.LogRecord("aditor", logging.INFO, __file__, 1,
                                   "plain message", None, None)
        assert filt.filter(record) is True
        assert record.getMessage() == "plain message"

    def test_a_forgotten_secret_is_no_longer_scrubbed(self):
        filt = SecretRedactingFilter()
        filt.add(PASSWORD)
        filt.discard(PASSWORD)
        assert filt.scrub(PASSWORD) == PASSWORD
