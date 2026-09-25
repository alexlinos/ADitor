"""Tests for the platform-specific guidance and the certificate export.

Two things are guarded here.

**The guidance differs by machine, and by the right axis.** A domain-joined
Windows machine must be told to chase autoenrollment, and an unjoined machine
must be told to import by hand — swapping those two answers is not a cosmetic
error. A manual import on a joined machine hides a broken enterprise PKI that
every other domain member is also sitting behind.

**Nothing runs anything.** ADitor writes a ``.crt`` and prints commands. There
is no code path here that touches a trust store, and the tests assert that over
the module's own source as well as its behaviour, because "we only build
strings" is a property that one convenience helper would quietly end.

Nothing here touches the real keychain, the real trust store or the operator's
own environment: ``detect_machine`` takes its platform and environment as
arguments, and every write goes to ``tmp_path``.
"""

import os
import sys

import pytest
from aditor.app.certificates import certificate_facts
from aditor.app.trust import (
    MACHINE_MACOS,
    MACHINE_OTHER,
    MACHINE_WINDOWS_JOINED,
    MACHINE_WINDOWS_STANDALONE,
    MACHINE_WINDOWS_UNKNOWN,
    PATH_PLACEHOLDER,
    TrustExportError,
    detect_machine,
    export_ca_certificate,
    export_filename,
    install_commands,
)

from .synthetic_certificates import chain, der, issue

JOINED = {"USERDNSDOMAIN": "test.local", "USERDOMAIN": "TEST",
          "COMPUTERNAME": "WS01"}
LOCAL_ACCOUNT = {"USERDOMAIN": "WS01", "COMPUTERNAME": "WS01"}
DOMAIN_ACCOUNT = {"USERDOMAIN": "TEST", "COMPUTERNAME": "WS01"}
BARE = {"PATH": "C:\\Windows"}


def code_shape(module_name):
    """``(imported module names, called names)`` for one app module.

    Over the AST rather than the text: both new modules discuss subprocesses,
    trust stores and ``certutil`` at length in prose, and a text search cannot
    tell the discussion from the deed.
    """
    import ast
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1] / "src" / "aditor"
              / "app" / f"{module_name}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported, called = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Attribute):
                called.add(target.attr)
            elif isinstance(target, ast.Name):
                called.add(target.id)
    return imported, called


def root_facts():
    return certificate_facts(der(chain().root))


def commands(context):
    return " ".join(step.command for step in context.steps)


def prose(context):
    return " ".join(f"{step.label} {step.note}" for step in context.steps)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

class TestDetection:
    def test_a_domain_logon_is_detected_as_joined(self):
        context = detect_machine("win32", JOINED)
        assert context.kind == MACHINE_WINDOWS_JOINED
        assert context.domain_joined is True
        assert "USERDNSDOMAIN" in context.evidence

    def test_a_domain_account_without_userdnsdomain_still_reads_as_joined(self):
        context = detect_machine("win32", DOMAIN_ACCOUNT)
        assert context.domain_joined is True
        assert "domain account" in context.evidence

    def test_a_local_account_on_windows_reads_as_not_joined(self):
        context = detect_machine("win32", LOCAL_ACCOUNT)
        assert context.kind == MACHINE_WINDOWS_STANDALONE
        assert context.domain_joined is False

    def test_no_markers_at_all_is_unknown_rather_than_a_guess(self):
        context = detect_machine("win32", BARE)
        assert context.kind == MACHINE_WINDOWS_UNKNOWN
        assert context.domain_joined is None
        # And unknown does not claim manual import is the answer.
        assert context.manual_import_is_the_fix is False

    def test_macos_is_outside_autoenrollment_whatever_its_environment(self):
        # A Mac can be bound to AD; it still gets no Group Policy certificate
        # autoenrollment, so the remedy is the same either way.
        for env in (JOINED, LOCAL_ACCOUNT, BARE):
            context = detect_machine("darwin", env)
            assert context.kind == MACHINE_MACOS
            assert context.manual_import_is_the_fix is True

    def test_linux_gets_the_generic_unix_guidance(self):
        context = detect_machine("linux", BARE)
        assert context.kind == MACHINE_OTHER
        assert context.manual_import_is_the_fix is True

    def test_the_real_machine_is_readable_without_arguments(self):
        # Reads sys.platform and os.environ; runs no subprocess and opens no
        # socket, which is why it is safe on a UI path.
        context = detect_machine()
        assert context.kind in {MACHINE_WINDOWS_JOINED,
                                MACHINE_WINDOWS_STANDALONE,
                                MACHINE_WINDOWS_UNKNOWN, MACHINE_MACOS,
                                MACHINE_OTHER}
        assert context.steps


# --------------------------------------------------------------------------- #
# Acceptance criterion 6: the two cases get different guidance
# --------------------------------------------------------------------------- #

class TestJoinedAndUnjoinedDifferMeaningfully:
    def test_the_joined_machine_is_sent_to_autoenrollment_first(self):
        context = detect_machine("win32", JOINED)
        assert context.manual_import_is_the_fix is False
        text = commands(context)
        assert "gpupdate" in text
        assert "certutil -pulse" in text
        assert "gpresult" in text
        # The first step is not a command at all: it is the reason not to
        # reach for one.
        assert context.steps[0].command == ""
        assert "autoenrollment" in context.steps[0].note

    def test_the_joined_machine_is_told_why_a_manual_import_is_wrong(self):
        context = detect_machine("win32", JOINED)
        text = prose(context).lower()
        assert "hides the cause" in text or "hides a fault" in text
        assert "every other domain member" in text

    def test_a_manual_import_on_a_joined_machine_is_last_and_labelled(self):
        context = detect_machine("win32", JOINED)
        addstore = [index for index, step in enumerate(context.steps)
                    if "addstore" in step.command]
        assert addstore == [len(context.steps) - 1]
        last = context.steps[-1]
        assert "stopgap" in last.note
        assert "Only if" in last.label

    def test_the_unjoined_machine_is_told_manual_trust_is_correct(self):
        context = detect_machine("win32", LOCAL_ACCOUNT)
        assert context.manual_import_is_the_fix is True
        assert "addstore" in commands(context)
        assert "not joined" in context.headline
        assert "correct fix" in context.headline

    def test_the_two_cases_do_not_share_a_headline_or_a_first_command(self):
        joined = detect_machine("win32", JOINED)
        alone = detect_machine("win32", LOCAL_ACCOUNT)
        assert joined.headline != alone.headline
        assert joined.steps[0].label != alone.steps[0].label
        # The joined machine's guidance leads with policy; the unjoined
        # machine's never mentions it, because there is none to repair.
        assert "gpupdate" not in commands(alone)
        assert "certutil -pulse" not in commands(alone)

    def test_the_unknown_machine_offers_both_and_says_how_to_settle_it(self):
        context = detect_machine("win32", BARE)
        text = commands(context)
        assert "PartOfDomain" in text
        assert "gpupdate" in text          # if it turns out to be joined
        assert "addstore" in text          # if it turns out not to be
        assert "could not tell" in context.headline

    def test_macos_gets_macos_commands_and_no_windows_ones(self):
        context = detect_machine("darwin", BARE)
        text = commands(context)
        assert "security add-trusted-cert" in text
        assert "System.keychain" in text
        assert "certutil" not in text
        assert "gpupdate" not in text

    def test_macos_is_warned_that_the_keychain_is_not_what_python_reads(self):
        # The hour-losing detail: ADitor's LDAPS goes through OpenSSL, which on
        # macOS does not read the keychain, so the import can appear to have
        # worked while this app still reports an untrusted issuer.
        context = detect_machine("darwin", BARE)
        text = prose(context)
        assert "does not read the login or System keychain" in text
        assert "get_default_verify_paths" in commands(context)

    def test_every_platform_leads_with_confirming_the_fingerprint(self):
        for system, env in (("win32", LOCAL_ACCOUNT), ("darwin", BARE),
                            ("linux", BARE)):
            context = detect_machine(system, env)
            assert "fingerprint" in context.steps[0].label.lower(), system
        # The joined machine leads with "do not import yet" instead, and its
        # import step still carries the confirmation requirement.
        joined = detect_machine("win32", JOINED)
        assert "confirmed the fingerprint" in joined.steps[-1].note


# --------------------------------------------------------------------------- #
# The commands are text, and nothing here runs them
# --------------------------------------------------------------------------- #

class TestCommandsAreOnlyText:
    def test_the_path_is_substituted_into_every_command(self, tmp_path):
        context = detect_machine("win32", LOCAL_ACCOUNT)
        path = tmp_path / "root.crt"
        steps = install_commands(context, path)
        assert any(str(path) in step.command for step in steps)
        assert all("{path}" not in step.command for step in steps)

    def test_without_an_export_the_placeholder_is_obviously_unrunnable(self):
        steps = install_commands(detect_machine("win32", LOCAL_ACCOUNT))
        addstore = [step for step in steps if "addstore" in step.command][0]
        assert PATH_PLACEHOLDER in addstore.command
        assert "<" in PATH_PLACEHOLDER and ">" in PATH_PLACEHOLDER

    def test_the_module_never_executes_a_command(self):
        # "We only build strings" is a property one convenience helper would
        # quietly end, so it is asserted over the module's *code* -- imports
        # and called names, via the AST, not the prose, which discusses
        # subprocesses at length in order to explain why there are none.
        imported, called = code_shape("trust")
        assert imported.isdisjoint({"subprocess", "shutil", "ctypes",
                                    "multiprocessing", "asyncio", "pty"})
        assert called.isdisjoint({"system", "popen", "spawnl", "spawnv",
                                  "execv", "execvp", "run", "Popen",
                                  "check_output", "check_call", "call",
                                  "getoutput"})

    def test_the_module_reaches_no_trust_store_api(self):
        imported, called = code_shape("trust")
        assert imported.isdisjoint({"keyring", "wincertstore", "certifi",
                                    "Security", "ctypes", "winreg"})
        assert called.isdisjoint({"add_trusted_cert", "addstore",
                                  "load_verify_locations", "SetProcAddress"})

    def test_neither_new_module_imports_anything_that_could_install(self):
        for module in ("trust", "certificates"):
            imported, _ = code_shape(module)
            assert imported.isdisjoint({"subprocess", "ctypes", "winreg",
                                        "keyring", "wincertstore"}), module


# --------------------------------------------------------------------------- #
# The export
# --------------------------------------------------------------------------- #

class TestExport:
    def test_it_writes_a_pem_crt_that_reloads(self, tmp_path):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        facts = root_facts()
        path = export_ca_certificate(facts, tmp_path)
        assert path.suffix == ".crt"
        body = path.read_text(encoding="ascii")
        assert body.startswith("-----BEGIN CERTIFICATE-----")
        reloaded = x509.load_pem_x509_certificate(body.encode("ascii"))
        assert reloaded.fingerprint(
            hashes.SHA256()).hex() == facts.fingerprint_hex

    def test_the_name_carries_the_subject_and_the_fingerprint_prefix(self):
        facts = root_facts()
        name = export_filename(facts)
        assert name.startswith("test-CA-Root-")
        assert facts.fingerprint_hex[:8] in name
        assert name.endswith(".crt")

    def test_two_different_cas_do_not_collide(self, tmp_path):
        first = export_ca_certificate(root_facts(), tmp_path)
        second = export_ca_certificate(
            certificate_facts(der(chain().rogue_root)), tmp_path)
        assert first != second
        assert first.exists() and second.exists()

    def test_the_same_ca_exported_twice_is_the_same_file(self, tmp_path):
        first = export_ca_certificate(root_facts(), tmp_path)
        second = export_ca_certificate(root_facts(), tmp_path)
        assert first == second

    @pytest.mark.parametrize("hostile", [
        "../../../../etc/ssl/certs/evil",
        "..\\..\\Windows\\System32\\evil",
        "/etc/ssl/certs/absolute",
        "CN=a/b/c",
        "....//....//x",
        "con",
    ])
    def test_a_hostile_subject_cannot_escape_the_export_directory(
            self, tmp_path, hostile):
        # A certificate subject is attacker-influenceable text and it becomes a
        # file name, so the name is built from an allow-list rather than
        # sanitised by removal.
        certificate, _ = issue(hostile, not_before=root_facts().not_before,
                               not_after=root_facts().not_after, is_ca=True)
        facts = certificate_facts(der(certificate))
        name = export_filename(facts)
        assert "/" not in name and "\\" not in name
        assert ".." not in name
        path = export_ca_certificate(facts, tmp_path / "out")
        assert path.parent == tmp_path / "out"
        assert path.resolve().parent == (tmp_path / "out").resolve()

    def test_a_caller_supplied_name_is_still_confined(self, tmp_path):
        path = export_ca_certificate(root_facts(), tmp_path,
                                     "../../escaped.crt")
        assert path.parent == tmp_path
        assert path.name == "escaped.crt"

    @pytest.mark.skipif(sys.platform.startswith("win"),
                        reason="chmod does not make a Windows folder read-only")
    def test_an_unwritable_directory_is_an_error_not_a_traceback(self,
                                                                tmp_path):
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        os.chmod(blocked, 0o500)
        try:
            with pytest.raises(TrustExportError) as caught:
                export_ca_certificate(root_facts(), blocked / "sub")
            assert "Could not write" in str(caught.value)
        finally:
            os.chmod(blocked, 0o700)

    def test_a_dotted_name_is_refused(self, tmp_path):
        with pytest.raises(TrustExportError):
            export_ca_certificate(root_facts(), tmp_path, "..")

    @pytest.mark.skipif(sys.platform.startswith("win"),
                        reason="POSIX permission bits; Windows uses ACLs")
    def test_the_export_directory_is_created_owner_only(self, tmp_path):
        target = tmp_path / "exported-certificates"
        export_ca_certificate(root_facts(), target)
        assert oct(target.stat().st_mode)[-3:] == "700"

    def test_nothing_is_written_outside_the_directory_given(self, tmp_path):
        before = set(tmp_path.rglob("*"))
        target = tmp_path / "here"
        export_ca_certificate(root_facts(), target)
        written = set(tmp_path.rglob("*")) - before
        assert all(str(item).startswith(str(target)) for item in written)
