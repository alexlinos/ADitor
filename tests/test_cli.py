"""The ``aditor`` CLI: exit codes, and that a scan lands as one snapshot folder.

No directory: the config, the LDAP manager and the scan itself are patched, so
these tests only prove the CLI's own wiring.
"""

from types import SimpleNamespace
from unittest.mock import patch

from aditor.cli import EXIT_ATTENTION, EXIT_ERROR, EXIT_OK, main
from aditor.hardening.collect import GpoReadFailure
from aditor.hardening.scanfile import write_scan

from tests.test_hardening_diff import SIGNING_CONTROL, finding, later, scan


def _config(password="secret", cleartext=()):
    ad = SimpleNamespace(password=password, bind_dn="CN=svc,DC=test,DC=local",
                         domain="test.local", server="ldaps://dc.test.local",
                         cleartext_servers=list(cleartext))
    return SimpleNamespace(active_directory=ad, security=None, performance=None)


def _run_scan(tmp_path, payload=None, error=None, password="secret", tty=True,
              cleartext=()):
    with patch("aditor.config.loader.load_config",
               return_value=_config(password, cleartext)), \
         patch("aditor.core.ldap_manager.LDAPManager"), \
         patch("aditor.hardening.collect.Scanner.scan",
               return_value=payload, side_effect=error), \
         patch("sys.stdin.isatty", return_value=tty):
        return main(["scan", "--out", str(tmp_path)])


def test_clean_scan_exits_zero_and_writes_one_snapshot(tmp_path):
    assert _run_scan(tmp_path, scan([finding(SIGNING_CONTROL)])) == EXIT_OK
    [folder] = tmp_path.iterdir()
    assert sorted(p.name for p in folder.iterdir()) == ["report.html", "scan.json"]


def test_a_fail_finding_exits_one(tmp_path):
    payload = scan([finding(SIGNING_CONTROL, result="fail")])
    assert _run_scan(tmp_path, payload) == EXIT_ATTENTION


def test_an_unreadable_directory_exits_two_and_writes_nothing(tmp_path, capsys):
    error = GpoReadFailure(Exception("invalidCredentials"))
    assert _run_scan(tmp_path, error=error) == EXIT_ERROR
    assert "invalidCredentials" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_unset_password_without_a_terminal_exits_two(tmp_path):
    assert _run_scan(tmp_path, password="${AD_MCP_PASSWORD}", tty=False) == EXIT_ERROR


def test_diff_exits_one_on_a_regression_and_zero_otherwise(tmp_path):
    before = scan([finding(SIGNING_CONTROL, result="pass")])
    regressed = later(before)
    regressed["findings"][0]["result"] = "fail"
    old, same, bad = (tmp_path / n for n in ("old.json", "same.json", "bad.json"))
    write_scan(before, str(old))
    write_scan(later(before), str(same))
    write_scan(regressed, str(bad))

    assert main(["diff", str(old), str(same)]) == EXIT_OK
    assert main(["diff", str(old), str(bad)]) == EXIT_ATTENTION
    assert main(["diff", str(old), str(tmp_path / "missing.json")]) == EXIT_ERROR


def test_a_plain_ldap_server_is_warned_about(tmp_path, capsys):
    """Plain ldap:// is allowed, but the password crosses the wire in clear."""
    _run_scan(tmp_path, scan([finding(SIGNING_CONTROL)]),
              cleartext=["ldap://dc.test.local:389"])
    err = capsys.readouterr().err
    assert "ldap://dc.test.local:389 is plain LDAP" in err
    assert "clear text" in err
