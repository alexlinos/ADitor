"""Tests for the Scan screen: one scan, its own counts, visible progress.

The acceptance property is exact: the scan runs **once**, and the counts the
screen shows come from *that* scan. So these tests drive the real
:class:`aditor.hardening.collect.Scanner` end to end and count how many
times it read the directory — not a stub returning a canned payload, which would
prove nothing about the "one scan" guarantee.

Offline throughout, using the same shape as ``test_hardening_tools.py``: the LDAP
manager is a Mock, ``smbclient`` is stubbed into ``sys.modules`` so the optional
``smb`` extra is not needed, and the SYSVOL read is patched. Every GPO, DN and
GUID is synthesized.
"""

import json
import sys
from unittest.mock import Mock, patch

import pytest

from aditor.app.render import render_counts, render_scan_result
from aditor.app.scanning import (
    STAGE_DONE,
    STAGE_FAILED,
    STAGE_READ,
    ScanJob,
    ScanProgress,
    ScanResult,
    run_scan,
)
from aditor.app.settings import ConnectionSettings
from aditor.hardening.collect import Scanner

BASE_DN = "DC=test,DC=local"
POLICIES_DN = f"CN=Policies,CN=System,{BASE_DN}"
PASSWORD = "N0t-A-Real-Password-9f3ac1"

GUID_A = "11111111-1111-1111-1111-111111111111"
GUID_B = "22222222-2222-2222-2222-222222222222"
GUID_C = "33333333-3333-3333-3333-333333333333"

LDAP_LINES = [
    "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    "\\LdapEnforceChannelBinding=4,2",
    "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    "\\LDAPServerIntegrity=4,2",
]


def a_connection(**overrides) -> ConnectionSettings:
    values = {
        "server": "ldaps://dc01.test.local:636",
        "domain": "test.local",
        "base_dn": BASE_DN,
        "bind_dn": f"CN=svc-aditor,OU=Service Accounts,{BASE_DN}",
        "validate_certificate": True,
    }
    values.update(overrides)
    return ConnectionSettings(**values)


def gpo_entry(guid, display_name):
    return {
        "dn": f"CN={{{guid}}},CN=Policies,CN=System,{BASE_DN}",
        "attributes": {
            "cn": "{" + guid + "}",
            "displayName": display_name,
            "gPCFileSysPath":
                rf"\\test.local\SysVol\test.local\Policies\{{{guid}}}",
        },
    }


def sysvol_contents(*registry_lines):
    return {
        "machine_registry_pol": {"entries": []},
        "security_templates": [{
            "sections": {"Unicode": ["Unicode=yes"],
                         "Registry Values": list(registry_lines),
                         "Version": ["Revision=1"]},
        }],
    }


class RecordingManager:
    """A Mock-backed LDAP manager that counts what the scan asked it for."""

    def __init__(self, gpo_entries):
        self.ad_config = Mock()
        self.ad_config.base_dn = BASE_DN
        self.ad_config.domain = "test.local"
        self.ad_config.server = "ldaps://dc01.test.local:636"
        self.ad_config.bind_dn = f"CN=svc-aditor,{BASE_DN}"
        self.gpo_entries = gpo_entries
        self.policy_searches = 0
        self.disconnected = 0

    def search(self, search_base=None, search_filter=None, **_kwargs):
        if "gPLink" in (search_filter or ""):
            return []
        if search_base == POLICIES_DN:
            self.policy_searches += 1
            return self.gpo_entries
        return []

    def disconnect(self):
        self.disconnected += 1


@pytest.fixture
def three_gpos():
    return RecordingManager([
        gpo_entry(GUID_A, "Default Domain Policy"),
        gpo_entry(GUID_B, "LDAP Hardening"),
        gpo_entry(GUID_C, "Workstation Baseline"),
    ])


def scan(settings, manager, output_dir, progress=None, reads=None):
    """Run the real scan against the fixtures, with SMB and SYSVOL stubbed."""
    calls = reads if reads is not None else []

    def read_sysvol(sysvol_path, include_registry=True, max_value_chars=6000):
        calls.append(sysvol_path)
        if GUID_B in sysvol_path:
            return sysvol_contents(*LDAP_LINES)
        return sysvol_contents()

    with patch.dict(sys.modules, {"smbclient": Mock()}), \
         patch.object(Scanner, "_read_gpo_sysvol", side_effect=read_sysvol):
        return run_scan(settings, PASSWORD, output_dir, progress,
                        factory=lambda *_args: manager)


# --------------------------------------------------------------------------- #
# One scan, and the counts come from it
# --------------------------------------------------------------------------- #

class TestOneScan:
    def test_a_snapshot_folder_with_both_files_is_written(self, tmp_path,
                                                          three_gpos):
        result = scan(a_connection(), three_gpos, tmp_path)
        assert result.ok is True, result.error
        folder = tmp_path / result.payload["snapshot_name"]
        assert (folder / "scan.json").is_file()
        assert (folder / "report.html").is_file()

    def test_the_directory_is_read_exactly_once(self, tmp_path, three_gpos):
        reads = []
        result = scan(a_connection(), three_gpos, tmp_path, reads=reads)
        assert result.ok is True
        # One policy enumeration and one SYSVOL read per GPO. Two scans would
        # double both -- which is exactly what writing the JSON and the report
        # from two separate scans would have done.
        assert three_gpos.policy_searches == 1
        assert len(reads) == 3

    def test_the_tool_reports_that_it_ran_one_scan(self, tmp_path, three_gpos):
        result = scan(a_connection(), three_gpos, tmp_path)
        assert result.payload["scans_run"] == 1

    def test_the_displayed_counts_are_the_scans_own(self, tmp_path, three_gpos):
        result = scan(a_connection(), three_gpos, tmp_path)
        stored = json.loads(
            (tmp_path / result.payload["snapshot_name"] / "scan.json")
            .read_text(encoding="utf-8"))
        # Not recomputed, not re-scanned: the same numbers, from the same run.
        assert result.counts == stored["counts"]
        assert result.payload["scan"]["scan_id"] == stored["scan"]["scan_id"]

    def test_both_files_carry_the_same_scan_id(self, tmp_path, three_gpos):
        result = scan(a_connection(), three_gpos, tmp_path)
        folder = tmp_path / result.payload["snapshot_name"]
        scan_id = result.payload["scan"]["scan_id"]
        assert scan_id in (folder / "report.html").read_text(encoding="utf-8")
        assert scan_id == json.loads(
            (folder / "scan.json").read_text(encoding="utf-8")
        )["scan"]["scan_id"]

    def test_the_counts_reach_the_rendered_panel_unaltered(self, tmp_path,
                                                           three_gpos):
        result = scan(a_connection(), three_gpos, tmp_path)
        html = render_scan_result(result)
        assert f'>{result.counts["pass"]}<' in html
        assert "Scan complete" in html
        # The tool's own one-scan assertion is shown, not merely relied on.
        assert "Scans run" in html

    def test_the_connection_is_released_afterwards(self, tmp_path, three_gpos):
        scan(a_connection(), three_gpos, tmp_path)
        assert three_gpos.disconnected == 1

    def test_the_report_path_is_reported_for_the_open_button(self, tmp_path,
                                                             three_gpos):
        result = scan(a_connection(), three_gpos, tmp_path)
        assert result.report_path.endswith("report.html")
        assert result.snapshot_dir


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #

class TestProgress:
    def test_the_total_and_the_per_gpo_count_are_both_reported(self, tmp_path,
                                                               three_gpos):
        progress = ScanProgress()
        scan(a_connection(), three_gpos, tmp_path, progress)
        state = progress.snapshot()
        assert state["gpos_total"] == 3
        assert state["gpos_read"] == 3
        assert state["finished"] is True
        assert state["ok"] is True

    def test_the_bar_moves_while_the_gpos_are_read(self, tmp_path):
        # The whole reason progress exists: a 72-GPO domain spends seconds in
        # SYSVOL and a still window reads as a hang.
        progress = ScanProgress()
        seen = []

        manager = RecordingManager(
            [gpo_entry(f"{n:08d}-0000-0000-0000-000000000000", f"GPO {n}")
             for n in range(1, 11)])

        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            seen.append(progress.percent())
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(Scanner, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            run_scan(a_connection(), PASSWORD, tmp_path, progress,
                     factory=lambda *_args: manager)

        assert seen == sorted(seen), "progress must never go backwards"
        assert seen[0] < seen[-1], "progress must actually move"
        assert progress.snapshot()["percent"] == 100

    def test_the_stage_becomes_read_once_the_total_is_known(self, tmp_path,
                                                            three_gpos):
        progress = ScanProgress()
        stages = []

        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            stages.append(progress.snapshot()["stage"])
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(Scanner, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            run_scan(a_connection(), PASSWORD, tmp_path, progress,
                     factory=lambda *_args: three_gpos)
        assert stages == [STAGE_READ] * 3

    def test_the_progress_message_never_carries_a_gpo_name(self, tmp_path,
                                                            three_gpos):
        # A GPO display name is directory content. The count answers the only
        # question the operator has ("is it moving") without an escaping
        # question in a progress line.
        progress = ScanProgress()
        messages = []

        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            messages.append(progress.snapshot()["message"])
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(Scanner, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            run_scan(a_connection(), PASSWORD, tmp_path, progress,
                     factory=lambda *_args: three_gpos)
        joined = " ".join(messages)
        assert "Default Domain Policy" not in joined
        assert "GPO 1 of 3" in joined

    def test_an_unknown_total_creeps_without_claiming_completion(self):
        progress = ScanProgress()
        progress.set_stage(STAGE_READ)
        for _ in range(100):
            progress.count_read()
        # Never past the read stage's ceiling: the bar must not claim progress
        # it cannot know it has made.
        assert progress.percent() <= 50

    def test_a_failure_marks_the_progress_failed(self, tmp_path):
        result = run_scan(a_connection(base_dn=""), PASSWORD, tmp_path,
                          progress := ScanProgress())
        assert result.ok is False
        assert progress.snapshot()["stage"] == STAGE_FAILED
        assert progress.snapshot()["ok"] is False


# --------------------------------------------------------------------------- #
# The observers do not alter the scan
# --------------------------------------------------------------------------- #

class TestObserversArePassive:
    def test_the_sysvol_results_are_passed_through_unchanged(self, tmp_path,
                                                             three_gpos):
        # The LDAP-hardening GPO sets both keys; if the wrapper dropped or
        # mangled the return value those controls would not pass.
        result = scan(a_connection(), three_gpos, tmp_path)
        stored = json.loads(
            (tmp_path / result.payload["snapshot_name"] / "scan.json")
            .read_text(encoding="utf-8"))
        found = [finding for finding in stored["findings"]
                 if finding.get("result") == "pass"]
        assert found, "the stubbed GPO content must still reach the evaluator"

    def test_an_exception_from_the_sysvol_read_still_propagates(self, tmp_path,
                                                                three_gpos):
        # A wrapper that swallowed an error would turn an unreadable GPO into a
        # clean one, which is the exact failure the evaluator refuses to make.
        def read_sysvol(sysvol_path, include_registry=True,
                       max_value_chars=6000):
            raise OSError("SMB session setup failed")

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(Scanner, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            result = run_scan(a_connection(), PASSWORD, tmp_path,
                              factory=lambda *_args: three_gpos)
        assert result.ok is True
        stored = json.loads(
            (tmp_path / result.payload["snapshot_name"] / "scan.json")
            .read_text(encoding="utf-8"))
        assert stored["scan"]["gpos_unreadable"] == 3
        assert len(stored["gpo_read_errors"]) == 3

    def test_the_unreadable_gpo_warning_is_rendered(self, tmp_path,
                                                    three_gpos):
        def read_sysvol(sysvol_path, include_registry=True,
                       max_value_chars=6000):
            raise OSError("SMB session setup failed")

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(Scanner, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            result = run_scan(a_connection(), PASSWORD, tmp_path,
                              factory=lambda *_args: three_gpos)
        html = render_scan_result(result)
        assert "could not be read" in html
        assert "unknown rather than as clean" in html


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #

class TestRefusals:
    def test_an_incomplete_connection_is_refused_before_anything_is_dialled(
            self, tmp_path):
        def factory(*_args):
            raise AssertionError("must not build a manager")

        result = run_scan(a_connection(base_dn="", server=""), PASSWORD,
                          tmp_path, factory=factory)
        assert result.ok is False
        assert "Base DN" in result.error
        assert list(tmp_path.iterdir()) == []

    def test_no_password_is_refused(self, tmp_path):
        result = run_scan(a_connection(), "", tmp_path)
        assert result.ok is False
        assert "no password" in result.error

    def test_a_scan_failure_writes_nothing_and_says_so(self, tmp_path,
                                                        three_gpos):
        def exploding_search(**_kwargs):
            raise RuntimeError("LDAP bind lost")

        three_gpos.search = exploding_search
        with patch.dict(sys.modules, {"smbclient": Mock()}):
            result = run_scan(a_connection(), PASSWORD, tmp_path,
                              factory=lambda *_args: three_gpos)
        assert result.ok is False
        assert "LDAP bind lost" in result.error
        assert list(tmp_path.iterdir()) == []
        assert "Nothing was written" in render_scan_result(result)

    def test_a_missing_smb_extra_is_reported_as_itself(self, tmp_path,
                                                        three_gpos):
        # The scan reads SYSVOL over SMB; without smbprotocol the tool refuses
        # rather than reporting an empty domain.
        with patch.dict(sys.modules, {"smbclient": None}):
            result = run_scan(a_connection(), PASSWORD, tmp_path,
                              factory=lambda *_args: three_gpos)
        assert result.ok is False
        assert "smbprotocol" in result.error


# --------------------------------------------------------------------------- #
# The background job
# --------------------------------------------------------------------------- #

class TestScanJob:
    def test_a_job_runs_to_completion_and_exposes_its_result(self, tmp_path,
                                                              three_gpos):
        job = ScanJob()

        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(Scanner, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            job.start(a_connection(), PASSWORD, tmp_path,
                      factory=lambda *_args: three_gpos)
            job.join(30)

        assert job.running() is False
        assert job.result().ok is True
        assert job.progress()["stage"] == STAGE_DONE

    def test_progress_is_pollable_before_the_job_finishes(self):
        job = ScanJob()
        # No scan started: the poll must still answer rather than raise, since
        # the page polls on a timer.
        state = job.progress()
        assert state["running"] is False
        assert state["percent"] >= 0


class TestScanResultShape:
    def test_a_failed_result_has_empty_counts_rather_than_none(self):
        result = ScanResult(ok=False, error="nope")
        assert result.counts == {}
        assert result.headline == {}
        assert result.report_path == ""

    def test_render_counts_defaults_a_missing_figure_to_zero(self):
        html = render_counts({})
        assert html.count(">0<") >= 8
