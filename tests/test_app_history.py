"""Tests for History: list snapshots, open a report, diff two.

The load-bearing property is the last one. A diff whose ``attribution`` is
``ambiguous`` must **not** be rendered as a count of improvements: the two scans
ran different tool versions, so a difference may be the scanner or the catalog
rather than the domain. This project has actually seen a control go fail -> pass
because the scanner learned to read Group Policy Preferences, with the domain
untouched. If a UI reduces that to "3 improvements" it has destroyed the whole
integrity of the feature, so several tests below pin the wording.

No LDAP, no SMB, no clock. Snapshot folders are written by hand into
``tmp_path`` from synthesized payloads, which is also what lets the diff be
driven across a deliberate version change.
"""

import json
import sys
from pathlib import Path

import pytest
from aditor.app.history import (
    HistoryError,
    diff_snapshots,
    list_snapshots,
    read_entry,
    report_uri,
    scan_path,
)
from aditor.app.render import render_diff, render_history
from aditor.hardening import SCAN_ENGINE_VERSION

BASE_DN = "DC=test,DC=local"
CONTROL_ID = "TEST-01-LDAP-CHANNEL-BINDING"


def a_payload(scan_id, timestamp, *, catalog_version="1.0.0",
              engine_version=SCAN_ENGINE_VERSION, result="fail",
              rollout_state="not_started", gpos=3, unreadable=0):
    """A scan payload of the shape ``aditor scan`` stores."""
    counts = {
        "total": 2, "scored": 2, "pass": 1 if result == "pass" else 0,
        "fail": 1 if result == "fail" else 0, "error": 0, "unknown": 0,
        "not_applicable": 0, "conflicts": 0, "os_default": 0,
        "os_default_pass": 0, "needs_baseline_value": 0,
        "rendered": 2, "hidden": 0,
    }
    return {
        "scan": {
            "tool": "scan_hardening",
            "tool_version": engine_version,
            "scan_id": scan_id,
            "timestamp": timestamp,
            "domain": "test.local",
            "base_dn": BASE_DN,
            "gpos_scanned": gpos,
            "gpos_unreadable": unreadable,
            "include_not_applicable": True,
            "read_only": True,
            "catalog_version": catalog_version,
            "catalog_source": "controls.json",
            "control_count": 2,
        },
        "counts": counts,
        "findings": [
            {
                "control_id": CONTROL_ID,
                "title": "LDAP channel binding is required",
                "severity": "high",
                "result": result,
                "rollout_state": rollout_state,
                "scored": True,
                "evidence": {"source": "gpo", "found": [], "notes": []},
                "expected": {"operator": "equals", "final": 2},
                "remediation": "Set LdapEnforceChannelBinding to 2.",
            },
            {
                "control_id": "TEST-02-ALWAYS-PASSES",
                "title": "A control that never moves",
                "severity": "medium",
                "result": "pass",
                "rollout_state": "enforced",
                "scored": True,
                "evidence": {"source": "gpo", "found": [], "notes": []},
                "expected": {"operator": "equals", "final": 1},
                "remediation": "",
            },
        ],
        "unscored_control_ids": [],
        "unknown_control_ids": [],
        "gpo_read_errors": [],
    }


def write_snapshot_folder(root: Path, name: str, payload: dict,
                          with_report=True) -> Path:
    folder = root / name
    folder.mkdir(parents=True)
    (folder / "scan.json").write_text(json.dumps(payload), encoding="utf-8")
    if with_report:
        # The real writer produces a full document; History only needs to know
        # a report is there and openable.
        (folder / "report.html").write_text(
            "<!DOCTYPE html><html><!-- aditor-hardening-report --><body>"
            "</body></html>", encoding="utf-8")
    return folder


@pytest.fixture
def archive(tmp_path):
    root = tmp_path / "snapshots"
    write_snapshot_folder(root, "2026-08-18T101500Z-aaaaaaaa",
                          a_payload("a" * 32, "2026-08-18T10:15:00+00:00"))
    write_snapshot_folder(root, "2026-08-19T101500Z-bbbbbbbb",
                          a_payload("b" * 32, "2026-08-19T10:15:00+00:00",
                                    result="pass",
                                    rollout_state="enforced"))
    return root


# --------------------------------------------------------------------------- #
# Listing
# --------------------------------------------------------------------------- #

class TestListSnapshots:
    def test_it_lists_newest_first(self, archive):
        entries = list_snapshots(archive)
        assert [entry.name for entry in entries] == [
            "2026-08-19T101500Z-bbbbbbbb", "2026-08-18T101500Z-aaaaaaaa"]

    def test_each_entry_carries_the_scans_own_provenance(self, archive):
        newest = list_snapshots(archive)[0]
        assert newest.scan_id == "b" * 32
        assert newest.domain == "test.local"
        assert newest.base_dn == BASE_DN
        assert newest.catalog_version == "1.0.0"
        assert newest.engine_version == SCAN_ENGINE_VERSION
        assert newest.gpos_scanned == 3
        assert newest.counts["pass"] == 1

    def test_a_directory_that_is_not_a_snapshot_is_skipped(self, archive):
        (archive / "notes").mkdir()
        (archive / "notes" / "readme.txt").write_text("hello")
        assert len(list_snapshots(archive)) == 2

    def test_a_loose_file_is_skipped(self, archive):
        (archive / "baseline.json").write_text("{}")
        assert len(list_snapshots(archive)) == 2

    def test_an_unreadable_scan_is_listed_rather_than_hidden(self, archive):
        # A scan that is on disk and unparseable is something the operator has
        # to see; hiding it makes the archive look smaller than it is.
        folder = archive / "2026-08-20T101500Z-cccccccc"
        folder.mkdir()
        (folder / "scan.json").write_text("{ truncated")
        entries = list_snapshots(archive)
        assert len(entries) == 3
        broken = [entry for entry in entries if not entry.readable]
        assert len(broken) == 1
        assert broken[0].error

    def test_a_snapshot_with_no_report_says_so(self, tmp_path):
        root = tmp_path / "snapshots"
        write_snapshot_folder(root, "2026-08-18T101500Z-dddddddd",
                              a_payload("d" * 32, "2026-08-18T10:15:00+00:00"),
                              with_report=False)
        assert list_snapshots(root)[0].has_report is False

    def test_a_missing_directory_is_an_empty_list(self, tmp_path):
        assert list_snapshots(tmp_path / "nope") == []

    def test_the_limit_is_honoured(self, archive):
        assert len(list_snapshots(archive, limit=1)) == 1

    def test_read_entry_returns_none_for_a_non_snapshot(self, tmp_path):
        (tmp_path / "plain").mkdir()
        assert read_entry(tmp_path / "plain") is None


class TestHistoryRendering:
    def test_the_table_offers_a_before_and_an_after_column(self, archive):
        html = render_history(list_snapshots(archive), archive)
        # Radios, not checkboxes: a diff has a direction, and guessing it from
        # click order inverts every regression into an improvement.
        assert 'name="diff-before"' in html
        assert 'name="diff-after"' in html
        assert "earlier" in html.lower() and "later" in html.lower()

    def test_each_row_offers_the_report(self, archive):
        html = render_history(list_snapshots(archive), archive)
        assert html.count("data-open-report=") == 2

    def test_an_empty_archive_says_where_scans_will_land(self, tmp_path):
        html = render_history([], tmp_path / "snapshots")
        assert "No scans yet" in html
        assert "snapshots" in html

    @pytest.mark.skipif(sys.platform.startswith("win"),
                        reason="'<' and '>' are not allowed in Windows names")
    def test_a_hostile_folder_name_is_escaped(self, tmp_path):
        root = tmp_path / "snapshots"
        write_snapshot_folder(
            root, "2026-08-18T101500Z-x<script>",
            a_payload("e" * 32, "2026-08-18T10:15:00+00:00"))
        html = render_history(list_snapshots(root), root)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_a_hostile_domain_value_is_escaped(self, tmp_path):
        root = tmp_path / "snapshots"
        payload = a_payload("f" * 32, "2026-08-18T10:15:00+00:00")
        payload["scan"]["catalog_version"] = '"><img src=x onerror=1>'
        write_snapshot_folder(root, "2026-08-18T101500Z-ffffffff", payload)
        html = render_history(list_snapshots(root), root)
        assert "<img" not in html


# --------------------------------------------------------------------------- #
# Opening a report — confined to the archive
# --------------------------------------------------------------------------- #

class TestReportUri:
    def test_a_real_snapshot_yields_a_file_uri(self, archive):
        uri = report_uri(archive, "2026-08-19T101500Z-bbbbbbbb")
        assert uri.startswith("file://")
        assert uri.endswith("report.html")

    @pytest.mark.parametrize("name", [
        "../../../etc/passwd",
        "..",
        "/etc/passwd",
        r"..\..\windows\win.ini",
        "",
    ])
    def test_a_path_is_refused_because_only_a_name_is_accepted(self, archive,
                                                              name):
        # The page is the least trustworthy input in the app, and this value
        # ends up at the operating system's "open this file" call.
        with pytest.raises(HistoryError):
            report_uri(archive, name)

    def test_a_snapshot_without_a_report_is_refused_with_a_useful_message(
            self, tmp_path):
        root = tmp_path / "snapshots"
        write_snapshot_folder(root, "2026-08-18T101500Z-eeeeeeee",
                              a_payload("e" * 32, "2026-08-18T10:15:00+00:00"),
                              with_report=False)
        with pytest.raises(HistoryError, match="no report.html"):
            report_uri(root, "2026-08-18T101500Z-eeeeeeee")

    def test_scan_path_applies_the_same_guards(self, archive):
        assert scan_path(archive, "2026-08-19T101500Z-bbbbbbbb").name == \
            "scan.json"
        with pytest.raises(HistoryError):
            scan_path(archive, "../elsewhere")


# --------------------------------------------------------------------------- #
# The diff — two files, no LDAP at all
# --------------------------------------------------------------------------- #

class TestDiff:
    def test_it_diffs_two_snapshot_folders(self, archive):
        diff = diff_snapshots(archive, "2026-08-18T101500Z-aaaaaaaa",
                              "2026-08-19T101500Z-bbbbbbbb")
        assert diff["success"] is True
        assert diff["totals"]["improvements"] == 1
        assert diff["attribution"]["verdict"] == "domain"

    def test_diffing_a_snapshot_against_itself_is_refused(self, archive):
        with pytest.raises(HistoryError, match="same snapshot"):
            diff_snapshots(archive, "2026-08-18T101500Z-aaaaaaaa",
                           "2026-08-18T101500Z-aaaaaaaa")

    def test_two_domains_cannot_be_compared(self, tmp_path):
        root = tmp_path / "snapshots"
        write_snapshot_folder(root, "2026-08-18T101500Z-aaaaaaaa",
                              a_payload("a" * 32, "2026-08-18T10:15:00+00:00"))
        other = a_payload("b" * 32, "2026-08-19T10:15:00+00:00")
        other["scan"]["base_dn"] = "DC=other,DC=local"
        write_snapshot_folder(root, "2026-08-19T101500Z-bbbbbbbb", other)
        with pytest.raises(HistoryError, match="different domains"):
            diff_snapshots(root, "2026-08-18T101500Z-aaaaaaaa",
                           "2026-08-19T101500Z-bbbbbbbb")

    def test_a_missing_snapshot_is_refused(self, archive):
        with pytest.raises(HistoryError):
            diff_snapshots(archive, "2026-08-18T101500Z-aaaaaaaa", "nope")


# --------------------------------------------------------------------------- #
# Attribution — the part that must not become a bare count
# --------------------------------------------------------------------------- #

@pytest.fixture
def cross_version_archive(tmp_path):
    """Two scans of one domain, taken on different scanner versions."""
    root = tmp_path / "snapshots"
    write_snapshot_folder(
        root, "2026-08-18T101500Z-aaaaaaaa",
        a_payload("a" * 32, "2026-08-18T10:15:00+00:00",
                  engine_version="1.2.0", result="fail"))
    write_snapshot_folder(
        root, "2026-08-19T101500Z-bbbbbbbb",
        a_payload("b" * 32, "2026-08-19T10:15:00+00:00",
                  engine_version="1.3.0", result="pass",
                  rollout_state="enforced"))
    return root


class TestAmbiguousAttribution:
    @pytest.fixture
    def diff(self, cross_version_archive):
        return diff_snapshots(cross_version_archive,
                              "2026-08-18T101500Z-aaaaaaaa",
                              "2026-08-19T101500Z-bbbbbbbb")

    def test_the_diff_itself_calls_it_ambiguous(self, diff):
        assert diff["attribution"]["verdict"] == "ambiguous"
        # And there *is* an improvement to be misreported.
        assert diff["totals"]["improvements"] == 1

    def test_it_renders_as_a_warning_not_a_count(self, diff):
        html = render_diff(diff)
        assert "Different ADitor versions" in html
        assert "banner-bad" in html
        # The banner comes before the numbers, because every number below it
        # depends on it.
        assert html.index("Different ADitor versions") < html.index("Improvements")

    def test_it_repeats_why_rather_than_only_labelling_it(self, diff):
        html = render_diff(diff)
        # The version delta, in words, in the panel: "ambiguous" alone tells
        # the operator nothing they can act on.
        assert "engine_version 1.2.0" in html
        assert "1.3.0" in html
        assert "may come from the tool rather than" in html

    def test_the_counts_carry_the_qualifier(self, diff):
        html = render_diff(diff)
        # The improvement count is shown, but never as a score.
        assert html.count("not attributable to the domain") >= 2
        assert "ambiguous attribution" in html

    def test_the_improvement_card_repeats_the_caveat(self, diff):
        html = render_diff(diff)
        assert "do not report it as domain progress" in html

    def test_a_same_version_diff_reads_calmly_and_has_no_qualifier(self,
                                                                   archive):
        diff = diff_snapshots(archive, "2026-08-18T101500Z-aaaaaaaa",
                              "2026-08-19T101500Z-bbbbbbbb")
        html = render_diff(diff)
        assert "Same ADitor version" in html
        assert "banner-ok" in html
        assert "not attributable to the domain" not in html

    def test_caveats_are_shown_even_on_a_domain_verdict(self, tmp_path):
        # A GPO that became unreadable can move a verdict without the domain
        # moving, and that has to be visible even when the versions match.
        root = tmp_path / "snapshots"
        write_snapshot_folder(root, "2026-08-18T101500Z-aaaaaaaa",
                              a_payload("a" * 32, "2026-08-18T10:15:00+00:00"))
        write_snapshot_folder(
            root, "2026-08-19T101500Z-bbbbbbbb",
            a_payload("b" * 32, "2026-08-19T10:15:00+00:00", gpos=2,
                      unreadable=1))
        html = render_diff(diff_snapshots(root, "2026-08-18T101500Z-aaaaaaaa",
                                          "2026-08-19T101500Z-bbbbbbbb"))
        assert "Read these anyway" in html
        assert "could not be read" in html

    def test_a_catalog_version_change_is_also_ambiguous(self, tmp_path):
        root = tmp_path / "snapshots"
        write_snapshot_folder(
            root, "2026-08-18T101500Z-aaaaaaaa",
            a_payload("a" * 32, "2026-08-18T10:15:00+00:00",
                      catalog_version="1.0.0"))
        write_snapshot_folder(
            root, "2026-08-19T101500Z-bbbbbbbb",
            a_payload("b" * 32, "2026-08-19T10:15:00+00:00",
                      catalog_version="1.1.0", result="pass",
                      rollout_state="enforced"))
        html = render_diff(diff_snapshots(root, "2026-08-18T101500Z-aaaaaaaa",
                                          "2026-08-19T101500Z-bbbbbbbb"))
        assert "Different ADitor versions" in html
        assert "catalog_version 1.0.0" in html


class TestDiffRenderingSafety:
    def test_a_hostile_control_title_is_escaped(self, tmp_path):
        root = tmp_path / "snapshots"
        before = a_payload("a" * 32, "2026-08-18T10:15:00+00:00")
        after = a_payload("b" * 32, "2026-08-19T10:15:00+00:00",
                          result="pass", rollout_state="enforced")
        after["findings"][0]["title"] = '<img src=x onerror="alert(1)">'
        write_snapshot_folder(root, "2026-08-18T101500Z-aaaaaaaa", before)
        write_snapshot_folder(root, "2026-08-19T101500Z-bbbbbbbb", after)
        html = render_diff(diff_snapshots(root, "2026-08-18T101500Z-aaaaaaaa",
                                          "2026-08-19T101500Z-bbbbbbbb"))
        assert "<img" not in html
        assert "&lt;img" in html

    def test_an_empty_diff_payload_does_not_raise(self):
        # A malformed payload must render *something* rather than throwing
        # inside the window, where there is no console to read.
        assert render_diff({}) != ""
        assert render_diff({"attribution": None, "totals": None}) != ""
