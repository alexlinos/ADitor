"""Tests for the snapshot folder: one scan, one dated folder, both artifacts.

**Offline by construction.** ``snapshot`` is file I/O over a dict — no LDAP, no
SMB, no server, no keychain, no clock and no domain controller. The only side
effect exercised is writing under ``tmp_path``. The module has no scanner in it
at all, which is the point: the scan runs once, in the tool layer, and both files
here render that one payload.

**Fixture hygiene.** Every payload is synthesized (``DC=test,DC=local``,
placeholder GUIDs, invented GPO names), because a snapshot folder embeds the
domain's GPO display names, registry values and DNs. No real snapshot is
committed.

What the review cares about:

* the folder name — derived from the **scan's own** timestamp, never from
  ``now()``, and carrying no colon so it is legal on Windows;
* the one guard this module adds: an existing snapshot folder is refused, never
  merged into;
* that both files hold the same scan, which is the whole reason the module exists;
* that a snapshot folder can stand in for a ``scan.json`` when diffing.
"""

from unittest.mock import patch

import pytest
from aditor.hardening.report import ReportPathError
from aditor.hardening.scanfile import (
    SCAN_FILE_MARKER,
    ScanFileError,
    read_scan,
    write_scan,
)
from aditor.hardening.snapshot import (
    SNAPSHOT_REPORT_FILENAME,
    SNAPSHOT_SCAN_FILENAME,
    SnapshotError,
    resolve_scan_path,
    snapshot_folder_name,
    write_snapshot,
)

BASE_DN = "DC=test,DC=local"
GUID_A = "11111111-1111-1111-1111-111111111111"
SCAN_ID = "b288e925" + "0" * 24


def scan_payload(**scan_overrides):
    """A minimal but complete synthetic scan payload.

    ``scan_overrides`` patch the provenance block, which is the only part the
    folder name is derived from.
    """
    scan = {
        "tool": "scan_hardening",
        "tool_version": "1.3.0",
        "scan_id": SCAN_ID,
        "timestamp": "2026-08-20T16:26:47.123456+00:00",
        "domain": "test.local",
        "base_dn": BASE_DN,
        "gpos_scanned": 1,
        "gpos_unreadable": 0,
        "include_not_applicable": True,
        "read_only": True,
        "catalog_version": "2026.08.3",
        "control_count": 1,
    }
    scan.update(scan_overrides)
    return {
        "scan": scan,
        "counts": {"pass": 1, "fail": 0, "total": 1, "hidden": 0},
        "findings": [{
            "control_id": "DEVORE-03-LDAP-SERVER-SIGNING",
            "title": "Domain controller LDAP server signing",
            "severity": "high",
            "result": "pass",
            "rollout_state": "enforced",
            "scored": True,
            "evidence": {
                "source": "gpo",
                "found": [{
                    "gpo_dn": f"CN={{{GUID_A}}},CN=Policies,CN=System,{BASE_DN}",
                    "gpo_display_name": "Example DC LDAP Signing",
                    "value": 2,
                    "delivery": "security-template",
                }],
                "expected": {"operator": "equals", "final": 2},
            },
            "conflict": None,
        }],
        "unscored_control_ids": [],
        "unknown_control_ids": [],
        "gpo_read_errors": [],
    }


class TestFolderName:
    """Acceptance 3: no colon, and the name comes from the scan, not the clock."""

    def test_the_name_is_the_scans_timestamp_then_its_short_id(self):
        assert snapshot_folder_name(scan_payload()) == \
            "2026-08-20T162647Z-b288e925"

    def test_the_name_contains_no_colon(self):
        """ISO-8601's ``16:26:47`` is an illegal Windows filename."""
        assert ":" not in snapshot_folder_name(scan_payload())

    def test_the_name_carries_nothing_a_filesystem_objects_to(self):
        name = snapshot_folder_name(scan_payload())

        for character in ':/\\*?"<>| ':
            assert character not in name, character

    def test_the_name_is_derived_from_the_scan_not_from_now(self):
        """The directory listing and the provenance must tell one story.

        Re-deriving the time here would let the folder name drift from the
        payload by however long the scan took, so a frozen clock far from the
        scan's timestamp must make no difference at all.
        """
        first = snapshot_folder_name(scan_payload())
        second = snapshot_folder_name(
            scan_payload(timestamp="2019-01-02T03:04:05+00:00"))

        assert first == "2026-08-20T162647Z-b288e925"
        assert second == "2019-01-02T030405Z-b288e925"

    def test_two_scans_in_the_same_second_get_different_names(self):
        """Acceptance 4, at the naming level: the second is not an identity."""
        same_second = "2026-08-20T16:26:47.900000+00:00"
        first = snapshot_folder_name(
            scan_payload(timestamp=same_second, scan_id="a" * 32))
        second = snapshot_folder_name(
            scan_payload(timestamp=same_second, scan_id="f" * 32))

        assert first != second
        assert first.startswith("2026-08-20T162647Z")
        assert second.startswith("2026-08-20T162647Z")

    def test_a_non_utc_timestamp_is_normalised_to_utc(self):
        """The Z in the name has to be true."""
        name = snapshot_folder_name(
            scan_payload(timestamp="2026-08-20T18:26:47+02:00"))

        assert name == "2026-08-20T162647Z-b288e925"

    def test_a_timestamp_without_an_offset_is_read_as_utc(self):
        name = snapshot_folder_name(
            scan_payload(timestamp="2026-08-20T16:26:47"))

        assert name == "2026-08-20T162647Z-b288e925"

    def test_a_z_suffixed_timestamp_is_accepted(self):
        name = snapshot_folder_name(scan_payload(timestamp="2026-08-20T16:26:47Z"))

        assert name == "2026-08-20T162647Z-b288e925"

    def test_a_missing_timestamp_is_refused_rather_than_filled_in(self):
        payload = scan_payload()
        del payload["scan"]["timestamp"]

        with pytest.raises(SnapshotError, match="states no 'timestamp'"):
            snapshot_folder_name(payload)

    def test_an_unparsable_timestamp_is_refused_by_name(self):
        with pytest.raises(SnapshotError, match="not an ISO-8601 datetime"):
            snapshot_folder_name(scan_payload(timestamp="last Tuesday"))

    def test_a_missing_scan_id_is_refused(self):
        payload = scan_payload()
        del payload["scan"]["scan_id"]

        with pytest.raises(SnapshotError, match="states no 'scan_id'"):
            snapshot_folder_name(payload)

    def test_a_payload_with_no_provenance_block_is_refused(self):
        with pytest.raises(SnapshotError, match="no 'scan' provenance block"):
            snapshot_folder_name({"counts": {}, "findings": []})

    def test_a_non_dict_payload_is_refused(self):
        with pytest.raises(SnapshotError, match="must be a JSON object"):
            snapshot_folder_name(["not", "a", "scan"])

    def test_a_scan_id_that_is_not_a_plain_identifier_cannot_name_a_folder(self):
        """A hand-edited payload must not be able to steer the path."""
        with pytest.raises(SnapshotError, match="not a safe directory name"):
            snapshot_folder_name(scan_payload(scan_id="../../etc"))


class TestWriteSnapshot:
    """The folder: created fresh, filled with both artifacts, never merged into."""

    def test_it_writes_one_folder_holding_exactly_the_two_files(self, tmp_path):
        snapshot = write_snapshot(scan_payload(), str(tmp_path))

        assert snapshot.folder == tmp_path / "2026-08-20T162647Z-b288e925"
        assert sorted(p.name for p in snapshot.folder.iterdir()) == \
            [SNAPSHOT_REPORT_FILENAME, SNAPSHOT_SCAN_FILENAME]

    def test_it_reports_both_paths_and_both_byte_counts(self, tmp_path):
        snapshot = write_snapshot(scan_payload(), str(tmp_path))

        assert snapshot.scan_path == snapshot.folder / SNAPSHOT_SCAN_FILENAME
        assert snapshot.report_path == snapshot.folder / SNAPSHOT_REPORT_FILENAME
        assert snapshot.scan_bytes == snapshot.scan_path.stat().st_size
        assert snapshot.report_bytes == snapshot.report_path.stat().st_size

    def test_both_files_hold_the_same_scan(self, tmp_path):
        """The trap this module exists to close, at the unit level."""
        payload = scan_payload()
        snapshot = write_snapshot(payload, str(tmp_path))

        stored = read_scan(str(snapshot.scan_path))
        document = snapshot.report_path.read_text(encoding="utf-8")

        assert stored["scan"]["scan_id"] == payload["scan"]["scan_id"]
        assert payload["scan"]["scan_id"] in document
        assert stored["scan"]["timestamp"] in document

    def test_the_scan_file_is_a_recognisable_stored_scan(self, tmp_path):
        snapshot = write_snapshot(scan_payload(), str(tmp_path))

        head = snapshot.scan_path.read_text(encoding="utf-8")[:200]
        assert SCAN_FILE_MARKER in head

    def test_the_report_is_still_self_contained(self, tmp_path):
        """Acceptance 7: the guarantee must survive the new write path."""
        snapshot = write_snapshot(scan_payload(), str(tmp_path))
        document = snapshot.report_path.read_text(encoding="utf-8")

        assert document.startswith("<!DOCTYPE html>")
        assert '<meta charset="utf-8">' in document
        assert document.rstrip().endswith("</html>")
        # The forbidden set ``TestSelfContained`` in test_hardening_report.py
        # pins: nothing that fetches a resource, nothing that executes.
        for token in ("<script", "src=", "<link ", "@import", "url(",
                      "<iframe", "<object", "<embed", "onerror=", "onload=",
                      "onclick=", "javascript:"):
            assert token not in document, token
        assert document.count("<style>") == 1

    def test_missing_parent_directories_are_created(self, tmp_path):
        snapshot = write_snapshot(scan_payload(),
                                  str(tmp_path / "audits" / "2026"))

        assert snapshot.folder.parent == tmp_path / "audits" / "2026"
        assert snapshot.scan_path.is_file()

    def test_an_existing_snapshot_folder_is_refused_by_name(self, tmp_path):
        """Acceptance 5: refuse, never overwrite and never merge."""
        first = write_snapshot(scan_payload(), str(tmp_path))
        marker = first.folder / "operator-notes.txt"
        marker.write_text("do not lose me", encoding="utf-8")

        with pytest.raises(SnapshotError) as raised:
            write_snapshot(scan_payload(), str(tmp_path))

        assert str(first.folder) in str(raised.value)
        assert "already exists" in str(raised.value)
        # Nothing in it was touched.
        assert marker.read_text(encoding="utf-8") == "do not lose me"
        assert sorted(p.name for p in first.folder.iterdir()) == [
            "operator-notes.txt", SNAPSHOT_REPORT_FILENAME,
            SNAPSHOT_SCAN_FILENAME]

    def test_two_scans_in_the_same_second_land_in_different_folders(self,
                                                                   tmp_path):
        """Acceptance 4, end to end on disk."""
        same_second = "2026-08-20T16:26:47.010000+00:00"
        first = write_snapshot(
            scan_payload(timestamp=same_second, scan_id="a" * 32), str(tmp_path))
        second = write_snapshot(
            scan_payload(timestamp=same_second, scan_id="f" * 32), str(tmp_path))

        assert first.folder != second.folder
        assert first.scan_path.is_file() and second.scan_path.is_file()
        assert len(list(tmp_path.iterdir())) == 2

    def test_an_output_dir_that_is_a_file_is_refused(self, tmp_path):
        not_a_dir = tmp_path / "notes.txt"
        not_a_dir.write_text("x", encoding="utf-8")

        with pytest.raises(SnapshotError, match="is not a directory"):
            write_snapshot(scan_payload(), str(not_a_dir))

    def test_an_empty_output_dir_is_refused_and_says_there_is_no_default(self):
        with pytest.raises(SnapshotError) as raised:
            write_snapshot(scan_payload(), "   ")

        assert "non-empty directory path" in str(raised.value)
        assert "no default" in str(raised.value)

    def test_a_relative_output_dir_resolves_against_the_working_directory(
            self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        snapshot = write_snapshot(scan_payload(), "snapshots")

        assert snapshot.folder.parent == tmp_path / "snapshots"

    def test_a_user_relative_output_dir_is_expanded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))  # what Windows reads

        snapshot = write_snapshot(scan_payload(), "~/snapshots")

        assert snapshot.folder.parent == tmp_path / "snapshots"

    def test_a_failed_write_leaves_no_half_snapshot_behind(self, tmp_path):
        """One of the two files alone would read later as a whole snapshot."""
        with patch("aditor.hardening.snapshot.write_report",
                   side_effect=ReportPathError("disk full")):
            with pytest.raises(ReportPathError):
                write_snapshot(scan_payload(), str(tmp_path))

        assert list(tmp_path.iterdir()) == []

    def test_a_bad_payload_is_refused_before_any_folder_is_created(self,
                                                                  tmp_path):
        with pytest.raises(SnapshotError):
            write_snapshot(scan_payload(timestamp="not a date"), str(tmp_path))

        assert list(tmp_path.iterdir()) == []


class TestResolveScanPath:
    """A snapshot folder standing in for its scan.json — acceptance 6's plumbing."""

    def test_a_snapshot_folder_resolves_to_its_scan_json(self, tmp_path):
        snapshot = write_snapshot(scan_payload(), str(tmp_path))

        assert resolve_scan_path(str(snapshot.folder)) == str(snapshot.scan_path)

    def test_a_file_path_is_returned_unchanged(self, tmp_path):
        target = tmp_path / "scan.json"
        write_scan(scan_payload(), str(target))

        assert resolve_scan_path(str(target)) == str(target)

    def test_a_path_that_does_not_exist_is_returned_unchanged(self, tmp_path):
        """The existing 'does not exist' message must keep naming what was asked
        for, not something this resolver invented."""
        missing = str(tmp_path / "gone.json")

        assert resolve_scan_path(missing) == missing

    def test_a_directory_without_a_scan_json_is_refused_clearly(self, tmp_path):
        empty = tmp_path / "not-a-snapshot"
        empty.mkdir()

        with pytest.raises(ScanFileError) as raised:
            resolve_scan_path(str(empty))

        assert str(empty) in str(raised.value)
        assert "holds no scan.json" in str(raised.value)
        assert "aditor scan" in str(raised.value)

    def test_a_folder_holding_only_a_report_is_not_a_snapshot_folder(self,
                                                                    tmp_path):
        half = tmp_path / "half"
        half.mkdir()
        (half / SNAPSHOT_REPORT_FILENAME).write_text("<html></html>",
                                                     encoding="utf-8")

        with pytest.raises(ScanFileError, match="holds no scan.json"):
            resolve_scan_path(str(half))

    def test_a_relative_folder_resolves_against_the_working_directory(
            self, tmp_path, monkeypatch):
        snapshot = write_snapshot(scan_payload(), str(tmp_path))
        monkeypatch.chdir(tmp_path)

        assert resolve_scan_path(snapshot.folder.name) == str(snapshot.scan_path)

    def test_a_non_string_is_handed_on_untouched(self):
        """The read side already has messages for these; do not pre-empt them."""
        assert resolve_scan_path(None) is None
        assert resolve_scan_path("") == ""
