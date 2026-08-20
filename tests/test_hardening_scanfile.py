"""Tests for storing a hardening scan as JSON and reading it back.

**Offline by construction.** ``scanfile`` is file I/O over a dict — no LDAP, no
SMB, no server, no keychain, no domain controller. The only side effect
exercised is writing a file, and that happens under ``tmp_path``.

**Fixture hygiene.** Every payload is synthesized: ``DC=test,DC=local``,
placeholder GUIDs, invented GPO names. That matters more here than almost
anywhere else in the suite, because a stored scan *embeds* the domain's GPO
display names, registry values and DNs — the environmental detail this repo
keeps out of git. No real scan is committed.

What the review cares about:

* the round trip — what ``write_scan`` writes, ``read_scan`` reads back
  unchanged, which is what makes the diff tool's inputs trustworthy;
* the path guards, which mirror the report writer's: ``.json`` only, and never
  clobber a file that is not one of ours;
* the refusals, which have to name the problem rather than raise from inside
  ``json`` — including handing the tool an HTML report by mistake.
"""

import json

import pytest
from aditor.hardening.scanfile import (
    SCAN_FILE_FORMAT_VERSION,
    SCAN_FILE_MARKER,
    ScanFileError,
    read_scan,
    scan_document,
    validate_scan_payload,
    write_scan,
)

BASE_DN = "DC=test,DC=local"
GUID_A = "11111111-1111-1111-1111-111111111111"


def scan_payload(**overrides):
    """A minimal but complete synthetic scan payload."""
    payload = {
        "scan": {
            "tool": "scan_hardening",
            "tool_version": "1.3.0",
            "scan_id": "a" * 32,
            "timestamp": "2026-08-01T09:00:00+00:00",
            "domain": "test.local",
            "base_dn": BASE_DN,
            "gpos_scanned": 1,
            "gpos_unreadable": 0,
            "include_not_applicable": True,
            "read_only": True,
            "catalog_version": "2026.08.3",
            "control_count": 1,
        },
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
    payload.update(overrides)
    return payload


class TestScanDocument:
    """The envelope: two fields added, nothing else touched."""

    def test_the_marker_is_the_first_key_so_the_head_of_a_file_identifies_it(self):
        document = scan_document(scan_payload())

        assert list(document)[:2] == ["format", "scan_format_version"]
        assert document["format"] == SCAN_FILE_MARKER
        assert document["scan_format_version"] == SCAN_FILE_FORMAT_VERSION

    def test_the_payload_is_carried_through_unchanged(self):
        payload = scan_payload()
        document = scan_document(payload)

        for key, value in payload.items():
            assert document[key] == value

    def test_a_non_dict_payload_is_refused(self):
        with pytest.raises(ScanFileError, match="must be a JSON object"):
            scan_document(["not", "a", "scan"])


class TestRoundTrip:
    """Acceptance 2: what write_scan writes, read_scan reads back."""

    def test_a_written_scan_reads_back_with_every_field_intact(self, tmp_path):
        payload = scan_payload()
        target = tmp_path / "scan.json"

        path, size = write_scan(payload, str(target))

        assert path == target
        assert size == target.stat().st_size
        restored = read_scan(str(target))
        for key, value in payload.items():
            assert restored[key] == value

    def test_the_written_file_is_readable_json_with_the_marker_up_front(
            self, tmp_path):
        target = tmp_path / "scan.json"
        write_scan(scan_payload(), str(target))

        head = target.read_bytes()[:200]
        assert SCAN_FILE_MARKER.encode("ascii") in head
        # Indented, so a human and plain `diff` can both read it.
        assert target.read_text(encoding="utf-8").startswith("{\n  ")
        assert json.loads(target.read_text(encoding="utf-8"))["format"] == \
            SCAN_FILE_MARKER

    def test_rerunning_over_our_own_output_overwrites_it(self, tmp_path):
        target = tmp_path / "scan.json"
        write_scan(scan_payload(), str(target))

        second = scan_payload()
        second["scan"]["scan_id"] = "b" * 32
        write_scan(second, str(target))

        assert read_scan(str(target))["scan"]["scan_id"] == "b" * 32

    def test_a_relative_path_resolves_and_a_tilde_expands(self, tmp_path,
                                                          monkeypatch):
        monkeypatch.chdir(tmp_path)
        path, _size = write_scan(scan_payload(), "nested/scan.json")

        assert path == tmp_path / "nested" / "scan.json"
        assert path.is_file()

    def test_missing_parent_directories_are_created(self, tmp_path):
        target = tmp_path / "scans" / "2026" / "august" / "scan.json"
        write_scan(scan_payload(), str(target))

        assert target.is_file()


class TestOutputPathGuards:
    """Writing is the only side effect, so a doubtful path is refused loudly."""

    @pytest.mark.parametrize("bad", ["", "   ", None, 42, []])
    def test_an_unusable_path_is_refused(self, bad):
        with pytest.raises(ScanFileError, match="non-empty file path"):
            write_scan(scan_payload(), bad)

    @pytest.mark.parametrize("name", ["scan.html", "scan.txt", "scan", "scan.py"])
    def test_only_a_json_suffix_is_accepted(self, tmp_path, name):
        with pytest.raises(ScanFileError, match=r"must end in \.json"):
            write_scan(scan_payload(), str(tmp_path / name))
        assert list(tmp_path.iterdir()) == []

    def test_a_directory_is_refused_with_a_usable_suggestion(self, tmp_path):
        # The suffix guard catches a bare directory first, so this needs a
        # directory that does carry the suffix to reach the directory guard.
        directory = tmp_path / "scans.json"
        directory.mkdir()

        with pytest.raises(ScanFileError, match="is a directory") as caught:
            write_scan(scan_payload(), str(directory))
        assert "hardening-scan.json" in str(caught.value)

    def test_a_bare_directory_is_caught_by_the_suffix_guard(self, tmp_path):
        with pytest.raises(ScanFileError, match=r"must end in \.json"):
            write_scan(scan_payload(), str(tmp_path))

    def test_an_existing_file_that_is_not_our_scan_is_never_clobbered(
            self, tmp_path):
        target = tmp_path / "budget.json"
        target.write_text('{"quarterly": "numbers someone cared about"}',
                          encoding="utf-8")

        with pytest.raises(ScanFileError, match="refusing to overwrite it"):
            write_scan(scan_payload(), str(target))
        assert "quarterly" in target.read_text(encoding="utf-8")

    def test_an_html_report_is_not_clobbered_by_a_json_suffix_mistake(
            self, tmp_path):
        """Belt and braces: the suffix guard already stops this, so prove it."""
        report = tmp_path / "report.html"
        report.write_text("<!DOCTYPE html><html>aditor-hardening-report</html>",
                          encoding="utf-8")

        with pytest.raises(ScanFileError, match=r"must end in \.json"):
            write_scan(scan_payload(), str(report))
        assert report.read_text(encoding="utf-8").startswith("<!DOCTYPE")

    def test_a_parent_that_is_a_file_is_refused(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")

        with pytest.raises(ScanFileError, match="is not a directory"):
            write_scan(scan_payload(), str(blocker / "scan.json"))

    def test_an_unserialisable_payload_is_refused_before_any_file_appears(
            self, tmp_path):
        payload = scan_payload()
        payload["counts"] = {"total": {1, 2, 3}}  # a set is not JSON

        with pytest.raises(ScanFileError, match="could not be serialised"):
            write_scan(payload, str(tmp_path / "scan.json"))
        assert list(tmp_path.iterdir()) == []


class TestReadGuards:
    """A refusal has to say what the file is instead, not raise from json."""

    def test_a_missing_file_says_so_and_says_what_to_do(self, tmp_path):
        with pytest.raises(ScanFileError, match="does not exist") as caught:
            read_scan(str(tmp_path / "absent.json"))
        assert "write_hardening_scan" in str(caught.value)

    def test_a_directory_is_not_a_scan_file(self, tmp_path):
        with pytest.raises(ScanFileError, match="is a directory"):
            read_scan(str(tmp_path))

    @pytest.mark.parametrize("bad", ["", "  ", None, 7])
    def test_an_unusable_path_is_refused(self, bad):
        with pytest.raises(ScanFileError, match="non-empty file path"):
            read_scan(bad)

    def test_invalid_json_is_named_as_such(self, tmp_path):
        target = tmp_path / "scan.json"
        target.write_text("{not json at all", encoding="utf-8")

        with pytest.raises(ScanFileError, match="is not valid JSON"):
            read_scan(str(target))

    def test_an_html_report_handed_to_the_reader_is_diagnosed(self, tmp_path):
        """The likeliest mistake: diffing the report instead of the scan."""
        target = tmp_path / "report.json"
        target.write_text("<!DOCTYPE html><html><body>report</body></html>",
                          encoding="utf-8")

        with pytest.raises(ScanFileError, match="looks like an HTML file") as caught:
            read_scan(str(target))
        assert "write_hardening_scan" in str(caught.value)

    def test_non_utf8_bytes_are_diagnosed_rather_than_crashing(self, tmp_path):
        target = tmp_path / "scan.json"
        target.write_bytes(b"\xff\xfe\x00\x00not text")

        with pytest.raises(ScanFileError, match="not UTF-8 text"):
            read_scan(str(target))


class TestPayloadValidation:
    """Acceptance 8's companion: "not a scan payload" must be a clear error."""

    def test_a_valid_payload_passes_and_is_returned(self):
        payload = scan_payload()
        assert validate_scan_payload(payload, "<payload>") is payload

    @pytest.mark.parametrize("missing", ["scan", "counts", "findings"])
    def test_a_missing_top_level_block_names_the_missing_key(self, missing):
        payload = scan_payload()
        del payload[missing]

        with pytest.raises(ScanFileError, match="not a hardening scan payload") \
                as caught:
            validate_scan_payload(payload, "before.json")
        assert missing in str(caught.value)
        assert "before.json" in str(caught.value)

    def test_the_error_names_which_file_was_wrong(self):
        with pytest.raises(ScanFileError, match="after.json"):
            validate_scan_payload({"nope": True}, "after.json")

    def test_a_failed_scan_response_is_not_a_scan(self):
        failed = {"success": False, "error": "LDAP server down",
                  "operation": "scan_hardening"}

        with pytest.raises(ScanFileError,
                           match="failed-scan error response") as caught:
            validate_scan_payload(failed, "before.json")
        assert "LDAP server down" in str(caught.value)

    @pytest.mark.parametrize("payload", [None, [], "a scan", 3])
    def test_a_non_object_payload_is_refused(self, payload):
        with pytest.raises(ScanFileError, match="expected a hardening scan"):
            validate_scan_payload(payload, "<payload>")

    def test_a_scan_without_a_base_dn_cannot_be_compared_and_says_so(self):
        payload = scan_payload()
        del payload["scan"]["base_dn"]

        with pytest.raises(ScanFileError, match="does not state a 'base_dn'"):
            validate_scan_payload(payload, "before.json")

    @pytest.mark.parametrize("block,message", [
        ("scan", "'scan' provenance block must be an object"),
        ("counts", "'counts' block must be an object"),
    ])
    def test_a_block_of_the_wrong_type_is_named(self, block, message):
        payload = scan_payload()
        payload[block] = "not an object"

        with pytest.raises(ScanFileError, match=message):
            validate_scan_payload(payload, "before.json")

    def test_findings_of_the_wrong_type_is_named(self):
        payload = scan_payload()
        payload["findings"] = {"not": "a list"}

        with pytest.raises(ScanFileError, match="'findings' must be a list"):
            validate_scan_payload(payload, "before.json")
