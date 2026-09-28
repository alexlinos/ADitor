"""The History screen and the diff, read by a first-time admin.

Readable times, plain plurals, a short attribution line, and each newly added
check listed with what it found — in the app and in ``aditor diff``.
"""

from aditor.app.history import SnapshotEntry
from aditor.app.render import render_diff, render_history
from aditor.cli import main
from aditor.hardening.scanfile import write_scan

from tests.test_directory_state import obj, payload_with


def entry(counts=None, **overrides):
    values = dict(name="2026-09-28T164120Z-5ccf1c35", folder="/s/x",
                  scan_path="/s/x/scan.json", report_path="/s/x/report.html",
                  has_report=True, readable=True,
                  timestamp="2026-09-28T16:41:20.221561+00:00",
                  catalog_version="2026.09.1", engine_version="1.4.0",
                  gpos_scanned=73,
                  counts=counts or {"fail": 1, "conflicts": 0, "pass": 14})
    values.update(overrides)
    return SnapshotEntry(**values)


def ambiguous_diff():
    """An August-style scan (no directory checks) against a new one."""
    from aditor.hardening.diff import diff_scans

    new = payload_with(groups=[obj("Schema Admins", kind="group",
                                   detail="1 member(s): Administrator",
                                   members=["CN=Administrator"])],
                       scan_id="b" * 32, timestamp="2026-09-28T16:41:20+00:00")
    old = payload_with(scan_id="a" * 32, timestamp="2026-09-28T13:49:13+00:00")
    old["findings"] = []
    old["scan"]["catalog_version"] = "2026.08.3"
    old["scan"]["tool_version"] = "1.3.0"
    return old, new, diff_scans(old, new)


class TestHistoryTable:

    def test_times_are_readable(self):
        html = render_history([entry()])
        assert "2026-09-28 16:41 UTC" in html
        assert "16:41:20.221561" not in html

    def test_conflicts_are_plural_unless_there_is_one(self):
        assert "0 conflicts" in render_history([entry()])
        one = entry(counts={"fail": 0, "conflicts": 1, "pass": 1})
        assert "1 conflict<" in render_history([one])


class TestDiff:

    def test_the_attribution_is_short_and_the_long_text_is_one_click_away(self):
        _old, _new, diff = ambiguous_diff()
        html = render_diff(diff)
        banner = html[:html.index("</div>")]
        assert "Different ADitor versions" in banner
        assert "What changed:" in banner
        assert "<summary>Why this matters</summary>" in html
        # The long paragraph is still there for whoever wants it.
        assert "ATTRIBUTION IS AMBIGUOUS" in html

    def test_each_added_check_is_listed_with_its_first_result(self):
        _old, _new, diff = ambiguous_diff()
        html = render_diff(diff)
        added = html[html.index("Added to the catalog"):]
        assert "3 (1 fail, 2 pass)" in added
        # Worst first.
        assert added.index("DEVORE-07-EMPTY-PRIVILEGED-GROUPS") < \
            added.index("DEVORE-04-SPN-ACCOUNTS-AES")
        assert "first finding, not a regression" in added

    def test_the_cli_lists_the_new_checks_too(self, tmp_path, capsys):
        old, new, _diff = ambiguous_diff()
        before, after = tmp_path / "old.json", tmp_path / "new.json"
        write_scan(old, str(before))
        write_scan(new, str(after))
        code = main(["diff", str(before), str(after)])
        out = capsys.readouterr().out
        assert "Different ADitor versions" in out
        assert "ATTRIBUTION IS AMBIGUOUS" not in out  # the short form only
        assert "fail: DEVORE-07-EMPTY-PRIVILEGED-GROUPS (high)" in out
        assert code == 0  # new checks aren't regressions
