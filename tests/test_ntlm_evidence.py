"""NTLMv1 evidence: who still uses it, and when an empty list means anything."""

import csv
import re

import pytest

from aditor.cli import main
from aditor.hardening.ntlm_evidence import (
    EXPORT_SCRIPT, MIN_DAYS, VERDICT_BLOCKED, VERDICT_CLEAR, VERDICT_NOT_YET,
    EvidenceError, read_evidence, verdict)

COLUMNS = ("Host", "Log", "Kind", "EventId", "Time", "Account", "Domain",
           "Client", "ClientIp", "Server", "Process")
NOW = "2026-10-05T12:00:00+00:00"


def row(host, kind, time=NOW, **fields):
    out = {c: "" for c in COLUMNS}
    out.update(Host=host, Kind=kind, Time=time, **fields)
    return out


def healthy(host):
    """A host whose Security log goes back to 1 September, with logon
    auditing on: more than MIN_DAYS of evidence."""
    return [row(host, "exported"),
            row(host, "log-oldest", "2026-09-01T00:00:00+00:00"),
            row(host, "last-logon", EventId="4624")]


def v1(host, account, client, time="2026-10-04T08:00:00+00:00", event="4624"):
    return row(host, "ntlmv1", time, EventId=event, Account=account,
               Domain="EXAMPLE", Client=client, Server=host)


def write(tmp_path, rows, name="export.csv"):
    path = tmp_path / name
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


class TestVerdict:

    def test_any_ntlmv1_blocks_and_is_grouped_by_account_and_client(self):
        rows = healthy("FS01") + [v1("FS01", "svc-scan", "COPIER1"),
                                  v1("FS01", "svc-scan", "COPIER1"),
                                  v1("FS01", "jdoe", "OLDPC")]
        result = verdict(rows)

        assert result["verdict"] == VERDICT_BLOCKED
        assert [(s["account"], s["count"]) for s in result["sources"]] == [
            ("svc-scan", 2), ("jdoe", 1)]

    def test_clean_logs_with_auditing_over_the_window_are_clear(self):
        result = verdict(healthy("DC01") + healthy("FS01"))

        assert result["verdict"] == VERDICT_CLEAR
        assert "only the hosts exported" in result["summary"]

    def test_an_empty_list_is_not_clear_without_logon_auditing(self):
        rows = [r for r in healthy("FS01") if r["Kind"] != "last-logon"]
        result = verdict(rows)

        assert result["verdict"] == VERDICT_NOT_YET
        assert "logon auditing looks off" in result["summary"]

    def test_an_empty_list_is_not_clear_when_the_log_is_short(self):
        rows = [row("DC01", "exported"),
                row("DC01", "log-oldest", "2026-10-05T06:00:00+00:00"),
                row("DC01", "last-logon")]
        result = verdict(rows)

        assert result["verdict"] == VERDICT_NOT_YET
        assert "only goes back 0.2 days" in result["summary"]
        assert f"{MIN_DAYS} are needed" in result["summary"]

    def test_an_unreadable_host_is_not_clear(self):
        rows = [row("APP01", "exported"),
                row("APP01", "error", Account="Security log: Access is denied")]
        result = verdict(rows)

        assert result["verdict"] == VERDICT_NOT_YET
        assert "Access is denied" in result["summary"]

    def test_the_new_ntlm_log_counts_as_evidence_too(self):
        rows = healthy("DC01") + [v1("DC01", "kiosk", "KIOSK7", event="4032")]
        result = verdict(rows)

        assert result["verdict"] == VERDICT_BLOCKED
        assert result["sources"][0]["via"] == "NTLM log"

    def test_no_hosts_is_not_clear(self):
        assert verdict([])["verdict"] == VERDICT_NOT_YET


class TestReading:

    def test_a_csv_that_is_not_an_export_is_refused(self, tmp_path):
        path = tmp_path / "other.csv"
        path.write_text("Name,Value\nx,1\n", encoding="utf-8")
        with pytest.raises(EvidenceError, match="isn't an ADitor NTLMv1 export"):
            read_evidence([path])

    def test_several_exports_are_combined(self, tmp_path):
        a = write(tmp_path, healthy("DC01"), "a.csv")
        b = write(tmp_path, healthy("FS01") + [v1("FS01", "x", "Y")], "b.csv")
        assert verdict(read_evidence([a, b]))["verdict"] == VERDICT_BLOCKED


class TestTheScriptIsReadOnly:

    def test_it_only_reads(self):
        """No cmdlet in it may change a machine: it reads logs, writes a CSV."""
        code = EXPORT_SCRIPT.replace("Microsoft-Windows-NTLM", "")  # a log name
        verbs = set(re.findall(r"\b([A-Z][a-z]+)-[A-Z][A-Za-z]+\b", code))
        assert verbs <= {"Get", "Where", "ForEach", "Select", "Export", "Write"}

    def test_it_skips_anonymous_logons_and_reads_both_sources(self):
        assert "S-1-5-7" in EXPORT_SCRIPT
        assert "LmPackageName']='NTLM V1'" in EXPORT_SCRIPT
        assert "Microsoft-Windows-NTLM/Operational" in EXPORT_SCRIPT
        assert "4032" in EXPORT_SCRIPT


class TestCommands:

    def test_ntlm_script_prints_the_script(self, capsys):
        assert main(["ntlm-script"]) == 0
        assert capsys.readouterr().out == EXPORT_SCRIPT

    def test_ntlm_check_exit_codes(self, tmp_path, capsys):
        clear = write(tmp_path, healthy("DC01"), "clear.csv")
        blocked = write(tmp_path, healthy("FS01") + [v1("FS01", "a", "B")],
                        "blocked.csv")

        assert main(["ntlm-check", str(clear)]) == 0
        assert main(["ntlm-check", str(blocked)]) == 1
        assert "EXAMPLE\\a from B to FS01" in capsys.readouterr().out
        assert main(["ntlm-check", str(tmp_path / "missing.csv")]) == 2


class TestInTheReport:

    @pytest.fixture
    def payload(self):
        from tests.test_hardening_report import sample_scan
        return sample_scan("Sample Workstation Baseline GPO")

    def card(self, document):
        start = document.index('id="devore-01-ntlm-lmcompatibilitylevel"')
        return document[start:document.index("</article>", start)]

    def test_without_evidence_the_card_says_how_to_get_it(self, payload):
        from aditor.hardening.report import render_report
        card = self.card(render_report(payload))
        assert "Who still uses NTLMv1?" in card
        assert "aditor-cli ntlm-script" in card

    def test_with_evidence_the_card_lists_who_and_start_here_warns(self, payload):
        from aditor.hardening.report import render_report
        payload["ntlmv1_evidence"] = verdict(
            healthy("FS01") + [v1("FS01", "svc-scan", "COPIER1")])
        document = render_report(payload)

        assert "svc-scan" in self.card(document)
        assert "COPIER1" in self.card(document)
        start = document[document.index('id="start-here"'):
                         document.index('<nav class="toc"')]
        assert "Still using NTLMv1:" in start
