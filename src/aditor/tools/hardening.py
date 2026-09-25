"""The hardening scan tools: read the domain's GPOs, evaluate the catalog.

This module is response shaping only: the LDAP queries and SYSVOL reads live
in :mod:`aditor.hardening.collect`. The control definitions live in
:mod:`aditor.hardening.catalog`, the verdict logic in
:mod:`aditor.hardening.evaluator`, the HTML rendering in
:mod:`aditor.hardening.report`, and the parsing in :mod:`aditor.gpo.parsers`;
all four are pure and unit-tested offline.

Five tools, one scan:

* ``scan_hardening`` returns the structured JSON — the **source of truth**.
* ``write_hardening_report`` runs the same scan and writes it as one
  self-contained HTML file. It derives nothing of its own: the renderer consumes
  the identical payload, so the document and the JSON cannot disagree.
* ``write_hardening_scan`` runs the same scan and writes the **JSON** to a file,
  so two runs can be compared later. It is the report tool's sibling: same scan,
  same path guards, different medium.
* ``write_hardening_snapshot`` runs the scan **once** and writes both of the
  above into one dated folder. The two writers above each run their own scan, so
  calling them in turn would leave a folder holding two different scans; this
  tool exists to make that impossible — see
  :mod:`aditor.hardening.snapshot`.
* ``diff_hardening_scans`` compares two stored scans. It is the one tool here
  that touches no directory at all — two files (or two snapshot folders) in, one
  diff out.

Writing files is the only side effect any of these tools has.

The scan is **read-only**: it enumerates ``groupPolicyContainer`` objects, reads
each one's SYSVOL folder, and compares what it finds against the catalog. It
changes nothing in the directory.

**A saved scan is directory content.** Like a rendered report, it embeds this
domain's GPO display names, registry values and DNs, and both tool descriptions
say so.

Every response carries a provenance header — scan engine version, catalog
version, timestamp, domain and base DN — because a report that cannot state
"against which baseline, when, which domain" is not audit-grade.
"""

from typing import Any, Dict, List, Optional, Sequence

from ..core.logging import log_ldap_operation
from ..hardening.catalog import CatalogError, load_catalog
from ..hardening.collect import GpoReadFailure, RSOP_NOTE, Scanner
from ..hardening.evaluator import (
    DELIVERIES,
    EVIDENCE_SOURCES,
    RESULTS,
)
from ..hardening.diff import (
    ATTRIBUTION_AMBIGUOUS,
    ATTRIBUTION_DOMAIN,
    DIFF_FORMAT_VERSION,
    ScanDiffError,
    diff_scan_files,
)
from ..hardening.report import (
    REPORT_FORMAT_VERSION,
    ReportPathError,
    headline_counts,
    write_report,
)
from ..hardening.scanfile import (
    SCAN_FILE_FORMAT_VERSION,
    ScanFileError,
    write_scan,
)
from ..hardening.snapshot import (
    SNAPSHOT_FORMAT_VERSION,
    SNAPSHOT_REPORT_FILENAME,
    SNAPSHOT_SCAN_FILENAME,
    SnapshotError,
    write_snapshot,
)
from .base import BaseTool


class HardeningTools(BaseTool):
    """Read-only hardening scan over the domain's Group Policy content."""

    def __init__(self, ldap_manager: Any) -> None:
        super().__init__(ldap_manager)
        # The collection itself lives in aditor.hardening.collect, which the
        # CLI uses directly; these tools only shape its payload for MCP.
        self.scanner = Scanner(ldap_manager)

    # --- the tool ----------------------------------------------------------

    def scan_hardening(self, control_ids: Optional[Sequence[str]] = None,
                       include_not_applicable: bool = False
                       ) -> List[Dict[str, Any]]:
        """Scan the domain's GPOs against the hardening control catalog.

        Args:
            control_ids: Evaluate only these control ids (case-insensitive).
                ``None`` (the default) evaluates the whole catalog. Ids that
                match nothing are reported in ``unknown_control_ids`` rather
                than silently dropped.
            include_not_applicable: Include findings whose control did not apply
                — an unset conditional setting, for instance. Controls flagged
                ``needs_baseline_value`` are always included regardless, since a
                control the engine cannot evaluate must not look like a pass.

        Returns:
            List of MCP content objects with the provenance header, the
            findings, and the counts.
        """
        try:
            payload = self._scan(control_ids, include_not_applicable,
                                 operation="scan_hardening")
        except GpoReadFailure as failure:
            return self._handle_ldap_error(failure.cause, "scan_hardening",
                                           self.ldap.ad_config.base_dn)
        return self._format_response(payload, "scan_hardening")

    def write_hardening_report(self, output_path: str,
                               control_ids: Optional[Sequence[str]] = None
                               ) -> List[Dict[str, Any]]:
        """Run the hardening scan and write it as one self-contained HTML file.

        The document is the same scan ``scan_hardening`` returns, rendered: the
        JSON stays the source of truth and the renderer adds nothing to it. The
        file is standalone — inline CSS, no external asset, no script — so it can
        be emailed, attached to a ticket, or printed to PDF by a browser.

        ``include_not_applicable`` is deliberately not exposed. The report has a
        dedicated section for not-applicable findings and its whole job is to show
        everything that was evaluated, so hiding a bucket of it would only make
        the document disagree with its own counts.

        Args:
            output_path: Where to write the ``.html`` file. ``~`` is expanded and
                a relative path resolves against the working directory. Missing
                parent directories are created. An existing file is overwritten
                **only** if it is a previous ADitor report; anything else is
                refused rather than clobbered.
            control_ids: Report on only these control ids (case-insensitive).
                ``None`` (the default) reports the whole catalog.

        Returns:
            List of MCP content objects with the written path, the byte count,
            the provenance header and the headline counts. On any failure the
            payload carries ``success: False`` and **no file is written**.
        """
        try:
            payload = self._scan(control_ids, include_not_applicable=True,
                                 operation="write_hardening_report")
        except GpoReadFailure as failure:
            return self._handle_ldap_error(failure.cause,
                                           "write_hardening_report",
                                           self.ldap.ad_config.base_dn)

        if payload.get("success") is False:
            # A catalog, argument or dependency failure. Report it and write
            # nothing: an HTML file whose content is an error message is worse
            # than no file, because it looks like a report.
            return self._format_response(payload, "write_hardening_report")

        try:
            path, size = write_report(payload, output_path)
        except ReportPathError as exc:
            return self._format_response({
                "success": False,
                "error": str(exc),
                "operation": "write_hardening_report",
                "scan_succeeded": True,
                "note": "The scan completed; only the write was refused. Fix the "
                        "output path and re-run — no file was created or "
                        "modified.",
            }, "write_hardening_report")

        log_ldap_operation("write_hardening_report",
                           self.ldap.ad_config.base_dn, True,
                           f"Wrote {size} bytes to {path}")

        return self._format_response({
            "success": True,
            "operation": "write_hardening_report",
            "output_path": str(path),
            "bytes_written": size,
            "format": "html",
            "report_format_version": REPORT_FORMAT_VERSION,
            "self_contained": True,
            "counts": payload["counts"],
            "headline": headline_counts(payload),
            "scan": payload["scan"],
            "notes": [
                "Self-contained HTML: inline CSS, no external assets, no "
                "scripts. Opens from a file:// path and needs no network access.",
                "Ordered by actionability: read failures and unknown verdicts "
                "first, then failures, conflicts, hardening opportunities at the "
                "OS default, unscored controls, and passes last.",
                "The JSON from scan_hardening is the source of truth; this "
                "document renders it and adds nothing to it.",
                "PDF is deliberately not produced. Print the HTML from a browser "
                "if a PDF is needed.",
                "The report embeds GPO display names, registry values and DNs "
                "from this domain. Treat the file as containing directory "
                "content when sharing it.",
            ],
        }, "write_hardening_report")

    def write_hardening_scan(self, output_path: str,
                             control_ids: Optional[Sequence[str]] = None
                             ) -> List[Dict[str, Any]]:
        """Run the hardening scan and write the JSON payload to a file.

        The sibling of ``write_hardening_report``: the same read-only scan, the
        same path guards, a different medium. The report is for a reader; this is
        for ``diff_hardening_scans``, which needs the structured payload rather
        than a rendered document.

        ``include_not_applicable`` is deliberately not exposed, and is always
        true. A stored scan is an input to a later comparison, and a scan that
        filtered part of the catalog out cannot be told apart from one whose
        catalog was smaller — the diff has to guess, and says so in
        ``catalog_changes.comparable``. Storing everything removes the guess.

        Args:
            output_path: Where to write the ``.json`` file. ``~`` is expanded and
                a relative path resolves against the working directory. Missing
                parent directories are created. An existing file is overwritten
                **only** if it is a previous ADitor scan; anything else is
                refused rather than clobbered.
            control_ids: Scan only these control ids (case-insensitive).
                ``None`` (the default) scans the whole catalog, which is what a
                scan meant for diffing should normally do.

        Returns:
            List of MCP content objects with the written path, the byte count,
            the provenance header and the headline counts. On any failure the
            payload carries ``success: False`` and **no file is written**.
        """
        try:
            payload = self._scan(control_ids, include_not_applicable=True,
                                 operation="write_hardening_scan")
        except GpoReadFailure as failure:
            return self._handle_ldap_error(failure.cause,
                                           "write_hardening_scan",
                                           self.ldap.ad_config.base_dn)

        if payload.get("success") is False:
            # A catalog, argument or dependency failure. Report it and write
            # nothing: a stored file whose content is an error payload is worse
            # than no file, because a later diff would try to compare it.
            return self._format_response(payload, "write_hardening_scan")

        try:
            path, size = write_scan(payload, output_path)
        except ScanFileError as exc:
            return self._format_response({
                "success": False,
                "error": str(exc),
                "operation": "write_hardening_scan",
                "scan_succeeded": True,
                "note": "The scan completed; only the write was refused. Fix the "
                        "output path and re-run — no file was created or "
                        "modified.",
            }, "write_hardening_scan")

        log_ldap_operation("write_hardening_scan",
                           self.ldap.ad_config.base_dn, True,
                           f"Wrote {size} bytes to {path}")

        return self._format_response({
            "success": True,
            "operation": "write_hardening_scan",
            "output_path": str(path),
            "bytes_written": size,
            "format": "json",
            "scan_format_version": SCAN_FILE_FORMAT_VERSION,
            "counts": payload["counts"],
            "headline": headline_counts(payload),
            "scan": payload["scan"],
            "notes": [
                "This is the same payload scan_hardening returns, written to a "
                "file. Nothing is derived and nothing is dropped, so the file "
                "and the tool's own output cannot disagree.",
                "Diff two of these with diff_hardening_scans to see what "
                "changed. Keep the scan engine and catalog versions in the "
                "provenance header in mind when you do: a diff across versions "
                "cannot be attributed to the domain, and the diff will say so.",
                "The whole catalog was scanned and nothing was filtered out, so "
                "a later diff can tell a catalog change from a control that was "
                "simply not evaluated.",
                "The file contains this domain's GPO display names, registry "
                "values and DNs. Treat it as containing directory content when "
                "sharing, attaching or committing it — the same caveat the HTML "
                "report carries.",
            ],
        }, "write_hardening_scan")

    def write_hardening_snapshot(self, output_dir: str
                                 ) -> List[Dict[str, Any]]:
        """Run the hardening scan **once** and write both artifacts to one folder.

        ::

            <output_dir>/2026-08-20T162647Z-b288e925/
                scan.json      <- the payload (source of truth)
                report.html    <- the rendered document

        The reason this tool exists rather than the caller running the other two:
        ``write_hardening_scan`` and ``write_hardening_report`` each run their
        **own** scan. Calling both would put a report and a payload from two
        different scans in one folder — different ``scan_id``, different
        timestamps, and on a domain that moved in between, different findings.
        The JSON is the evidence of record, so a report that disagrees with it
        undermines the provenance the folder exists to keep. Here the scan runs
        once and both writers are handed that one payload.

        The folder is named from the scan's **own** timestamp, not from a fresh
        clock reading, so the directory listing and the provenance inside the
        files agree; and it carries no colon, because that is an illegal Windows
        filename and the packaging target is a Windows ``.exe``. The short
        ``scan_id`` suffix keeps two scans in the same second apart.

        Neither ``control_ids`` nor ``include_not_applicable`` is exposed, and
        the whole catalog is always scanned. A snapshot is a record of the domain
        at a moment and an input to a later ``diff_hardening_scans``; a snapshot
        that filtered part of the catalog out could not be told apart from one
        whose catalog was smaller, and the pair of files would no longer be a
        complete account of the run.

        Args:
            output_dir: The directory to create the snapshot folder **inside**.
                ``~`` is expanded and a relative path resolves against the
                working directory. Missing parents are created. There is
                deliberately no default: both files hold real directory content,
                so where they land is the operator's choice.

        Returns:
            List of MCP content objects with the snapshot folder, the
            ``scan_id``, both file paths and byte counts, the provenance header
            and the headline counts. On any failure the payload carries
            ``success: False``, and a refusal after the folder was created leaves
            no folder behind — a snapshot is both files or neither.
        """
        try:
            payload = self._scan(None, include_not_applicable=True,
                                 operation="write_hardening_snapshot")
        except GpoReadFailure as failure:
            return self._handle_ldap_error(failure.cause,
                                           "write_hardening_snapshot",
                                           self.ldap.ad_config.base_dn)

        if payload.get("success") is False:
            # A catalog, argument or dependency failure. Report it and write
            # nothing: a folder holding an error payload would be read later as
            # a snapshot of the domain.
            return self._format_response(payload, "write_hardening_snapshot")

        try:
            snapshot = write_snapshot(payload, output_dir)
        except (SnapshotError, ScanFileError, ReportPathError) as exc:
            return self._format_response({
                "success": False,
                "error": str(exc),
                "operation": "write_hardening_snapshot",
                "scan_succeeded": True,
                "note": "The scan completed; only the write was refused. Fix "
                        "the output directory and re-run — no snapshot folder "
                        "was left behind.",
            }, "write_hardening_snapshot")

        log_ldap_operation("write_hardening_snapshot",
                           self.ldap.ad_config.base_dn, True,
                           f"Wrote {snapshot.scan_bytes + snapshot.report_bytes}"
                           f" bytes to {snapshot.folder}")

        return self._format_response({
            "success": True,
            "operation": "write_hardening_snapshot",
            "snapshot_dir": str(snapshot.folder),
            "snapshot_name": snapshot.folder.name,
            "snapshot_format_version": SNAPSHOT_FORMAT_VERSION,
            # Named at the top level as well as inside ``scan``: it is the one
            # value that proves both files came from the same run.
            "scan_id": payload["scan"]["scan_id"],
            "scans_run": 1,
            "files": {
                "scan": {
                    "name": SNAPSHOT_SCAN_FILENAME,
                    "path": str(snapshot.scan_path),
                    "bytes_written": snapshot.scan_bytes,
                    "format": "json",
                    "scan_format_version": SCAN_FILE_FORMAT_VERSION,
                },
                "report": {
                    "name": SNAPSHOT_REPORT_FILENAME,
                    "path": str(snapshot.report_path),
                    "bytes_written": snapshot.report_bytes,
                    "format": "html",
                    "report_format_version": REPORT_FORMAT_VERSION,
                    "self_contained": True,
                },
            },
            "bytes_written": snapshot.scan_bytes + snapshot.report_bytes,
            "counts": payload["counts"],
            "headline": headline_counts(payload),
            "scan": payload["scan"],
            "notes": [
                "The scan ran ONCE and both files render that one payload, so "
                "the report and the JSON carry the same scan_id, the same "
                "timestamp and the same findings. Running "
                "write_hardening_scan and write_hardening_report separately "
                "would give you two different scans in one folder.",
                "The folder name is the scan's own timestamp plus a scan_id "
                "prefix, with no colon in it: colons are illegal in Windows "
                "filenames, and the name is derived from the payload rather "
                "than from the clock so the directory listing and the files "
                "agree.",
                "An existing snapshot folder is refused, never overwritten or "
                "merged into. Each run gets its own folder.",
                "The whole catalog was scanned and nothing was filtered out, so "
                "a later diff can tell a catalog change from a control that "
                "was simply not evaluated.",
                "diff_hardening_scans accepts these folders directly — pass "
                "two snapshot folders and it reads the scan.json inside each.",
                "BOTH FILES CONTAIN DIRECTORY CONTENT: this domain's GPO "
                "display names, registry values and DNs. Treat the folder "
                "accordingly when sharing it, attaching it to a ticket, or "
                "committing it.",
            ],
        }, "write_hardening_snapshot")

    def diff_hardening_scans(self, before_path: str, after_path: str
                             ) -> List[Dict[str, Any]]:
        """Compare two scans written by ``write_hardening_scan``.

        The one tool in this module that touches no directory: it reads two files
        and returns a diff. No LDAP, no SMB, no SYSVOL.

        Either path may be a ``.json`` scan file or a snapshot folder written by
        ``write_hardening_snapshot``, in which case the ``scan.json`` inside it
        is read — so ``diff <folder-a> <folder-b>`` works without the caller
        reaching inside either folder.

        **Read ``attribution`` first.** It is the payload's opening key because
        every number below it depends on it. If the two scans ran different
        catalog or engine versions, a difference may be the *tool* rather than
        the domain, and the diff refuses to present it as domain progress.

        Args:
            before_path: The earlier scan — its ``.json`` file, or the snapshot
                folder holding it.
            after_path: The later scan, in either of the same two forms.

        Returns:
            List of MCP content objects with the diff. On a refusal — either file
            not being a scan, or the two describing different domains — the
            payload carries ``success: False`` and a message saying which.
        """
        try:
            diff = diff_scan_files(before_path, after_path)
        except (ScanFileError, ScanDiffError) as exc:
            return self._format_response({
                "success": False,
                "error": str(exc),
                "operation": "diff_hardening_scans",
                "note": "Nothing was read from the directory and nothing was "
                        "written. Both inputs must be JSON scans written by "
                        "write_hardening_scan — or snapshot folders written by "
                        "write_hardening_snapshot — and both must be scans of "
                        "the same domain.",
            }, "diff_hardening_scans")

        # success/operation first, then the diff with ``attribution`` still the
        # first thing a reader meets in the body.
        response: Dict[str, Any] = {
            "success": True,
            "operation": "diff_hardening_scans",
            "read_only": True,
            "diff_format_version": DIFF_FORMAT_VERSION,
        }
        response.update(diff)

        headline = (
            "ATTRIBUTION IS AMBIGUOUS — these scans ran different tool "
            "versions, so the differences below may be the scanner or the "
            "catalog rather than the domain. Read attribution.summary before "
            "reporting any of this as progress."
            if diff["attribution"]["verdict"] == ATTRIBUTION_AMBIGUOUS else
            "Both scans ran the same catalog and engine version, so the "
            "differences below can be attributed to the domain.")
        response["headline"] = headline

        log_ldap_operation("diff_hardening_scans",
                           diff["scans"].get("base_dn") or "", True,
                           f"{diff['totals']['regressions']} regression(s), "
                           f"{diff['totals']['improvements']} improvement(s), "
                           f"attribution {diff['attribution']['verdict']}")

        return self._format_response(response, "diff_hardening_scans")

    # --- the shared scan ---------------------------------------------------- #

    def _scan(self, control_ids: Optional[Sequence[str]],
              include_not_applicable: bool,
              operation: str) -> Dict[str, Any]:
        """Run the scan in :mod:`aditor.hardening.collect`."""
        return self.scanner.scan(control_ids, include_not_applicable, operation)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for the hardening scan operations."""
        try:
            catalog = load_catalog()
            catalog_info: Dict[str, Any] = {
                "catalog_version": catalog.version,
                "control_ids": [c.id for c in catalog.controls],
                "unscored_control_ids": [c.id for c in catalog.unscored_controls],
            }
        except CatalogError as exc:  # pragma: no cover - defensive
            catalog_info = {"catalog_error": str(exc)}

        return {
            "operations": ["scan_hardening", "write_hardening_report",
                           "write_hardening_scan", "write_hardening_snapshot",
                           "diff_hardening_scans"],
            # The scan itself changes nothing in the directory. The write tools'
            # one side effect is the file (or the folder of two files) each
            # writes, and diff_hardening_scans reads its inputs and touches no
            # directory.
            "read_only": True,
            "writes_files": ["write_hardening_report", "write_hardening_scan",
                             "write_hardening_snapshot"],
            "report_formats": ["html"],
            "report_format_version": REPORT_FORMAT_VERSION,
            "scan_format_version": SCAN_FILE_FORMAT_VERSION,
            "snapshot_format_version": SNAPSHOT_FORMAT_VERSION,
            "snapshot_files": [SNAPSHOT_SCAN_FILENAME,
                               SNAPSHOT_REPORT_FILENAME],
            "diff_format_version": DIFF_FORMAT_VERSION,
            "diff_attributions": [ATTRIBUTION_DOMAIN, ATTRIBUTION_AMBIGUOUS],
            "check_types": ["gpo-security-template", "gpo-registry-pol"],
            "deliveries": list(DELIVERIES),
            "results": list(RESULTS),
            "rollout_states": ["not_started", "audit", "enforced"],
            "evidence_sources": list(EVIDENCE_SOURCES),
            "notes": [
                "Reads GPO settings from SYSVOL over SMB; needs the optional "
                "'smbprotocol' package and SYSVOL read access.",
                "A gpo-registry-pol control is satisfied by a value delivered "
                "either by the admin-template Registry.pol or by a Group Policy "
                "Preferences Registry.xml item - a registry value with no ADMX "
                "policy behind it can only come from a preference. There is no "
                "separate check_type for preferences: a control asserts a "
                "registry key, and how the value got there is evidence. Each "
                "found value records it in evidence.found[].delivery.",
                "delivery matters to an auditor. A preference TATTOOS: the value "
                "stays in the registry if its GPO is unlinked, where a policy "
                "value reverts, so a pass delivered by preference is a weaker "
                "statement about ongoing state. A preference item's action is "
                "also carried: 'C' (Create) writes only when the value is absent "
                "and so does not correct drift, while 'D' (Delete) removes the "
                "value and is never counted as configuring it. A 'D' scoped to "
                "the whole KEY (no value name) is disclosed in the finding's "
                "notes: it removes the key the value lives in, so if the control "
                "passes, another GPO is clearing the ground under it and which "
                "one lands depends on client-side extension ordering. Item-level "
                "targeting (<Filters>) is not resolved, but a filtered item says "
                "so in the evidence rather than implying domain-wide coverage.",
                "A policy value and a preference value disagreeing on the same "
                "key is reported as a 'policy-preference-disagreement' conflict: "
                "which one lands depends on client-side extension ordering, not "
                "on link precedence, and this scan resolves neither.",
                RSOP_NOTE,
                "Controls flagged needs_baseline_value are reported but not "
                "scored: their exact expected value is not stated by the source "
                "and is never guessed.",
                "evidence.source says what a verdict rests on. 'os-default' means "
                "no GPO sets the key and the control was judged against a "
                "Microsoft-documented Windows default — a pass there is not "
                "evidence that Group Policy enforces the value, and its "
                "rollout_state is capped at 'audit' because nothing enforces a "
                "default. counts.os_default reports how many findings are in that "
                "position; it is not a number to subtract from pass, because such a "
                "finding can also be fail, not_applicable or error — "
                "counts.os_default_pass is the subset that passed.",
                "Every count describes what was evaluated, not what was rendered. "
                "counts.rendered and counts.hidden reconcile the totals with the "
                "length of the findings list when include_not_applicable is false.",
                "evidence.source 'unknown' means the scan did not establish the "
                "setting's state — the control is not evaluated at all, GPOs could "
                "not be read, or the setting is one a GPO scan cannot see. Where "
                "any GPO is unreadable, a control with a documented OS default "
                "reports 'error' instead of judging the key unset: an unread GPO "
                "could set it, so the default cannot be assumed effective.",
                "result 'unknown' is a verdict-less verdict, distinct from "
                "'error': nothing went wrong, but the control's documented "
                "remediation writes the registry directly on the domain "
                "controllers (catalog field gpo_deliverable: false), so its key "
                "appearing in no GPO is not evidence that it is unset. Such a "
                "finding carries rollout_state null, evidence.source 'unknown' and "
                "a note with the exact 'reg query' command that reads the live "
                "value. It is never a pass and is never hidden. The field is "
                "narrow by design — for every other control a GPO is the normal "
                "delivery mechanism, so absence from GPO is strong evidence — and "
                "it changes only the absent case: such a control found in a GPO is "
                "scored on its value like any other.",
                "write_hardening_report renders this same scan as one "
                "self-contained HTML file (inline CSS, no external assets, no "
                "scripts) ordered by actionability: read failures and unknown "
                "verdicts first, passes last. The JSON is the source of truth; "
                "the document adds nothing to it. PDF is deliberately not "
                "produced — print the HTML from a browser if one is needed.",
                "write_hardening_scan writes the same JSON payload to a .json "
                "file so two runs can be compared later. A stored scan embeds "
                "this domain's GPO display names, registry values and DNs, "
                "exactly as the HTML report does; treat the file as directory "
                "content when sharing or committing it.",
                "write_hardening_snapshot runs the scan ONCE and writes both "
                "artifacts — scan.json and report.html — into one new folder "
                "named after the scan's own timestamp plus a scan_id prefix "
                "(no colon, so the name is legal on Windows). The other two "
                "write tools each run their own scan, so calling both would "
                "put two different scans in one folder; here both files render "
                "one payload and therefore carry the same scan_id, timestamp "
                "and findings. An existing snapshot folder is refused rather "
                "than overwritten or merged into. Both files embed this "
                "domain's GPO display names, registry values and DNs.",
                "diff_hardening_scans compares two stored scans and touches no "
                "directory. Either input may be a .json scan file or a "
                "snapshot folder, whose scan.json is then read. Its first key "
                "is 'attribution': 'domain' when both "
                "scans ran the same catalog_version AND engine_version, "
                "'ambiguous' otherwise. A cross-version difference may be the "
                "TOOL rather than the domain — this project has seen a control "
                "go fail -> pass purely because the scanner learned to read "
                "Group Policy Preferences, with the domain unchanged — so an "
                "ambiguous diff must never be reported as domain progress. "
                "Regressions are listed before improvements; a rollout moving "
                "enforced -> audit is a regression even when result stays "
                "'pass'; a control added to or removed from the catalog goes to "
                "catalog_changes and is never counted as either; and a control "
                "whose verdict held but whose evidence moved (a different "
                "value, GPO, delivery mechanism, evidence source, or a conflict "
                "appearing or clearing) goes to evidence_changes.",
            ],
            **catalog_info,
        }
