"""The hardening scan tools: read the domain's GPOs, evaluate the catalog.

This module is orchestration only — LDAP queries, SYSVOL reads over SMB, and
response shaping. The control definitions live in
:mod:`aditor.hardening.catalog`, the verdict logic in
:mod:`aditor.hardening.evaluator`, the HTML rendering in
:mod:`aditor.hardening.report`, and the parsing in :mod:`aditor.gpo.parsers`;
all four are pure and unit-tested offline.

Two tools, one scan:

* ``scan_hardening`` returns the structured JSON — the **source of truth**.
* ``write_hardening_report`` runs the same scan and writes it as one
  self-contained HTML file. It derives nothing of its own: the renderer consumes
  the identical payload, so the document and the JSON cannot disagree. Writing
  that file is the only side effect either tool has.

The scan is **read-only**: it enumerates ``groupPolicyContainer`` objects, reads
each one's SYSVOL folder, and compares what it finds against the catalog. It
changes nothing in the directory.

Every response carries a provenance header — scan engine version, catalog
version, timestamp, domain and base DN — because a report that cannot state
"against which baseline, when, which domain" is not audit-grade.
"""

from datetime import datetime, timezone
from uuid import uuid4
from typing import Any, Dict, List, Optional, Sequence

import ldap3

from ..core.logging import log_ldap_operation
from ..gpo.parsers import parse_gp_link, parse_security_template_registry_values
from ..hardening import SCAN_ENGINE_VERSION
from ..hardening.catalog import Catalog, CatalogError, load_catalog
from ..hardening.evaluator import (
    EVIDENCE_SOURCES,
    GpoLink,
    GpoSnapshot,
    evaluate_controls,
)
from ..hardening.report import (
    REPORT_FORMAT_VERSION,
    ReportPathError,
    headline_counts,
    write_report,
)
from .base import BaseTool
from .gpo import GPOTools

# The GptTmpl.inf section holding registry-backed security options.
_REGISTRY_VALUES_SECTION = "Registry Values"

# How this release resolves (or rather, does not resolve) policy precedence.
_RSOP_NOTE = (
    "Precedence is not resolved: this scan reports every GPO that sets a "
    "control's key, with its link path and enforced flag, and flags "
    "disagreements as conflicts. Where a finding carries a conflict, confirm the "
    "effective value with RSoP / gpresult before acting on it."
)


class _GpoReadFailure(Exception):
    """The LDAP enumeration or SYSVOL read failed outright.

    Raised inside :meth:`HardeningTools._scan` so both tools can turn the same
    failure into their own response shape — ``scan_hardening`` through the shared
    ``_handle_ldap_error`` path it has always used, ``write_hardening_report``
    into an error payload that writes no file. The alternative, returning a
    pre-formatted MCP response from the shared scan, would force the report tool
    to parse JSON back out of its own scan.
    """

    def __init__(self, cause: Exception) -> None:
        super().__init__(str(cause))
        self.cause = cause


class HardeningTools(BaseTool):
    """Read-only hardening scan over the domain's Group Policy content."""

    def __init__(self, ldap_manager: Any) -> None:
        super().__init__(ldap_manager)
        # GPO enumeration and the SYSVOL/SMB read are already solved in
        # GPOTools; reuse them rather than growing a second implementation.
        self.gpo = GPOTools(ldap_manager)

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
        except _GpoReadFailure as failure:
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
        except _GpoReadFailure as failure:
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

    # --- the shared scan ---------------------------------------------------- #

    def _scan(self, control_ids: Optional[Sequence[str]],
              include_not_applicable: bool,
              operation: str) -> Dict[str, Any]:
        """Run the scan and return the payload dict both tools render.

        Returns either the full scan payload or a ``success: False`` dict for a
        catalog, argument or missing-dependency failure. ``operation`` only names
        the caller in error messages, so a reader of a failed
        ``write_hardening_report`` is not told to fix ``scan_hardening``.

        Raises:
            _GpoReadFailure: the LDAP enumeration or SYSVOL read failed outright.
        """
        try:
            catalog = load_catalog()
        except CatalogError as exc:
            return {
                "success": False,
                "error": f"hardening control catalog failed to load: {exc}",
                "operation": operation,
            }

        controls, unknown_ids = catalog.select(control_ids)
        if not controls:
            return {
                "success": False,
                "error": ("no controls selected"
                          + (f"; unknown control_ids: {', '.join(unknown_ids)}"
                             if unknown_ids else "")),
                "known_control_ids": [c.id for c in catalog.controls],
                "operation": operation,
            }

        try:
            import smbclient  # noqa: F401  (from the smbprotocol package)
        except ImportError:
            return {
                "success": False,
                "error": f"{operation} reads GPO settings from SYSVOL, which "
                         f"requires the 'smbprotocol' package. Install it with: "
                         f"uv pip install smbprotocol",
                "operation": operation,
            }

        try:
            links_by_guid = self._links_by_gpo_guid()
            snapshots, read_errors = self._read_gpo_snapshots(links_by_guid)
        except Exception as exc:
            raise _GpoReadFailure(exc) from exc

        findings, counts = evaluate_controls(
            controls, snapshots, include_not_applicable=include_not_applicable)

        log_ldap_operation(operation, self.ldap.ad_config.base_dn, True,
                           f"Evaluated {counts['total']} controls against "
                           f"{len(snapshots)} GPOs")

        return {
            "scan": self._provenance(catalog, snapshots, read_errors,
                                     include_not_applicable),
            "counts": counts,
            "findings": findings,
            "unscored_control_ids": [c.id for c in controls if not c.scored],
            "unknown_control_ids": list(unknown_ids),
            "gpo_read_errors": read_errors,
        }

    # --- provenance --------------------------------------------------------

    def _provenance(self, catalog: Catalog, snapshots: Sequence[GpoSnapshot],
                    read_errors: Sequence[Dict[str, str]],
                    include_not_applicable: bool) -> Dict[str, Any]:
        """The audit header: what ran, against what baseline, when, and where."""
        config = self.ldap.ad_config
        provenance: Dict[str, Any] = {
            "tool": "scan_hardening",
            "tool_version": SCAN_ENGINE_VERSION,
            # Identity for this run. The timestamp orders scans; this names one,
            # so a diff (or a report quoted in a ticket) can refer to it
            # unambiguously even if two scans share a timestamp.
            "scan_id": uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": config.domain,
            "base_dn": config.base_dn,
            "gpos_scanned": len(snapshots),
            "gpos_unreadable": len(read_errors),
            "include_not_applicable": include_not_applicable,
            "read_only": True,
            "precedence": _RSOP_NOTE,
        }
        provenance.update(catalog.provenance())
        provenance["catalog_notes"] = list(catalog.notes)
        return provenance

    # --- GPO reads ---------------------------------------------------------

    def _links_by_gpo_guid(self) -> Dict[str, List[GpoLink]]:
        """Map each GPO GUID to the links that reference it, domain-wide.

        One subtree search for objects carrying ``gPLink`` (the domain root, OUs
        and, where in scope, sites), parsed with the same ``parse_gp_link`` that
        backs ``get_linked_gpos`` — one query instead of one per GPO.
        """
        links: Dict[str, List[GpoLink]] = {}
        results = self.ldap.search(
            search_base=self.ldap.ad_config.base_dn,
            search_filter="(gPLink=*)",
            attributes=["gPLink", "gPOptions", "distinguishedName"],
            search_scope=ldap3.SUBTREE,
        )
        for entry in results or []:
            attributes = entry.get("attributes", {}) or {}
            target_dn = entry.get("dn") or self._get_attr_value(
                attributes, "distinguishedName", "")
            try:
                block_inheritance = bool(
                    int(self._get_attr_value(attributes, "gPOptions", 0)) & 1)
            except (TypeError, ValueError):
                block_inheritance = False

            for link in parse_gp_link(self._get_attr_value(attributes, "gPLink", "")):
                guid = (link.get("guid") or "").strip("{}").lower()
                if not guid:
                    continue
                links.setdefault(guid, []).append(GpoLink(
                    target_dn=target_dn,
                    enforced=bool(link.get("enforced")),
                    link_enabled=bool(link.get("link_enabled")),
                    block_inheritance=block_inheritance,
                ))
        return links

    def _read_gpo_snapshots(self, links_by_guid: Dict[str, List[GpoLink]]
                            ) -> tuple:
        """Read and parse every GPO's policy content.

        A GPO whose SYSVOL folder cannot be read becomes a snapshot carrying a
        ``read_error`` rather than an empty one, so findings can distinguish "not
        configured" from "could not tell" — and the scan continues instead of
        failing wholesale on one unreadable GPO.

        Returns:
            ``(snapshots, read_errors)``.
        """
        results = self.ldap.search(
            search_base=f"CN=Policies,CN=System,{self.ldap.ad_config.base_dn}",
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["cn", "displayName", "gPCFileSysPath"],
            search_scope=ldap3.SUBTREE,
        )

        snapshots: List[GpoSnapshot] = []
        read_errors: List[Dict[str, str]] = []
        for entry in results or []:
            attributes = entry.get("attributes", {}) or {}
            cn = self._get_attr_value(attributes, "cn", "") or ""
            guid = cn.strip("{}") if isinstance(cn, str) else ""
            display_name = self._get_attr_value(attributes, "displayName", "") or ""
            sysvol_path = self._get_attr_value(attributes, "gPCFileSysPath", "") or ""
            links = tuple(links_by_guid.get(guid.lower(), ()))

            try:
                contents = self.gpo._read_gpo_sysvol(sysvol_path,
                                                     include_registry=True,
                                                     max_value_chars=6000)
            except Exception as exc:
                read_errors.append({"gpo_dn": entry.get("dn", ""),
                                    "display_name": display_name,
                                    "error": str(exc)})
                snapshots.append(GpoSnapshot(dn=entry.get("dn", ""),
                                             display_name=display_name,
                                             guid=guid, links=links,
                                             read_error=str(exc)))
                continue

            snapshots.append(GpoSnapshot(
                dn=entry.get("dn", ""),
                display_name=display_name,
                guid=guid,
                security_template_entries=_template_entries(contents),
                registry_pol_entries=_machine_pol_entries(contents),
                links=links,
            ))
        return snapshots, read_errors

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
            "operations": ["scan_hardening", "write_hardening_report"],
            # The scan itself changes nothing in the directory.
            # write_hardening_report's one side effect is the file it writes.
            "read_only": True,
            "writes_files": ["write_hardening_report"],
            "report_formats": ["html"],
            "report_format_version": REPORT_FORMAT_VERSION,
            "check_types": ["gpo-security-template", "gpo-registry-pol"],
            "results": ["pass", "fail", "not_applicable", "error"],
            "rollout_states": ["not_started", "audit", "enforced"],
            "evidence_sources": list(EVIDENCE_SOURCES),
            "notes": [
                "Reads GPO settings from SYSVOL over SMB; needs the optional "
                "'smbprotocol' package and SYSVOL read access.",
                _RSOP_NOTE,
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
                "'unknown' means the scan did not establish the setting's state — "
                "either the control is not evaluated at all, or GPOs could not be "
                "read. Where any GPO is unreadable, a control with a documented OS "
                "default reports 'error' instead of judging the key unset: an "
                "unread GPO could set it, so the default cannot be assumed "
                "effective.",
                "write_hardening_report renders this same scan as one "
                "self-contained HTML file (inline CSS, no external assets, no "
                "scripts) ordered by actionability: read failures and unknown "
                "verdicts first, passes last. The JSON is the source of truth; "
                "the document adds nothing to it. PDF is deliberately not "
                "produced — print the HTML from a browser if one is needed.",
            ],
            **catalog_info,
        }


# --------------------------------------------------------------------------- #
# Content extraction (module-level so it stays trivially testable)
# --------------------------------------------------------------------------- #

def _template_entries(contents: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Structured ``[Registry Values]`` entries from every GptTmpl.inf found."""
    entries: List[Dict[str, Any]] = []
    for template in contents.get("security_templates") or []:
        sections = template.get("sections") or {}
        entries.extend(parse_security_template_registry_values(
            sections.get(_REGISTRY_VALUES_SECTION)))
    return entries


def _machine_pol_entries(contents: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parsed machine ``Registry.pol`` entries (user-side policy is not scanned)."""
    pol = contents.get("machine_registry_pol")
    if not isinstance(pol, dict):
        return []
    return list(pol.get("entries") or [])
