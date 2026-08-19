"""The hardening scan tool: read the domain's GPOs, evaluate the catalog.

This module is orchestration only — LDAP queries, SYSVOL reads over SMB, and
response shaping. The control definitions live in
:mod:`aditor.hardening.catalog`, the verdict logic in
:mod:`aditor.hardening.evaluator`, and the parsing in
:mod:`aditor.gpo.parsers`; all three are pure and unit-tested offline.

The scan is **read-only**: it enumerates ``groupPolicyContainer`` objects, reads
each one's SYSVOL folder, and compares what it finds against the catalog. It
changes nothing.

Every response carries a provenance header — scan engine version, catalog
version, timestamp, domain and base DN — because a report that cannot state
"against which baseline, when, which domain" is not audit-grade.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import ldap3

from ..core.logging import log_ldap_operation
from ..gpo.parsers import parse_gp_link, parse_security_template_registry_values
from ..hardening import SCAN_ENGINE_VERSION
from ..hardening.catalog import Catalog, CatalogError, load_catalog
from ..hardening.evaluator import GpoLink, GpoSnapshot, evaluate_controls
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
            catalog = load_catalog()
        except CatalogError as exc:
            return self._format_response({
                "success": False,
                "error": f"hardening control catalog failed to load: {exc}",
                "operation": "scan_hardening",
            }, "scan_hardening")

        controls, unknown_ids = catalog.select(control_ids)
        if not controls:
            return self._format_response({
                "success": False,
                "error": ("no controls selected"
                          + (f"; unknown control_ids: {', '.join(unknown_ids)}"
                             if unknown_ids else "")),
                "known_control_ids": [c.id for c in catalog.controls],
                "operation": "scan_hardening",
            }, "scan_hardening")

        try:
            import smbclient  # noqa: F401  (from the smbprotocol package)
        except ImportError:
            return self._format_response({
                "success": False,
                "error": "scan_hardening reads GPO settings from SYSVOL, which "
                         "requires the 'smbprotocol' package. Install it with: "
                         "uv pip install smbprotocol",
                "operation": "scan_hardening",
            }, "scan_hardening")

        try:
            links_by_guid = self._links_by_gpo_guid()
            snapshots, read_errors = self._read_gpo_snapshots(links_by_guid)
        except Exception as exc:
            return self._handle_ldap_error(exc, "scan_hardening",
                                           self.ldap.ad_config.base_dn)

        findings, counts = evaluate_controls(
            controls, snapshots, include_not_applicable=include_not_applicable)

        log_ldap_operation("scan_hardening", self.ldap.ad_config.base_dn, True,
                           f"Evaluated {counts['total']} controls against "
                           f"{len(snapshots)} GPOs")

        return self._format_response({
            "scan": self._provenance(catalog, snapshots, read_errors,
                                     include_not_applicable),
            "counts": counts,
            "findings": findings,
            "unscored_control_ids": [c.id for c in controls if not c.scored],
            "unknown_control_ids": list(unknown_ids),
            "gpo_read_errors": read_errors,
        }, "scan_hardening")

    # --- provenance --------------------------------------------------------

    def _provenance(self, catalog: Catalog, snapshots: Sequence[GpoSnapshot],
                    read_errors: Sequence[Dict[str, str]],
                    include_not_applicable: bool) -> Dict[str, Any]:
        """The audit header: what ran, against what baseline, when, and where."""
        config = self.ldap.ad_config
        provenance: Dict[str, Any] = {
            "tool": "scan_hardening",
            "tool_version": SCAN_ENGINE_VERSION,
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
            "operations": ["scan_hardening"],
            "read_only": True,
            "check_types": ["gpo-security-template", "gpo-registry-pol"],
            "results": ["pass", "fail", "not_applicable", "error"],
            "rollout_states": ["not_started", "audit", "enforced"],
            "notes": [
                "Reads GPO settings from SYSVOL over SMB; needs the optional "
                "'smbprotocol' package and SYSVOL read access.",
                _RSOP_NOTE,
                "Controls flagged needs_baseline_value are reported but not "
                "scored: their exact expected value is not stated by the source "
                "and is never guessed.",
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
