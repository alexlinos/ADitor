"""Collect the scan: read the domain's GPOs and evaluate the catalog.

This is the one part of the hardening engine that touches a directory: LDAP
queries for the GPO containers and their links, and a SYSVOL read over SMB for
each GPO's policy files. Everything it hands on is plain data — the verdicts
come from :mod:`aditor.hardening.evaluator`, the parsing from
:mod:`aditor.gpo.parsers`, and writing the result is
:mod:`aditor.hardening.snapshot`'s job.

The scan is **read-only**: it enumerates ``groupPolicyContainer`` objects, reads
each one's SYSVOL folder, and compares what it finds against the catalog. It
changes nothing in the directory.

Every payload carries a provenance header — scan engine version, catalog
version, timestamp, domain and base DN — because a report that cannot state
"against which baseline, when, which domain" is not audit-grade.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from uuid import uuid4

import ldap3

from ..core.logging import log_ldap_operation
from ..gpo.parsers import (
    extract_applocker,
    parse_gp_link,
    parse_ini,
    parse_registry_pol,
    parse_registry_xml,
    parse_security_template_registry_values,
)
from . import SCAN_ENGINE_VERSION
from .catalog import Catalog, CatalogError, load_catalog
from .evaluator import GpoLink, GpoSnapshot, evaluate_controls

# The GptTmpl.inf section holding registry-backed security options.
_REGISTRY_VALUES_SECTION = "Registry Values"

# The Registry preferences file, per side. Group Policy Preferences deliver
# registry values that have no ADMX policy behind them, so a GPO's real
# hardening often lives here rather than in Registry.pol.
_REGISTRY_XML_FILES = (
    (r"machine\preferences\registry\registry.xml", "machine_registry_xml"),
    (r"user\preferences\registry\registry.xml", "user_registry_xml"),
)

# How this release resolves (or rather, does not resolve) policy precedence.
RSOP_NOTE = (
    "Precedence is not resolved: this scan reports every GPO that sets a "
    "control's key, with its link path and enforced flag, and flags "
    "disagreements as conflicts. Where a finding carries a conflict, confirm the "
    "effective value with RSoP / gpresult before acting on it."
)


class GpoReadFailure(Exception):
    """The LDAP enumeration or SYSVOL read failed outright.

    Raised by :meth:`Scanner.scan` so each caller can turn the same failure into
    its own response shape. ``cause`` is the original exception, whose message
    is the actual LDAP/SMB error — the thing an operator needs to see, because
    "invalid credentials", "certificate not trusted" and "host unreachable" have
    different fixes.
    """

    def __init__(self, cause: Exception) -> None:
        super().__init__(str(cause))
        self.cause = cause


def _attr(attributes: Dict[str, Any], name: str, default: Any = None) -> Any:
    """One LDAP attribute value: the first element if ldap3 returned a list."""
    value = attributes.get(name)
    if value is None:
        return default
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value


class Scanner:
    """Read-only hardening scan over the domain's Group Policy content."""

    def __init__(self, ldap_manager: Any) -> None:
        self.ldap = ldap_manager

    # --- the scan ----------------------------------------------------------

    def scan(self, control_ids: Optional[Sequence[str]] = None,
             include_not_applicable: bool = True,
             operation: str = "scan_hardening") -> Dict[str, Any]:
        """Run the scan and return the payload every writer renders.

        Returns either the full scan payload or a ``success: False`` dict for a
        catalog, argument or missing-dependency failure. ``operation`` only names
        the caller in error messages and the log.

        Raises:
            GpoReadFailure: the LDAP enumeration or SYSVOL read failed outright.
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
            raise GpoReadFailure(exc) from exc

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
            "precedence": RSOP_NOTE,
        }
        provenance.update(catalog.provenance())
        provenance["catalog_notes"] = list(catalog.notes)
        return provenance

    # --- GPO reads ---------------------------------------------------------

    def _links_by_gpo_guid(self) -> Dict[str, List[GpoLink]]:
        """Map each GPO GUID to the links that reference it, domain-wide.

        One subtree search for objects carrying ``gPLink`` (the domain root, OUs
        and, where in scope, sites), parsed with ``parse_gp_link`` — one query
        instead of one per GPO.
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
            target_dn = entry.get("dn") or _attr(attributes, "distinguishedName", "")
            try:
                block_inheritance = bool(int(_attr(attributes, "gPOptions", 0)) & 1)
            except (TypeError, ValueError):
                block_inheritance = False

            for link in parse_gp_link(_attr(attributes, "gPLink", "")):
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
                            ) -> Tuple[List[GpoSnapshot], List[Dict[str, str]]]:
        """Read and parse every GPO's policy content.

        A GPO whose SYSVOL folder cannot be read becomes a snapshot carrying a
        ``read_error`` rather than an empty one, so findings can distinguish "not
        configured" from "could not tell" — and the scan continues instead of
        failing wholesale on one unreadable GPO.
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
            cn = _attr(attributes, "cn", "") or ""
            guid = cn.strip("{}") if isinstance(cn, str) else ""
            display_name = _attr(attributes, "displayName", "") or ""
            sysvol_path = _attr(attributes, "gPCFileSysPath", "") or ""
            links = tuple(links_by_guid.get(guid.lower(), ()))

            try:
                contents = self._read_gpo_sysvol(sysvol_path,
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
                registry_xml_entries=_machine_preference_entries(contents),
                links=links,
            ))
        return snapshots, read_errors

    # --- SMB / SYSVOL ------------------------------------------------------

    def _smb_target(self, sysvol_path: str) -> Dict[str, str]:
        """Derive SMB (host, share, relative path) for a gPCFileSysPath.

        gPCFileSysPath is a domain DFS UNC such as
        ``\\\\domain\\SysVol\\domain\\Policies\\{GUID}``. We connect to the
        specific DC (from the LDAP server URL) to avoid DFS resolution, but
        reuse the share and path components from gPCFileSysPath.
        """
        host = urlparse(self.ldap.ad_config.server).hostname or self.ldap.ad_config.domain
        parts = [p for p in sysvol_path.replace('/', '\\').split('\\') if p]
        # parts: [<server-or-domain>, <share>, <relative...>]
        share = parts[1] if len(parts) > 1 else 'SYSVOL'
        relative = '\\'.join(parts[2:]) if len(parts) > 2 else ''
        return {"host": host, "share": share, "relative": relative,
                "unc": rf"\\{host}\{share}\{relative}"}

    def _read_gpo_sysvol(self, sysvol_path: str, include_registry: bool,
                         max_value_chars: int) -> Dict[str, Any]:
        """Read and parse the files under a GPO's SYSVOL folder."""
        import smbclient

        target = self._smb_target(sysvol_path)
        cfg = self.ldap.ad_config
        base = target["unc"]

        out: Dict[str, Any] = {
            "smb_source": base,
            "files": [],
            "gpt_ini": {},
            "machine_registry_pol": None,
            "user_registry_pol": None,
            "applocker": None,
            "security_templates": [],
            "scripts": [],
        }

        try:
            smbclient.register_session(target["host"], username=cfg.bind_dn,
                                       password=cfg.password)

            # Inventory every file in the GPO folder.
            file_index: Dict[str, str] = {}
            for dirpath, _dirs, filenames in smbclient.walk(base):
                for fname in filenames:
                    full = dirpath + "\\" + fname
                    rel = full[len(base):].lstrip("\\")
                    try:
                        size = smbclient.stat(full).st_size
                    except Exception:
                        size = None
                    out["files"].append({"path": rel, "size": size})
                    file_index[rel.lower()] = full

            def read_bytes(rel_lower: str) -> Optional[bytes]:
                full = file_index.get(rel_lower)
                if not full:
                    return None
                with smbclient.open_file(full, mode="rb") as fh:
                    return fh.read()

            # GPT.INI (version marker)
            gpt = read_bytes("gpt.ini")
            if gpt is not None:
                out["gpt_ini"] = parse_ini(gpt)

            # Registry.pol (machine + user)
            machine_entries: List[Dict[str, Any]] = []
            if include_registry:
                for side, key in (("machine\\registry.pol", "machine_registry_pol"),
                                  ("user\\registry.pol", "user_registry_pol")):
                    data = read_bytes(side)
                    if data is None:
                        continue
                    entries, truncated = parse_registry_pol(data, max_value_chars)
                    out[key] = {
                        "entry_count": len(entries),
                        "entries_truncated": truncated,
                        "entries": entries,
                    }
                    if side.startswith("machine"):
                        machine_entries = entries

                # Group Policy Preferences registry items. Deliberately only
                # added to the response when the file exists, so a GPO with no
                # preferences returns exactly the shape it returned before this
                # was read at all — the common case must not change.
                for rel, key in _REGISTRY_XML_FILES:
                    data = read_bytes(rel)
                    if data is None:
                        continue
                    preferences = parse_registry_xml(data)
                    out[key] = {
                        "entry_count": len(preferences),
                        "entries": preferences,
                    }

            # AppLocker rules (live inside the machine Registry.pol as SrpV2)
            applocker = extract_applocker(machine_entries)
            if applocker:
                out["applocker"] = applocker

            # Security templates (GptTmpl.inf), scripts.ini
            for rel_lower, full in file_index.items():
                if rel_lower.endswith("gpttmpl.inf"):
                    data = read_bytes(rel_lower)
                    if data is not None:
                        out["security_templates"].append({
                            "path": full[len(base):].lstrip("\\"),
                            "sections": parse_ini(data),
                        })
                elif rel_lower.endswith("scripts.ini") or rel_lower.endswith("psscripts.ini"):
                    data = read_bytes(rel_lower)
                    if data is not None:
                        out["scripts"].append({
                            "path": full[len(base):].lstrip("\\"),
                            "sections": parse_ini(data),
                        })
        finally:
            try:
                smbclient.reset_connection_cache()
            except Exception:
                pass

        return out


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


def _machine_preference_entries(contents: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parsed machine ``Registry.xml`` preference items.

    Machine side only, matching ``_machine_pol_entries``: every control in the
    catalog is a machine setting. The block is absent altogether for a GPO with
    no preferences, so ``.get`` is doing real work here.
    """
    preferences = contents.get("machine_registry_xml")
    if not isinstance(preferences, dict):
        return []
    return list(preferences.get("entries") or [])
