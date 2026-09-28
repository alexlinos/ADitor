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

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from uuid import uuid4

import ldap3
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

from ..core.logging import log_ldap_operation
from ..gpo.parsers import (
    parse_gp_link,
    parse_ini,
    parse_registry_pol,
    parse_registry_xml,
    parse_security_template_registry_values,
)
from . import SCAN_ENGINE_VERSION
from .catalog import (
    DIRECTORY_CHECK_NON_EMPTY_GROUPS,
    DIRECTORY_CHECK_SPN_WITHOUT_AES,
    DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION,
    WELL_KNOWN_GROUPS,
    Catalog,
    CatalogError,
    Control,
    load_catalog,
)
from .evaluator import GpoLink, GpoSnapshot, evaluate_controls

# The GptTmpl.inf section holding registry-backed security options.
_REGISTRY_VALUES_SECTION = "Registry Values"

_MACHINE_REGISTRY_POL = r"machine\registry.pol"

# userAccountControl and msDS-SupportedEncryptionTypes bits the directory
# checks read (Microsoft's documented values).
_UAC_ACCOUNTDISABLE = 0x2
_UAC_SERVER_TRUST_ACCOUNT = 0x2000  # a writable domain controller's account
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_ETYPE_RC4 = 0x4
_ETYPE_AES = 0x8 | 0x10  # AES128-CTS-HMAC-SHA1-96 | AES256-CTS-HMAC-SHA1-96
# LDAP_MATCHING_RULE_BIT_AND, for filtering on a userAccountControl bit.
_BIT_AND = "1.2.840.113556.1.4.803"
# Group Policy Preferences deliver registry values that have no ADMX policy
# behind them, so a GPO's real hardening often lives here rather than in
# Registry.pol.
_MACHINE_REGISTRY_XML = r"machine\preferences\registry\registry.xml"

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
        directory = self._read_directory_state(controls)

        findings, counts = evaluate_controls(
            controls, snapshots, include_not_applicable=include_not_applicable,
            directory=directory)

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
                contents = self._read_gpo_sysvol(sysvol_path)
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

    # --- directory state ---------------------------------------------------

    def _read_directory_state(self, controls: Sequence[Control]
                              ) -> Dict[str, Dict[str, Any]]:
        """Run the directory query each selected directory-state control names.

        Keyed by **control id**, not by query: two controls can name the same
        query with different targets, and each must be judged on its own
        result. A query that raises is recorded as that control's ``error``
        rather than failing the scan: the GPO findings are still sound, and
        the affected control reports an error, never a pass.
        """
        runners = {
            DIRECTORY_CHECK_SPN_WITHOUT_AES: self._spn_accounts_without_aes,
            DIRECTORY_CHECK_NON_EMPTY_GROUPS: self._non_empty_groups,
            DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION:
                self._unconstrained_delegation,
        }
        out: Dict[str, Dict[str, Any]] = {}
        for control in controls:
            if not (control.check_type == "directory-state" and control.scored
                    and control.directory_check in runners):
                continue
            try:
                out[control.id] = runners[control.directory_check](control)
            except Exception as exc:
                out[control.id] = {"objects": [], "notes": [],
                                   "error": str(exc)}
        return out

    def _search(self, search_filter: str, attributes: List[str],
                base: Optional[str] = None, scope: Any = ldap3.SUBTREE
                ) -> List[Dict[str, Any]]:
        return list(self.ldap.search(
            search_base=base or self.ldap.ad_config.base_dn,
            search_filter=search_filter,
            attributes=attributes,
            search_scope=scope,
        ) or [])

    def _spn_accounts_without_aes(self, _control: Control) -> Dict[str, Any]:
        """Enabled service accounts with an SPN whose encryption types lack AES.

        User accounts and managed service accounts (sMSA, gMSA). Computer
        accounts are skipped (Windows maintains theirs) and so is krbtgt. A
        blank ``msDS-SupportedEncryptionTypes`` counts as no AES: the account
        then gets whatever the domain default is, which depends on the domain
        controllers' patch level.
        """
        entries = self._search(
            "(&(|(objectCategory=person)"
            "(objectCategory=msDS-GroupManagedServiceAccount)"
            "(objectCategory=msDS-ManagedServiceAccount))"
            "(servicePrincipalName=*)(!(sAMAccountName=krbtgt))"
            f"(!(userAccountControl:{_BIT_AND}:={_UAC_ACCOUNTDISABLE})))",
            ["sAMAccountName", "msDS-SupportedEncryptionTypes", "objectClass"])
        objects = []
        for entry in entries:
            try:
                attributes = entry.get("attributes", {}) or {}
                raw = _attr(attributes, "msDS-SupportedEncryptionTypes")
                blank = raw in (None, "", [])
                etypes = 0 if blank else _as_int(raw)
                if etypes & _ETYPE_AES:
                    continue
                if blank:
                    detail = ("not set: uses the domain default, which is RC4 "
                              "on domain controllers without the 2026 Kerberos "
                              "updates")
                elif etypes & _ETYPE_RC4:
                    detail = (f"set to {etypes} (0x{etypes & 0xFFFFFFFF:X}): "
                              f"RC4 and no AES")
                else:
                    detail = (f"set to {etypes} (0x{etypes & 0xFFFFFFFF:X}): "
                              f"no AES")
                objects.append(_object(entry, attributes, _account_kind(
                    attributes), detail))
            except Exception as exc:
                objects.append(_unreadable(entry, exc))
        return {"objects": _sorted(objects), "notes": [], "error": None}

    def _domain_sid(self) -> str:
        """The domain's SID, read from the domain object itself."""
        entries = self._search("(objectClass=*)", ["objectSid"],
                               scope=ldap3.BASE)
        sid = _sid_text(_attr((entries[0].get("attributes") or {})
                              if entries else {}, "objectSid"))
        if not sid:
            raise RuntimeError("could not read the domain's SID, so the "
                               "domain groups could not be looked up")
        return sid

    def _non_empty_groups(self, control: Control) -> Dict[str, Any]:
        """The control's target groups that have any member.

        Each group is found by its well-known SID, not its name (names are
        localized and can be renamed). Members are the group's ``member``
        values **plus** every account whose ``primaryGroupID`` is the group,
        because AD leaves an account out of its primary group's ``member``.
        A group that should always exist but isn't found is an error, not an
        empty group: the bind account may simply not be able to see it.
        """
        objects, notes, missing = [], [], []
        domain_sid = None
        for name in control.directory_targets:
            scope, ident, always_exists = WELL_KNOWN_GROUPS[name]
            if scope == "domain":
                domain_sid = domain_sid or self._domain_sid()
                sid, rid = f"{domain_sid}-{ident}", ident
            else:
                sid, rid = ident, None
            entries = self._search(
                f"(&(objectClass=group)(objectSid={escape_filter_chars(sid)}))",
                ["sAMAccountName", "member"])
            if not entries:
                if always_exists:
                    missing.append(f"{name} ({sid})")
                else:
                    notes.append(f"{name} ({sid}) was not found. That is "
                                 f"normal for this group in some domains "
                                 f"(it exists only in the forest root, or "
                                 f"only with a newer schema or role).")
                continue
            entry = entries[0]
            try:
                attributes = entry.get("attributes", {}) or {}
                members = [_text(m) for m in _as_list(attributes.get("member"))]
                if rid is not None:
                    members += [str(e.get("dn") or "") for e in self._search(
                        f"(primaryGroupID={rid})", ["sAMAccountName"])]
                members = sorted({m for m in members if m}, key=str.lower)
                if not members:
                    continue
                shown = ", ".join(_rdn(m) for m in members[:5])
                more = (f" and {len(members) - 5} more"
                        if len(members) > 5 else "")
                local = _text(_attr(attributes, "sAMAccountName")) or name
                label = name if local == name else f"{name} ({local})"
                objects.append({
                    "value": label, "dn": _text(entry.get("dn")),
                    "object_class": "group",
                    "detail": f"{len(members)} member(s): {shown}{more}",
                    "members": members,
                })
            except Exception as exc:
                objects.append(_unreadable(entry, exc, name))
        if missing:
            raise RuntimeError(
                "these groups should exist in every domain but were not found, "
                "so their members could not be checked (the bind account may "
                f"not be able to read them): {', '.join(missing)}")
        return {"objects": _sorted(objects), "notes": notes, "error": None}

    def _unconstrained_delegation(self, _control: Control) -> Dict[str, Any]:
        """Accounts, other than writable domain controllers, trusted for
        delegation to any service. Disabled accounts are listed and marked:
        re-enabling one brings the exposure back.

        Writable DCs are recognised by their account type (a computer with
        SERVER_TRUST_ACCOUNT), not by ``primaryGroupID``, which can be set on
        any account. Read-only DCs don't carry this flag by design, so an RODC
        that has it is listed.
        """
        entries = self._search(
            f"(&(userAccountControl:{_BIT_AND}:={_UAC_TRUSTED_FOR_DELEGATION})"
            f"(!(&(objectCategory=computer)"
            f"(userAccountControl:{_BIT_AND}:={_UAC_SERVER_TRUST_ACCOUNT}))))",
            ["sAMAccountName", "objectClass", "userAccountControl"])
        objects = []
        for entry in entries:
            try:
                attributes = entry.get("attributes", {}) or {}
                kind = _account_kind(attributes)
                disabled = _as_int(_attr(attributes, "userAccountControl")) \
                    & _UAC_ACCOUNTDISABLE
                detail = f"{kind} trusted for delegation to any service"
                if disabled:
                    detail += " (disabled; re-enabling it restores this)"
                objects.append(_object(entry, attributes, kind, detail))
            except Exception as exc:
                objects.append(_unreadable(entry, exc))
        return {"objects": _sorted(objects), "notes": [], "error": None}

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

    def _read_gpo_sysvol(self, sysvol_path: str) -> Dict[str, Any]:
        """Read and parse the policy files the scan evaluates from one GPO.

        Machine side only — every control in the catalog is a machine setting:
        ``Registry.pol``, the Preferences ``Registry.xml`` (whose block is
        present only when the file exists) and every ``GptTmpl.inf``.
        """
        import smbclient

        target = self._smb_target(sysvol_path)
        cfg = self.ldap.ad_config
        base = target["unc"]
        out: Dict[str, Any] = {"machine_registry_pol": None,
                               "security_templates": []}

        try:
            smbclient.register_session(target["host"], username=cfg.bind_dn,
                                       password=cfg.password)

            # Relative path (lower-cased, as SYSVOL is case-insensitive) -> UNC.
            files: Dict[str, str] = {}
            for dirpath, _dirs, filenames in smbclient.walk(base):
                for fname in filenames:
                    full = dirpath + "\\" + fname
                    files[full[len(base):].lstrip("\\").lower()] = full

            def read(full: str) -> bytes:
                with smbclient.open_file(full, mode="rb") as fh:
                    return fh.read()

            if _MACHINE_REGISTRY_POL in files:
                entries, _truncated = parse_registry_pol(
                    read(files[_MACHINE_REGISTRY_POL]))
                out["machine_registry_pol"] = {"entries": entries}
            if _MACHINE_REGISTRY_XML in files:
                out["machine_registry_xml"] = {
                    "entries": parse_registry_xml(read(files[_MACHINE_REGISTRY_XML]))}
            out["security_templates"] = [
                {"sections": parse_ini(read(full))}
                for rel, full in files.items() if rel.endswith("gpttmpl.inf")]
        finally:
            try:
                smbclient.reset_connection_cache()
            except Exception:
                pass

        return out


# --------------------------------------------------------------------------- #
# Content extraction (module-level so it stays trivially testable)
# --------------------------------------------------------------------------- #

def _text(value: Any) -> str:
    """A directory value as plain text: bytes decoded, lists reduced, never
    ``None`` — so a finding always serialises and always renders."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _as_int(value: Any) -> int:
    """An integer attribute, 0 when it isn't one. ``0x..`` strings parse."""
    value = value[0] if isinstance(value, (list, tuple)) and value else value
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return 0


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _account_kind(attributes: Dict[str, Any]) -> str:
    classes = {_text(c).lower() for c in _as_list(attributes.get("objectClass"))}
    if classes & {"msds-groupmanagedserviceaccount",
                  "msds-managedserviceaccount"}:
        return "managed service account"
    if "computer" in classes:
        return "computer"
    return "user"


def _object(entry: Dict[str, Any], attributes: Dict[str, Any], kind: str,
            detail: str) -> Dict[str, Any]:
    return {"value": _text(_attr(attributes, "sAMAccountName")),
            "dn": _text(entry.get("dn")), "object_class": kind,
            "detail": detail}


def _unreadable(entry: Any, exc: Exception, name: str = "") -> Dict[str, Any]:
    """A matching entry whose attributes couldn't be read.

    Listed, never skipped: the query matched it, so skipping it could turn a
    fail into a pass.
    """
    dn = _text(entry.get("dn")) if isinstance(entry, dict) else ""
    return {"value": name or _rdn(dn) or "(unreadable entry)", "dn": dn,
            "object_class": "unknown",
            "detail": f"listed because its attributes couldn't be read: {exc}"}


def _sid_text(value: Any) -> str:
    """A SID as ``S-1-5-21-...``, from ldap3's formatted string or raw bytes."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)) and len(value) >= 8:
        revision, count = value[0], value[1]
        authority = int.from_bytes(value[2:8], "big")
        subs = [int.from_bytes(value[8 + 4 * i:12 + 4 * i], "little")
                for i in range(count)]
        return "-".join(["S", str(revision), str(authority)] + [str(x) for x in subs])
    return ""


def _sorted(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Directory objects in a stable order, so two scans list them alike."""
    return sorted(objects, key=lambda o: (str(o.get("value")).lower(),
                                          str(o.get("dn")).lower()))


def _rdn(dn: Any) -> str:
    """``CN=Doe\\, Jane,OU=...`` -> ``Doe, Jane``: a member's name, for display."""
    text = _text(dn)
    try:
        value = parse_dn(text)[0][1]
    except Exception:
        value = text.split(",", 1)[0].split("=", 1)[-1]
    return re.sub(r"\\([0-9A-Fa-f]{2}|.)",
                  lambda m: (chr(int(m.group(1), 16)) if len(m.group(1)) == 2
                             else m.group(1)), value)


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
