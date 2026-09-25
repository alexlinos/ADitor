"""Group Policy Object (GPO) tools for Active Directory.

Read-only tooling over the Group Policy container.

The enumeration tools (``get_gpos``/``get_gpo``/``get_linked_gpos``) query
LDAP metadata only — the ``groupPolicyContainer`` objects under
``CN=Policies,CN=System,<base_dn>`` and the ``gPLink`` attribute on linkable
objects. ``get_gpo_contents`` additionally reads the GPO's files from SYSVOL
over SMB and parses the common policy formats (Registry.pol, Group Policy
Preferences ``Registry.xml``, GptTmpl.inf, scripts.ini, AppLocker rules). SMB
support requires the optional ``smbprotocol`` dependency.

This module is orchestration only: LDAP queries, SMB reads, and response
shaping. All parsing/decoding lives in :mod:`aditor.gpo.parsers` as pure,
offline-testable functions.
"""

from typing import List, Dict, Any, Optional
import base64

import ldap3

from .base import BaseTool
from ..core.logging import log_ldap_operation
from ..hardening.collect import Scanner
from ..gpo.parsers import (
    decode_gpo_status,
    decode_version,
    normalize_guid,
    parse_gp_link,
    summarize_gpo_contents,
)

class GPOTools(BaseTool):
    """Read-only tools for inspecting Active Directory Group Policy Objects."""

    def _policies_dn(self) -> str:
        """DN of the Group Policy container for the configured domain."""
        return f"CN=Policies,CN=System,{self.ldap.ad_config.base_dn}"

    def get_gpos(self, name_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all Group Policy Objects in the domain.

        Args:
            name_filter: Optional case-insensitive substring to match against
                the GPO display name (e.g. "password" or "firewall").

        Returns:
            List of MCP content objects with GPO metadata.
        """
        try:
            search_filter = "(objectClass=groupPolicyContainer)"
            if name_filter:
                escaped = self._escape_ldap_filter(name_filter)
                search_filter = (
                    f"(&(objectClass=groupPolicyContainer)"
                    f"(displayName=*{escaped}*))"
                )

            results = self.ldap.search(
                search_base=self._policies_dn(),
                search_filter=search_filter,
                attributes=[
                    'cn', 'displayName', 'gPCFileSysPath', 'versionNumber',
                    'flags', 'gPCFunctionalityVersion', 'gPCMachineExtensionNames',
                    'gPCUserExtensionNames', 'gPCWQLFilter', 'whenCreated',
                    'whenChanged', 'objectGUID'
                ],
                search_scope=ldap3.SUBTREE
            )

            gpos = [self._format_gpo(entry) for entry in results]
            gpos.sort(key=lambda g: (g.get('display_name') or '').lower())

            log_ldap_operation("get_gpos", self._policies_dn(), True, f"Found {len(gpos)} GPOs")

            return self._format_response({
                "gpos": gpos,
                "count": len(gpos),
                "policies_container": self._policies_dn()
            }, "get_gpos")

        except Exception as e:
            return self._handle_ldap_error(e, "get_gpos", self._policies_dn())

    def get_gpo(self, identifier: str) -> List[Dict[str, Any]]:
        """
        Get detailed information about a single GPO.

        Args:
            identifier: The GPO GUID (with or without braces) or its exact
                display name.

        Returns:
            List of MCP content objects with the GPO's metadata.
        """
        try:
            guid = normalize_guid(identifier)
            if guid is not None:
                search_filter = f"(&(objectClass=groupPolicyContainer)(cn={{{self._escape_ldap_filter(guid)}}}))"
            else:
                search_filter = (
                    f"(&(objectClass=groupPolicyContainer)"
                    f"(displayName={self._escape_ldap_filter(identifier)}))"
                )

            results = self.ldap.search(
                search_base=self._policies_dn(),
                search_filter=search_filter,
                attributes=[
                    'cn', 'displayName', 'gPCFileSysPath', 'versionNumber',
                    'flags', 'gPCFunctionalityVersion', 'gPCMachineExtensionNames',
                    'gPCUserExtensionNames', 'gPCWQLFilter', 'whenCreated',
                    'whenChanged', 'objectGUID'
                ],
                search_scope=ldap3.SUBTREE
            )

            if not results:
                return self._format_response({
                    "success": False,
                    "error": f"GPO '{identifier}' not found",
                    "identifier": identifier
                }, "get_gpo")

            gpo = self._format_gpo(results[0])
            gpo['linked_to'] = self._find_links(gpo['guid'])

            log_ldap_operation("get_gpo", results[0]['dn'], True, f"Retrieved GPO {identifier}")

            return self._format_response(gpo, "get_gpo")

        except Exception as e:
            return self._handle_ldap_error(e, "get_gpo", identifier)

    def get_linked_gpos(self, target_dn: str) -> List[Dict[str, Any]]:
        """
        Get the GPOs linked to a specific OU, domain, or site.

        Reads the ``gPLink`` attribute on the target object, resolves each
        linked GPO GUID to its display name, and reports link enforcement and
        inheritance-blocking status.

        Args:
            target_dn: Distinguished name of the OU/domain/site to inspect.

        Returns:
            List of MCP content objects with the resolved links.
        """
        try:
            results = self.ldap.search(
                search_base=target_dn,
                search_filter="(objectClass=*)",
                attributes=['gPLink', 'gPOptions', 'name'],
                search_scope=ldap3.BASE
            )

            if not results:
                return self._format_response({
                    "success": False,
                    "error": f"Object '{target_dn}' not found",
                    "target_dn": target_dn
                }, "get_linked_gpos")

            attrs = results[0]['attributes']
            gp_link = self._get_attr_value(attrs, 'gPLink', '')
            gp_options = self._get_attr_value(attrs, 'gPOptions', 0)

            links = parse_gp_link(gp_link)
            for link in links:
                link['display_name'] = self._resolve_gpo_name(link['guid'])

            try:
                block_inheritance = bool(int(gp_options) & 1)
            except (TypeError, ValueError):
                block_inheritance = False

            log_ldap_operation("get_linked_gpos", target_dn, True, f"Found {len(links)} linked GPOs")

            return self._format_response({
                "target_dn": target_dn,
                "block_inheritance": block_inheritance,
                "linked_gpos": links,
                "count": len(links)
            }, "get_linked_gpos")

        except Exception as e:
            return self._handle_ldap_error(e, "get_linked_gpos", target_dn)

    def get_gpo_contents(self, identifier: str, include_registry: bool = True,
                         max_value_chars: int = 6000,
                         summary: bool = False) -> List[Dict[str, Any]]:
        """
        Read a GPO's actual settings from its SYSVOL folder (read-only).

        Resolves the GPO, then reads and parses the policy files under its
        ``gPCFileSysPath``: GPT.INI, Machine/User ``Registry.pol`` (admin
        template + AppLocker settings), Machine/User
        ``Preferences\\Registry\\Registry.xml`` (Group Policy Preferences
        registry items), ``GptTmpl.inf`` security templates, and script
        registrations. Requires the optional ``smbprotocol`` dependency and
        SYSVOL read access for the bind account.

        ``machine_registry_xml`` / ``user_registry_xml`` appear **only when the
        GPO actually has a preferences file**. A GPO with no Registry
        preferences returns exactly what it returned before this file was read,
        which keeps the common case byte-identical; a GPO that has one gains a
        block shaped like the ``Registry.pol`` ones
        (``{entry_count, entries}``). There is no ``entries_truncated`` because
        nothing in a Registry.xml is truncated — a preference item's value is a
        single registry value, where one ``Registry.pol`` value can be an
        AppLocker rule set of tens of KB.

        Args:
            identifier: GPO GUID (with or without braces) or exact display name.
            include_registry: Parse Registry.pol files (default True).
            max_value_chars: Truncate individual registry/rule values longer
                than this (default 6000).
            summary: Return the same top-level shape with the heavy bodies
                dropped (default False). Registry ``entries[]`` are omitted
                (their ``entry_count``/``entries_truncated`` are kept, and a
                Registry.xml block keeps its ``entry_count``), each
                AppLocker rule's full XML becomes a
                ``{type, id, name, action, sid}`` digest, and security
                template / script sections are reduced to section names. The
                response gains ``"detail": "summary"``. Rules-heavy GPOs (e.g.
                72 AppLocker rules) otherwise run to tens of KB.

        Returns:
            List of MCP content objects with the parsed GPO contents.
        """
        try:
            # Resolve the GPO via LDAP to get its GUID, name, and SYSVOL path.
            guid = normalize_guid(identifier)
            if guid is not None:
                search_filter = f"(&(objectClass=groupPolicyContainer)(cn={{{self._escape_ldap_filter(guid)}}}))"
            else:
                search_filter = (
                    f"(&(objectClass=groupPolicyContainer)"
                    f"(displayName={self._escape_ldap_filter(identifier)}))"
                )
            results = self.ldap.search(
                search_base=self._policies_dn(),
                search_filter=search_filter,
                attributes=['cn', 'displayName', 'gPCFileSysPath', 'versionNumber'],
                search_scope=ldap3.SUBTREE
            )
            if not results:
                return self._format_response({
                    "success": False,
                    "error": f"GPO '{identifier}' not found",
                    "identifier": identifier
                }, "get_gpo_contents")

            attrs = results[0]['attributes']
            cn = self._get_attr_value(attrs, 'cn', '')
            resolved_guid = cn.strip('{}') if isinstance(cn, str) else ''
            display_name = self._get_attr_value(attrs, 'displayName', '')
            sysvol_path = self._get_attr_value(attrs, 'gPCFileSysPath', '')

            try:
                import smbclient  # noqa: F401  (from the smbprotocol package)
            except ImportError:
                return self._format_response({
                    "success": False,
                    "error": "SMB support requires the 'smbprotocol' package. "
                             "Install it with: uv pip install smbprotocol",
                    "identifier": identifier
                }, "get_gpo_contents")

            contents = self._read_gpo_sysvol(
                sysvol_path, include_registry, max_value_chars
            )

            result = {
                "identifier": identifier,
                "guid": resolved_guid,
                "display_name": display_name,
                "sysvol_path": sysvol_path,
            }
            result.update(summarize_gpo_contents(contents) if summary else contents)
            if summary:
                result["detail"] = "summary"
                result["note"] = (
                    "Heavy bodies omitted: registry entries, full AppLocker rule "
                    "XML, and template/script section bodies. Call again with "
                    "summary=false for the complete contents."
                )

            log_ldap_operation("get_gpo_contents", results[0]['dn'], True,
                               f"Read SYSVOL contents for GPO {identifier}")

            return self._format_response(result, "get_gpo_contents")

        except Exception as e:
            return self._handle_ldap_error(e, "get_gpo_contents", identifier)

    # --- SMB / SYSVOL ------------------------------------------------------

    def _read_gpo_sysvol(self, sysvol_path: str, include_registry: bool,
                         max_value_chars: int) -> Dict[str, Any]:
        """Read and parse the files under a GPO's SYSVOL folder.

        The reader lives in :mod:`aditor.hardening.collect`, where the scan
        uses it; this tool shares it rather than keeping a second copy.
        """
        return Scanner(self.ldap)._read_gpo_sysvol(
            sysvol_path, include_registry, max_value_chars)

    # --- helpers -----------------------------------------------------------

    def _format_gpo(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Shape a raw groupPolicyContainer entry into a response dict."""
        attrs = entry['attributes']
        cn = self._get_attr_value(attrs, 'cn', '')
        guid = cn.strip('{}') if isinstance(cn, str) else ''

        object_guid = self._get_attr_value(attrs, 'objectGUID', b'')
        if isinstance(object_guid, bytes):
            object_guid = base64.b64encode(object_guid).decode('utf-8')

        machine_ext = self._get_attr_value(attrs, 'gPCMachineExtensionNames', '')
        user_ext = self._get_attr_value(attrs, 'gPCUserExtensionNames', '')

        return {
            'dn': entry['dn'],
            'guid': guid,
            'display_name': self._get_attr_value(attrs, 'displayName', ''),
            'sysvol_path': self._get_attr_value(attrs, 'gPCFileSysPath', ''),
            'version': decode_version(self._get_attr_value(attrs, 'versionNumber', 0)),
            'status': decode_gpo_status(self._get_attr_value(attrs, 'flags', 0)),
            'functionality_version': self._get_attr_value(attrs, 'gPCFunctionalityVersion', 0),
            'has_computer_settings': bool(machine_ext),
            'has_user_settings': bool(user_ext),
            'wmi_filter': self._get_attr_value(attrs, 'gPCWQLFilter', ''),
            'when_created': self._get_attr_value(attrs, 'whenCreated'),
            'when_changed': self._get_attr_value(attrs, 'whenChanged'),
            'object_guid': object_guid
        }

    def _resolve_gpo_name(self, guid: str) -> str:
        """Look up a GPO's display name by GUID; '' if unresolvable."""
        if not guid:
            return ''
        try:
            results = self.ldap.search(
                search_base=f"CN={{{guid}}},{self._policies_dn()}",
                search_filter="(objectClass=groupPolicyContainer)",
                attributes=['displayName'],
                search_scope=ldap3.BASE
            )
            if results:
                return self._get_attr_value(results[0]['attributes'], 'displayName', '')
        except Exception:
            pass
        return ''

    def _find_links(self, guid: str) -> List[str]:
        """Find OU/domain DNs whose gPLink references this GPO GUID."""
        if not guid:
            return []
        try:
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(gPLink=*{{{self._escape_ldap_filter(guid)}}}*)",
                attributes=['distinguishedName'],
                search_scope=ldap3.SUBTREE
            )
            return [entry['dn'] for entry in results]
        except Exception:
            return []

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for GPO operations."""
        return {
            "operations": ["get_gpos", "get_gpo", "get_linked_gpos", "get_gpo_contents"],
            "read_only": True,
            "policies_container": self._policies_dn(),
            "gpo_attributes": [
                "cn", "displayName", "gPCFileSysPath", "versionNumber",
                "flags", "gPCFunctionalityVersion", "gPCMachineExtensionNames",
                "gPCUserExtensionNames", "gPCWQLFilter"
            ],
            "notes": [
                "get_gpos/get_gpo/get_linked_gpos read LDAP metadata only.",
                "get_gpo_contents additionally reads SYSVOL over SMB and parses "
                "Registry.pol (PReg), Preferences\\Registry\\Registry.xml "
                "(Group Policy Preferences registry items), GptTmpl.inf, "
                "scripts.ini, and AppLocker rules; requires the optional "
                "'smbprotocol' package plus SYSVOL read access.",
                "machine_registry_xml / user_registry_xml carry Group Policy "
                "Preferences registry items and are present only when the GPO has "
                "a Preferences\\Registry\\Registry.xml at all. A preference "
                "item's action is C(reate)/R(eplace)/U(pdate)/D(elete): a Delete "
                "item removes the value rather than setting it, and Create writes "
                "only when the value is absent, so it does not correct drift. "
                "DWORD/QWORD values in that file are stored as hexadecimal "
                "strings (value=\"00000038\" is 56).",
                "get_gpo_contents(summary=True) keeps the same shape but drops "
                "registry entries, digests AppLocker rule XML, and reduces "
                "template/script sections to section names.",
                "flags: 0=all enabled, 1=user disabled, 2=computer disabled, "
                "3=all disabled.",
                "gPLink option bitmask: bit 0=link disabled, bit 1=enforced."
            ]
        }
