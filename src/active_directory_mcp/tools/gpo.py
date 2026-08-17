"""Group Policy Object (GPO) tools for Active Directory.

Read-only tooling over the Group Policy container. Everything here queries
LDAP metadata only (the ``groupPolicyContainer`` objects under
``CN=Policies,CN=System,<base_dn>`` and the ``gPLink`` attribute on linkable
objects). The actual policy *settings* live in SYSVOL and are not read here.
"""

from typing import List, Dict, Any, Optional
import base64

import ldap3

from .base import BaseTool
from ..core.logging import log_ldap_operation


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
            guid = self._normalize_guid(identifier)
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

            links = self._parse_gp_link(gp_link)
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
            'version': self._decode_version(self._get_attr_value(attrs, 'versionNumber', 0)),
            'status': self._decode_gpo_status(self._get_attr_value(attrs, 'flags', 0)),
            'functionality_version': self._get_attr_value(attrs, 'gPCFunctionalityVersion', 0),
            'has_computer_settings': bool(machine_ext),
            'has_user_settings': bool(user_ext),
            'wmi_filter': self._get_attr_value(attrs, 'gPCWQLFilter', ''),
            'when_created': self._get_attr_value(attrs, 'whenCreated'),
            'when_changed': self._get_attr_value(attrs, 'whenChanged'),
            'object_guid': object_guid
        }

    def _decode_version(self, version: Any) -> Dict[str, Any]:
        """Split the packed versionNumber into user/computer revisions."""
        try:
            v = int(version)
        except (TypeError, ValueError):
            v = 0
        return {
            'raw': v,
            'computer_version': (v >> 16) & 0xFFFF,
            'user_version': v & 0xFFFF
        }

    def _decode_gpo_status(self, flags: Any) -> Dict[str, Any]:
        """Decode the GPO ``flags`` attribute into enabled/disabled halves."""
        try:
            f = int(flags)
        except (TypeError, ValueError):
            f = 0
        descriptions = {
            0: "All settings enabled",
            1: "User settings disabled",
            2: "Computer settings disabled",
            3: "All settings disabled"
        }
        return {
            'raw': f,
            'computer_settings_enabled': not bool(f & 2),
            'user_settings_enabled': not bool(f & 1),
            'description': descriptions.get(f & 3, "Unknown")
        }

    def _normalize_guid(self, value: str) -> Optional[str]:
        """Return the bare GUID if ``value`` looks like one, else None."""
        if not isinstance(value, str):
            return None
        candidate = value.strip().strip('{}')
        parts = candidate.split('-')
        if len(parts) == 5 and all(c in '0123456789abcdefABCDEF-' for c in candidate):
            return candidate
        return None

    def _parse_gp_link(self, gp_link: str) -> List[Dict[str, Any]]:
        """Parse a gPLink attribute into ordered link descriptors.

        gPLink format: ``[LDAP://cn={GUID},cn=policies,cn=system,DC=..;<opt>]``
        repeated per link, listed in reverse precedence order. The per-link
        option is a bitmask: bit 0 = link disabled, bit 1 = enforced.
        """
        links: List[Dict[str, Any]] = []
        if not gp_link:
            return links
        try:
            for part in gp_link.split('['):
                part = part.strip()
                if not part or ';' not in part:
                    continue
                path, options = part.rstrip(']').rsplit(';', 1)
                try:
                    opt = int(options)
                except ValueError:
                    opt = 0

                guid = ''
                if '{' in path and '}' in path:
                    guid = path[path.find('{') + 1:path.find('}')]

                links.append({
                    'guid': guid,
                    'path': path,
                    'link_enabled': not bool(opt & 1),
                    'enforced': bool(opt & 2)
                })
        except Exception:
            return links
        return links

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
            "operations": ["get_gpos", "get_gpo", "get_linked_gpos"],
            "read_only": True,
            "policies_container": self._policies_dn(),
            "gpo_attributes": [
                "cn", "displayName", "gPCFileSysPath", "versionNumber",
                "flags", "gPCFunctionalityVersion", "gPCMachineExtensionNames",
                "gPCUserExtensionNames", "gPCWQLFilter"
            ],
            "notes": [
                "Reads LDAP metadata only; policy settings live in SYSVOL and "
                "are not parsed.",
                "flags: 0=all enabled, 1=user disabled, 2=computer disabled, "
                "3=all disabled.",
                "gPLink option bitmask: bit 0=link disabled, bit 1=enforced."
            ]
        }
