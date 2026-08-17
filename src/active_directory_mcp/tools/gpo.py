"""Group Policy Object (GPO) tools for Active Directory.

Read-only tooling over the Group Policy container.

The enumeration tools (``get_gpos``/``get_gpo``/``get_linked_gpos``) query
LDAP metadata only — the ``groupPolicyContainer`` objects under
``CN=Policies,CN=System,<base_dn>`` and the ``gPLink`` attribute on linkable
objects. ``get_gpo_contents`` additionally reads the GPO's files from SYSVOL
over SMB and parses the common policy formats (Registry.pol, GptTmpl.inf,
scripts.ini, AppLocker rules). SMB support requires the optional
``smbprotocol`` dependency.
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import struct
import base64

import ldap3

from .base import BaseTool
from ..core.logging import log_ldap_operation

# Windows registry value types found in Registry.pol (PReg) records.
_REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

# AppLocker per-collection EnforcementMode DWORD values (registry form).
_APPLOCKER_ENFORCEMENT = {0: "AuditOnly", 1: "Enabled"}


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

    def get_gpo_contents(self, identifier: str, include_registry: bool = True,
                         max_value_chars: int = 6000) -> List[Dict[str, Any]]:
        """
        Read a GPO's actual settings from its SYSVOL folder (read-only).

        Resolves the GPO, then reads and parses the policy files under its
        ``gPCFileSysPath``: GPT.INI, Machine/User ``Registry.pol`` (admin
        template + AppLocker settings), ``GptTmpl.inf`` security templates,
        and script registrations. Requires the optional ``smbprotocol``
        dependency and SYSVOL read access for the bind account.

        Args:
            identifier: GPO GUID (with or without braces) or exact display name.
            include_registry: Parse Registry.pol files (default True).
            max_value_chars: Truncate individual registry/rule values longer
                than this (default 6000).

        Returns:
            List of MCP content objects with the parsed GPO contents.
        """
        try:
            # Resolve the GPO via LDAP to get its GUID, name, and SYSVOL path.
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
            result.update(contents)

            log_ldap_operation("get_gpo_contents", results[0]['dn'], True,
                               f"Read SYSVOL contents for GPO {identifier}")

            return self._format_response(result, "get_gpo_contents")

        except Exception as e:
            return self._handle_ldap_error(e, "get_gpo_contents", identifier)

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
                out["gpt_ini"] = self._parse_ini(gpt)

            # Registry.pol (machine + user)
            machine_entries: List[Dict[str, Any]] = []
            if include_registry:
                for side, key in (("machine\\registry.pol", "machine_registry_pol"),
                                  ("user\\registry.pol", "user_registry_pol")):
                    data = read_bytes(side)
                    if data is None:
                        continue
                    entries, truncated = self._parse_registry_pol(data, max_value_chars)
                    out[key] = {
                        "entry_count": len(entries),
                        "entries_truncated": truncated,
                        "entries": entries,
                    }
                    if side.startswith("machine"):
                        machine_entries = entries

            # AppLocker rules (live inside the machine Registry.pol as SrpV2)
            applocker = self._extract_applocker(machine_entries)
            if applocker:
                out["applocker"] = applocker

            # Security templates (GptTmpl.inf), scripts.ini
            for rel_lower, full in file_index.items():
                if rel_lower.endswith("gpttmpl.inf"):
                    data = read_bytes(rel_lower)
                    if data is not None:
                        out["security_templates"].append({
                            "path": full[len(base):].lstrip("\\"),
                            "sections": self._parse_ini(data),
                        })
                elif rel_lower.endswith("scripts.ini") or rel_lower.endswith("psscripts.ini"):
                    data = read_bytes(rel_lower)
                    if data is not None:
                        out["scripts"].append({
                            "path": full[len(base):].lstrip("\\"),
                            "sections": self._parse_ini(data),
                        })
        finally:
            try:
                smbclient.reset_connection_cache()
            except Exception:
                pass

        return out

    def _parse_registry_pol(self, data: bytes, max_value_chars: int):
        """Parse a Registry.pol (PReg) blob into a list of registry entries.

        Format: 4-byte 'PReg' signature, 4-byte version, then repeated
        ``[key;value;type;size;data]`` records with UTF-16LE, null-terminated
        strings and little-endian integers.
        """
        entries: List[Dict[str, Any]] = []
        truncated = False
        if data[:4] != b"PReg":
            return entries, truncated

        i, n = 8, len(data)
        while i < n - 1:
            if data[i:i + 2] != b"[\x00":
                i += 2
                continue
            i += 2
            try:
                def read_str():
                    nonlocal i
                    start = i
                    while i < n and data[i:i + 2] != b";\x00":
                        i += 2
                    s = data[start:i].decode("utf-16-le", errors="replace").rstrip("\x00")
                    i += 2
                    return s

                key = read_str()
                value = read_str()
                rtype = struct.unpack("<I", data[i:i + 4])[0]; i += 4
                i += 2  # ';'
                size = struct.unpack("<I", data[i:i + 4])[0]; i += 4
                i += 2  # ';'
                raw = data[i:i + size]; i += size
                if data[i:i + 2] == b"]\x00":
                    i += 2
            except (struct.error, IndexError):
                break

            if rtype in (1, 2):
                val = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            elif rtype == 4 and len(raw) == 4:
                val = struct.unpack("<I", raw)[0]
            elif rtype == 5 and len(raw) == 4:
                val = struct.unpack(">I", raw)[0]
            elif rtype == 11 and len(raw) == 8:
                val = struct.unpack("<Q", raw)[0]
            elif rtype == 7:
                val = [s for s in raw.decode("utf-16-le", errors="replace").split("\x00") if s]
            else:
                val = base64.b64encode(raw).decode("ascii") if raw else ""

            if isinstance(val, str) and len(val) > max_value_chars:
                val = val[:max_value_chars] + "...[truncated]"
                truncated = True

            entries.append({
                "key": key,
                "value": value,
                "type": _REG_TYPES.get(rtype, rtype),
                "data": val,
            })
        return entries, truncated

    def _extract_applocker(self, machine_entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Pull AppLocker rules/enforcement out of parsed machine registry entries."""
        collections: Dict[str, Dict[str, Any]] = {}
        for e in machine_entries:
            key = e.get("key", "")
            if "SrpV2" not in key:
                continue
            after = key.split("SrpV2", 1)[1].strip("\\")
            parts = after.split("\\") if after else []
            collection = parts[0] if parts else "Unknown"
            col = collections.setdefault(collection, {"enforcement_mode": None, "rules": []})

            if e.get("value") == "EnforcementMode":
                col["enforcement_mode"] = _APPLOCKER_ENFORCEMENT.get(e.get("data"), e.get("data"))
            elif e.get("value") == "Value" and len(parts) >= 2:
                col["rules"].append({"id": parts[1], "xml": e.get("data")})

        if not collections:
            return None
        for name, col in collections.items():
            col["rule_count"] = len(col["rules"])
        return {"collections": collections}

    def _parse_ini(self, data: bytes) -> Dict[str, Any]:
        """Parse an INF/INI blob (UTF-16 or UTF-8) into {section: [lines]}."""
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", errors="replace")
        else:
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = data.decode("latin-1", errors="replace")

        sections: Dict[str, Any] = {}
        current = "_root"
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                sections.setdefault(current, [])
            else:
                sections.setdefault(current, []).append(line)
        return sections

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
                "Registry.pol (PReg), GptTmpl.inf, scripts.ini, and AppLocker "
                "rules; requires the optional 'smbprotocol' package plus SYSVOL "
                "read access.",
                "flags: 0=all enabled, 1=user disabled, 2=computer disabled, "
                "3=all disabled.",
                "gPLink option bitmask: bit 0=link disabled, bit 1=enforced."
            ]
        }
