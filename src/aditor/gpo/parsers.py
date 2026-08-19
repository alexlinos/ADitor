"""Pure parsers for Group Policy data.

Every function here is a pure function of its arguments: no ``self``, no LDAP,
no SMB, no configuration, no I/O. That is what makes them testable offline
against synthesized fixtures (``tests/test_gpo_parsers.py``) instead of only
against a live domain controller.

Covered formats:

- ``Registry.pol`` — the PReg binary admin-template format (``parse_registry_pol``)
- ``GptTmpl.inf`` / ``scripts.ini`` — INF/INI text, UTF-16 or UTF-8 (``parse_ini``)
- the ``[Registry Values]`` section of a ``GptTmpl.inf`` security template, whose
  raw lines ``parse_ini`` hands back verbatim
  (``parse_security_template_registry_values``, ``normalize_registry_key``)
- AppLocker ``SrpV2`` policy, which lives inside the machine ``Registry.pol``
  as per-rule XML blobs (``extract_applocker``, ``applocker_rule_digest``)
- the packed ``versionNumber`` and ``flags`` attributes (``decode_version``,
  ``decode_gpo_status``)
- the ``gPLink`` attribute found on OUs, domains and sites (``parse_gp_link``)
"""

import base64
import struct
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree

# Windows registry value types found in Registry.pol (PReg) records.
REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

# Registry hive prefixes, mapped onto one canonical spelling per hive. GPO
# security templates write ``MACHINE\...``; Registry.pol, the Microsoft docs and
# our control catalog write ``HKLM\...``. Both must compare equal.
_HIVE_ALIASES = {
    "MACHINE": "HKLM",
    "HKLM": "HKLM",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "USER": "HKCU",
    "HKCU": "HKCU",
    "HKEY_CURRENT_USER": "HKCU",
    "USERS": "HKU",
    "HKU": "HKU",
    "HKEY_USERS": "HKU",
    "CLASSES_ROOT": "HKCR",
    "HKCR": "HKCR",
    "HKEY_CLASSES_ROOT": "HKCR",
}

# AppLocker per-collection EnforcementMode DWORD values (registry form).
APPLOCKER_ENFORCEMENT = {0: "AuditOnly", 1: "Enabled"}

# Keys kept from a parsed Registry.pol block when summarizing.
_REGISTRY_SUMMARY_KEYS = ("entry_count", "entries_truncated")

# Rule-XML attributes that make up a summary digest, in output order.
_DIGEST_ATTRS = (("id", "id"), ("name", "name"), ("action", "action"),
                 ("sid", "userorgroupsid"))


def parse_registry_pol(data: bytes, max_value_chars: int = 6000
                       ) -> Tuple[List[Dict[str, Any]], bool]:
    """Parse a Registry.pol (PReg) blob into a list of registry entries.

    Format: 4-byte ``PReg`` signature, 4-byte version, then repeated
    ``[key;value;type;size;data]`` records with UTF-16LE, null-terminated
    strings and little-endian integers.

    Args:
        data: Raw file bytes.
        max_value_chars: Truncate individual string values longer than this.

    Returns:
        ``(entries, truncated)`` — the decoded entries and whether any value
        was truncated. A blob without the ``PReg`` signature, or one that runs
        out mid-record, yields the entries decoded so far rather than raising.
    """
    entries: List[Dict[str, Any]] = []
    truncated = False
    if not data or data[:4] != b"PReg":
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
            rtype = struct.unpack("<I", data[i:i + 4])[0]
            i += 4 + 2  # DWORD + ';'
            size = struct.unpack("<I", data[i:i + 4])[0]
            i += 4 + 2  # DWORD + ';'
            raw = data[i:i + size]
            i += size
            if data[i:i + 2] == b"]\x00":
                i += 2
        except (struct.error, IndexError):
            break

        if rtype in (1, 2):
            val: Any = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
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
            "type": REG_TYPES.get(rtype, rtype),
            "data": val,
        })
    return entries, truncated


def parse_ini(data: bytes) -> Dict[str, Any]:
    """Parse an INF/INI blob (UTF-16 or UTF-8) into ``{section: [lines]}``.

    Lines before the first ``[section]`` header are grouped under ``_root``.
    """
    if not data:
        return {}
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


def normalize_registry_key(key: Any, default_hive: Optional[str] = None) -> str:
    """Canonicalise a registry path so two spellings of it compare equal.

    Needed because the same setting is written differently depending on where it
    is read from. A GPO security template writes::

        MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity

    while Microsoft's documentation and our control catalog write::

        HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity

    Same key, three differences: the hive alias, the case, and (sometimes) stray
    or doubled separators. Normalisation maps the hive onto its canonical short
    name (``MACHINE`` -> ``HKLM``), collapses separators, and upper-cases the
    result. Registry paths are case-insensitive on Windows, so the upper-cased
    form is a **comparison key only** — never display it back to a user; show
    the ``key`` the parser found instead.

    Args:
        key: The path to normalise, in any of the spellings above.
        default_hive: Hive to assume when the path names none. ``Registry.pol``
            keys are stored *without* a hive (the machine file is implicitly
            ``HKLM``, the user file ``HKCU``), so a caller comparing those
            against a catalog key passes the hive the file implies.

    Returns:
        The normalised path, or ``''`` for empty/non-string input.
    """
    if not isinstance(key, str):
        return ""
    parts = [p for p in key.replace("/", "\\").split("\\") if p.strip()]
    if not parts:
        return ""
    hive = _HIVE_ALIASES.get(parts[0].strip().upper())
    if hive:
        parts[0] = hive
    elif default_hive:
        parts.insert(0, default_hive)
    return "\\".join(p.strip() for p in parts).upper()


def parse_security_template_registry_values(
    lines: Any,
) -> List[Dict[str, Any]]:
    """Parse a ``GptTmpl.inf`` ``[Registry Values]`` section into entries.

    ``parse_ini`` returns that section as raw strings, e.g.::

        MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2

    The line shape is ``<key>=<type-code>,<data>`` where the type code is the
    numeric Windows registry type (``4`` = ``REG_DWORD``) and everything after
    the **first** comma is the data — the split is on the first comma only,
    because string data may itself contain commas, and ``REG_MULTI_SZ`` data is
    a comma-separated list.

    Data decoding follows the type code: integer types (``REG_DWORD``,
    ``REG_DWORD_BIG_ENDIAN``, ``REG_QWORD``) become ``int`` (``0x``-prefixed
    hex accepted); ``REG_SZ``/``REG_EXPAND_SZ`` are unquoted strings;
    ``REG_MULTI_SZ`` becomes a list of strings; anything else is left as the raw
    string. Data that does not fit its declared type (``...=4,abc``) is kept as
    the raw string rather than discarded — the evaluator reports the mismatch as
    evidence instead of the parser silently dropping a configured setting.

    Malformed input is **skipped, never raised on**: lines with no ``=``, an
    empty key, a non-numeric type code, or no ``,`` separating type from data,
    plus section headers, ``;``/``#`` comments and non-string items.

    Args:
        lines: The section's lines, as returned by ``parse_ini`` (any iterable
            of strings; ``None`` and non-strings are tolerated).

    Returns:
        A list of ``{key, type, type_name, value}`` dicts, in file order.
        ``type`` is the numeric code, ``type_name`` its symbolic name (or
        ``UNKNOWN_<n>`` for a code Windows does not define).
    """
    entries: List[Dict[str, Any]] = []
    if not lines or isinstance(lines, (str, bytes)):
        return entries

    for line in lines:
        if not isinstance(line, str):
            continue
        line = line.strip()
        if not line or line.startswith((";", "#")) or line.startswith("["):
            continue
        if "=" not in line:
            continue

        key, _, remainder = line.partition("=")
        key = key.strip()
        if not key:
            continue

        # TYPE,DATA — first comma only; string data can contain commas.
        type_text, comma, data = remainder.partition(",")
        if not comma:
            continue
        try:
            type_code = int(type_text.strip())
        except ValueError:
            continue

        entries.append({
            "key": key,
            "type": type_code,
            "type_name": REG_TYPES.get(type_code, f"UNKNOWN_{type_code}"),
            "value": _decode_template_value(type_code, data.strip()),
        })
    return entries


def _decode_template_value(type_code: int, data: str) -> Any:
    """Decode one ``[Registry Values]`` data field according to its type code.

    Blank data yields ``None`` for integer types (nothing was configured) and
    ``''`` for string types (an explicitly empty string).
    """
    if type_code in (4, 5, 11):
        if not data:
            return None
        try:
            return int(data, 16) if data.lower().startswith("0x") else int(data)
        except ValueError:
            return data
    if type_code == 7:
        return [item for item in (_unquote(part) for part in data.split(",")) if item]
    if type_code in (1, 2):
        return _unquote(data)
    return data


def _unquote(text: str) -> str:
    """Strip one layer of matching double quotes and surrounding whitespace."""
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def extract_applocker(machine_entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Pull AppLocker rules/enforcement out of parsed machine registry entries.

    AppLocker policy is stored under ``...\\SrpV2\\<Collection>\\<RuleId>``
    with the rule XML in the ``Value`` entry and the collection's
    ``EnforcementMode`` alongside it.

    Returns:
        ``{"collections": {name: {enforcement_mode, rules, rule_count}}}`` or
        ``None`` when the entries contain no AppLocker policy at all.
    """
    collections: Dict[str, Dict[str, Any]] = {}
    for e in machine_entries or []:
        key = e.get("key", "") or ""
        if "SrpV2" not in key:
            continue
        after = key.split("SrpV2", 1)[1].strip("\\")
        parts = after.split("\\") if after else []
        collection = parts[0] if parts else "Unknown"
        col = collections.setdefault(collection, {"enforcement_mode": None, "rules": []})

        if e.get("value") == "EnforcementMode":
            col["enforcement_mode"] = APPLOCKER_ENFORCEMENT.get(e.get("data"), e.get("data"))
        elif e.get("value") == "Value" and len(parts) >= 2:
            col["rules"].append({"id": parts[1], "xml": e.get("data")})

    if not collections:
        return None
    for col in collections.values():
        col["rule_count"] = len(col["rules"])
    return {"collections": collections}


def applocker_rule_digest(rule_xml: Any, fallback_id: str = "") -> Dict[str, str]:
    """Reduce one AppLocker rule's XML to ``{type, id, name, action, sid}``.

    The rule element is parsed as real XML, so attribute *order* is irrelevant
    (it varies between rules and between rule kinds — ``FilePublisherRule``,
    ``FilePathRule``, ``FileHashRule``, ...). Attribute names are matched
    case-insensitively and XML namespaces are stripped.

    Unparseable or truncated XML yields the same five keys with empty strings
    (``id`` falling back to ``fallback_id``, the registry-derived rule GUID)
    rather than raising.
    """
    digest = {"type": "", "id": fallback_id or "", "name": "", "action": "", "sid": ""}
    if not isinstance(rule_xml, str) or not rule_xml.strip():
        return digest

    try:
        element = ElementTree.fromstring(rule_xml)
    except ElementTree.ParseError:
        return digest

    digest["type"] = _local_name(element.tag)
    attributes = {_local_name(name).lower(): value
                  for name, value in element.attrib.items()}
    for field, attr_name in _DIGEST_ATTRS:
        value = attributes.get(attr_name)
        if value:
            digest[field] = value
    return digest


def summarize_applocker(applocker: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Replace every AppLocker rule's full XML with a digest.

    ``enforcement_mode`` and ``rule_count`` are preserved verbatim.
    """
    if not applocker:
        return applocker
    collections = applocker.get("collections") or {}
    summarized: Dict[str, Any] = {}
    for name, col in collections.items():
        rules = col.get("rules") or []
        summarized[name] = {
            "enforcement_mode": col.get("enforcement_mode"),
            "rule_count": col.get("rule_count", len(rules)),
            "rules": [applocker_rule_digest(rule.get("xml"), rule.get("id", ""))
                      for rule in rules],
        }
    return {"collections": summarized}


def summarize_gpo_contents(contents: Dict[str, Any]) -> Dict[str, Any]:
    """Drop the heavy bodies from parsed GPO contents (``summary=True`` mode).

    Kept: identity, ``files[]``, ``gpt_ini``, each Registry.pol's
    ``entry_count``/``entries_truncated``, and AppLocker
    ``enforcement_mode``/``rule_count``. Registry ``entries[]`` are omitted,
    AppLocker rule XML becomes a digest, and security template / script
    sections are reduced to their section names.

    The input dict is not mutated.
    """
    out: Dict[str, Any] = dict(contents)

    for key in ("machine_registry_pol", "user_registry_pol"):
        pol = contents.get(key)
        if isinstance(pol, dict):
            out[key] = {name: pol[name] for name in _REGISTRY_SUMMARY_KEYS if name in pol}

    if contents.get("applocker"):
        out["applocker"] = summarize_applocker(contents["applocker"])

    for key in ("security_templates", "scripts"):
        items = contents.get(key)
        if isinstance(items, list):
            out[key] = [
                {"path": item.get("path"), "sections": list(item.get("sections") or {})}
                for item in items
            ]

    return out


def decode_version(version: Any) -> Dict[str, Any]:
    """Split the packed ``versionNumber`` into user/computer revisions.

    AD packs this as ``versionNumber = user * 65536 + computer``, i.e. the
    computer revision is the low word and the user revision is the high word.
    """
    try:
        v = int(version)
    except (TypeError, ValueError):
        v = 0
    return {
        'raw': v,
        'computer_version': v & 0xFFFF,
        'user_version': (v >> 16) & 0xFFFF,
    }


def decode_gpo_status(flags: Any) -> Dict[str, Any]:
    """Decode the GPO ``flags`` attribute into enabled/disabled halves."""
    try:
        f = int(flags)
    except (TypeError, ValueError):
        f = 0
    descriptions = {
        0: "All settings enabled",
        1: "User settings disabled",
        2: "Computer settings disabled",
        3: "All settings disabled",
    }
    return {
        'raw': f,
        'computer_settings_enabled': not bool(f & 2),
        'user_settings_enabled': not bool(f & 1),
        'description': descriptions.get(f & 3, "Unknown"),
    }


def parse_gp_link(gp_link: Any) -> List[Dict[str, Any]]:
    """Parse a ``gPLink`` attribute into ordered link descriptors.

    gPLink format: ``[LDAP://cn={GUID},cn=policies,cn=system,DC=..;<opt>]``
    repeated per link, listed in reverse precedence order. The per-link option
    is a **bitmask**: bit 0 (=1) means the link is disabled, bit 1 (=2) means
    the link is enforced. ``options == 0`` therefore means "enabled, not
    enforced" — and ``options == 2`` means "enabled *and* enforced", not
    "disabled".

    This is the single implementation in the codebase; ldap3 hands back
    ``gPLink`` as a plain ``str``, so callers must read it with
    ``_get_attr_value`` and pass the string itself (never ``value[0]``, which
    is the character ``'['``).

    Returns:
        A list of ``{guid, path, link_enabled, enforced}`` dicts — empty for
        empty/None/non-string input or unparseable content.
    """
    links: List[Dict[str, Any]] = []
    if not gp_link or not isinstance(gp_link, str):
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
                'enforced': bool(opt & 2),
            })
    except Exception:
        return links
    return links


def normalize_guid(value: Any) -> Optional[str]:
    """Return the bare GUID if ``value`` looks like one, else ``None``."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().strip('{}')
    parts = candidate.split('-')
    if len(parts) == 5 and all(c in '0123456789abcdefABCDEF-' for c in candidate):
        return candidate
    return None


def _local_name(tag: Any) -> str:
    """Strip any ``{namespace}`` prefix from an XML tag or attribute name."""
    if not isinstance(tag, str):
        return ''
    return tag.rsplit('}', 1)[-1]
