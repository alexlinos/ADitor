"""Pure parsers for Group Policy data.

Every function here is a pure function of its arguments: no ``self``, no LDAP,
no SMB, no configuration, no I/O. That is what makes them testable offline
against synthesized fixtures (``tests/test_gpo_parsers.py``) instead of only
against a live domain controller.

Covered formats:

- ``Registry.pol`` — the PReg binary admin-template format (``parse_registry_pol``)
- ``Preferences\\Registry\\Registry.xml`` — Group Policy *Preferences* registry
  items, the only way a GPO can deliver a registry value that has no ADMX policy
  behind it (``parse_registry_xml``)
- ``GptTmpl.inf`` / ``scripts.ini`` — INF/INI text, UTF-16 or UTF-8 (``parse_ini``)
- the ``[Registry Values]`` section of a ``GptTmpl.inf`` security template, whose
  raw lines ``parse_ini`` hands back verbatim
  (``parse_security_template_registry_values``, ``normalize_registry_key``)
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

# Registry value type *names*, as a Group Policy Preferences Registry.xml writes
# them, mapped back onto the numeric Windows type code every other parser here
# reports. Registry.xml is the only format that names the type instead of
# numbering it, so this is the one place the mapping has to run backwards.
_REG_TYPE_CODES = {name: code for code, name in REG_TYPES.items()}

# Group Policy Preferences item actions, as written in the ``action`` attribute.
# The distinction is load-bearing rather than cosmetic:
#
# * ``C`` (Create) writes the value **only if it does not already exist**, so it
#   does not correct a value that has drifted below the intended one.
# * ``R`` (Replace) deletes and rewrites; ``U`` (Update) writes the value
#   whether or not it exists. Both correct drift on every policy refresh.
# * ``D`` (Delete) **removes** the value. A Delete item must never be read as
#   configuring the value it names.
REGISTRY_XML_ACTIONS = {"C": "Create", "R": "Replace", "U": "Update",
                        "D": "Delete"}

# MS-GPPREF makes ``action`` optional and defaults it to Update, so an item that
# omits the attribute is an Update — not an unknown.
REGISTRY_XML_DEFAULT_ACTION = "U"

# Actions that write the value they name (i.e. everything but Delete).
REGISTRY_XML_WRITE_ACTIONS = frozenset({"C", "R", "U"})

# Actions that overwrite an existing value, and so correct drift. Create does
# not: it writes only when the value is absent.
REGISTRY_XML_DRIFT_CORRECTING_ACTIONS = frozenset({"R", "U"})

# Type codes whose Registry.xml ``value`` attribute is a **hexadecimal** string.
# This is the single most dangerous detail in the format: ``value="00000038"``
# on a REG_DWORD is 0x38 = 56, and reading it as decimal 38 (= 0x26) inverts the
# operator's intent — 0x38 disables RC4 and DES for Kerberos, 0x26 re-enables
# both. See ``_decode_preference_value``.
_HEX_VALUE_TYPES = frozenset({4, 5, 11})  # REG_DWORD, _BIG_ENDIAN, REG_QWORD

# Attribute values that mean "true" in a Registry.xml boolean attribute.
_XML_TRUE = frozenset({"1", "true", "yes"})

# Keys kept from a parsed Registry.pol block when summarizing.
_REGISTRY_SUMMARY_KEYS = ("entry_count", "entries_truncated")

# Keys kept from a parsed Registry.xml block when summarizing. There is no
# ``entries_truncated`` because ``parse_registry_xml`` truncates nothing: a
# preference item's value is one registry value, where a single Registry.pol
# value can be an AppLocker rule set of tens of KB.
_REGISTRY_XML_SUMMARY_KEYS = ("entry_count",)

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


def parse_registry_xml(data: Any) -> List[Dict[str, Any]]:
    """Parse a Group Policy Preferences ``Registry.xml`` into registry entries.

    **Why this format matters.** ``Registry.pol`` can only carry values that an
    ADMX template defines. An arbitrary registry value — ``Kdc``'s
    ``DefaultDomainSupportedEncTypes``, ``WinHttpAutoProxySvc``'s ``Start``,
    ``Wintrust``'s ``EnableCertPaddingCheck`` — has no ADMX policy behind it, so
    a GPO delivers it as a Registry **preference** item under
    ``{Machine,User}\\Preferences\\Registry\\Registry.xml``. A scanner that reads
    only ``Registry.pol`` and ``GptTmpl.inf`` therefore cannot see a large part
    of the hardening an operator has actually done, and reports it as missing.

    File shape::

        <RegistrySettings>
          <Registry name="..." disabled="0">
            <Properties action="U" displayDecimal="0" default="0"
                        hive="HKEY_LOCAL_MACHINE"
                        key="SYSTEM\\CurrentControlSet\\Services\\Kdc"
                        name="DefaultDomainSupportedEncTypes"
                        type="REG_DWORD" value="00000038"/>
          </Registry>
          <Collection name="...">          <!-- nests, arbitrarily deep -->
            <Registry>...</Registry>
          </Collection>
        </RegistrySettings>

    **``value`` is hexadecimal for the integer types.** ``value="00000038"`` on a
    ``REG_DWORD`` means ``0x38`` — **56** decimal, not 38. Reading it as decimal
    is not a cosmetic error: for ``DefaultDomainSupportedEncTypes``, ``0x38``
    (AES128 + AES256 + the future flag) *disables* RC4 and DES, while 38 decimal
    is ``0x26``, which *enables* both. The wrong parse turns a hardened domain
    into a report that says RC4 is on — and a correctly-hardened one into a
    ``fail``. ``displayDecimal`` is a **GPMC display hint only** and is
    deliberately ignored: it changes how the console shows the number, never how
    the file stores it.

    Other real-world shapes handled:

    * ``action`` is ``C``reate / ``R``eplace / ``U``pdate / ``D``elete, and is
      optional (absent means ``U``, per MS-GPPREF). Delete items are returned —
      they are part of the truth about the GPO — but a caller must not treat
      one as configuring the value it names; see
      :data:`REGISTRY_XML_WRITE_ACTIONS`.
    * **Bare items** carry a ``key`` with no ``name`` and no ``type``, so they
      concern the key rather than a value in it, and the ``action`` decides what
      they mean. A bare **create/update/replace** is the key-creation item GPMC
      writes per key when a preference builds a key tree: it configures no value
      and is **skipped**, rather than emitted as a value with empty data. A bare
      **delete** (``action="D"``) removes the whole key and everything in it —
      including a hardened value some other GPO sets there — so it is
      **emitted**, with ``value_name`` ``None`` and ``deletes_key`` ``True``.
      Dropping those hid a GPO clearing the key under a value the scan then
      reported as configured (P2-WP5); the evaluator discloses them.
    * ``<Collection>`` groups nest ``<Registry>`` items arbitrarily deep, so the
      whole tree is walked; entries come back in document order.
    * ``REG_SZ``/``REG_EXPAND_SZ`` values stay literal — ``value="1"`` is the
      string ``"1"``, not the number 1 — because that is what the GPO writes and
      the difference belongs in the evidence.
    * ``REG_MULTI_SZ`` items keep their values in ``<Values><Value>`` children;
      those are collected into a list. ``REG_BINARY`` stays the literal hex
      string it is in the file: it is not an integer and must not be decoded as
      one.
    * ``<Filters>`` with any child means the item carries **item-level
      targeting**, so it may not apply everywhere the GPO is linked. Resolving
      the filters is out of scope; ``has_filters`` records that they exist so a
      caller can say so rather than implying the item applies domain-wide.
    * ``disabled="1"`` on the item means the preference is switched off in GPMC
      and writes nothing.
    * The hive is spelled in full (``HKEY_LOCAL_MACHINE``);
      :func:`normalize_registry_key` already folds that onto ``HKLM``.

    Args:
        data: Raw file bytes (or text). ``None``/empty yields ``[]``.

    Returns:
        One dict per value-configuring item **plus one per key-scoped delete**,
        in document order:

        * ``hive`` / ``key`` / ``value_name`` — exactly as written in the file.
          Join them (and normalise) to get the full path; nothing here is
          upper-cased, because these fields are what a report shows a reader.
          ``value_name`` is ``None`` on a key-scoped delete, which names no
          value.
        * ``type`` — the numeric Windows type code, or ``None`` for a type name
          Windows does not define (or an item with no ``type`` at all).
        * ``type_name`` — the type as the file names it, or ``None``.
        * ``value`` — decoded per the rules above.
        * ``action`` — one of ``C``/``R``/``U``/``D`` (upper-cased; an
          unrecognised action is passed through verbatim rather than guessed at).
        * ``order`` — 1-based position in the file, so two items that set the
          same value can be told apart in evidence.
        * ``has_filters`` / ``disabled`` — booleans, as above.
        * ``deletes_key`` — ``True`` only for a key-scoped delete, which sets no
          value and whose ``key`` is the key being removed. Present on every
          entry so a caller reads a boolean rather than a missing key.

        Malformed, truncated or non-XML input returns ``[]`` and never raises: an
        unreadable preferences file must not abort a domain-wide scan.
    """
    entries: List[Dict[str, Any]] = []
    if not data:
        return entries
    try:
        root = ElementTree.fromstring(data)
    except Exception:
        # Includes ElementTree.ParseError plus the TypeError/ValueError that a
        # non-XML object or an undecodable encoding declaration raises.
        return entries

    order = 0
    # ``iter()`` walks the whole tree in document order, which is what makes
    # arbitrarily nested <Collection> grouping a non-issue.
    for element in root.iter():
        if _local_name(element.tag) != "Registry":
            continue
        properties, has_filters = _registry_xml_parts(element)
        if properties is None:
            continue

        attrs = {_local_name(name).lower(): value
                 for name, value in properties.attrib.items()}
        value_name = (attrs.get("name") or "").strip()
        type_name = (attrs.get("type") or "").strip().upper() or None
        action = _preference_action(attrs.get("action"))

        # A bare item names neither a value nor a type, so it is about the KEY
        # rather than about a value in it — and the action decides which of two
        # very different things that is. With a create/update/replace it is the
        # key-creation item GPMC writes per key when a preference builds a key
        # tree: it configures no value, so emitting it would invent a configured
        # value the GPO does not set, and it is dropped. With ``D`` it deletes
        # the whole key and everything in it, which can include a hardened value
        # another GPO put there, so dropping it would hide a real change and let
        # such a value read as configured. Those are emitted, with no
        # ``value_name`` and ``deletes_key`` set.
        deletes_key = False
        if not value_name and not type_name:
            if action != "D":
                continue
            deletes_key = True

        type_code = _REG_TYPE_CODES.get(type_name) if type_name else None
        multi_values = [child.text or "" for child in properties.iter()
                        if _local_name(child.tag) == "Value"]

        order += 1
        entries.append({
            "hive": (attrs.get("hive") or "").strip(),
            "key": (attrs.get("key") or "").strip(),
            "value_name": None if deletes_key else value_name,
            "type": None if deletes_key else type_code,
            "type_name": None if deletes_key else type_name,
            "value": None if deletes_key else _decode_preference_value(
                type_code, attrs.get("value"), multi_values),
            "action": action,
            "order": order,
            "has_filters": has_filters,
            "disabled": _xml_flag(element.attrib.get("disabled")),
            "deletes_key": deletes_key,
        })
    return entries


def _registry_xml_parts(element: Any) -> Tuple[Any, bool]:
    """Find a ``<Registry>`` item's ``<Properties>`` child and its filter flag.

    An empty ``<Filters/>`` element is not targeting — only a ``<Filters>`` with
    at least one child filter narrows where the item applies.
    """
    properties = None
    has_filters = False
    for child in element:
        name = _local_name(child.tag)
        if name == "Properties" and properties is None:
            properties = child
        elif name == "Filters" and len(child):
            has_filters = True
    return properties, has_filters


def _decode_preference_value(type_code: Optional[int], raw: Optional[str],
                             multi_values: List[str]) -> Any:
    """Decode one Registry.xml ``value`` per its declared type.

    Integer types are **base 16** (see :func:`parse_registry_xml`). A value that
    is not valid hex is returned as the literal string rather than dropped, so
    the evaluator can report the mismatch as evidence instead of the parser
    silently losing a configured setting. Everything else stays literal.
    """
    if type_code == 7:  # REG_MULTI_SZ — stored as <Values><Value> children.
        if multi_values:
            return multi_values
        return raw if raw is not None else ""
    if type_code in _HEX_VALUE_TYPES:
        return _hex_value(raw)
    return raw if raw is not None else ""


def _hex_value(raw: Optional[str]) -> Any:
    """Parse a Registry.xml integer value, which is a hex string.

    ``"00000038"`` -> 56. An empty value means nothing was configured (``None``);
    a value that will not parse as hex comes back as the literal string.
    """
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    body = text[2:] if text[:2].lower() == "0x" else text
    try:
        return int(body, 16)
    except ValueError:
        return text


def _preference_action(raw: Optional[str]) -> str:
    """Normalise a preference item's ``action``, defaulting to Update."""
    if raw is None:
        return REGISTRY_XML_DEFAULT_ACTION
    action = raw.strip().upper()
    if not action:
        return REGISTRY_XML_DEFAULT_ACTION
    return action


def _xml_flag(raw: Optional[str]) -> bool:
    """Read a Registry.xml boolean attribute (``"1"``/``"true"``)."""
    return isinstance(raw, str) and raw.strip().lower() in _XML_TRUE


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


def _local_name(tag: Any) -> str:
    """Strip any ``{namespace}`` prefix from an XML tag or attribute name."""
    if not isinstance(tag, str):
        return ''
    return tag.rsplit('}', 1)[-1]
