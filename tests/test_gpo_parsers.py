"""Unit tests for the pure GPO parsers in :mod:`aditor.gpo.parsers`.

These tests never touch the network, LDAP, SMB or a domain controller — the
parsers are pure functions of bytes and strings.

**Fixture hygiene.** No blob here was captured from a live domain. Registry.pol
fixtures are *built* by ``build_preg`` from ``(key, value, type, data)`` tuples,
which makes them provably free of real SIDs, publisher names, file paths and GPO
GUIDs, and lets us construct cases a real capture cannot supply (a truncated
record, a bad signature). Names follow the repo's ``DC=test,DC=local``
placeholder convention; the only SIDs used are universal well-known ones
(``S-1-1-0`` Everyone, ``S-1-5-32-544`` BUILTIN\\Administrators) that contain no
domain identifier.
"""

import struct

import pytest

from aditor.gpo.parsers import (
    decode_gpo_status,
    decode_version,
    extract_applocker,
    normalize_guid,
    parse_gp_link,
    parse_ini,
    parse_registry_pol,
)

# Registry value type codes, spelled out here rather than imported from the
# implementation so the fixtures encode the Windows format independently.
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_MULTI_SZ = 7
REG_QWORD = 11

# Synthetic rule GUIDs. Deliberately obvious placeholders, not real rule ids.
FAKE_RULE_ID_1 = "aaaaaaaa-0000-0000-0000-000000000001"
FAKE_RULE_ID_2 = "aaaaaaaa-0000-0000-0000-000000000002"


# --- PReg fixture builder --------------------------------------------------
#
# Registry.pol layout (Windows "PReg" format):
#   b"PReg" + <version:DWORD> then, repeated:
#   "[" key "\0" ";" value "\0" ";" <type:DWORD> ";" <size:DWORD> ";" data "]"
# with every literal character and string encoded UTF-16LE and integers
# little-endian.

def _u16(text: str) -> bytes:
    """UTF-16LE encode without a BOM."""
    return text.encode("utf-16-le")


def preg_record(key: str, value: str, reg_type: int, data: bytes) -> bytes:
    """Encode a single PReg ``[key;value;type;size;data]`` record."""
    return (
        _u16("[")
        + _u16(key + "\x00")
        + _u16(";")
        + _u16(value + "\x00")
        + _u16(";")
        + struct.pack("<I", reg_type)
        + _u16(";")
        + struct.pack("<I", len(data))
        + _u16(";")
        + data
        + _u16("]")
    )


def build_preg(records, signature: bytes = b"PReg", version: int = 1) -> bytes:
    """Build a synthetic Registry.pol blob.

    Args:
        records: iterable of ``(key, value, reg_type, data)`` tuples, where
            ``data`` is the raw little-endian/UTF-16LE payload bytes.
        signature: file signature; override to test a non-PReg file.
        version: format version DWORD.

    Returns:
        The complete blob's bytes.
    """
    body = b"".join(preg_record(*record) for record in records)
    return signature + struct.pack("<I", version) + body


def sz(text: str) -> bytes:
    """Payload bytes for a REG_SZ / REG_EXPAND_SZ value."""
    return _u16(text + "\x00")


def multi_sz(*items: str) -> bytes:
    """Payload bytes for a REG_MULTI_SZ value (null-separated, null-terminated)."""
    return _u16("".join(item + "\x00" for item in items) + "\x00")


def dword(number: int) -> bytes:
    """Payload bytes for a REG_DWORD value."""
    return struct.pack("<I", number)


def qword(number: int) -> bytes:
    """Payload bytes for a REG_QWORD value."""
    return struct.pack("<Q", number)


class TestParseRegistryPol:
    """parse_registry_pol against synthesized PReg blobs."""

    def test_string_and_expand_string_values(self):
        blob = build_preg([
            (r"Software\Policies\Test", "BannerText", REG_SZ, sz("Authorized use only")),
            (r"Software\Policies\Test", "LogPath", REG_EXPAND_SZ, sz(r"%SystemRoot%\logs")),
        ])

        entries, truncated = parse_registry_pol(blob)

        assert truncated is False
        assert entries == [
            {"key": r"Software\Policies\Test", "value": "BannerText",
             "type": "REG_SZ", "data": "Authorized use only"},
            {"key": r"Software\Policies\Test", "value": "LogPath",
             "type": "REG_EXPAND_SZ", "data": r"%SystemRoot%\logs"},
        ]

    def test_dword_and_qword_values(self):
        blob = build_preg([
            (r"Software\Policies\Test", "MinPwdLength", REG_DWORD, dword(14)),
            (r"Software\Policies\Test", "MaxSize", REG_QWORD, qword(4294967296)),
            (r"Software\Policies\Test", "BigEndian", REG_DWORD_BIG_ENDIAN,
             struct.pack(">I", 258)),
        ])

        entries, truncated = parse_registry_pol(blob)

        assert truncated is False
        assert [(e["value"], e["type"], e["data"]) for e in entries] == [
            ("MinPwdLength", "REG_DWORD", 14),
            ("MaxSize", "REG_QWORD", 4294967296),
            ("BigEndian", "REG_DWORD_BIG_ENDIAN", 258),
        ]

    def test_multi_sz_value_becomes_a_list(self):
        blob = build_preg([
            (r"Software\Policies\Test", "AllowedHosts", REG_MULTI_SZ,
             multi_sz("host-a", "host-b", "host-c")),
        ])

        entries, _ = parse_registry_pol(blob)

        assert entries[0]["type"] == "REG_MULTI_SZ"
        assert entries[0]["data"] == ["host-a", "host-b", "host-c"]

    def test_binary_value_is_base64_encoded(self):
        raw = bytes([0x00, 0x01, 0xFE, 0xFF])
        blob = build_preg([
            (r"Software\Policies\Test", "Blob", REG_BINARY, raw),
        ])

        entries, _ = parse_registry_pol(blob)

        import base64
        assert entries[0]["type"] == "REG_BINARY"
        assert entries[0]["data"] == base64.b64encode(raw).decode("ascii")
        assert base64.b64decode(entries[0]["data"]) == raw

    def test_empty_binary_value_is_empty_string(self):
        blob = build_preg([
            (r"Software\Policies\Test", "Empty", REG_BINARY, b""),
        ])

        entries, _ = parse_registry_pol(blob)

        assert entries[0]["data"] == ""

    def test_long_value_is_truncated_and_flagged(self):
        blob = build_preg([
            (r"Software\Policies\Test", "Long", REG_SZ, sz("x" * 500)),
            (r"Software\Policies\Test", "Short", REG_SZ, sz("fine")),
        ])

        entries, truncated = parse_registry_pol(blob, max_value_chars=100)

        assert truncated is True
        assert entries[0]["data"] == "x" * 100 + "...[truncated]"
        # A short value in the same file is untouched.
        assert entries[1]["data"] == "fine"

    def test_value_at_the_limit_is_not_truncated(self):
        blob = build_preg([
            (r"Software\Policies\Test", "Exact", REG_SZ, sz("y" * 100)),
        ])

        entries, truncated = parse_registry_pol(blob, max_value_chars=100)

        assert truncated is False
        assert entries[0]["data"] == "y" * 100

    def test_non_preg_signature_returns_no_entries(self):
        blob = build_preg(
            [(r"Software\Policies\Test", "Ignored", REG_DWORD, dword(1))],
            signature=b"NOPE",
        )

        assert parse_registry_pol(blob) == ([], False)

    def test_empty_and_stub_input_return_no_entries(self):
        assert parse_registry_pol(b"") == ([], False)
        assert parse_registry_pol(b"PReg") == ([], False)
        assert parse_registry_pol(b"PReg" + struct.pack("<I", 1)) == ([], False)

    def test_blob_truncated_mid_record_returns_empty_without_raising(self):
        blob = build_preg([
            (r"Software\Policies\Test", "Cut", REG_SZ, sz("never finished")),
        ])
        # Chop inside the first record's key string.
        entries, truncated = parse_registry_pol(blob[:20])

        assert entries == []
        assert truncated is False

    def test_records_before_a_truncation_are_kept(self):
        blob = build_preg([
            (r"Software\Policies\Test", "Good", REG_DWORD, dword(7)),
            (r"Software\Policies\Test", "Cut", REG_SZ, sz("never finished")),
        ])
        first_record_len = len(preg_record(
            r"Software\Policies\Test", "Good", REG_DWORD, dword(7)))
        entries, _ = parse_registry_pol(blob[:8 + first_record_len + 12])

        assert [e["value"] for e in entries] == ["Good"]
        assert entries[0]["data"] == 7

    def test_unknown_type_code_falls_back_to_the_raw_code(self):
        blob = build_preg([
            (r"Software\Policies\Test", "Weird", 99, b"\x01\x02"),
        ])

        entries, _ = parse_registry_pol(blob)

        assert entries[0]["type"] == 99


class TestParseIni:
    """parse_ini across the encodings GPO text files actually use."""

    INI_TEXT = (
        "[Version]\n"
        "signature=\"$CHICAGO$\"\n"
        "Revision=1\n"
        "\n"
        "[System Access]\n"
        "MinimumPasswordLength = 14\n"
        "PasswordComplexity = 1\n"
    )

    def test_utf16le_with_bom(self):
        data = b"\xff\xfe" + self.INI_TEXT.encode("utf-16-le")

        sections = parse_ini(data)

        assert list(sections) == ["Version", "System Access"]
        assert sections["Version"] == ['signature="$CHICAGO$"', "Revision=1"]
        assert sections["System Access"] == [
            "MinimumPasswordLength = 14", "PasswordComplexity = 1"]

    def test_utf16be_with_bom(self):
        data = b"\xfe\xff" + self.INI_TEXT.encode("utf-16-be")

        sections = parse_ini(data)

        assert list(sections) == ["Version", "System Access"]

    def test_utf8_without_bom(self):
        sections = parse_ini(self.INI_TEXT.encode("utf-8"))

        assert list(sections) == ["Version", "System Access"]
        assert sections["System Access"][0] == "MinimumPasswordLength = 14"

    def test_utf8_with_bom_strips_the_bom(self):
        sections = parse_ini(self.INI_TEXT.encode("utf-8-sig"))

        assert list(sections) == ["Version", "System Access"]

    def test_lines_before_the_first_section_go_under_root(self):
        sections = parse_ini(b"orphan=1\n[Real]\nkey=2\n")

        assert sections["_root"] == ["orphan=1"]
        assert sections["Real"] == ["key=2"]

    def test_undecodable_bytes_fall_back_to_latin1(self):
        sections = parse_ini(b"[Version]\nname=caf\xe9\n")

        assert sections["Version"] == ["name=caf\xe9"]

    def test_empty_input(self):
        assert parse_ini(b"") == {}

    def test_section_with_no_lines_is_present_but_empty(self):
        sections = parse_ini(b"[Empty]\n[Full]\nk=v\n")

        assert sections["Empty"] == []
        assert sections["Full"] == ["k=v"]


def applocker_entry(collection, rule_id, xml):
    """A parsed machine-registry entry holding one AppLocker rule."""
    return {
        "key": rf"Software\Policies\Microsoft\Windows\SrpV2\{collection}\{rule_id}",
        "value": "Value",
        "type": "REG_SZ",
        "data": xml,
    }


def enforcement_entry(collection, mode):
    """A parsed machine-registry entry holding a collection's EnforcementMode."""
    return {
        "key": rf"Software\Policies\Microsoft\Windows\SrpV2\{collection}",
        "value": "EnforcementMode",
        "type": "REG_DWORD",
        "data": mode,
    }


# Synthetic rule XML: universal well-known SIDs only, placeholder paths.
EXE_PATH_RULE = (
    '<FilePathRule Id="{id}" Name="Allow Program Files" Description="" '
    'UserOrGroupSid="S-1-1-0" Action="Allow">'
    '<Conditions><FilePathCondition Path="%PROGRAMFILES%\\*" /></Conditions>'
    '</FilePathRule>'
)
EXE_HASH_RULE = (
    '<FileHashRule Id="{id}" Name="Block sample tool" Description="" '
    'UserOrGroupSid="S-1-5-32-544" Action="Deny">'
    '<Conditions><FileHashCondition><FileHash Type="SHA256" '
    'Data="0x00" SourceFileName="sample.exe" SourceFileLength="1" />'
    '</FileHashCondition></Conditions></FileHashRule>'
)


class TestExtractApplocker:
    """extract_applocker over parsed machine-registry entries."""

    def test_groups_rules_into_collections_with_counts(self):
        entries = [
            {"key": r"Software\Policies\Test", "value": "Unrelated",
             "type": "REG_DWORD", "data": 1},
            enforcement_entry("Exe", 1),
            applocker_entry("Exe", FAKE_RULE_ID_1, EXE_PATH_RULE.format(id=FAKE_RULE_ID_1)),
            applocker_entry("Exe", FAKE_RULE_ID_2, EXE_HASH_RULE.format(id=FAKE_RULE_ID_2)),
            enforcement_entry("Msi", 0),
            applocker_entry("Msi", FAKE_RULE_ID_1, EXE_PATH_RULE.format(id=FAKE_RULE_ID_1)),
        ]

        result = extract_applocker(entries)

        assert set(result["collections"]) == {"Exe", "Msi"}
        exe = result["collections"]["Exe"]
        assert exe["enforcement_mode"] == "Enabled"
        assert exe["rule_count"] == 2
        assert [rule["id"] for rule in exe["rules"]] == [FAKE_RULE_ID_1, FAKE_RULE_ID_2]
        assert exe["rules"][0]["xml"].startswith("<FilePathRule")
        msi = result["collections"]["Msi"]
        assert msi["enforcement_mode"] == "AuditOnly"
        assert msi["rule_count"] == 1

    def test_unmapped_enforcement_mode_passes_through(self):
        result = extract_applocker([enforcement_entry("Dll", 2)])

        assert result["collections"]["Dll"]["enforcement_mode"] == 2
        assert result["collections"]["Dll"]["rule_count"] == 0

    def test_collection_with_rules_but_no_enforcement_mode(self):
        result = extract_applocker([
            applocker_entry("Script", FAKE_RULE_ID_1,
                            EXE_PATH_RULE.format(id=FAKE_RULE_ID_1)),
        ])

        script = result["collections"]["Script"]
        assert script["enforcement_mode"] is None
        assert script["rule_count"] == 1

    def test_no_applocker_entries_returns_none(self):
        assert extract_applocker([]) is None
        assert extract_applocker(None) is None
        assert extract_applocker([
            {"key": r"Software\Policies\Test", "value": "X",
             "type": "REG_DWORD", "data": 1},
        ]) is None

    def test_bare_srpv2_key_lands_in_unknown_collection(self):
        result = extract_applocker([
            {"key": r"Software\Policies\Microsoft\Windows\SrpV2",
             "value": "EnforcementMode", "type": "REG_DWORD", "data": 1},
        ])

        assert result["collections"]["Unknown"]["enforcement_mode"] == "Enabled"


class TestDecodeVersion:
    """decode_version — expectations derived from AD's documented encoding.

    Active Directory packs a GPO's revision counters into one integer as
    ``versionNumber = user * 65536 + computer``. Every expectation below is
    computed from *that* formula, never by re-applying the implementation's own
    shifts/masks — re-encoding with the code's convention is exactly what let
    the historical half-swap bug (computer and user revisions transposed) pass
    its original test.
    """

    WORD = 65536  # AD's multiplier for the user half

    def test_machine_only_gpo_regression(self):
        """A machine-only GPO revised 3 times: raw 3 -> computer 3, user 0.

        This is the half-swap regression. With the bug, raw=3 reported
        user_version=3 / computer_version=0, which a human only caught by
        eyeballing live output.
        """
        raw = 0 * self.WORD + 3  # user=0, computer=3

        decoded = decode_version(raw)

        assert raw == 3
        assert decoded["computer_version"] == 3
        assert decoded["user_version"] == 0
        assert decoded["raw"] == 3

    def test_user_only_gpo(self):
        raw = 1 * self.WORD + 0  # user=1, computer=0

        decoded = decode_version(raw)

        assert decoded["user_version"] == 1
        assert decoded["computer_version"] == 0

    @pytest.mark.parametrize("user,computer", [
        (0, 0),
        (0, 3),
        (1, 0),
        (2, 5),
        (12, 34),
        (65535, 65535),
    ])
    def test_halves_match_the_ad_formula(self, user, computer):
        raw = user * self.WORD + computer

        decoded = decode_version(raw)

        assert decoded == {
            "raw": raw,
            "computer_version": computer,
            "user_version": user,
        }

    def test_numeric_string_is_accepted(self):
        assert decode_version("3")["computer_version"] == 3

    @pytest.mark.parametrize("bad", [None, "", "abc", [], {}])
    def test_unusable_input_decodes_as_zero(self, bad):
        assert decode_version(bad) == {
            "raw": 0, "computer_version": 0, "user_version": 0}


class TestDecodeGpoStatus:
    """decode_gpo_status over the four documented flags values."""

    def test_flags_0_all_enabled(self):
        assert decode_gpo_status(0) == {
            "raw": 0,
            "computer_settings_enabled": True,
            "user_settings_enabled": True,
            "description": "All settings enabled",
        }

    def test_flags_1_user_disabled(self):
        status = decode_gpo_status(1)
        assert status["user_settings_enabled"] is False
        assert status["computer_settings_enabled"] is True
        assert status["description"] == "User settings disabled"

    def test_flags_2_computer_disabled(self):
        status = decode_gpo_status(2)
        assert status["computer_settings_enabled"] is False
        assert status["user_settings_enabled"] is True
        assert status["description"] == "Computer settings disabled"

    def test_flags_3_all_disabled(self):
        status = decode_gpo_status(3)
        assert status["computer_settings_enabled"] is False
        assert status["user_settings_enabled"] is False
        assert status["description"] == "All settings disabled"

    @pytest.mark.parametrize("bad", [None, "", "abc", []])
    def test_unusable_input_decodes_as_all_enabled(self, bad):
        assert decode_gpo_status(bad)["raw"] == 0
        assert decode_gpo_status(bad)["description"] == "All settings enabled"


# gPLink strings use the repo's DC=test,DC=local placeholder convention and
# synthetic GUIDs.
GUID_A = "11111111-1111-1111-1111-111111111111"
GUID_B = "22222222-2222-2222-2222-222222222222"
GUID_C = "33333333-3333-3333-3333-333333333333"


def gp_link(*links) -> str:
    """Build a gPLink attribute value from ``(guid, options)`` pairs."""
    return "".join(
        f"[LDAP://cn={{{guid}}},cn=policies,cn=system,DC=test,DC=local;{options}]"
        for guid, options in links
    )


class TestParseGpLink:
    """parse_gp_link — the single shared implementation.

    The per-link option is a bitmask: bit 0 (=1) link disabled, bit 1 (=2)
    enforced. ``options == 2`` therefore means enabled *and* enforced.
    """

    def test_single_plain_link(self):
        links = parse_gp_link(gp_link((GUID_A, 0)))

        assert len(links) == 1
        assert links[0]["guid"] == GUID_A
        assert links[0]["link_enabled"] is True
        assert links[0]["enforced"] is False
        assert links[0]["path"].startswith("LDAP://cn={")

    def test_enforced_link_is_enabled_and_enforced(self):
        links = parse_gp_link(gp_link((GUID_A, 2)))

        assert links[0]["link_enabled"] is True
        assert links[0]["enforced"] is True

    def test_disabled_link(self):
        links = parse_gp_link(gp_link((GUID_A, 1)))

        assert links[0]["link_enabled"] is False
        assert links[0]["enforced"] is False

    def test_both_bits_disabled_and_enforced(self):
        links = parse_gp_link(gp_link((GUID_A, 3)))

        assert links[0]["link_enabled"] is False
        assert links[0]["enforced"] is True

    def test_multiple_links_keep_attribute_order(self):
        links = parse_gp_link(gp_link((GUID_A, 0), (GUID_B, 2), (GUID_C, 1)))

        assert [link["guid"] for link in links] == [GUID_A, GUID_B, GUID_C]
        assert [link["enforced"] for link in links] == [False, True, False]
        assert [link["link_enabled"] for link in links] == [True, True, False]

    @pytest.mark.parametrize("empty", ["", None, [], 0])
    def test_empty_input_yields_no_links(self, empty):
        assert parse_gp_link(empty) == []

    def test_non_string_input_yields_no_links(self):
        # Guards the historical bug of handing in gp_link[0] of a str.
        assert parse_gp_link(["[LDAP://cn={x};0]"]) == []
        assert parse_gp_link(123) == []

    def test_malformed_values_are_skipped(self):
        assert parse_gp_link("garbage-with-no-brackets") == []
        assert parse_gp_link("[LDAP://cn={" + GUID_A + "},cn=policies]") == []

    def test_non_numeric_options_default_to_enabled_unenforced(self):
        links = parse_gp_link(
            "[LDAP://cn={" + GUID_A + "},cn=policies,cn=system,DC=test,DC=local;x]")

        assert links[0]["link_enabled"] is True
        assert links[0]["enforced"] is False

    def test_link_without_a_guid_still_parses(self):
        links = parse_gp_link("[LDAP://cn=broken,cn=policies,DC=test,DC=local;0]")

        assert len(links) == 1
        assert links[0]["guid"] == ""


class TestNormalizeGuid:
    """normalize_guid distinguishes GUIDs from display names."""

    def test_bare_guid(self):
        assert normalize_guid(GUID_A) == GUID_A

    def test_braced_guid_is_unwrapped(self):
        assert normalize_guid("{" + GUID_A + "}") == GUID_A

    def test_whitespace_is_stripped(self):
        assert normalize_guid("  " + GUID_A + "  ") == GUID_A

    def test_uppercase_hex_is_accepted(self):
        assert normalize_guid(GUID_A.upper()) == GUID_A.upper()

    @pytest.mark.parametrize("not_a_guid", [
        "Default Domain Policy",
        "1111-1111-1111-1111",
        "gggggggg-1111-1111-1111-111111111111",
        None,
        123,
        "",
    ])
    def test_non_guids_return_none(self, not_a_guid):
        assert normalize_guid(not_a_guid) is None
