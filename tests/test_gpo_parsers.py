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
    REGISTRY_XML_ACTIONS,
    REGISTRY_XML_DRIFT_CORRECTING_ACTIONS,
    REGISTRY_XML_WRITE_ACTIONS,
    applocker_rule_digest,
    decode_gpo_status,
    decode_version,
    extract_applocker,
    normalize_guid,
    normalize_registry_key,
    parse_gp_link,
    parse_ini,
    parse_registry_pol,
    parse_registry_xml,
    parse_security_template_registry_values,
    summarize_applocker,
    summarize_gpo_contents,
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


class TestParseSecurityTemplateRegistryValues:
    """parse_security_template_registry_values on GptTmpl.inf line shapes.

    The two LDAP lines below are the exact shape a real ``GptTmpl.inf``
    ``[Registry Values]`` section uses (the value name is the last path
    component; ``4,2`` is ``REG_DWORD`` data ``2``). They are hand-written here,
    not captured: no domain name, GPO GUID or SID appears in a
    ``[Registry Values]`` line at all.
    """

    LDAP_SERVER_SIGNING = (
        r"MACHINE\System\CurrentControlSet\Services\NTDS\Parameters"
        r"\LDAPServerIntegrity=4,2"
    )
    LDAP_CHANNEL_BINDING = (
        r"MACHINE\System\CurrentControlSet\Services\NTDS\Parameters"
        r"\LdapEnforceChannelBinding=4,2"
    )

    def test_real_world_dword_line(self):
        entries = parse_security_template_registry_values([self.LDAP_SERVER_SIGNING])

        assert entries == [{
            "key": r"MACHINE\System\CurrentControlSet\Services\NTDS"
                   r"\Parameters\LDAPServerIntegrity",
            "type": REG_DWORD,
            "type_name": "REG_DWORD",
            "value": 2,
        }]

    def test_the_two_real_ldap_lines_from_one_gpo(self):
        """One GPO's section, as read live: two settings, two entries."""
        entries = parse_security_template_registry_values(
            ["  " + self.LDAP_CHANNEL_BINDING, "  " + self.LDAP_SERVER_SIGNING])

        assert [e["key"].rsplit("\\", 1)[1] for e in entries] == [
            "LdapEnforceChannelBinding", "LDAPServerIntegrity"]
        assert [e["value"] for e in entries] == [2, 2]

    def test_leading_whitespace_is_stripped(self):
        entries = parse_security_template_registry_values(
            ["\t   MACHINE\\Software\\Test\\Flag=4,1   "])

        assert entries[0]["key"] == r"MACHINE\Software\Test\Flag"
        assert entries[0]["value"] == 1

    def test_dword_zero_is_a_value_not_a_blank(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient"
             r"\EnableMulticast=4,0"])

        assert entries[0]["value"] == 0

    def test_hex_dword_data(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\System\CurrentControlSet\services\KDC"
             r"\DefaultDomainSupportedEncTypes=4,0x38"])

        assert entries[0]["value"] == 0x38 == 56

    def test_qword_and_big_endian_dword(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Big=5,7", r"MACHINE\Software\Test\Wide=11,9"])

        assert [(e["type_name"], e["value"]) for e in entries] == [
            ("REG_DWORD_BIG_ENDIAN", 7), ("REG_QWORD", 9)]

    def test_string_value_is_unquoted(self):
        entries = parse_security_template_registry_values(
            [r'MACHINE\Software\Test\Banner=1,"Authorised users only"'])

        assert entries[0]["type_name"] == "REG_SZ"
        assert entries[0]["value"] == "Authorised users only"

    def test_value_containing_commas_splits_on_the_first_comma_only(self):
        entries = parse_security_template_registry_values(
            [r'MACHINE\Software\Test\Notice=1,"one, two, three"'])

        assert entries[0]["type"] == REG_SZ
        assert entries[0]["value"] == "one, two, three"

    def test_unquoted_value_containing_commas_is_kept_whole(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Notice=1,one, two, three"])

        assert entries[0]["value"] == "one, two, three"

    def test_expand_sz_value(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Path=2,%SystemRoot%\System32"])

        assert entries[0]["type_name"] == "REG_EXPAND_SZ"
        assert entries[0]["value"] == r"%SystemRoot%\System32"

    def test_multi_sz_value_splits_into_a_list(self):
        entries = parse_security_template_registry_values(
            [r'MACHINE\Software\Test\Allowed=7,"alpha","beta","gamma"'])

        assert entries[0]["type"] == REG_MULTI_SZ
        assert entries[0]["value"] == ["alpha", "beta", "gamma"]

    def test_multi_sz_without_quotes_and_with_blank_items(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Allowed=7,alpha,,beta,"])

        assert entries[0]["value"] == ["alpha", "beta"]

    def test_blank_dword_data_is_none(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Unset=4,"])

        assert entries[0]["type_name"] == "REG_DWORD"
        assert entries[0]["value"] is None

    def test_blank_string_data_is_the_empty_string(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Empty=1,"])

        assert entries[0]["value"] == ""

    def test_non_numeric_dword_data_is_kept_raw_not_dropped(self):
        """A configured-but-unparseable value must still surface as evidence."""
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Broken=4,not-a-number"])

        assert entries[0]["value"] == "not-a-number"

    def test_unknown_type_code_is_labelled_and_kept(self):
        entries = parse_security_template_registry_values(
            [r"MACHINE\Software\Test\Odd=99,payload"])

        assert entries[0]["type"] == 99
        assert entries[0]["type_name"] == "UNKNOWN_99"
        assert entries[0]["value"] == "payload"

    @pytest.mark.parametrize("malformed", [
        "no-separator-at-all",
        r"MACHINE\Software\Test\NoComma=4",
        r"MACHINE\Software\Test\BadType=four,2",
        r"MACHINE\Software\Test\EmptyType=,2",
        "=4,2",
        "   ",
        "[Registry Values]",
        "; a comment",
        "# another comment",
    ])
    def test_malformed_lines_are_skipped_never_raised_on(self, malformed):
        assert parse_security_template_registry_values([malformed]) == []

    def test_malformed_lines_do_not_lose_the_good_ones(self):
        entries = parse_security_template_registry_values([
            "garbage",
            self.LDAP_SERVER_SIGNING,
            r"MACHINE\Software\Test\BadType=x,1",
            self.LDAP_CHANNEL_BINDING,
        ])

        assert len(entries) == 2

    @pytest.mark.parametrize("empty", [None, [], {}, "", b""])
    def test_empty_and_non_list_input_returns_empty(self, empty):
        assert parse_security_template_registry_values(empty) == []

    def test_non_string_items_are_ignored(self):
        entries = parse_security_template_registry_values(
            [None, 42, ["nested"], self.LDAP_SERVER_SIGNING])

        assert len(entries) == 1

    def test_parses_the_section_parse_ini_actually_returns(self):
        """End to end from UTF-16 INF bytes, the way SYSVOL delivers them."""
        inf = (
            "[Unicode]\n"
            "Unicode=yes\n"
            "[Registry Values]\n"
            + self.LDAP_CHANNEL_BINDING + "\n"
            + self.LDAP_SERVER_SIGNING + "\n"
            "[Version]\n"
            "Revision=1\n"
        )
        sections = parse_ini(b"\xff\xfe" + inf.encode("utf-16-le"))

        entries = parse_security_template_registry_values(
            sections["Registry Values"])

        assert {e["key"].rsplit("\\", 1)[1]: e["value"] for e in entries} == {
            "LdapEnforceChannelBinding": 2, "LDAPServerIntegrity": 2}


class TestParseRegistryXml:
    """parse_registry_xml on Group Policy Preferences Registry.xml shapes.

    **Fixture hygiene.** Every document below is hand-written from the format's
    documented shape — nothing here was copied out of a real domain's
    ``Registry.xml``. The item names used (``DefaultDomainSupportedEncTypes``,
    ``Start``, ``EnableCertPaddingCheck``) are Microsoft-documented registry
    value names, not domain content: no GPO GUID, uid, ``changed`` timestamp,
    domain name, DC hostname or SID appears anywhere in this class.

    The class's centrepiece is
    ``test_a_dword_value_is_hexadecimal_not_decimal``. Registry.xml stores
    DWORD/QWORD data as a **hex** string, so ``value="00000038"`` is 0x38 = 56.
    Reading it as decimal 38 (= 0x26) does not merely mis-report the number: for
    ``DefaultDomainSupportedEncTypes`` it inverts the setting's meaning, turning
    "RC4 and DES disabled" into "RC4 and DES enabled".
    """

    KDC_KEY = r"SYSTEM\CurrentControlSet\Services\Kdc"

    @staticmethod
    def item(properties, *, item_attrs="", children=""):
        """One ``<Registry>`` item with the given ``<Properties>`` attributes."""
        return (f'<Registry clsid="{{9CD4B2F4-0000-0000-0000-000000000001}}" '
                f'name="Item" image="7"{item_attrs}>'
                f'<Properties {properties}/>{children}</Registry>')

    @classmethod
    def document(cls, *items):
        """A complete Registry.xml as bytes, UTF-8 with the XML declaration."""
        body = "".join(items)
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<RegistrySettings clsid="{A3CCFC41-0000-0000-0000-000000000002}">'
            f'{body}</RegistrySettings>'
        ).encode("utf-8")

    @classmethod
    def kdc_document(cls, value="00000038", **extra):
        """The live-observed shape: one REG_DWORD preference under Kdc."""
        attrs = " ".join(f'{name}="{text}"' for name, text in extra.items())
        return cls.document(cls.item(
            f'action="U" displayDecimal="0" default="0" '
            f'hive="HKEY_LOCAL_MACHINE" key="{cls.KDC_KEY}" '
            f'name="DefaultDomainSupportedEncTypes" type="REG_DWORD" '
            f'value="{value}" {attrs}'))

    # --- the hex/decimal trap ---------------------------------------------

    def test_a_dword_value_is_hexadecimal_not_decimal(self):
        """``value="00000038"`` is 0x38 = 56. Decimal 38 would be 0x26.

        0x38 = AES128 | AES256 | the "future types" bit, with the RC4 and DES
        bits clear. 0x26 has the RC4 bit *set* — so parsing this field as decimal
        reports the exact opposite of what the operator configured, and fails a
        control on a domain that is correctly hardened.
        """
        entries = parse_registry_xml(self.kdc_document())

        assert entries[0]["value"] == 56
        assert entries[0]["value"] != 38, (
            "0x38 parsed as decimal 38 is 0x26, which re-enables RC4 and DES")

    def test_a_qword_value_is_hexadecimal_too(self):
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Big" '
            'type="REG_QWORD" value="0000000100000038"')))

        assert entries[0]["value"] == 0x100000038
        assert entries[0]["value"] != 100000038
        assert entries[0]["type"] == REG_QWORD

    @pytest.mark.parametrize("written,expected", [
        ("00000038", 56), ("38", 56), ("0x38", 56), ("0X0038", 56),
        ("00000001", 1), ("00000004", 4), ("0000000f", 15), ("FFFFFFFF", 0xFFFFFFFF),
        ("00000000", 0),
    ])
    def test_dword_hex_spellings(self, written, expected):
        entries = parse_registry_xml(self.kdc_document(value=written))

        assert entries[0]["value"] == expected

    @pytest.mark.parametrize("display_decimal", ["0", "1"])
    def test_displaydecimal_is_a_ui_hint_and_never_changes_the_parse(
            self, display_decimal):
        """GPMC's decimal/hex radio button changes the display, not the file."""
        entries = parse_registry_xml(self.document(self.item(
            f'action="U" displayDecimal="{display_decimal}" '
            f'hive="HKEY_LOCAL_MACHINE" key="{self.KDC_KEY}" '
            f'name="DefaultDomainSupportedEncTypes" type="REG_DWORD" '
            f'value="00000038"')))

        assert entries[0]["value"] == 56

    def test_an_empty_dword_value_is_none_not_zero(self):
        entries = parse_registry_xml(self.kdc_document(value=""))

        assert entries[0]["value"] is None

    def test_a_dword_value_that_is_not_hex_is_kept_as_the_literal_string(self):
        """Kept as evidence rather than dropped: the evaluator reports it."""
        entries = parse_registry_xml(self.kdc_document(value="not-a-number"))

        assert entries[0]["value"] == "not-a-number"

    # --- the live-observed case, end to end -------------------------------

    def test_the_live_observed_kdc_item_parses_completely(self):
        entries = parse_registry_xml(self.kdc_document())

        assert entries == [{
            "hive": "HKEY_LOCAL_MACHINE",
            "key": self.KDC_KEY,
            "value_name": "DefaultDomainSupportedEncTypes",
            "type": REG_DWORD,
            "type_name": "REG_DWORD",
            "value": 56,
            "action": "U",
            "order": 1,
            "has_filters": False,
            "disabled": False,
        }]

    def test_the_full_hive_name_folds_onto_hklm_for_comparison(self):
        """HKEY_LOCAL_MACHINE must compare equal to the catalog's HKLM."""
        entry = parse_registry_xml(self.kdc_document())[0]
        full_key = "\\".join([entry["hive"], entry["key"], entry["value_name"]])

        assert normalize_registry_key(full_key) == normalize_registry_key(
            r"HKLM\System\CurrentControlSet\services\KDC"
            r"\DefaultDomainSupportedEncTypes")

    # --- string and list types --------------------------------------------

    def test_a_reg_sz_value_stays_the_literal_string(self):
        """``value="1"`` on a REG_SZ is the string "1", not the number 1."""
        entries = parse_registry_xml(self.document(self.item(
            'action="U" hive="HKEY_LOCAL_MACHINE" '
            'key="SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config" '
            'name="EnableCertPaddingCheck" type="REG_SZ" value="1"')))

        assert entries[0]["value"] == "1"
        assert isinstance(entries[0]["value"], str)
        assert entries[0]["type"] == REG_SZ

    def test_a_reg_expand_sz_value_is_not_expanded(self):
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Path" '
            'type="REG_EXPAND_SZ" value="%SystemRoot%\\System32"')))

        assert entries[0]["value"] == r"%SystemRoot%\System32"

    def test_a_reg_binary_value_stays_the_literal_hex_string(self):
        """Binary data is not a number and must not be decoded as one."""
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Blob" '
            'type="REG_BINARY" value="00ff10"')))

        assert entries[0]["value"] == "00ff10"
        assert entries[0]["type"] == REG_BINARY

    def test_a_reg_multi_sz_value_collects_its_value_children(self):
        entries = parse_registry_xml(self.document(
            '<Registry name="Item"><Properties hive="HKEY_LOCAL_MACHINE" '
            'key="SOFTWARE\\Test" name="List" type="REG_MULTI_SZ">'
            '<Values><Value>alpha</Value><Value>beta</Value></Values>'
            '</Properties></Registry>'))

        assert entries[0]["value"] == ["alpha", "beta"]
        assert entries[0]["type"] == REG_MULTI_SZ

    def test_an_unknown_type_name_keeps_the_name_and_has_no_code(self):
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Odd" '
            'type="REG_SOMETHING_NEW" value="x"')))

        assert entries[0]["type"] is None
        assert entries[0]["type_name"] == "REG_SOMETHING_NEW"
        assert entries[0]["value"] == "x"

    # --- action semantics -------------------------------------------------

    @pytest.mark.parametrize("written,expected", [
        ("C", "C"), ("R", "R"), ("U", "U"), ("D", "D"),
        ("c", "C"), ("d", "D"), (" U ", "U"),
    ])
    def test_the_action_attribute_is_normalised_to_upper_case(self, written,
                                                              expected):
        entries = parse_registry_xml(self.document(self.item(
            f'action="{written}" hive="HKEY_LOCAL_MACHINE" '
            f'key="SOFTWARE\\Test" name="Flag" type="REG_DWORD" '
            f'value="00000001"')))

        assert entries[0]["action"] == expected

    def test_a_missing_action_attribute_means_update(self):
        """MS-GPPREF defaults the optional ``action`` attribute to Update."""
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Flag" '
            'type="REG_DWORD" value="00000001"')))

        assert entries[0]["action"] == "U"

    def test_a_delete_item_is_returned_and_labelled_delete(self):
        """The parser reports it; the evaluator is what must not count it.

        A ``D`` item removes the value, so a caller that treats it as
        configuring the value would report hardening that the GPO is actively
        undoing. The parser's job is to say plainly which action it is.
        """
        entries = parse_registry_xml(self.document(self.item(
            f'action="D" hive="HKEY_LOCAL_MACHINE" key="{self.KDC_KEY}" '
            f'name="DefaultDomainSupportedEncTypes" type="REG_DWORD" '
            f'value="00000038"')))

        assert entries[0]["action"] == "D"
        assert entries[0]["action"] not in REGISTRY_XML_WRITE_ACTIONS

    def test_create_is_a_write_but_not_drift_correcting(self):
        entries = parse_registry_xml(self.document(self.item(
            'action="C" hive="HKEY_LOCAL_MACHINE" '
            'key="SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc" '
            'name="Start" type="REG_DWORD" value="00000004"')))

        assert entries[0]["value"] == 4
        assert entries[0]["action"] in REGISTRY_XML_WRITE_ACTIONS
        assert entries[0]["action"] not in REGISTRY_XML_DRIFT_CORRECTING_ACTIONS

    @pytest.mark.parametrize("action", ["R", "U"])
    def test_replace_and_update_correct_drift(self, action):
        entries = parse_registry_xml(self.document(self.item(
            f'action="{action}" hive="HKEY_LOCAL_MACHINE" '
            f'key="SOFTWARE\\Test" name="Flag" type="REG_DWORD" '
            f'value="00000001"')))

        assert entries[0]["action"] in REGISTRY_XML_DRIFT_CORRECTING_ACTIONS

    def test_an_unrecognised_action_is_passed_through_not_guessed_at(self):
        entries = parse_registry_xml(self.document(self.item(
            'action="Z" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
            'name="Flag" type="REG_DWORD" value="00000001"')))

        assert entries[0]["action"] == "Z"
        assert entries[0]["action"] not in REGISTRY_XML_ACTIONS

    # --- bare key-creation items ------------------------------------------

    def test_a_bare_key_creation_item_is_skipped(self):
        """Creating a key configures no value, so it must not become one."""
        entries = parse_registry_xml(self.document(self.item(
            'action="C" default="0" hive="HKEY_LOCAL_MACHINE" '
            'key="SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config"')))

        assert entries == []

    def test_a_bare_key_item_with_empty_name_and_type_is_skipped(self):
        entries = parse_registry_xml(self.document(self.item(
            'action="C" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
            'name="" type="" value=""')))

        assert entries == []

    def test_bare_key_items_are_skipped_around_the_real_value(self):
        """The observed CVE-2013-3900 shape: key creations plus two values."""
        entries = parse_registry_xml(self.document(
            self.item('action="C" hive="HKEY_LOCAL_MACHINE" '
                      'key="SOFTWARE\\Microsoft\\Cryptography\\Wintrust"'),
            self.item('action="C" hive="HKEY_LOCAL_MACHINE" '
                      'key="SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config"'),
            self.item('action="U" hive="HKEY_LOCAL_MACHINE" '
                      'key="SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config" '
                      'name="EnableCertPaddingCheck" type="REG_SZ" value="1"'),
            self.item('action="U" hive="HKEY_LOCAL_MACHINE" '
                      'key="SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography'
                      '\\Wintrust\\Config" '
                      'name="EnableCertPaddingCheck" type="REG_SZ" value="1"'),
        ))

        assert [entry["value_name"] for entry in entries] == [
            "EnableCertPaddingCheck", "EnableCertPaddingCheck"]
        assert [entry["order"] for entry in entries] == [1, 2], \
            "order counts emitted values, so skipped key items leave no gaps"
        assert "WOW6432Node" in entries[1]["key"]

    def test_an_item_with_a_name_but_no_type_is_still_reported(self):
        """Half-written is not the same as absent — report it, type unknown."""
        entries = parse_registry_xml(self.document(self.item(
            'action="U" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
            'name="Flag" value="00000001"')))

        assert entries[0]["value_name"] == "Flag"
        assert entries[0]["type"] is None
        assert entries[0]["value"] == "00000001", \
            "with no declared type the data cannot be assumed to be hex"

    def test_a_registry_item_with_no_properties_child_is_skipped(self):
        entries = parse_registry_xml(self.document(
            '<Registry name="Item" clsid="{9CD4B2F4-0000-0000-0000-0000}"/>'))

        assert entries == []

    # --- nesting ----------------------------------------------------------

    def test_items_inside_a_collection_are_found(self):
        entries = parse_registry_xml(self.document(
            '<Collection clsid="{53B533F5-0000-0000-0000-000000000003}" '
            'name="Wintrust">'
            + self.item('hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
                        'name="Inner" type="REG_DWORD" value="00000010"')
            + '</Collection>'))

        assert [entry["value_name"] for entry in entries] == ["Inner"]
        assert entries[0]["value"] == 16

    def test_items_nested_several_collections_deep_are_found(self):
        inner = self.item('hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
                          'name="Deep" type="REG_DWORD" value="00000038"')
        nested = inner
        for level in range(4):
            nested = f'<Collection name="Level{level}">{nested}</Collection>'

        entries = parse_registry_xml(self.document(nested))

        assert [entry["value_name"] for entry in entries] == ["Deep"]
        assert entries[0]["value"] == 56

    def test_order_follows_document_order_across_collections(self):
        entries = parse_registry_xml(self.document(
            self.item('hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
                      'name="First" type="REG_DWORD" value="00000001"'),
            '<Collection name="Group">'
            + self.item('hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
                        'name="Second" type="REG_DWORD" value="00000002"')
            + '</Collection>',
            self.item('hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" '
                      'name="Third" type="REG_DWORD" value="00000003"'),
        ))

        assert [(entry["value_name"], entry["order"]) for entry in entries] == [
            ("First", 1), ("Second", 2), ("Third", 3)]

    def test_a_namespaced_document_still_parses(self):
        entries = parse_registry_xml(
            b'<RegistrySettings xmlns="http://example.invalid/gpp">'
            b'<Registry><Properties hive="HKEY_LOCAL_MACHINE" '
            b'key="SOFTWARE\\Test" name="Flag" type="REG_DWORD" '
            b'value="00000038"/></Registry></RegistrySettings>')

        assert [entry["value"] for entry in entries] == [56]

    # --- item-level targeting and disabled items --------------------------

    def test_a_filtered_item_is_flagged_as_carrying_targeting(self):
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Flag" '
            'type="REG_DWORD" value="00000038"',
            children='<Filters><FilterGroup bool="AND" not="0" '
                     'name="Placeholder Group"/></Filters>')))

        assert entries[0]["has_filters"] is True

    def test_an_empty_filters_element_is_not_targeting(self):
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Flag" '
            'type="REG_DWORD" value="00000038"',
            children='<Filters/>')))

        assert entries[0]["has_filters"] is False

    def test_an_item_with_no_filters_element_is_not_targeting(self):
        entries = parse_registry_xml(self.kdc_document())

        assert entries[0]["has_filters"] is False

    @pytest.mark.parametrize("written,expected", [
        ('1', True), ('true', True), ('TRUE', True), ('yes', True),
        ('0', False), ('false', False), ('', False),
    ])
    def test_the_disabled_attribute_is_read(self, written, expected):
        entries = parse_registry_xml(self.document(self.item(
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Flag" '
            'type="REG_DWORD" value="00000038"',
            item_attrs=f' disabled="{written}"')))

        assert entries[0]["disabled"] is expected

    def test_an_item_without_a_disabled_attribute_is_enabled(self):
        assert parse_registry_xml(self.kdc_document())[0]["disabled"] is False

    # --- malformed input --------------------------------------------------

    @pytest.mark.parametrize("bad", [
        b"<RegistrySettings><Registry>",                 # truncated
        b"not xml at all",
        b"<RegistrySettings>&nope;</RegistrySettings>",  # bad entity
        b"\x00\x01\x02\x03",
        b"<?xml version='1.0' encoding='not-a-codec'?><RegistrySettings/>",
    ])
    def test_malformed_xml_returns_an_empty_list_and_never_raises(self, bad):
        assert parse_registry_xml(bad) == []

    @pytest.mark.parametrize("empty", [None, b"", "", 0, [], {}])
    def test_empty_and_falsy_input_returns_an_empty_list(self, empty):
        assert parse_registry_xml(empty) == []

    def test_a_non_bytes_non_string_object_returns_an_empty_list(self):
        assert parse_registry_xml(object()) == []

    def test_a_document_with_no_registry_items_returns_an_empty_list(self):
        assert parse_registry_xml(self.document()) == []

    def test_text_input_is_accepted_as_well_as_bytes(self):
        assert parse_registry_xml(
            '<RegistrySettings><Registry><Properties '
            'hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Test" name="Flag" '
            'type="REG_DWORD" value="00000038"/></Registry>'
            '</RegistrySettings>')[0]["value"] == 56


class TestNormalizeRegistryKey:
    """normalize_registry_key bridges the MACHINE\\ and HKLM\\ namespaces."""

    TEMPLATE_KEY = (r"MACHINE\System\CurrentControlSet\Services\NTDS"
                    r"\Parameters\LDAPServerIntegrity")
    CATALOG_KEY = (r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS"
                   r"\Parameters\LDAPServerIntegrity")

    def test_gpo_and_catalog_spellings_of_the_same_key_match(self):
        """The live-verified mismatch: MACHINE\\System vs HKLM\\SYSTEM."""
        assert (normalize_registry_key(self.TEMPLATE_KEY)
                == normalize_registry_key(self.CATALOG_KEY))

    def test_comparison_is_case_insensitive(self):
        assert (normalize_registry_key(self.TEMPLATE_KEY.lower())
                == normalize_registry_key(self.CATALOG_KEY.upper()))

    @pytest.mark.parametrize("prefix", [
        "MACHINE", "machine", "HKLM", "hklm", "HKEY_LOCAL_MACHINE",
    ])
    def test_every_machine_hive_alias_normalises_to_hklm(self, prefix):
        assert normalize_registry_key(prefix + r"\Software\Test\Flag") == \
            r"HKLM\SOFTWARE\TEST\FLAG"

    @pytest.mark.parametrize("prefix,expected", [
        ("USER", "HKCU"), ("HKCU", "HKCU"), ("HKEY_CURRENT_USER", "HKCU"),
        ("HKEY_USERS", "HKU"), ("HKEY_CLASSES_ROOT", "HKCR"),
    ])
    def test_other_hive_aliases(self, prefix, expected):
        assert normalize_registry_key(prefix + r"\Test").startswith(expected + "\\")

    def test_unknown_hive_prefix_is_left_alone(self):
        assert normalize_registry_key(r"SOMETHINGELSE\Test") == r"SOMETHINGELSE\TEST"

    def test_separators_are_collapsed_and_trimmed(self):
        assert normalize_registry_key("  MACHINE\\\\Software\\Test\\ ") == \
            r"HKLM\SOFTWARE\TEST"

    def test_forward_slashes_are_treated_as_separators(self):
        assert normalize_registry_key("MACHINE/Software/Test") == r"HKLM\SOFTWARE\TEST"

    def test_value_names_containing_spaces_survive(self):
        assert normalize_registry_key(
            r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
            r"\16 LDAP Interface Events").endswith(r"\16 LDAP INTERFACE EVENTS")

    @pytest.mark.parametrize("empty", [None, "", "   ", 42, "\\\\", ["MACHINE"]])
    def test_empty_and_non_string_input_returns_empty_string(self, empty):
        assert normalize_registry_key(empty) == ""

    def test_default_hive_fills_in_for_a_hiveless_registry_pol_key(self):
        """PReg keys carry no hive; the machine file is implicitly HKLM."""
        pol_key = r"Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast"

        assert (normalize_registry_key(pol_key, "HKLM")
                == normalize_registry_key(r"HKLM\Software\Policies\Microsoft"
                                          r"\Windows NT\DNSClient\EnableMulticast"))

    def test_default_hive_does_not_override_a_hive_that_is_present(self):
        assert normalize_registry_key(r"MACHINE\Software\Test", "HKCU") == \
            r"HKLM\SOFTWARE\TEST"

    def test_without_a_default_hive_a_hiveless_key_is_left_hiveless(self):
        assert normalize_registry_key(r"Software\Test") == r"SOFTWARE\TEST"


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


class TestApplockerRuleDigest:
    """applocker_rule_digest must read attributes as XML, order-independently."""

    def test_publisher_rule_digest(self):
        rule = (
            '<FilePublisherRule Id="' + FAKE_RULE_ID_1 + '" '
            'Name="Signed vendor apps" Description="" '
            'UserOrGroupSid="S-1-1-0" Action="Allow">'
            '<Conditions><FilePublisherCondition PublisherName="O=EXAMPLE VENDOR" '
            'ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" '
            'HighSection="*" /></FilePublisherCondition></Conditions>'
            '</FilePublisherRule>'
        )

        assert applocker_rule_digest(rule) == {
            "type": "FilePublisherRule",
            "id": FAKE_RULE_ID_1,
            "name": "Signed vendor apps",
            "action": "Allow",
            "sid": "S-1-1-0",
        }

    def test_path_rule_digest(self):
        digest = applocker_rule_digest(EXE_PATH_RULE.format(id=FAKE_RULE_ID_1))

        assert digest["type"] == "FilePathRule"
        assert digest["name"] == "Allow Program Files"
        assert digest["action"] == "Allow"
        assert digest["sid"] == "S-1-1-0"

    def test_hash_rule_digest(self):
        digest = applocker_rule_digest(EXE_HASH_RULE.format(id=FAKE_RULE_ID_2))

        assert digest["type"] == "FileHashRule"
        assert digest["action"] == "Deny"
        assert digest["sid"] == "S-1-5-32-544"
        assert digest["id"] == FAKE_RULE_ID_2

    def test_attribute_order_does_not_matter(self):
        """The whole point: live rules do not agree on attribute order."""
        canonical = (
            '<FilePathRule Id="' + FAKE_RULE_ID_1 + '" Name="Rule" '
            'Description="" UserOrGroupSid="S-1-1-0" Action="Deny" />'
        )
        shuffled = (
            '<FilePathRule Action="Deny" UserOrGroupSid="S-1-1-0" '
            'Name="Rule" Description="" Id="' + FAKE_RULE_ID_1 + '" />'
        )

        assert applocker_rule_digest(shuffled) == applocker_rule_digest(canonical)
        assert applocker_rule_digest(shuffled)["action"] == "Deny"

    def test_multiline_and_whitespace_formatting(self):
        rule = (
            '<FilePathRule\n'
            '    Action="Allow"\n'
            '    Name="Wrapped"\n'
            '    Id="' + FAKE_RULE_ID_1 + '"\n'
            '    UserOrGroupSid="S-1-1-0">\n'
            '  <Conditions />\n'
            '</FilePathRule>\n'
        )

        digest = applocker_rule_digest(rule)

        assert digest["name"] == "Wrapped"
        assert digest["action"] == "Allow"

    def test_namespaced_xml_is_handled(self):
        rule = (
            '<FilePathRule xmlns="urn:example:applocker" Id="' + FAKE_RULE_ID_1
            + '" Name="Namespaced" Action="Allow" UserOrGroupSid="S-1-1-0" />'
        )

        digest = applocker_rule_digest(rule)

        assert digest["type"] == "FilePathRule"
        assert digest["name"] == "Namespaced"

    def test_missing_attributes_become_empty_strings(self):
        digest = applocker_rule_digest('<FilePathRule Name="Only a name" />')

        assert digest == {"type": "FilePathRule", "id": "",
                          "name": "Only a name", "action": "", "sid": ""}

    def test_truncated_xml_falls_back_to_the_registry_rule_id(self):
        truncated = ('<FilePathRule Id="' + FAKE_RULE_ID_1
                     + '" Name="Cut off" Act...[truncated]')

        digest = applocker_rule_digest(truncated, fallback_id=FAKE_RULE_ID_1)

        assert digest == {"type": "", "id": FAKE_RULE_ID_1,
                          "name": "", "action": "", "sid": ""}

    @pytest.mark.parametrize("empty", [None, "", "   ", 42, [], {}])
    def test_non_xml_input_yields_a_blank_digest(self, empty):
        assert applocker_rule_digest(empty, fallback_id="x") == {
            "type": "", "id": "x", "name": "", "action": "", "sid": ""}

    def test_digest_has_exactly_the_five_summary_fields(self):
        digest = applocker_rule_digest(EXE_PATH_RULE.format(id=FAKE_RULE_ID_1))

        assert set(digest) == {"type", "id", "name", "action", "sid"}


class TestSummarizeApplocker:
    """summarize_applocker keeps enforcement/counts, drops rule XML."""

    def _applocker(self):
        return extract_applocker([
            enforcement_entry("Exe", 1),
            applocker_entry("Exe", FAKE_RULE_ID_1, EXE_PATH_RULE.format(id=FAKE_RULE_ID_1)),
            applocker_entry("Exe", FAKE_RULE_ID_2, EXE_HASH_RULE.format(id=FAKE_RULE_ID_2)),
        ])

    def test_rules_become_digests(self):
        summarized = summarize_applocker(self._applocker())

        exe = summarized["collections"]["Exe"]
        assert exe["enforcement_mode"] == "Enabled"
        assert exe["rule_count"] == 2
        assert all("xml" not in rule for rule in exe["rules"])
        assert [rule["type"] for rule in exe["rules"]] == [
            "FilePathRule", "FileHashRule"]
        assert [rule["name"] for rule in exe["rules"]] == [
            "Allow Program Files", "Block sample tool"]

    def test_source_is_not_mutated(self):
        applocker = self._applocker()

        summarize_applocker(applocker)

        assert applocker["collections"]["Exe"]["rules"][0]["xml"].startswith(
            "<FilePathRule")

    def test_none_passes_through(self):
        assert summarize_applocker(None) is None


class TestSummarizeGpoContents:
    """summarize_gpo_contents drops the heavy bodies, keeps the shape."""

    def _contents(self):
        return {
            "smb_source": r"\\dc.test.local\SYSVOL\test.local\Policies\{" + GUID_A + "}",
            "files": [{"path": "GPT.INI", "size": 59}],
            "gpt_ini": {"General": ["Version=3"]},
            "machine_registry_pol": {
                "entry_count": 2,
                "entries_truncated": True,
                "entries": [
                    {"key": r"Software\Policies\Test", "value": "A",
                     "type": "REG_DWORD", "data": 1},
                    {"key": r"Software\Policies\Test", "value": "B",
                     "type": "REG_SZ", "data": "x"},
                ],
            },
            "user_registry_pol": {
                "entry_count": 0, "entries_truncated": False, "entries": []},
            "applocker": extract_applocker([
                enforcement_entry("Exe", 1),
                applocker_entry("Exe", FAKE_RULE_ID_1,
                                EXE_PATH_RULE.format(id=FAKE_RULE_ID_1)),
            ]),
            "security_templates": [{
                "path": r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
                "sections": {"Version": ["Revision=1"],
                             "System Access": ["MinimumPasswordLength = 14"]},
            }],
            "scripts": [{
                "path": r"Machine\Scripts\scripts.ini",
                "sections": {"Startup": ["0CmdLine=setup.cmd"]},
            }],
        }

    def test_identity_and_light_fields_are_kept(self):
        contents = self._contents()

        summarized = summarize_gpo_contents(contents)

        assert summarized["smb_source"] == contents["smb_source"]
        assert summarized["files"] == contents["files"]
        assert summarized["gpt_ini"] == contents["gpt_ini"]
        assert set(summarized) == set(contents), "top-level shape must not change"

    def test_registry_entries_are_omitted_but_counts_kept(self):
        summarized = summarize_gpo_contents(self._contents())

        assert summarized["machine_registry_pol"] == {
            "entry_count": 2, "entries_truncated": True}
        assert summarized["user_registry_pol"] == {
            "entry_count": 0, "entries_truncated": False}

    def test_applocker_rules_become_digests(self):
        summarized = summarize_gpo_contents(self._contents())

        exe = summarized["applocker"]["collections"]["Exe"]
        assert exe["enforcement_mode"] == "Enabled"
        assert exe["rule_count"] == 1
        assert exe["rules"][0]["name"] == "Allow Program Files"
        assert "xml" not in exe["rules"][0]

    def test_templates_and_scripts_reduce_to_section_names(self):
        summarized = summarize_gpo_contents(self._contents())

        template = summarized["security_templates"][0]
        assert template["path"].endswith("GptTmpl.inf")
        assert template["sections"] == ["Version", "System Access"]
        assert summarized["scripts"][0]["sections"] == ["Startup"]

    def test_input_is_not_mutated(self):
        contents = self._contents()

        summarize_gpo_contents(contents)

        assert len(contents["machine_registry_pol"]["entries"]) == 2
        assert isinstance(contents["security_templates"][0]["sections"], dict)

    def test_registry_xml_blocks_reduce_to_their_count(self):
        contents = self._contents()
        contents["machine_registry_xml"] = {
            "entry_count": 1,
            "entries": [{"hive": "HKEY_LOCAL_MACHINE", "key": r"SOFTWARE\Test",
                         "value_name": "Flag", "type": 4,
                         "type_name": "REG_DWORD", "value": 56, "action": "U",
                         "order": 1, "has_filters": False, "disabled": False}],
        }

        summarized = summarize_gpo_contents(contents)

        assert summarized["machine_registry_xml"] == {"entry_count": 1}
        assert len(contents["machine_registry_xml"]["entries"]) == 1, \
            "the input dict must not be mutated"

    def test_a_gpo_with_no_registry_xml_block_gains_none(self):
        """The key is absent for a GPO with no preferences; keep it absent."""
        summarized = summarize_gpo_contents(self._contents())

        assert "machine_registry_xml" not in summarized
        assert "user_registry_xml" not in summarized

    def test_missing_and_none_sections_are_tolerated(self):
        summarized = summarize_gpo_contents({
            "files": [],
            "gpt_ini": {},
            "machine_registry_pol": None,
            "user_registry_pol": None,
            "applocker": None,
            "security_templates": [],
            "scripts": [],
        })

        assert summarized["machine_registry_pol"] is None
        assert summarized["applocker"] is None
        assert summarized["security_templates"] == []


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
