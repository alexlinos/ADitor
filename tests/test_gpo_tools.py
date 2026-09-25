"""Tests for the GPO tool layer (orchestration, not parsing).

Parsing is covered in ``test_gpo_parsers.py``. Here we check the LDAP/SMB
orchestration and the ``summary`` flag of ``get_gpo_contents``. No network, no
LDAP, no SMB: the LDAP manager is a Mock, ``smbclient`` is stubbed into
``sys.modules`` so the test does not depend on the optional ``smb`` extra, and
the SYSVOL read is patched out entirely.

All names and identifiers below are placeholders (``DC=test,DC=local``,
synthetic GUIDs, universal well-known SIDs only).
"""

import builtins
import io
import json
import sys
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from aditor.tools.gpo import GPOTools

GPO_GUID = '11111111-1111-1111-1111-111111111111'
RULE_ID = 'aaaaaaaa-0000-0000-0000-000000000001'
PATH_RULE_XML = (
    '<FilePathRule Id="' + RULE_ID + '" Name="Allow Program Files" '
    'Description="" UserOrGroupSid="S-1-1-0" Action="Allow">'
    '<Conditions><FilePathCondition Path="%PROGRAMFILES%\\*" /></Conditions>'
    '</FilePathRule>'
)


@pytest.fixture
def mock_ldap_manager():
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    manager.ad_config.domain = "test.local"
    manager.ad_config.server = "ldaps://dc.test.local:636"
    manager.ad_config.bind_dn = "CN=binduser,DC=test,DC=local"
    manager.ad_config.password = "not-a-real-password"
    return manager


@pytest.fixture
def gpo_tools(mock_ldap_manager):
    return GPOTools(mock_ldap_manager)


@pytest.fixture
def resolved_gpo(mock_ldap_manager):
    """LDAP resolves the identifier to one groupPolicyContainer."""
    mock_ldap_manager.search.return_value = [{
        'dn': 'CN={' + GPO_GUID + '},CN=Policies,CN=System,DC=test,DC=local',
        'attributes': {
            'cn': '{' + GPO_GUID + '}',
            'displayName': 'Test Policy',
            'gPCFileSysPath': r'\\test.local\SysVol\test.local\Policies\{'
                              + GPO_GUID + '}',
            'versionNumber': 3,
        },
    }]
    return mock_ldap_manager


def sysvol_contents():
    """What _read_gpo_sysvol returns for a rules-heavy GPO."""
    return {
        "smb_source": r"\\dc.test.local\SYSVOL\test.local\Policies\{" + GPO_GUID + "}",
        "files": [{"path": "GPT.INI", "size": 59},
                  {"path": r"Machine\Registry.pol", "size": 1024}],
        "gpt_ini": {"General": ["Version=3"]},
        "machine_registry_pol": {
            "entry_count": 2,
            "entries_truncated": False,
            "entries": [
                {"key": r"Software\Policies\Test", "value": "MinPwdLength",
                 "type": "REG_DWORD", "data": 14},
                {"key": "Software\\Policies\\Microsoft\\Windows\\SrpV2\\Exe\\"
                        + RULE_ID,
                 "value": "Value", "type": "REG_SZ", "data": PATH_RULE_XML},
            ],
        },
        "user_registry_pol": None,
        "applocker": {"collections": {"Exe": {
            "enforcement_mode": "Enabled",
            "rules": [{"id": RULE_ID, "xml": PATH_RULE_XML}],
            "rule_count": 1,
        }}},
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


def read_contents(gpo_tools, **kwargs):
    """Call get_gpo_contents with SMB stubbed out, returning the parsed JSON."""
    with patch.dict(sys.modules, {'smbclient': Mock()}), \
         patch.object(GPOTools, '_read_gpo_sysvol',
                      return_value=sysvol_contents()) as read:
        result = gpo_tools.get_gpo_contents('Test Policy', **kwargs)
    assert read.called, "the SYSVOL read should have been reached"
    return json.loads(result[0].text)


class TestGetGpoContentsFullMode:
    """summary=False must behave exactly as before summary mode existed."""

    def test_full_output_shape(self, gpo_tools, resolved_gpo):
        response = read_contents(gpo_tools)

        assert response['identifier'] == 'Test Policy'
        assert response['guid'] == GPO_GUID
        assert response['display_name'] == 'Test Policy'
        assert response['sysvol_path'].endswith('{' + GPO_GUID + '}')
        # Identity keys plus every key _read_gpo_sysvol produced, nothing more.
        assert set(response) == {
            'identifier', 'guid', 'display_name', 'sysvol_path'
        } | set(sysvol_contents())

    def test_full_output_keeps_registry_entries_and_rule_xml(self, gpo_tools,
                                                             resolved_gpo):
        response = read_contents(gpo_tools)

        assert len(response['machine_registry_pol']['entries']) == 2
        rule = response['applocker']['collections']['Exe']['rules'][0]
        assert rule['xml'] == PATH_RULE_XML
        assert response['security_templates'][0]['sections']['Version'] == [
            'Revision=1']

    def test_full_output_has_no_detail_marker(self, gpo_tools, resolved_gpo):
        response = read_contents(gpo_tools)

        assert 'detail' not in response
        assert 'note' not in response

    def test_default_is_full(self, gpo_tools, resolved_gpo):
        assert read_contents(gpo_tools) == read_contents(gpo_tools, summary=False)


class TestGetGpoContentsSummaryMode:
    """summary=True keeps the shape and drops the heavy bodies."""

    def test_identity_and_files_are_kept(self, gpo_tools, resolved_gpo):
        response = read_contents(gpo_tools, summary=True)

        assert response['guid'] == GPO_GUID
        assert response['display_name'] == 'Test Policy'
        assert response['files'] == sysvol_contents()['files']
        assert response['gpt_ini'] == {"General": ["Version=3"]}

    def test_registry_entries_are_omitted(self, gpo_tools, resolved_gpo):
        response = read_contents(gpo_tools, summary=True)

        assert response['machine_registry_pol'] == {
            'entry_count': 2, 'entries_truncated': False}
        assert 'entries' not in response['machine_registry_pol']

    def test_applocker_rules_become_digests(self, gpo_tools, resolved_gpo):
        response = read_contents(gpo_tools, summary=True)

        collection = response['applocker']['collections']['Exe']
        assert collection['enforcement_mode'] == 'Enabled'
        assert collection['rule_count'] == 1
        assert collection['rules'] == [{
            'type': 'FilePathRule',
            'id': RULE_ID,
            'name': 'Allow Program Files',
            'action': 'Allow',
            'sid': 'S-1-1-0',
        }]

    def test_templates_and_scripts_reduce_to_section_names(self, gpo_tools,
                                                           resolved_gpo):
        response = read_contents(gpo_tools, summary=True)

        assert response['security_templates'][0]['sections'] == [
            'Version', 'System Access']
        assert response['scripts'][0]['sections'] == ['Startup']

    def test_detail_marker_and_note(self, gpo_tools, resolved_gpo):
        response = read_contents(gpo_tools, summary=True)

        assert response['detail'] == 'summary'
        assert 'summary=false' in response['note']

    def test_summary_is_smaller_and_carries_no_rule_xml(self, gpo_tools,
                                                        resolved_gpo):
        full = json.dumps(read_contents(gpo_tools))
        summary = json.dumps(read_contents(gpo_tools, summary=True))

        assert len(summary) < len(full)
        assert 'FilePathCondition' not in summary  # no rule XML body survived
        assert 'MinPwdLength' not in summary       # no registry entries survived

    def test_summary_adds_only_detail_and_note_to_the_shape(self, gpo_tools,
                                                            resolved_gpo):
        full = read_contents(gpo_tools)
        summary = read_contents(gpo_tools, summary=True)

        assert set(summary) - set(full) == {'detail', 'note'}


class FakeSmbClient:
    """An in-memory stand-in for the ``smbclient`` module.

    ``_read_gpo_sysvol`` does ``import smbclient`` inside the method, so
    substituting this object in ``sys.modules`` exercises the real walk/stat/read
    code path — including the **relative paths** it looks for, which is the part
    that can silently be wrong. Nothing here touches a network or a filesystem.
    """

    def __init__(self, files):
        # {relative SYSVOL path, spelled as Windows spells it: bytes}
        self.files = dict(files)
        self.sessions = []
        self.reset_calls = 0
        self.opened = []

    # --- the bits of the smbclient API _read_gpo_sysvol uses ---------------

    def register_session(self, host, username=None, password=None):
        self.sessions.append(host)

    def walk(self, base):
        by_directory = {}
        for relative in self.files:
            parts = relative.split("\\")
            directory = "\\".join([base] + parts[:-1])
            by_directory.setdefault(directory, []).append(parts[-1])
        for directory, names in by_directory.items():
            yield directory, [], names

    def _relative(self, full, base_marker="Policies\\{"):
        for relative in self.files:
            if full.endswith("\\" + relative):
                return relative
        raise FileNotFoundError(full)

    def stat(self, full):
        return SimpleNamespace(st_size=len(self.files[self._relative(full)]))

    @contextmanager
    def open_file(self, full, mode="rb"):
        relative = self._relative(full)
        self.opened.append(relative)
        yield io.BytesIO(self.files[relative])

    def reset_connection_cache(self):
        self.reset_calls += 1


def registry_xml(*properties):
    """A hand-written Registry.xml with one <Registry> item per argument."""
    items = "".join(f"<Registry name=\"Item\"><Properties {attrs}/></Registry>"
                    for attrs in properties)
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<RegistrySettings clsid="{A3CCFC41-0000-0000-0000-000000000002}">'
        f'{items}</RegistrySettings>'
    ).encode("utf-8")


KDC_PROPERTIES = (
    'action="U" displayDecimal="0" default="0" hive="HKEY_LOCAL_MACHINE" '
    'key="SYSTEM\\CurrentControlSet\\Services\\Kdc" '
    'name="DefaultDomainSupportedEncTypes" type="REG_DWORD" value="00000038"'
)
USER_PROPERTIES = (
    'action="C" hive="HKEY_CURRENT_USER" key="SOFTWARE\\Test" '
    'name="Flag" type="REG_DWORD" value="00000001"'
)

GPT_INI = b"[General]\r\nVersion=3\r\n"


class TestReadGpoSysvolFindsRegistryPreferences:
    """_read_gpo_sysvol must look in the right place for Registry.xml.

    The relative paths are the whole risk in this deliverable: a scanner that
    reads ``Preferences\\Registry.xml`` instead of
    ``Preferences\\Registry\\Registry.xml`` finds nothing and reports a clean
    domain. These tests drive the real walk/read code against an in-memory
    share so the path spelling is actually pinned.
    """

    def _read(self, gpo_tools, files, **kwargs):
        fake = FakeSmbClient(files)
        with patch.dict(sys.modules, {'smbclient': fake}):
            contents = gpo_tools._read_gpo_sysvol(
                rf'\\test.local\SysVol\test.local\Policies\{{{GPO_GUID}}}',
                kwargs.pop('include_registry', True),
                kwargs.pop('max_value_chars', 6000))
        return contents, fake

    def test_the_machine_preferences_file_is_read_and_parsed(self, gpo_tools):
        contents, _fake = self._read(gpo_tools, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml":
                registry_xml(KDC_PROPERTIES),
        })

        assert contents["machine_registry_xml"]["entry_count"] == 1
        entry = contents["machine_registry_xml"]["entries"][0]
        assert entry["value_name"] == "DefaultDomainSupportedEncTypes"
        assert entry["value"] == 56, "0x38, not decimal 38"
        assert entry["action"] == "U"

    def test_the_user_preferences_twin_is_read_too(self, gpo_tools):
        contents, _fake = self._read(gpo_tools, {
            "GPT.INI": GPT_INI,
            r"User\Preferences\Registry\Registry.xml":
                registry_xml(USER_PROPERTIES),
        })

        assert contents["user_registry_xml"]["entry_count"] == 1
        assert contents["user_registry_xml"]["entries"][0]["hive"] == \
            "HKEY_CURRENT_USER"
        assert "machine_registry_xml" not in contents

    def test_both_sides_are_read_independently(self, gpo_tools):
        contents, _fake = self._read(gpo_tools, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml":
                registry_xml(KDC_PROPERTIES),
            r"User\Preferences\Registry\Registry.xml":
                registry_xml(USER_PROPERTIES),
        })

        assert contents["machine_registry_xml"]["entries"][0]["value"] == 56
        assert contents["user_registry_xml"]["entries"][0]["value"] == 1

    def test_a_gpo_with_no_preferences_is_byte_identical_to_before(self,
                                                                  gpo_tools):
        """The common case must not change shape at all.

        Spelled out as an exact dict rather than a subset check: the keys are
        added **only** when the GPO has a preferences file, so a GPO without one
        must produce precisely the eight keys this method has always produced.
        """
        contents, _fake = self._read(gpo_tools, {"GPT.INI": GPT_INI})

        assert contents == {
            "smb_source": rf"\\dc.test.local\SysVol\test.local\Policies"
                          rf"\{{{GPO_GUID}}}",
            "files": [{"path": "GPT.INI", "size": len(GPT_INI)}],
            "gpt_ini": {"General": ["Version=3"]},
            "machine_registry_pol": None,
            "user_registry_pol": None,
            "applocker": None,
            "security_templates": [],
            "scripts": [],
        }

    def test_a_malformed_preferences_file_yields_an_empty_block_not_a_crash(
            self, gpo_tools):
        contents, _fake = self._read(gpo_tools, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml": b"<RegistrySettings",
        })

        assert contents["machine_registry_xml"] == {"entry_count": 0,
                                                    "entries": []}

    def test_include_registry_false_skips_the_preferences_file(self, gpo_tools):
        """Preferences are registry content, so the same switch governs them."""
        contents, _fake = self._read(gpo_tools, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml":
                registry_xml(KDC_PROPERTIES),
        }, include_registry=False)

        assert "machine_registry_xml" not in contents

    def test_the_preferences_file_is_listed_in_the_file_inventory(self,
                                                                 gpo_tools):
        contents, _fake = self._read(gpo_tools, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml":
                registry_xml(KDC_PROPERTIES),
        })

        assert any(entry["path"].endswith(r"Registry\Registry.xml")
                   for entry in contents["files"])


class TestGetGpoContentsRegistryPreferences:
    """The preferences block surfaces through the tool, full and summarized."""

    def _contents_with_preferences(self):
        contents = sysvol_contents()
        contents["machine_registry_xml"] = {
            "entry_count": 2,
            "entries": [
                {"hive": "HKEY_LOCAL_MACHINE",
                 "key": r"SYSTEM\CurrentControlSet\Services\Kdc",
                 "value_name": "DefaultDomainSupportedEncTypes",
                 "type": 4, "type_name": "REG_DWORD", "value": 56,
                 "action": "U", "order": 1, "has_filters": False,
                 "disabled": False},
                {"hive": "HKEY_LOCAL_MACHINE",
                 "key": r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
                 "value_name": "EnableCertPaddingCheck",
                 "type": 1, "type_name": "REG_SZ", "value": "1",
                 "action": "C", "order": 2, "has_filters": False,
                 "disabled": False},
            ],
        }
        return contents

    def _read(self, gpo_tools, **kwargs):
        with patch.dict(sys.modules, {'smbclient': Mock()}), \
             patch.object(GPOTools, '_read_gpo_sysvol',
                          return_value=self._contents_with_preferences()):
            result = gpo_tools.get_gpo_contents('Test Policy', **kwargs)
        return json.loads(result[0].text)

    def test_the_full_response_carries_every_preference_item(self, gpo_tools,
                                                             resolved_gpo):
        response = self._read(gpo_tools)

        block = response['machine_registry_xml']
        assert block['entry_count'] == 2
        assert [entry['value'] for entry in block['entries']] == [56, '1']
        assert [entry['action'] for entry in block['entries']] == ['U', 'C']

    def test_summary_reduces_the_block_to_its_count(self, gpo_tools,
                                                    resolved_gpo):
        response = self._read(gpo_tools, summary=True)

        assert response['machine_registry_xml'] == {'entry_count': 2}
        assert 'entries' not in response['machine_registry_xml']

    def test_summary_does_not_leak_a_preference_value(self, gpo_tools,
                                                      resolved_gpo):
        summary = json.dumps(self._read(gpo_tools, summary=True))

        assert 'DefaultDomainSupportedEncTypes' not in summary

    def test_the_block_does_not_disturb_the_rest_of_the_shape(self, gpo_tools,
                                                              resolved_gpo):
        response = self._read(gpo_tools)

        assert set(response) == {
            'identifier', 'guid', 'display_name', 'sysvol_path'
        } | set(self._contents_with_preferences())


class TestGetGpoContentsErrors:
    """Error paths stay unchanged."""

    def test_gpo_not_found(self, gpo_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []

        with patch.dict(sys.modules, {'smbclient': Mock()}):
            result = gpo_tools.get_gpo_contents('No Such Policy', summary=True)

        response = json.loads(result[0].text)
        assert response['success'] is False
        assert 'not found' in response['error']

    def test_missing_smbprotocol_is_reported(self, gpo_tools, resolved_gpo):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'smbclient':
                raise ImportError('No module named smbclient')
            return real_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=fake_import):
            result = gpo_tools.get_gpo_contents('Test Policy')

        response = json.loads(result[0].text)
        assert response['success'] is False
        assert 'smbprotocol' in response['error']


class TestGpoSchemaInfo:
    """The schema must describe what the tool actually does."""

    def test_operations_exist(self, gpo_tools):
        schema = gpo_tools.get_schema_info()

        for operation in schema['operations']:
            assert hasattr(gpo_tools, operation)

    def test_notes_document_summary_mode_and_the_gplink_bitmask(self, gpo_tools):
        notes = ' '.join(gpo_tools.get_schema_info()['notes'])

        assert 'summary=True' in notes
        assert 'bit 0=link disabled, bit 1=enforced' in notes

    def test_notes_document_the_preferences_file_and_its_hex_values(self,
                                                                   gpo_tools):
        notes = ' '.join(gpo_tools.get_schema_info()['notes'])

        assert r'Preferences\Registry\Registry.xml' in notes
        assert 'machine_registry_xml' in notes
        assert 'hexadecimal' in notes
        assert 'Delete' in notes and 'Create' in notes


class TestNoParsingLeftInTheToolModule:
    """gpo.py is orchestration only; the parsers moved to aditor.gpo.parsers."""

    @pytest.mark.parametrize('method_name', [
        '_parse_registry_pol',
        '_parse_ini',
        '_extract_applocker',
        '_decode_version',
        '_decode_gpo_status',
        '_parse_gp_link',
        '_normalize_guid',
    ])
    def test_pure_parsers_are_not_methods_anymore(self, method_name):
        assert not hasattr(GPOTools, method_name), (
            f"{method_name} moved to aditor.gpo.parsers in WP3; "
            "do not reintroduce it as a method"
        )

    # _smb_target moved to aditor.hardening.collect.Scanner with the SYSVOL
    # reader; _read_gpo_sysvol stays here as a delegate for get_gpo_contents.
    @pytest.mark.parametrize('method_name', [
        '_read_gpo_sysvol',
        '_resolve_gpo_name',
        '_find_links',
    ])
    def test_impure_helpers_stay_on_the_class(self, method_name):
        assert hasattr(GPOTools, method_name)
