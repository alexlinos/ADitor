"""Tests for the SYSVOL reader in :mod:`aditor.hardening.collect`.

Parsing is covered in ``test_gpo_parsers.py``. Here the real walk/read code in
:meth:`Scanner._read_gpo_sysvol` runs against an in-memory ``smbclient``, so the
relative paths it looks for are pinned. No network, no LDAP, no SMB.

All names and identifiers below are placeholders (``DC=test,DC=local``,
synthetic GUIDs).
"""

import io
import sys
from contextlib import contextmanager
from unittest.mock import Mock, patch

import pytest
from aditor.hardening.collect import Scanner

GPO_GUID = '11111111-1111-1111-1111-111111111111'


@pytest.fixture
def scanner():
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    manager.ad_config.domain = "test.local"
    manager.ad_config.server = "ldaps://dc.test.local:636"
    manager.ad_config.bind_dn = "CN=binduser,DC=test,DC=local"
    manager.ad_config.password = "not-a-real-password"
    return Scanner(manager)


class FakeSmbClient:
    """An in-memory stand-in for the ``smbclient`` module.

    ``_read_gpo_sysvol`` does ``import smbclient`` inside the method, so
    substituting this object in ``sys.modules`` exercises the real walk/read
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

GPT_INI = b"[General]\r\nVersion=3\r\n"


class TestReadGpoSysvolFindsRegistryPreferences:
    """_read_gpo_sysvol must look in the right place for Registry.xml.

    The relative paths are the whole risk in this deliverable: a scanner that
    reads ``Preferences\\Registry.xml`` instead of
    ``Preferences\\Registry\\Registry.xml`` finds nothing and reports a clean
    domain. These tests drive the real walk/read code against an in-memory
    share so the path spelling is actually pinned.
    """

    def _read(self, scanner, files):
        fake = FakeSmbClient(files)
        with patch.dict(sys.modules, {'smbclient': fake}):
            contents = scanner._read_gpo_sysvol(
                rf'\\test.local\SysVol\test.local\Policies\{{{GPO_GUID}}}')
        return contents, fake

    def test_the_machine_preferences_file_is_read_and_parsed(self, scanner):
        contents, _fake = self._read(scanner, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml":
                registry_xml(KDC_PROPERTIES),
        })

        assert len(contents["machine_registry_xml"]["entries"]) == 1
        entry = contents["machine_registry_xml"]["entries"][0]
        assert entry["value_name"] == "DefaultDomainSupportedEncTypes"
        assert entry["value"] == 56, "0x38, not decimal 38"
        assert entry["action"] == "U"

    def test_a_gpo_with_no_preferences_has_no_preferences_block(self, scanner):
        """The block is added only when the GPO has a preferences file."""
        contents, _fake = self._read(scanner, {"GPT.INI": GPT_INI})

        assert contents == {"machine_registry_pol": None,
                            "security_templates": []}

    def test_a_malformed_preferences_file_yields_an_empty_block_not_a_crash(
            self, scanner):
        contents, _fake = self._read(scanner, {
            "GPT.INI": GPT_INI,
            r"Machine\Preferences\Registry\Registry.xml": b"<RegistrySettings",
        })

        assert contents["machine_registry_xml"] == {"entries": []}

