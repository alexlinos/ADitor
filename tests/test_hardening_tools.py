"""Tests for the scan_hardening orchestration layer.

Parsing is covered in ``test_gpo_parsers.py``, catalog loading in
``test_hardening_catalog.py``, and verdict logic in
``test_hardening_evaluator.py``. Here we check the wiring: LDAP enumeration,
link resolution, the SYSVOL read, the provenance header, and argument handling.

No network, no LDAP, no SMB, no domain controller: the LDAP manager is a Mock,
``smbclient`` is stubbed into ``sys.modules`` so the test does not need the
optional ``smb`` extra, and the SYSVOL read is patched out. Every GPO, DN and
GUID below is synthesized (``DC=test,DC=local``, placeholder GUIDs).
"""

import json
import sys
from unittest.mock import Mock, patch

import pytest

from aditor.hardening import SCAN_ENGINE_VERSION
from aditor.tools.gpo import GPOTools
from aditor.tools.hardening import (
    HardeningTools,
    _machine_pol_entries,
    _template_entries,
)

BASE_DN = "DC=test,DC=local"
POLICIES_DN = f"CN=Policies,CN=System,{BASE_DN}"
DC_OU = f"OU=Domain Controllers,{BASE_DN}"

GUID_SIGNING = "11111111-1111-1111-1111-111111111111"
GUID_OVERRIDE = "22222222-2222-2222-2222-222222222222"

# The two [Registry Values] lines a real GPO was observed to carry.
LDAP_LINES = [
    "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    "\\LdapEnforceChannelBinding=4,2",
    "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    "\\LDAPServerIntegrity=4,2",
]


def gpo_dn(guid):
    return f"CN={{{guid}}},CN=Policies,CN=System,{BASE_DN}"


def gpo_entry(guid, display_name):
    """A groupPolicyContainer LDAP entry, as ldap3 hands it back."""
    return {
        "dn": gpo_dn(guid),
        "attributes": {
            "cn": "{" + guid + "}",
            "displayName": display_name,
            "gPCFileSysPath": rf"\\test.local\SysVol\test.local\Policies\{{{guid}}}",
        },
    }


def link_entry(target_dn, *gpo_guids, enforced=False, gp_options=0):
    """An object carrying a gPLink attribute."""
    options = 2 if enforced else 0
    gp_link = "".join(
        f"[LDAP://cn={{{guid}}},cn=policies,cn=system,{BASE_DN};{options}]"
        for guid in gpo_guids)
    return {
        "dn": target_dn,
        "attributes": {"gPLink": gp_link, "gPOptions": gp_options,
                       "distinguishedName": target_dn},
    }


def sysvol_contents(*registry_lines, pol_entries=None):
    """What GPOTools._read_gpo_sysvol returns for a GPO, synthesized."""
    return {
        "smb_source": r"\\dc.test.local\SYSVOL\test.local\Policies",
        "files": [{"path": "GPT.INI", "size": 59}],
        "gpt_ini": {"General": ["Version=3"]},
        "machine_registry_pol": {
            "entry_count": len(pol_entries or []),
            "entries_truncated": False,
            "entries": list(pol_entries or []),
        },
        "user_registry_pol": None,
        "applocker": None,
        "security_templates": [{
            "path": r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
            "sections": {
                "Unicode": ["Unicode=yes"],
                "Registry Values": list(registry_lines),
                "Version": ["Revision=1"],
            },
        }],
        "scripts": [],
    }


@pytest.fixture
def mock_ldap_manager():
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = BASE_DN
    manager.ad_config.domain = "test.local"
    manager.ad_config.server = "ldaps://dc.test.local:636"
    manager.ad_config.bind_dn = f"CN=binduser,{BASE_DN}"
    manager.ad_config.password = "not-a-real-password"
    return manager


@pytest.fixture
def tools(mock_ldap_manager):
    return HardeningTools(mock_ldap_manager)


def wire_ldap(manager, gpo_entries, link_entries):
    """Route the two searches scan_hardening makes to the right fixtures."""
    def search(search_base=None, search_filter=None, **_kwargs):
        if "gPLink" in (search_filter or ""):
            return link_entries
        if search_base == POLICIES_DN:
            return gpo_entries
        return []
    manager.search.side_effect = search


def run_scan(tools, contents_by_guid, **kwargs):
    """Call scan_hardening with SMB stubbed out; return the parsed JSON."""
    def read_sysvol(sysvol_path, include_registry=True, max_value_chars=6000):
        for guid, contents in contents_by_guid.items():
            if guid in sysvol_path:
                if isinstance(contents, Exception):
                    raise contents
                return contents
        return sysvol_contents()

    with patch.dict(sys.modules, {"smbclient": Mock()}), \
         patch.object(GPOTools, "_read_gpo_sysvol", side_effect=read_sysvol):
        result = tools.scan_hardening(**kwargs)
    return json.loads(result[0].text)


class TestContentExtraction:
    """The two helpers that turn get_gpo_contents output into evaluator input."""

    def test_registry_values_sections_become_structured_entries(self):
        entries = _template_entries(sysvol_contents(*LDAP_LINES))

        assert [e["value"] for e in entries] == [2, 2]
        assert entries[0]["type_name"] == "REG_DWORD"

    def test_entries_from_several_templates_are_merged(self):
        contents = sysvol_contents(LDAP_LINES[0])
        contents["security_templates"].append({
            "path": r"Machine\Microsoft\Windows NT\SecEdit\Other.inf",
            "sections": {"Registry Values": [LDAP_LINES[1]]},
        })

        assert len(_template_entries(contents)) == 2

    def test_a_gpo_with_no_template_yields_no_entries(self):
        contents = sysvol_contents()
        contents["security_templates"] = []

        assert _template_entries(contents) == []

    def test_a_template_without_a_registry_values_section_is_skipped(self):
        contents = sysvol_contents()
        contents["security_templates"][0]["sections"] = {"Version": ["Revision=1"]}

        assert _template_entries(contents) == []

    def test_machine_pol_entries_are_passed_through(self):
        entry = {"key": "Software\\Policies\\Test", "value": "Flag",
                 "type": "REG_DWORD", "data": 1}

        assert _machine_pol_entries(sysvol_contents(pol_entries=[entry])) == [entry]

    def test_a_gpo_with_no_registry_pol_yields_no_entries(self):
        contents = sysvol_contents()
        contents["machine_registry_pol"] = None

        assert _machine_pol_entries(contents) == []


class TestScanHardening:

    def test_the_live_verified_gpo_passes_both_ldap_controls(self, tools,
                                                             mock_ldap_manager):
        """End to end through the tool: LDAP -> SYSVOL -> parser -> evaluator."""
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Example DC LDAP Signing")],
                  [link_entry(DC_OU, GUID_SIGNING)])

        response = run_scan(
            tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)},
            control_ids=["DEVORE-03-LDAP-SERVER-SIGNING",
                         "DEVORE-05-LDAP-CHANNEL-BINDING"])

        assert response["counts"]["pass"] == 2
        assert response["counts"]["fail"] == 0
        results = {f["control_id"]: f for f in response["findings"]}
        for finding in results.values():
            assert finding["result"] == "pass"
            assert finding["rollout_state"] == "enforced"
            found = finding["evidence"]["found"][0]
            assert found["gpo_dn"] == gpo_dn(GUID_SIGNING)
            assert found["links"][0]["target_dn"] == DC_OU
            assert found["links"][0]["enforced"] is False

    def test_the_provenance_header_is_audit_grade(self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        scan = run_scan(tools, {})["scan"]

        assert scan["tool"] == "scan_hardening"
        assert scan["tool_version"] == SCAN_ENGINE_VERSION
        assert scan["catalog_version"]
        assert scan["catalog_source"].endswith("controls.json")
        assert scan["domain"] == "test.local"
        assert scan["base_dn"] == BASE_DN
        assert scan["timestamp"].endswith("+00:00")
        assert scan["gpos_scanned"] == 1
        assert scan["read_only"] is True
        assert "Precedence is not resolved" in scan["precedence"]
        assert scan["baseline"]["primary_source"]

    def test_counts_and_findings_cover_the_whole_catalog_by_default(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = run_scan(tools, {})

        assert response["counts"]["total"] == response["scan"]["control_count"]
        assert response["counts"]["needs_baseline_value"] == len(
            response["scan"]["unscored_control_ids"])

    def test_unscored_controls_are_reported_even_when_na_is_hidden(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = run_scan(tools, {}, include_not_applicable=False)

        reported = {f["control_id"] for f in response["findings"]}
        assert set(response["unscored_control_ids"]) <= reported
        for finding in response["findings"]:
            if finding["control_id"] in response["unscored_control_ids"]:
                assert finding["scored"] is False
                assert finding["unscored_reason"] == "needs_baseline_value"

    def test_include_not_applicable_shows_the_conditional_controls(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        hidden = run_scan(tools, {}, include_not_applicable=False)
        shown = run_scan(tools, {}, include_not_applicable=True)

        assert len(shown["findings"]) > len(hidden["findings"])
        assert shown["counts"]["total"] == hidden["counts"]["total"]
        assert shown["scan"]["include_not_applicable"] is True

    def test_a_two_gpo_conflict_is_surfaced_by_the_tool(self, tools,
                                                       mock_ldap_manager):
        wire_ldap(
            mock_ldap_manager,
            [gpo_entry(GUID_SIGNING, "Example DC LDAP Signing"),
             gpo_entry(GUID_OVERRIDE, "Legacy LDAP Exception")],
            [link_entry(DC_OU, GUID_SIGNING),
             link_entry(BASE_DN, GUID_OVERRIDE, enforced=True)])

        response = run_scan(
            tools,
            {GUID_SIGNING: sysvol_contents(LDAP_LINES[1]),
             GUID_OVERRIDE: sysvol_contents(
                 "MACHINE\\System\\CurrentControlSet\\Services\\NTDS"
                 "\\Parameters\\LDAPServerIntegrity=4,0")},
            control_ids=["DEVORE-03-LDAP-SERVER-SIGNING"])

        finding = response["findings"][0]
        assert finding["result"] == "fail"
        assert finding["conflict"]["kind"] == "enforced-override"
        assert response["counts"]["conflicts"] == 1
        assert {s["gpo_display_name"] for s in finding["conflict"]["settings"]} == {
            "Example DC LDAP Signing", "Legacy LDAP Exception"}

    def test_enforced_links_are_resolved_from_the_gplink_attribute(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Example DC LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING, enforced=True, gp_options=1)])

        response = run_scan(tools, {GUID_SIGNING: sysvol_contents(LDAP_LINES[1])},
                            control_ids=["DEVORE-03-LDAP-SERVER-SIGNING"])

        link = response["findings"][0]["evidence"]["found"][0]["links"][0]
        assert link == {"target_dn": BASE_DN, "enforced": True,
                        "link_enabled": True, "block_inheritance": True}

    def test_an_unlinked_gpo_is_still_scanned_and_reported_as_unlinked(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Orphaned Signing Policy")], [])

        response = run_scan(tools, {GUID_SIGNING: sysvol_contents(LDAP_LINES[1])},
                            control_ids=["DEVORE-03-LDAP-SERVER-SIGNING"])

        assert response["findings"][0]["evidence"]["found"][0]["links"] == []

    def test_registry_pol_controls_are_evaluated_too(self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LLMNR Off")], [])
        pol_entry = {"key": "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
                     "value": "EnableMulticast", "type": "REG_DWORD", "data": 0}

        response = run_scan(tools,
                            {GUID_SIGNING: sysvol_contents(pol_entries=[pol_entry])},
                            control_ids=["DEVORE-06-LLMNR-DISABLE"])

        finding = response["findings"][0]
        assert finding["result"] == "pass"
        assert finding["evidence"]["found"][0]["source_file"] == "Registry.pol"

    def test_an_unreadable_gpo_is_disclosed_and_does_not_abort_the_scan(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Example DC LDAP Signing"),
                   gpo_entry(GUID_OVERRIDE, "Unreadable Policy")], [])

        response = run_scan(
            tools,
            {GUID_SIGNING: sysvol_contents(LDAP_LINES[1]),
             GUID_OVERRIDE: OSError("SYSVOL access denied")},
            control_ids=["DEVORE-03-LDAP-SERVER-SIGNING"])

        assert response["scan"]["gpos_unreadable"] == 1
        assert response["gpo_read_errors"][0]["display_name"] == "Unreadable Policy"
        assert "access denied" in response["gpo_read_errors"][0]["error"]
        notes = response["findings"][0]["evidence"]["notes"]
        assert any("could not be read" in note for note in notes)
        assert response["findings"][0]["result"] == "pass"

    def test_a_domain_with_no_gpos_still_reports_every_control(self, tools,
                                                              mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [], [])

        response = run_scan(tools, {})

        assert response["scan"]["gpos_scanned"] == 0
        assert response["counts"]["fail"] > 0
        assert response["counts"]["error"] == 0


class TestScanHardeningArguments:

    def test_control_ids_narrow_the_scan(self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = run_scan(tools, {},
                            control_ids=["DEVORE-06-NBTNS-NODETYPE"])

        assert response["counts"]["total"] == 1
        assert [f["control_id"] for f in response["findings"]] == [
            "DEVORE-06-NBTNS-NODETYPE"]

    def test_control_ids_are_case_insensitive(self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = run_scan(tools, {},
                            control_ids=["devore-06-nbtns-nodetype"])

        assert [f["control_id"] for f in response["findings"]] == [
            "DEVORE-06-NBTNS-NODETYPE"]

    def test_unknown_control_ids_are_reported_not_silently_dropped(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = run_scan(tools, {},
                            control_ids=["DEVORE-06-NBTNS-NODETYPE", "MADE-UP-1"])

        assert response["unknown_control_ids"] == ["MADE-UP-1"]
        assert response["counts"]["total"] == 1

    def test_only_unknown_control_ids_is_an_error_listing_what_exists(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = run_scan(tools, {}, control_ids=["MADE-UP-1"])

        assert response["success"] is False
        assert "MADE-UP-1" in response["error"]
        assert "DEVORE-03-LDAP-SERVER-SIGNING" in response["known_control_ids"]


class TestScanHardeningFailureModes:

    def test_missing_smbprotocol_is_an_actionable_error(self, tools,
                                                        mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__

        def no_smbclient(name, *args, **kwargs):
            if name == "smbclient":
                raise ImportError("No module named 'smbclient'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_smbclient):
            result = tools.scan_hardening()
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "smbprotocol" in response["error"]

    def test_an_ldap_failure_is_reported_not_raised(self, tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = RuntimeError("LDAP server down")

        with patch.dict(sys.modules, {"smbclient": Mock()}):
            result = tools.scan_hardening()
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "LDAP server down" in response["error"]

    def test_a_broken_catalog_fails_loudly_before_any_scanning(
            self, tools, mock_ldap_manager):
        from aditor.hardening.catalog import CatalogError

        with patch("aditor.tools.hardening.load_catalog",
                   side_effect=CatalogError("duplicate control id 'X'")):
            result = tools.scan_hardening()
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "catalog failed to load" in response["error"]
        assert mock_ldap_manager.search.called is False


class TestSchemaInfo:

    def test_schema_info_advertises_the_catalog_and_its_limits(self, tools):
        info = tools.get_schema_info()

        assert info["operations"] == ["scan_hardening"]
        assert info["read_only"] is True
        assert info["catalog_version"]
        assert "DEVORE-03-LDAP-SERVER-SIGNING" in info["control_ids"]
        assert info["unscored_control_ids"]
        assert any("Precedence is not resolved" in note for note in info["notes"])
        assert any("needs_baseline_value" in note for note in info["notes"])
