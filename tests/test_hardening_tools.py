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
import re
import sys
from unittest.mock import Mock, patch

import pytest

from aditor.gpo.parsers import parse_registry_xml
from aditor.hardening import SCAN_ENGINE_VERSION, read_scan
from aditor.tools.gpo import GPOTools
from aditor.tools.hardening import (
    HardeningTools,
    _machine_pol_entries,
    _machine_preference_entries,
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


KDC_PREFERENCE_ENTRY = {
    "hive": "HKEY_LOCAL_MACHINE",
    "key": r"SYSTEM\CurrentControlSet\Services\Kdc",
    "value_name": "DefaultDomainSupportedEncTypes",
    "type": 4, "type_name": "REG_DWORD",
    # 0x38 — already hex-decoded by parse_registry_xml, which is what
    # _read_gpo_sysvol hands the snapshot builder.
    "value": 56,
    "action": "U", "order": 1, "has_filters": False, "disabled": False,
}


def preference_entry(**overrides):
    """One parsed Registry.xml item, defaulting to the live-observed KDC one."""
    entry = dict(KDC_PREFERENCE_ENTRY)
    entry.update(overrides)
    return entry


def sysvol_contents(*registry_lines, pol_entries=None, preference_entries=None):
    """What GPOTools._read_gpo_sysvol returns for a GPO, synthesized.

    ``machine_registry_xml`` is added only when ``preference_entries`` is given,
    matching the real reader: the block is absent for a GPO that has no
    Preferences\\Registry\\Registry.xml at all.
    """
    contents = {
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
    if preference_entries is not None:
        contents["machine_registry_xml"] = {
            "entry_count": len(preference_entries),
            "entries": list(preference_entries),
        }
    return contents


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

    def test_preference_entries_are_passed_through(self):
        entry = preference_entry()

        assert _machine_preference_entries(
            sysvol_contents(preference_entries=[entry])) == [entry]

    def test_a_gpo_with_no_preferences_yields_no_preference_entries(self):
        """The key is absent entirely for such a GPO, not None."""
        contents = sysvol_contents()

        assert "machine_registry_xml" not in contents
        assert _machine_preference_entries(contents) == []

    def test_an_empty_preferences_file_yields_no_entries(self):
        assert _machine_preference_entries(
            sysvol_contents(preference_entries=[])) == []

    def test_user_side_preferences_are_not_scanned(self):
        """Machine side only, matching _machine_pol_entries."""
        contents = sysvol_contents()
        contents["user_registry_xml"] = {
            "entry_count": 1, "entries": [preference_entry()]}

        assert _machine_preference_entries(contents) == []

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

    def test_an_os_default_verdict_travels_through_the_tool_labelled(
            self, tools, mock_ldap_manager):
        """No GPO sets LdapClientIntegrity: pass on the default, marked as such."""
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Example DC LDAP Signing")],
                  [link_entry(DC_OU, GUID_SIGNING)])

        response = run_scan(
            tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)},
            control_ids=["DEVORE-03-LDAP-CLIENT-SIGNING"])

        finding = response["findings"][0]
        assert finding["result"] == "pass"
        assert finding["rollout_state"] == "audit"
        assert finding["evidence"]["source"] == "os-default"
        assert finding["evidence"]["os_default"]["value"] == 1
        assert finding["evidence"]["found"] == []
        assert response["counts"]["os_default"] == 1

    def test_smb_signing_gpos_are_scored_end_to_end(self, tools,
                                                    mock_ldap_manager):
        """Previously unscored; the keys are spelled as GPOs spell them."""
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Example Client SMB Signing"),
                   gpo_entry(GUID_OVERRIDE, "Example Server SMB Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING, GUID_OVERRIDE)])

        response = run_scan(tools, {
            GUID_SIGNING: sysvol_contents(
                "MACHINE\\System\\CurrentControlSet\\Services"
                "\\LanmanWorkstation\\Parameters\\RequireSecuritySignature=4,1"),
            GUID_OVERRIDE: sysvol_contents(
                "MACHINE\\System\\CurrentControlSet\\Services"
                "\\LanManServer\\Parameters\\RequireSecuritySignature=4,1"),
        }, control_ids=["DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS",
                        "DEVORE-06-SMB-SERVER-SIGNING-ALWAYS"])

        assert response["counts"]["pass"] == 2
        assert response["counts"]["needs_baseline_value"] == 0
        assert response["unscored_control_ids"] == []

    def test_ntlm_auditing_configured_off_reports_fail_through_the_tool(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "NTLM Auditing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])

        response = run_scan(tools, {GUID_SIGNING: sysvol_contents(
            "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0"
            "\\AuditReceivingNTLMTraffic=4,0")},
            control_ids=["DEVORE-08-NTLM-AUDIT-INCOMING"])

        finding = response["findings"][0]
        assert finding["result"] == "fail"
        assert finding["evidence"]["found"][0]["value"] == 0
        assert response["counts"]["fail"] == 1

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

    def test_a_registry_preference_reaches_the_verdict_through_the_tool(
            self, tools, mock_ldap_manager):
        """The live case, end to end through the orchestration layer.

        The GPO has no Registry.pol and no [Registry Values] section: the
        Registry.xml preference item is its only registry source, exactly as
        observed on the domain where this control was wrongly reported as fail.
        """
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "DefaultDomainSupportedEncTypes")],
                  [link_entry(DC_OU, GUID_SIGNING)])

        response = run_scan(
            tools,
            {GUID_SIGNING: sysvol_contents(
                preference_entries=[preference_entry()])},
            control_ids=["DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"])

        finding = response["findings"][0]
        assert finding["result"] == "pass"
        found = finding["evidence"]["found"][0]
        assert found["value"] == 56
        assert found["delivery"] == "registry-preference"
        assert found["source_file"] == r"Preferences\Registry\Registry.xml"
        assert found["preference"]["action"] == "U"
        assert any("TATTOOS" in note for note in finding["evidence"]["notes"])

    def test_a_preference_that_deletes_the_value_does_not_pass(
            self, tools, mock_ldap_manager):
        """Not a pass — and since P2-WP5 not a `fail` either, but `unknown`.

        A Delete item is not a match, so no value was read. This control's
        documented remediation is a direct write on the DCs, so "no value read"
        does not license a failure verdict; the delete is still disclosed.
        """
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Undo Enc Types")], [])

        response = run_scan(
            tools,
            {GUID_SIGNING: sysvol_contents(
                preference_entries=[preference_entry(action="D")])},
            control_ids=["DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"])

        finding = response["findings"][0]
        assert finding["result"] == "unknown"
        assert finding["result"] != "pass"
        assert finding["rollout_state"] is None
        assert finding["evidence"]["found"] == []
        assert any("DELETE this value" in note
                   for note in finding["evidence"]["notes"])

    def test_a_gpo_with_no_preferences_scores_exactly_as_before(
            self, tools, mock_ldap_manager):
        """The block is absent for such a GPO, and nothing else moves."""
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Example DC LDAP Signing")], [])

        response = run_scan(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)},
                            control_ids=["DEVORE-03-LDAP-SERVER-SIGNING"])

        finding = response["findings"][0]
        assert finding["result"] == "pass"
        assert finding["evidence"]["found"][0]["delivery"] == "security-template"
        assert finding["evidence"]["found"][0]["preference"] is None

    def test_a_policy_and_a_preference_disagreeing_is_a_conflict(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Enc Types By Policy"),
                   gpo_entry(GUID_OVERRIDE, "Enc Types By Preference")], [])
        pol_entry = {"key": r"System\CurrentControlSet\services\KDC",
                     "value": "DefaultDomainSupportedEncTypes",
                     "type": "REG_DWORD", "data": 56}

        response = run_scan(
            tools,
            {GUID_SIGNING: sysvol_contents(pol_entries=[pol_entry]),
             GUID_OVERRIDE: sysvol_contents(
                 preference_entries=[preference_entry(value=38)])},
            control_ids=["DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"])

        finding = response["findings"][0]
        assert finding["result"] == "fail"
        assert finding["conflict"]["kind"] == "policy-preference-disagreement"
        assert {(s["value"], s["delivery"])
                for s in finding["conflict"]["settings"]} == {
            (56, "registry-pol"), (38, "registry-preference")}
        assert response["counts"]["conflicts"] == 1

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


class TestWriteHardeningReport:
    """The report tool's wiring: same scan, rendered, plus the path guard.

    The rendering itself is covered exhaustively in ``test_hardening_report.py``.
    What matters here is that the tool runs the identical scan, writes only where
    it is allowed to, and never writes a file when the scan or the path is bad.
    Still no network: the LDAP manager is a Mock and the SYSVOL read is patched.
    """

    def report(self, tools, contents_by_guid, output_path, **kwargs):
        """Call write_hardening_report with SMB stubbed out; parse the JSON."""
        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            for guid, contents in contents_by_guid.items():
                if guid in sysvol_path:
                    if isinstance(contents, Exception):
                        raise contents
                    return contents
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(GPOTools, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            result = tools.write_hardening_report(str(output_path), **kwargs)
        return json.loads(result[0].text)

    def test_writes_the_file_and_returns_path_and_headline_counts(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        target = tmp_path / "hardening.html"

        response = self.report(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)},
                               target)

        assert response["success"] is True
        assert response["output_path"] == str(target)
        assert response["bytes_written"] == target.stat().st_size
        assert response["format"] == "html"
        assert response["self_contained"] is True
        assert response["headline"]["gpos_scanned"] == 1
        assert response["headline"]["total"] == response["counts"]["total"]
        assert any("PDF is deliberately not produced" in note
                   for note in response["notes"])

    def test_the_written_file_is_valid_self_contained_html_with_provenance(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        target = tmp_path / "hardening.html"

        self.report(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)}, target)
        document = target.read_text(encoding="utf-8")

        assert document.startswith("<!DOCTYPE html>")
        assert document.rstrip().endswith("</html>")
        for token in ("<script", "src=", "<link ", "@import"):
            assert token not in document
        # Provenance rendered in the document, not only in the JSON.
        assert "Provenance" in document
        assert SCAN_ENGINE_VERSION in document
        assert BASE_DN in document
        assert "Catalog version" in document

    def test_the_document_renders_the_same_scan_the_json_tool_returns(
            self, tools, mock_ldap_manager, tmp_path):
        """One scan, two renderings: the report must not invent its own numbers."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        contents = {GUID_SIGNING: sysvol_contents(*LDAP_LINES)}

        scan = run_scan(tools, contents, include_not_applicable=True)
        response = self.report(tools, contents, tmp_path / "r.html")

        assert response["counts"] == scan["counts"]
        assert response["scan"]["catalog_version"] == \
            scan["scan"]["catalog_version"]

    def test_control_ids_narrow_the_report(self, tools, mock_ldap_manager,
                                           tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])

        response = self.report(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)},
                               tmp_path / "one.html",
                               control_ids=["DEVORE-03-LDAP-SERVER-SIGNING"])

        assert response["counts"]["total"] == 1
        document = (tmp_path / "one.html").read_text(encoding="utf-8")
        assert "DEVORE-03-LDAP-SERVER-SIGNING" in document
        assert "DEVORE-01-NTLM-LMCOMPATIBILITYLEVEL" not in document

    def test_unreadable_gpos_reach_the_document_as_a_warning(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Readable"),
                   gpo_entry(GUID_OVERRIDE, "Unreadable")],
                  [link_entry(BASE_DN, GUID_SIGNING, GUID_OVERRIDE)])
        target = tmp_path / "incomplete.html"

        response = self.report(tools, {
            GUID_SIGNING: sysvol_contents(*LDAP_LINES),
            GUID_OVERRIDE: PermissionError("access denied reading SYSVOL"),
        }, target)

        assert response["headline"]["gpos_unreadable"] == 1
        document = target.read_text(encoding="utf-8")
        assert "GPO read failures" in document
        assert "unknown, not clean" in document
        # Ahead of every verdict section, per the WP's acceptance criteria.
        assert document.index('id="read-failures"') < document.index('id="failures"')

    def test_a_bad_path_writes_nothing_and_says_the_scan_succeeded(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])

        response = self.report(tools, {}, tmp_path / "report.json")

        assert response["success"] is False
        assert ".html" in response["error"]
        assert response["scan_succeeded"] is True
        assert list(tmp_path.iterdir()) == []

    def test_refuses_to_clobber_a_file_that_is_not_a_report(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        target = tmp_path / "someones-page.html"
        target.write_text("<html>not ours</html>", encoding="utf-8")

        response = self.report(tools, {}, target)

        assert response["success"] is False
        assert "not an ADitor" in response["error"]
        assert target.read_text(encoding="utf-8") == "<html>not ours</html>"

    def test_creates_missing_parent_directories(self, tools, mock_ldap_manager,
                                                tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])

        response = self.report(tools, {}, tmp_path / "reports" / "2026" / "r.html")

        assert response["success"] is True
        assert (tmp_path / "reports" / "2026" / "r.html").is_file()

    def test_unknown_control_ids_fail_before_any_file_is_written(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])

        response = self.report(tools, {}, tmp_path / "r.html",
                               control_ids=["MADE-UP-1"])

        assert response["success"] is False
        assert "MADE-UP-1" in response["error"]
        assert response["operation"] == "write_hardening_report"
        assert list(tmp_path.iterdir()) == []

    def test_a_broken_catalog_writes_nothing(self, tools, mock_ldap_manager,
                                             tmp_path):
        from aditor.hardening.catalog import CatalogError

        with patch("aditor.tools.hardening.load_catalog",
                   side_effect=CatalogError("duplicate control id 'X'")):
            result = tools.write_hardening_report(str(tmp_path / "r.html"))
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "catalog failed to load" in response["error"]
        assert list(tmp_path.iterdir()) == []

    def test_an_ldap_failure_writes_nothing(self, tools, mock_ldap_manager,
                                            tmp_path):
        mock_ldap_manager.search.side_effect = RuntimeError("LDAP server down")

        with patch.dict(sys.modules, {"smbclient": Mock()}):
            result = tools.write_hardening_report(str(tmp_path / "r.html"))
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "LDAP server down" in response["error"]
        assert list(tmp_path.iterdir()) == []

    def test_missing_smbprotocol_names_this_tool_not_the_other_one(
            self, tools, mock_ldap_manager, tmp_path):
        """The error tells the reader which tool they called."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__

        def no_smbclient(name, *args, **kwargs):
            if name == "smbclient":
                raise ImportError("No module named 'smbclient'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_smbclient):
            result = tools.write_hardening_report(str(tmp_path / "r.html"))
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"].startswith("write_hardening_report reads GPO")
        assert list(tmp_path.iterdir()) == []

    def test_hostile_gpo_display_names_are_escaped_end_to_end(
            self, tools, mock_ldap_manager, tmp_path):
        """Directory data is untrusted all the way from LDAP to the browser."""
        hostile = "Bad <script>alert(\"x\")</script> & 'GPO'"
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, hostile)],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        target = tmp_path / "escaped.html"

        self.report(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)}, target)
        document = target.read_text(encoding="utf-8")

        assert "<script" not in document
        assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in document

    def test_the_scan_stays_read_only(self, tools, mock_ldap_manager, tmp_path):
        """The one side effect is the file; the directory is not touched."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        self.report(tools, {}, tmp_path / "r.html")

        assert mock_ldap_manager.add.called is False
        assert mock_ldap_manager.modify.called is False
        assert mock_ldap_manager.delete.called is False


class TestWriteHardeningScan:
    """The persistence tool's wiring: same scan, written as JSON.

    The file format and its guards are covered in ``test_hardening_scanfile.py``.
    What matters here is that the tool runs the identical scan, writes only where
    it is allowed to, and never leaves a file behind when the scan or the path is
    bad. Still no network: the LDAP manager is a Mock and the SYSVOL read is
    patched.
    """

    def save(self, tools, contents_by_guid, output_path, **kwargs):
        """Call write_hardening_scan with SMB stubbed out; parse the JSON."""
        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            for guid, contents in contents_by_guid.items():
                if guid in sysvol_path:
                    if isinstance(contents, Exception):
                        raise contents
                    return contents
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(GPOTools, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            result = tools.write_hardening_scan(str(output_path), **kwargs)
        return json.loads(result[0].text)

    def test_writes_the_json_and_returns_path_and_headline_counts(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        target = tmp_path / "scan.json"

        response = self.save(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)},
                             target)

        assert response["success"] is True
        assert response["output_path"] == str(target)
        assert response["bytes_written"] == target.stat().st_size
        assert response["format"] == "json"
        assert response["scan_format_version"]
        assert response["headline"]["total"] == response["counts"]["total"]

    def test_the_written_file_is_the_scan_the_json_tool_returns(
            self, tools, mock_ldap_manager, tmp_path):
        """One scan, two deliveries: the file must not invent its own numbers."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        contents = {GUID_SIGNING: sysvol_contents(*LDAP_LINES)}
        target = tmp_path / "scan.json"

        scan = run_scan(tools, contents, include_not_applicable=True)
        self.save(tools, contents, target)
        stored = read_scan(str(target))

        assert stored["counts"] == scan["counts"]
        assert [f["control_id"] for f in stored["findings"]] == \
            [f["control_id"] for f in scan["findings"]]
        assert [f["result"] for f in stored["findings"]] == \
            [f["result"] for f in scan["findings"]]
        assert stored["scan"]["catalog_version"] == \
            scan["scan"]["catalog_version"]
        assert stored["scan"]["base_dn"] == BASE_DN

    def test_the_stored_scan_covers_the_whole_catalog_and_hides_nothing(
            self, tools, mock_ldap_manager, tmp_path):
        """A scan meant for diffing must not leave the diff guessing."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        target = tmp_path / "scan.json"

        self.save(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)}, target)
        stored = read_scan(str(target))

        assert stored["scan"]["include_not_applicable"] is True
        assert stored["counts"]["hidden"] == 0
        assert stored["counts"]["total"] == stored["scan"]["control_count"]

    def test_the_notes_warn_that_the_file_holds_directory_content(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])

        response = self.save(tools, {}, tmp_path / "scan.json")

        notes = " ".join(response["notes"])
        assert "GPO display names, registry values and DNs" in notes
        assert "diff_hardening_scans" in notes

    def test_a_non_json_path_is_refused_and_nothing_is_written(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])

        response = self.save(tools, {}, tmp_path / "scan.html")

        assert response["success"] is False
        assert "must end in .json" in response["error"]
        assert response["scan_succeeded"] is True
        assert list(tmp_path.iterdir()) == []

    def test_an_unrelated_existing_file_is_not_clobbered(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        target = tmp_path / "package.json"
        target.write_text('{"name": "something else"}', encoding="utf-8")

        response = self.save(tools, {}, target)

        assert response["success"] is False
        assert "refusing to overwrite it" in response["error"]
        assert "something else" in target.read_text(encoding="utf-8")

    def test_missing_parent_directories_are_created(self, tools,
                                                    mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        response = self.save(tools, {}, tmp_path / "scans" / "2026" / "s.json")

        assert response["success"] is True
        assert (tmp_path / "scans" / "2026" / "s.json").is_file()

    def test_unknown_control_ids_fail_before_any_file_is_written(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])

        response = self.save(tools, {}, tmp_path / "s.json",
                             control_ids=["MADE-UP-1"])

        assert response["success"] is False
        assert "MADE-UP-1" in response["error"]
        assert response["operation"] == "write_hardening_scan"
        assert list(tmp_path.iterdir()) == []

    def test_a_broken_catalog_writes_nothing(self, tools, mock_ldap_manager,
                                             tmp_path):
        from aditor.hardening.catalog import CatalogError

        with patch("aditor.tools.hardening.load_catalog",
                   side_effect=CatalogError("duplicate control id 'X'")):
            result = tools.write_hardening_scan(str(tmp_path / "s.json"))
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "catalog failed to load" in response["error"]
        assert list(tmp_path.iterdir()) == []

    def test_an_ldap_failure_writes_nothing(self, tools, mock_ldap_manager,
                                            tmp_path):
        mock_ldap_manager.search.side_effect = RuntimeError("LDAP server down")

        with patch.dict(sys.modules, {"smbclient": Mock()}):
            result = tools.write_hardening_scan(str(tmp_path / "s.json"))
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert "LDAP server down" in response["error"]
        assert list(tmp_path.iterdir()) == []

    def test_missing_smbprotocol_names_this_tool_not_another(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__

        def no_smbclient(name, *args, **kwargs):
            if name == "smbclient":
                raise ImportError("No module named 'smbclient'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_smbclient):
            result = tools.write_hardening_scan(str(tmp_path / "s.json"))
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"].startswith("write_hardening_scan reads GPO")
        assert list(tmp_path.iterdir()) == []

    def test_the_scan_stays_read_only(self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])

        self.save(tools, {}, tmp_path / "s.json")

        assert mock_ldap_manager.add.called is False
        assert mock_ldap_manager.modify.called is False
        assert mock_ldap_manager.delete.called is False

    def test_rerunning_over_its_own_output_is_allowed(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "A Policy")], [])
        target = tmp_path / "s.json"

        first = self.save(tools, {}, target)
        second = self.save(tools, {}, target)

        assert first["success"] is True and second["success"] is True
        assert first["scan"]["scan_id"] != second["scan"]["scan_id"]


class TestDiffHardeningScans:
    """The diff tool's wiring. It reads two files and touches no directory.

    The diff logic itself is covered exhaustively in ``test_hardening_diff.py``.
    """

    def save(self, tools, contents_by_guid, output_path):
        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            for guid, contents in contents_by_guid.items():
                if guid in sysvol_path:
                    return contents
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(GPOTools, "_read_gpo_sysvol",
                          side_effect=read_sysvol):
            tools.write_hardening_scan(str(output_path))

    def diff(self, tools, before_path, after_path):
        return json.loads(tools.diff_hardening_scans(str(before_path),
                                                     str(after_path))[0].text)

    def test_two_real_scans_of_the_same_domain_diff_end_to_end(
            self, tools, mock_ldap_manager, tmp_path):
        """The round trip the reviewer will run live, offline."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")],
                  [link_entry(BASE_DN, GUID_SIGNING)])
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        # Before: the signing GPO sets nothing. After: it sets both LDAP values.
        self.save(tools, {GUID_SIGNING: sysvol_contents()}, before)
        self.save(tools, {GUID_SIGNING: sysvol_contents(*LDAP_LINES)}, after)

        response = self.diff(tools, before, after)

        assert response["success"] is True
        assert response["read_only"] is True
        # Same engine and catalog on both sides, so this really is the domain.
        assert response["attribution"]["verdict"] == "domain"
        improved = {e["control_id"] for e in response["improvements"]}
        assert "DEVORE-03-LDAP-SERVER-SIGNING" in improved
        assert "DEVORE-05-LDAP-CHANNEL-BINDING" in improved
        assert response["regressions"] == []
        assert response["scans"]["before"]["source"] == str(before)

    def test_the_response_headline_states_the_attribution(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        self.save(tools, {}, before)
        self.save(tools, {}, after)

        response = self.diff(tools, before, after)

        assert "attributed to the domain" in response["headline"]

    def test_an_ambiguous_diff_leads_with_a_warning_headline(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        self.save(tools, {}, before)
        self.save(tools, {}, after)
        # Rewrite the after scan as though a newer engine produced it.
        stored = json.loads(after.read_text(encoding="utf-8"))
        stored["scan"]["tool_version"] = "99.0.0"
        after.write_text(json.dumps(stored), encoding="utf-8")

        response = self.diff(tools, before, after)

        assert response["attribution"]["verdict"] == "ambiguous"
        assert response["headline"].startswith("ATTRIBUTION IS AMBIGUOUS")
        assert "may be the scanner or the catalog" in response["headline"]

    def test_two_domains_are_refused_with_a_clear_error(
            self, tools, mock_ldap_manager, tmp_path):
        """Acceptance 8, through the tool."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        self.save(tools, {}, before)
        self.save(tools, {}, after)
        stored = json.loads(after.read_text(encoding="utf-8"))
        stored["scan"]["base_dn"] = "DC=elsewhere,DC=local"
        after.write_text(json.dumps(stored), encoding="utf-8")

        response = self.diff(tools, before, after)

        assert response["success"] is False
        assert "different domains" in response["error"]
        assert BASE_DN in response["error"]
        assert "DC=elsewhere,DC=local" in response["error"]
        assert response["operation"] == "diff_hardening_scans"

    def test_a_file_that_is_not_a_scan_is_refused_by_name(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        self.save(tools, {}, before)
        not_a_scan = tmp_path / "notes.json"
        not_a_scan.write_text('{"just": "some json"}', encoding="utf-8")

        response = self.diff(tools, before, not_a_scan)

        assert response["success"] is False
        assert "not a hardening scan payload" in response["error"]
        assert "notes.json" in response["error"]

    def test_an_html_report_handed_to_the_diff_is_diagnosed(
            self, tools, mock_ldap_manager, tmp_path):
        """The likeliest mistake a caller makes."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        self.save(tools, {}, before)
        report = tmp_path / "report.json"
        report.write_text("<!DOCTYPE html><html>a report</html>",
                          encoding="utf-8")

        response = self.diff(tools, before, report)

        assert response["success"] is False
        assert "looks like an HTML file" in response["error"]

    def test_a_missing_file_is_refused(self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        self.save(tools, {}, before)

        response = self.diff(tools, before, tmp_path / "gone.json")

        assert response["success"] is False
        assert "does not exist" in response["error"]

    def test_the_diff_touches_no_directory_at_all(self, tools,
                                                  mock_ldap_manager, tmp_path):
        """No LDAP, no SMB, no SYSVOL: two files in, one diff out."""
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        self.save(tools, {}, before)
        self.save(tools, {}, after)
        mock_ldap_manager.reset_mock()

        with patch.object(GPOTools, "_read_gpo_sysvol",
                          side_effect=AssertionError("SYSVOL must not be read")):
            response = self.diff(tools, before, after)

        assert response["success"] is True
        assert mock_ldap_manager.search.called is False
        assert mock_ldap_manager.add.called is False
        assert mock_ldap_manager.modify.called is False
        assert mock_ldap_manager.delete.called is False

    def test_attribution_is_the_first_key_of_the_diff_body(
            self, tools, mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager, [gpo_entry(GUID_SIGNING, "LDAP Signing")], [])
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        self.save(tools, {}, before)
        self.save(tools, {}, after)

        keys = list(self.diff(tools, before, after))

        # The response envelope comes first, then attribution ahead of every
        # finding list — a reader must meet it before any number.
        assert keys.index("attribution") < keys.index("regressions")
        assert keys.index("regressions") < keys.index("improvements")


class TestSchemaInfo:

    def test_schema_info_advertises_the_catalog_and_its_limits(self, tools):
        info = tools.get_schema_info()

        assert info["operations"] == ["scan_hardening",
                                      "write_hardening_report",
                                      "write_hardening_scan",
                                      "diff_hardening_scans"]
        assert info["read_only"] is True
        assert info["writes_files"] == ["write_hardening_report",
                                        "write_hardening_scan"]
        assert info["catalog_version"]
        assert "DEVORE-03-LDAP-SERVER-SIGNING" in info["control_ids"]
        assert info["unscored_control_ids"]
        assert any("Precedence is not resolved" in note for note in info["notes"])
        assert any("needs_baseline_value" in note for note in info["notes"])

    def test_schema_info_explains_what_an_os_default_verdict_means(self, tools):
        info = tools.get_schema_info()

        assert info["evidence_sources"] == ["gpo", "os-default",
                                            "not-configured", "unknown"]
        assert any("not evidence that Group Policy enforces" in note
                   for note in info["notes"])

    def test_schema_info_advertises_the_delivery_vocabulary(self, tools):
        schema = tools.get_schema_info()

        assert schema["deliveries"] == ["security-template", "registry-pol",
                                        "registry-preference"]
        notes = " ".join(schema["notes"])
        assert "Registry.xml" in notes
        assert "TATTOOS" in notes
        assert "policy-preference-disagreement" in notes
        assert "no separate check_type for preferences" in notes
        assert schema["check_types"] == ["gpo-security-template",
                                        "gpo-registry-pol"], \
            "delivery is evidence, not a new check type"

    def test_schema_info_advertises_the_unknown_evidence_source(self, tools):
        """Every ``evidence.source`` a finding can carry must be advertised.

        ``unknown`` is what an unevaluated control and an unreadable-GPO error
        both report, and a consumer that has not been told about it would have to
        guess.
        """
        info = tools.get_schema_info()

        assert "unknown" in info["evidence_sources"]
        assert any("could not be read" in note for note in info["notes"])


class TestScanId:
    """A scan must be nameable, not merely timestamped — the diffing work needs it."""

    GUID = "11111111-1111-1111-1111-111111111111"

    def _scan(self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager, [gpo_entry(self.GUID, "Some GPO")], [])
        return run_scan(tools, {self.GUID: sysvol_contents()})

    def test_every_scan_carries_an_id(self, tools, mock_ldap_manager):
        scan_id = self._scan(tools, mock_ldap_manager)["scan"]["scan_id"]
        assert isinstance(scan_id, str) and len(scan_id) == 32
        int(scan_id, 16)  # hex, or this raises

    def test_two_scans_get_different_ids(self, tools, mock_ldap_manager):
        """Two scans can share a timestamp; they must not share an identity."""
        first = self._scan(tools, mock_ldap_manager)["scan"]["scan_id"]
        second = self._scan(tools, mock_ldap_manager)["scan"]["scan_id"]
        assert first != second

    def test_the_written_report_carries_its_scan_id(self, tools, mock_ldap_manager,
                                                    tmp_path):
        """The rendered document must name the scan that produced it."""
        wire_ldap(mock_ldap_manager, [gpo_entry(self.GUID, "Some GPO")], [])
        out = tmp_path / "r.html"

        def read_sysvol(sysvol_path, include_registry=True, max_value_chars=6000):
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(GPOTools, "_read_gpo_sysvol", side_effect=read_sysvol):
            json.loads(tools.write_hardening_report(str(out))[0].text)

        document = out.read_text(encoding="utf-8")
        assert "Scan id" in document
        assert re.search(r"\b[0-9a-f]{32}\b", document), "no scan id in the document"


# --------------------------------------------------------------------------- #
# P2-WP5 — the `unknown` result end to end through the tool layer
# --------------------------------------------------------------------------- #

DIAG_CONTROL_ID = "DEVORE-03-LDAP-DIAG-LOGGING"
DIAG_POL_ENTRY = {
    "key": r"SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics",
    "value": "16 LDAP Interface Events",
    "type": "REG_DWORD",
    "data": 3,
}


class TestUnknownVerdictThroughTheScan:
    """A control whose remediation leaves no GPO trace, scanned for real.

    Same stubbed-SMB path production takes, so the ``unknown`` result, its note
    and its counts are exercised through ``scan_hardening`` rather than only
    against the evaluator.
    """

    def test_a_domain_with_no_gpo_for_the_key_reports_unknown(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Some Unrelated Policy")], [])

        response = run_scan(tools, {GUID_SIGNING: sysvol_contents()},
                            control_ids=[DIAG_CONTROL_ID])

        finding = response["findings"][0]
        assert finding["result"] == "unknown"
        assert finding["rollout_state"] is None
        assert finding["evidence"]["source"] == "unknown"
        assert response["counts"]["unknown"] == 1
        assert response["counts"]["fail"] == 0
        assert response["counts"]["error"] == 0

    def test_the_finding_carries_the_reg_query_command(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Some Unrelated Policy")], [])

        response = run_scan(tools, {GUID_SIGNING: sysvol_contents()},
                            control_ids=[DIAG_CONTROL_ID])

        notes = response["findings"][0]["evidence"]["notes"]
        assert any('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS'
                   '\\Diagnostics" /v "16 LDAP Interface Events"' in note
                   for note in notes), notes

    def test_a_gpo_delivered_level_of_three_passes(self, tools,
                                                   mock_ldap_manager):
        """Fix 1a and 1b together, through the scan: 3 is a pass, not a fail."""
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "NTDS Diagnostics")], [])

        response = run_scan(
            tools, {GUID_SIGNING: sysvol_contents(pol_entries=[DIAG_POL_ENTRY])},
            control_ids=[DIAG_CONTROL_ID])

        finding = response["findings"][0]
        assert finding["result"] == "pass"
        assert finding["evidence"]["found"][0]["value"] == 3
        assert finding["evidence"]["source"] == "gpo"

    def test_the_headline_counts_report_the_unknown(self, tools,
                                                   mock_ldap_manager, tmp_path):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Some Unrelated Policy")], [])
        out = tmp_path / "r.html"

        def read_sysvol(sysvol_path, include_registry=True,
                        max_value_chars=6000):
            return sysvol_contents()

        with patch.dict(sys.modules, {"smbclient": Mock()}), \
             patch.object(GPOTools, "_read_gpo_sysvol", side_effect=read_sysvol):
            response = json.loads(
                tools.write_hardening_report(str(out))[0].text)

        assert response["headline"]["unknown"] >= 1
        document = out.read_text(encoding="utf-8")
        assert "this is not a pass" in document

    def test_schema_info_advertises_the_unknown_result(self, tools):
        info = tools.get_schema_info()

        assert info["results"] == ["pass", "fail", "unknown",
                                   "not_applicable", "error"]
        notes = " ".join(info["notes"])
        assert "gpo_deliverable" in notes
        assert "reg query" in notes
        assert "narrow by design" in notes


class TestKeyScopedDeleteThroughTheScan:
    """Fix 3 end to end: a GPO deleting the key under a hardened value.

    The preference item is produced by running the real ``parse_registry_xml``
    over hand-written XML, exactly as ``get_gpo_contents`` does before the scan
    sees it, so the parser change and the evaluator disclosure are exercised
    together rather than a hand-shaped dict being asserted against itself.
    """

    KDC_PREF_KEY = r"SYSTEM\CurrentControlSet\Services\Kdc"

    def key_delete_entry(self):
        document = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<RegistrySettings clsid="{A3CCFC41-0000-0000-0000-000000000002}">'
            '<Registry name="Item"><Properties action="D" '
            f'hive="HKEY_LOCAL_MACHINE" key="{self.KDC_PREF_KEY}"/>'
            '</Registry></RegistrySettings>').encode("utf-8")
        entries = parse_registry_xml(document)
        assert entries and entries[0]["deletes_key"] is True
        return entries[0]

    def test_a_pass_is_disclosed_as_standing_on_a_key_another_gpo_deletes(
            self, tools, mock_ldap_manager):
        wire_ldap(mock_ldap_manager,
                  [gpo_entry(GUID_SIGNING, "Enc Types By Preference"),
                   gpo_entry(GUID_OVERRIDE, "Undo Enc Types")], [])

        response = run_scan(
            tools,
            {GUID_SIGNING: sysvol_contents(
                preference_entries=[preference_entry()]),
             GUID_OVERRIDE: sysvol_contents(
                 preference_entries=[self.key_delete_entry()])},
            control_ids=["DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"])

        finding = response["findings"][0]
        assert finding["result"] == "pass"
        notes = " ".join(finding["evidence"]["notes"])
        assert "DELETE a registry KEY" in notes
        assert "Undo Enc Types" in notes
        assert "client-side extensions run" in notes
