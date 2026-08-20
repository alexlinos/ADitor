"""Drift-guard tests for the single tool registry.

These tests make registration drift impossible: the set of tools the server
exposes must equal the set declared in ``aditor.registry.TOOLS``, name-for-name.
Adding a tool is a one-file change (registry.py); if the server and registry
ever disagree, these tests fail.
"""

import asyncio
import json
import os
import tempfile

import pytest
from unittest.mock import Mock, patch

from aditor.registry import TOOLS, tool_names
from aditor.server import ActiveDirectoryMCPServer


# Security methods that exist on SecurityTools but are deliberately NOT exposed
# as MCP tools. ``generate_security_report`` is the prototype of the Phase-2
# report pipeline: real logic, but its shape is not committed to yet.
# (WP2 deleted the four fabricating stubs outright.)
UNREGISTERED_SECURITY_STUBS = {
    "generate_security_report",
}


@pytest.fixture
def config_file():
    """Minimal valid config on disk."""
    data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123",
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local",
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    yield path
    os.unlink(path)


@pytest.fixture
def server(config_file):
    with patch("aditor.core.ldap_manager.LDAPManager.test_connection") as mock_test, \
         patch("aditor.core.ldap_manager.LDAPManager.connect") as mock_connect:
        mock_test.return_value = {"connected": True, "server": "test.local"}
        mock_connect.return_value = Mock()
        yield ActiveDirectoryMCPServer(config_file, transport="stdio")


def test_registry_has_no_duplicate_names():
    names = tool_names()
    assert len(names) == len(set(names)), "duplicate tool names in registry.TOOLS"


def test_server_exposes_exactly_the_registry(server):
    """The server's exposed tool set must equal registry.TOOLS, name-for-name."""
    registry_names = {spec.name for spec in TOOLS}

    # What the server materialised for list_tools.
    exposed_names = {tool.name for tool in server._tools}
    assert exposed_names == registry_names

    # And the call_tool dispatch table must cover exactly the same set.
    assert set(server._tool_handlers) == registry_names


def test_list_tools_handler_matches_registry(server):
    """Exercise the actual async list_tools handler the SDK will call."""
    handler = server.mcp.request_handlers  # sanity: server is wired
    assert handler is not None

    exposed = asyncio.run(_list_tools_via_handler(server))
    assert {t.name for t in exposed} == {spec.name for spec in TOOLS}


async def _list_tools_via_handler(server):
    import mcp.types as types

    req_handler = server.mcp.request_handlers[types.ListToolsRequest]
    result = await req_handler(
        types.ListToolsRequest(method="tools/list")
    )
    # ServerResult wraps a ListToolsResult.
    return result.root.tools


def test_security_stubs_are_not_registered():
    registry_names = {spec.name for spec in TOOLS}
    assert registry_names.isdisjoint(UNREGISTERED_SECURITY_STUBS)


def test_expected_security_tools_are_registered(server):
    """The security tools ADitor commits to exposing (WP2 added the last one)."""
    expected = {
        "get_domain_info",
        "get_privileged_groups",
        "get_user_permissions",
        "get_inactive_users",
        "get_password_policy_violations",
        "audit_admin_accounts",
        "check_password_policy",
    }
    registry_names = {spec.name for spec in TOOLS}
    assert expected <= registry_names
    assert expected <= set(server._tool_handlers)


def test_password_policy_violations_exposes_include_disabled():
    """P2-WP6: the disabled-account opt-in has to reach the MCP schema."""
    spec = next(s for s in TOOLS if s.name == "get_password_policy_violations")
    parameter = spec.input_schema["properties"]["include_disabled"]
    assert parameter["type"] == "boolean"
    assert parameter["default"] is False
    assert "required" not in spec.input_schema
    # The description has to state the scope, or a caller cannot read the count.
    assert "include_disabled" in spec.description


def test_expected_tool_count(server):
    # 9 user + 8 group + 9 computer + 7 OU + 7 security + 4 GPO
    # + 5 hardening + 3 system = 52
    assert len(TOOLS) == 52
    assert len(server._tools) == 52


def test_scan_hardening_is_registered(server):
    """P2-WP1's tool. Adding a tool needs a Claude Code restart to be visible."""
    assert "scan_hardening" in {spec.name for spec in TOOLS}
    assert "scan_hardening" in set(server._tool_handlers)


def test_write_hardening_report_is_registered(server):
    """P2-WP3's tool. Adding a tool needs a Claude Code restart to be visible."""
    assert "write_hardening_report" in {spec.name for spec in TOOLS}
    assert "write_hardening_report" in set(server._tool_handlers)

    spec = next(s for s in TOOLS if s.name == "write_hardening_report")
    assert spec.input_schema["required"] == ["output_path"]
    assert "control_ids" in spec.input_schema["properties"]
    # The description has to say what the file contains: a rendered report
    # carries the domain's GPO names and registry values.
    assert "self-contained" in spec.description
    assert "only side effect" in spec.description


def test_write_hardening_scan_is_registered(server):
    """P2-WP7's persistence tool. Adding a tool needs a Claude Code restart."""
    assert "write_hardening_scan" in {spec.name for spec in TOOLS}
    assert "write_hardening_scan" in set(server._tool_handlers)

    spec = next(s for s in TOOLS if s.name == "write_hardening_scan")
    assert spec.input_schema["required"] == ["output_path"]
    assert "control_ids" in spec.input_schema["properties"]
    # The same caveat the report tool carries: a saved scan embeds the domain's
    # GPO names, registry values and DNs.
    assert "GPO\ndisplay names, registry values and DNs" in spec.description
    assert "DIRECTORY CONTENT" in spec.description
    assert "only side effect" in spec.description


def test_write_hardening_snapshot_is_registered(server):
    """P2-WP8's tool. Adding a tool needs a Claude Code restart."""
    assert "write_hardening_snapshot" in {spec.name for spec in TOOLS}
    assert "write_hardening_snapshot" in set(server._tool_handlers)

    spec = next(s for s in TOOLS if s.name == "write_hardening_snapshot")
    assert spec.input_schema["required"] == ["output_dir"]
    # No control_ids: a snapshot is a complete record of one moment.
    assert list(spec.input_schema["properties"]) == ["output_dir"]
    # The same caveat both sibling tools carry, for both files this time.
    assert "GPO\ndisplay names, registry values and DNs" in spec.description
    assert "DIRECTORY CONTENT" in spec.description
    assert "only side effect" in spec.description


def test_write_hardening_snapshot_description_warns_off_composing_by_hand():
    """The correctness trap is the reason the tool exists, so a caller has to
    meet it: running the two sibling writers in turn produces a folder holding
    two different scans, and nothing in the folder would say so."""
    description = next(s for s in TOOLS
                       if s.name == "write_hardening_snapshot").description

    assert "USE THIS RATHER THAN CALLING THE OTHER TWO WRITE TOOLS IN TURN" \
        in description
    assert "each run their OWN scan" in description
    assert "exactly once" in description
    # The two naming constraints a reviewer will check.
    assert "no colon" in description
    assert "scan's OWN timestamp" in description
    # And the refusal, so nobody expects a re-run to update a folder in place.
    assert "never overwritten" in description


def test_diff_hardening_scans_is_registered(server):
    """P2-WP7's diff tool. Adding a tool needs a Claude Code restart."""
    assert "diff_hardening_scans" in {spec.name for spec in TOOLS}
    assert "diff_hardening_scans" in set(server._tool_handlers)

    spec = next(s for s in TOOLS if s.name == "diff_hardening_scans")
    assert spec.input_schema["required"] == ["before_path", "after_path"]


def test_diff_hardening_scans_advertises_snapshot_folders_as_input():
    """P2-WP8: a caller holding two snapshot folders must not have to guess
    that reaching inside for scan.json is unnecessary."""
    spec = next(s for s in TOOLS if s.name == "diff_hardening_scans")

    assert "snapshot folder" in spec.description
    assert "diff <folder-a> <folder-b>" in spec.description
    for side in ("before_path", "after_path"):
        assert "snapshot folder" in spec.input_schema["properties"][side][
            "description"] or "same two" in spec.input_schema["properties"][
            side]["description"]


def test_diff_hardening_scans_description_leads_with_attribution():
    """The domain-versus-tool distinction is the whole feature, so it must be
    the first thing a caller reads — a model that skips it will report a
    cross-version difference as a fix that landed."""
    description = next(s for s in TOOLS
                       if s.name == "diff_hardening_scans").description

    assert "READ 'attribution' FIRST" in description
    assert "may be the TOOL rather" in description
    assert "Group Policy Preferences" in description
    assert "the domain never changed" in description
    # The three classification rules a caller must not get wrong.
    assert "regressions, FIRST" in description
    assert "even when result stays 'pass'" in description
    assert "NEVER counted as improvements or regressions" in description


def test_audit_admin_accounts_description_states_the_risk_model():
    """P2-WP6: a rating is only useful if the caller knows what it means."""
    spec = next(s for s in TOOLS if s.name == "audit_admin_accounts")
    description = spec.description
    # The two HIGH cases and the disabled demotion are the load-bearing claims.
    assert "PASSWD_NOTREQD" in description
    assert "kerberoastable" in description
    assert "disabled" in description
    # lastLogon's per-DC replication caveat must be disclosed to the caller.
    assert "not replicated" in description
