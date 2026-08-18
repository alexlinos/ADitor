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


# Security tools that are deliberately NOT registered yet (WP2 mock stubs).
UNREGISTERED_SECURITY_STUBS = {
    "find_weak_passwords",
    "analyze_permissions",
    "detect_privilege_escalation",
    "check_service_accounts",
    "check_password_policy",
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


def test_expected_tool_count(server):
    # 9 user + 8 group + 9 computer + 7 OU + 6 security + 4 GPO + 3 system = 46
    assert len(TOOLS) == 46
    assert len(server._tools) == 46
