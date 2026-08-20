"""Single source of truth for the Active Directory MCP tool set.

Every tool the server exposes is declared exactly once here as a
:class:`ToolSpec`. The server (``aditor.server``) builds its ``list_tools`` and
``call_tool`` handlers directly from :data:`TOOLS`, so adding, removing or
renaming a tool means editing this file and nothing else.

Each spec carries:

* ``name`` -- the MCP tool name (stable public API).
* ``description`` -- human/agent-facing help text.
* ``input_schema`` -- JSON Schema for the tool arguments.
* ``handler`` -- ``(tools, args) -> result`` where ``tools`` is the
  :class:`Tools` bundle and ``result`` is either a list of MCP content objects
  (as the tool classes already return) or a plain dict/list that the server
  serialises to JSON text.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List

from .core.ldap_manager import LDAPManager
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools
from .tools.gpo import GPOTools
from .tools.hardening import HardeningTools


@dataclass
class Tools:
    """Container bundling the instantiated tool classes over one LDAP manager."""

    ldap: LDAPManager
    user: UserTools
    group: GroupTools
    computer: ComputerTools
    ou: OrganizationalUnitTools
    security: SecurityTools
    gpo: GPOTools
    hardening: HardeningTools

    @classmethod
    def from_ldap(cls, ldap: LDAPManager) -> "Tools":
        """Build the full tool bundle around a single LDAP manager."""
        return cls(
            ldap=ldap,
            user=UserTools(ldap),
            group=GroupTools(ldap),
            computer=ComputerTools(ldap),
            ou=OrganizationalUnitTools(ldap),
            security=SecurityTools(ldap),
            gpo=GPOTools(ldap),
            hardening=HardeningTools(ldap),
        )


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of a single MCP tool."""

    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[["Tools", Dict[str, Any]], Any]


# --------------------------------------------------------------------------- #
# Descriptions (folded in from the former tools/definitions.py, keeping the
# richer multi-line help text over the terse inline strings).
# --------------------------------------------------------------------------- #

LIST_USERS_DESC = """List users in Active Directory with optional filtering.

Retrieves users from the specified organizational unit or the entire domain.
Supports custom LDAP filters and attribute selection for targeted queries.

Examples:
- list_users()
- list_users(ou="OU=Sales,DC=company,DC=com")
- list_users(filter_criteria="(department=IT)")"""

GET_USER_DESC = """Get detailed information about a specific user.

Retrieves comprehensive user information including attributes, group
memberships, account status, and computed security fields."""

CREATE_USER_DESC = """Create a new user account in Active Directory.

Creates a user with the specified attributes in the designated organizational
unit (defaults to the configured users OU, else CN=Users). Sets the user
principal name and applies initial account settings."""

MODIFY_USER_DESC = """Modify user attributes and properties.

Updates existing user attributes including personal information, security
settings, and organizational data."""

DELETE_USER_DESC = """Delete a user account from Active Directory.

Permanently removes the user account and associated data. Validates existence
before deletion."""

ENABLE_USER_DESC = """Enable a user account.

Activates a disabled user account by clearing the disabled flag in
userAccountControl."""

DISABLE_USER_DESC = """Disable a user account.

Deactivates a user account, preventing login while preserving account data."""

RESET_USER_PASSWORD_DESC = """Reset a user password, optionally auto-generating one.

Resets the password to a supplied value or a generated complex password, and
can force a change at next logon."""

GET_USER_GROUPS_DESC = """Get the groups a user is a member of.

Returns group membership detail including group types, scopes, and
descriptions."""

LIST_GROUPS_DESC = """List groups in Active Directory with optional filtering.

Retrieves security and distribution groups with detail about scope, type, and
membership counts."""

GET_GROUP_DESC = """Get detailed information about a specific group.

Returns group configuration, members, parent groups, and management settings."""

CREATE_GROUP_DESC = """Create a new group in Active Directory.

Creates a security or distribution group with the specified scope and
attributes (Global, DomainLocal, or Universal). Defaults to the configured
groups OU when no OU is supplied."""

MODIFY_GROUP_DESC = """Modify group attributes and properties.

Updates group information such as description and managedBy while preserving
membership."""

DELETE_GROUP_DESC = """Delete a group from Active Directory.

Permanently removes the group and its membership associations."""

ADD_GROUP_MEMBER_DESC = """Add a member to a group.

Adds a user, computer, or group as a member of the specified group by DN.
Supports nested memberships."""

REMOVE_GROUP_MEMBER_DESC = """Remove a member from a group.

Removes the specified member (by DN) from the group after validating
membership."""

GET_GROUP_MEMBERS_DESC = """Get the members of a group, optionally recursively.

Lists all members with an option to include members of nested groups."""

LIST_COMPUTERS_DESC = """List computer objects in Active Directory.

Retrieves computer accounts with operating-system information, last logon, and
security status."""

GET_COMPUTER_DESC = """Get detailed information about a specific computer.

Returns OS details, last logon, group memberships, and security settings."""

CREATE_COMPUTER_DESC = """Create a new computer object in Active Directory.

Creates a computer account with appropriate attributes. Defaults to the
configured computers OU when no OU is supplied."""

MODIFY_COMPUTER_DESC = """Modify computer attributes and properties.

Updates computer information such as description and location while preserving
critical account settings."""

DELETE_COMPUTER_DESC = """Delete a computer object from Active Directory.

Permanently removes the computer account and its trust relationship."""

ENABLE_COMPUTER_DESC = """Enable a computer account.

Activates a disabled computer account, allowing domain authentication."""

DISABLE_COMPUTER_DESC = """Disable a computer account.

Deactivates a computer account, preventing domain authentication."""

RESET_COMPUTER_PASSWORD_DESC = """Reset a computer account password.

Forces the computer to re-establish its trust relationship with the domain."""

GET_STALE_COMPUTERS_DESC = """Get computers that have not logged in for a number of days.

Identifies inactive computer accounts that may need cleanup."""

LIST_ORGANIZATIONAL_UNITS_DESC = """List Organizational Units in Active Directory.

Returns the OU hierarchy with management information and policy links."""

GET_ORGANIZATIONAL_UNIT_DESC = """Get detailed information about a specific OU.

Returns child objects, group-policy links, and management settings."""

CREATE_ORGANIZATIONAL_UNIT_DESC = """Create a new Organizational Unit.

Creates an OU with the specified attributes and management settings under the
given parent (defaults to the base DN)."""

MODIFY_ORGANIZATIONAL_UNIT_DESC = """Modify OU attributes and properties.

Updates OU information such as description, managedBy, and location while
preserving structure."""

DELETE_ORGANIZATIONAL_UNIT_DESC = """Delete an Organizational Unit.

Removes an OU, optionally with its contained objects. Validates emptiness
unless force deletion is requested."""

MOVE_ORGANIZATIONAL_UNIT_DESC = """Move an OU to a new parent.

Relocates an OU within the domain hierarchy while preserving its contents."""

GET_ORGANIZATIONAL_UNIT_CONTENTS_DESC = """Get the contents of an OU.

Lists the users, groups, computers, and sub-OUs contained in an OU, optionally
filtered by object type."""

GET_DOMAIN_INFO_DESC = """Get domain information and security settings.

Returns domain configuration including password policies, lockout settings, and
security parameters."""

GET_PRIVILEGED_GROUPS_DESC = """Get information about privileged groups.

Identifies and analyses high-privilege groups such as Domain Admins and
Enterprise Admins."""

GET_USER_PERMISSIONS_DESC = """Get effective permissions for a user.

Analyses a user's effective permissions through group memberships and flags
potential security risks."""

GET_INACTIVE_USERS_DESC = """Get users who have not logged in for a number of days.

Identifies inactive user accounts, optionally including disabled accounts."""

GET_PASSWORD_POLICY_VIOLATIONS_DESC = """Get user accounts with password policy violations.

Identifies accounts with expired passwords, never-expiring passwords, and other
policy non-compliance. Covers user accounts only - machine accounts rotate their
own passwords and are excluded - and by default only enabled accounts;
include_disabled=true adds the disabled ones. An account carrying
DONT_EXPIRE_PASSWORD is exempt from maxPwdAge, so it is never reported as
expired. Whatever was left out is counted in excluded_counts, so a short list
can be told apart from a clean domain."""

AUDIT_ADMIN_ACCOUNTS_DESC = """Audit administrative accounts for security compliance.

Reviews the members of Domain Admins, Enterprise Admins, Schema Admins and
Administrators. risk_level rates how usable the account is to an attacker, so the
list can be triaged: HIGH is PASSWD_NOTREQD on an enabled account, an enabled
SPN-bearing account whose password is a year or more old (kerberoastable), or a
non-expiring password over five years old; MEDIUM is a non-expiring password, a
fresher SPN account, or 180+ days without a logon; LOW is informational,
including a disabled account, which cannot authenticate and so is not
exploitable, though it should still be removed from the group. Each account
carries risk_drivers saying what drove its rating, and the payload restates the
model in risk_model. days_since_logon comes from lastLogon, which is per-DC and
not replicated, so it can read older than reality; it never drives HIGH alone."""

CHECK_PASSWORD_POLICY_DESC = """Check the domain password policy against a baseline (read-only).

Reads the domain-wide policy and evaluates the minimum password length (>= 8) and
password history length (>= 5), returning a per-check pass/fail result plus
recommendations for the checks that failed. Domain lockout settings are reported
for context but not scored. This is the domain policy itself; use
get_password_policy_violations for per-account non-compliance."""

GET_GPOS_DESC = """List all Group Policy Objects in the domain (read-only).

Enumerates groupPolicyContainer objects under CN=Policies,CN=System and returns
metadata: display name, GUID, SYSVOL path, version numbers, and which
configuration halves (user/computer) are enabled. Optional name_filter matches
a substring of the display name. Reads LDAP metadata only; SYSVOL settings are
not parsed here."""

GET_GPO_DESC = """Get detailed metadata for a single GPO by GUID or display name (read-only).

Looks up one GPO by GUID (with or without braces) or exact display name and
lists the OUs/domain that link it, along with version and status flags."""

GET_LINKED_GPOS_DESC = """Get the GPOs linked to an OU, domain, or site DN (read-only).

Reads the gPLink attribute on the target object, resolves each linked GPO GUID
to its display name, and reports link enabled/enforced status plus whether the
target blocks inheritance."""

GET_GPO_CONTENTS_DESC = """Read a GPO's actual settings from SYSVOL over SMB (read-only).

Unlike the other GPO tools (LDAP metadata only), this reads the GPO's files from
the SYSVOL share over SMB and parses the common policy formats: GPT.INI,
Machine/User Registry.pol (admin templates), GptTmpl.inf security templates,
script registrations, and AppLocker rules. Requires the optional 'smbprotocol'
package and SYSVOL read access for the bind account.

Rules-heavy GPOs (e.g. a 72-rule AppLocker policy) can return tens of KB. Pass
summary=true for the same shape without the heavy bodies: registry entry counts
instead of every entry, a {type, id, name, action, sid} digest per AppLocker rule
instead of its XML, and section names instead of template/script bodies."""

SCAN_HARDENING_DESC = """Scan the domain's GPOs against the AD hardening control catalog (read-only).

Enumerates every GPO, reads its settings from SYSVOL over SMB, and evaluates
them against the versioned control catalog derived from the Devore AD Hardening
Series (Parts 1-8). Requires the optional 'smbprotocol' package and SYSVOL read
access; it changes nothing.

Returns a provenance header (scan engine version, catalog version, timestamp,
domain and base DN), per-control findings, and counts. Each finding carries:
- result: pass | fail | not_applicable | error
- rollout_state: not_started | audit | enforced — most controls are
  audit-first-then-enforce, so a domain correctly mid-rollout reads as
  pass/audit rather than as a failure
- evidence: the expected value next to every value found, with the source GPO
  DN, its link path, and whether that link is enforced
- conflict: set when two GPOs give the same key different values, or when a
  compliant setting is contradicted by an enforced link

Precedence (RSoP) is deliberately NOT resolved: every GPO that sets a control's
key is reported and disagreements are flagged, rather than guessing which one
wins. Controls whose exact expected value the source does not state are
reported but not scored — never guessed.

Pass control_ids to scan a subset; include_not_applicable to see controls that
did not apply."""

WRITE_HARDENING_REPORT_DESC = """Run the hardening scan and write it as a self-contained HTML report.

Runs the same read-only scan as scan_hardening and renders it to a single .html
file: inline CSS, no external assets, no CDN, no JavaScript. It opens from a
file:// path, survives being emailed or attached to a ticket, and a browser can
print it to PDF. The JSON from scan_hardening remains the source of truth; the
document renders it and adds nothing to it.

The report is ordered by actionability, not catalog order:
1. GPO read failures and 'unknown' verdicts first — an unreadable GPO makes an
   unset key unknown rather than clean, so this leads the document
2. Failures, each with expected vs every value found, the source GPO DN and link
   path, severity, the catalog's remediation, and the rollout order (the interim
   audit step first where the control has one — jumping straight to enforcement
   causes lockouts)
3. Conflicts, with both GPO names and values and the reminder that precedence is
   unresolved and must be confirmed with gpresult / RSoP
4. Findings resting on a documented Windows default, as hardening opportunities —
   never as something Group Policy enforces
5. Controls with no sourced baseline value, marked not judged, never as passes
6. Passes last, compact, evidence retained

Writing the file is this tool's only side effect; the directory is not modified.
Parent directories are created as needed, the path must end in .html, and an
existing file is overwritten only if it is a previous ADitor report. The written
file contains this domain's GPO display names, registry values and DNs, so treat
it as containing directory content when sharing it.

Returns the written path, the byte count, the provenance header and the headline
counts. Pass control_ids to report on a subset of the catalog."""

WRITE_HARDENING_SCAN_DESC = """Run the hardening scan and write the JSON payload to a file.

The sibling of write_hardening_report: the same read-only scan, the same path
guards, a different medium. The report is for a reader; this is the structured
payload, written so two runs can be compared later with diff_hardening_scans.
Nothing is derived and nothing is dropped, so the file and scan_hardening's own
output cannot disagree.

The whole catalog is always scanned and not-applicable findings are always
included. A stored scan is an input to a later comparison, and a scan that
filtered part of the catalog out cannot be told apart from one whose catalog was
smaller, so storing everything removes that ambiguity from the diff.

Writing the file is this tool's only side effect; the directory is not modified.
Parent directories are created as needed, the path must end in .json, and an
existing file is overwritten only if it is a previous ADitor scan.

THE FILE CONTAINS DIRECTORY CONTENT. A saved scan embeds this domain's GPO
display names, registry values and DNs — the same caveat write_hardening_report
carries for the rendered document. Treat the file accordingly when sharing it,
attaching it to a ticket, or committing it.

Returns the written path, the byte count, the provenance header (scan engine
version, catalog version, timestamp, domain and base DN) and the headline counts.
Pass control_ids to scan a subset, though a scan meant for diffing should
normally cover the whole catalog."""

DIFF_HARDENING_SCANS_DESC = """Compare two hardening scans: did my fix land, did anything regress?

Reads two .json files written by write_hardening_scan and returns a structured
diff, keyed on control_id. This tool touches no directory at all — no LDAP, no
SMB, no SYSVOL. Two files in, one diff out.

READ 'attribution' FIRST. It is the payload's opening key because every number
below it depends on it:
- 'domain' — both scans ran the same catalog_version AND engine_version, so the
  differences can be attributed to the domain. This is the only case in which
  "the fix landed" can be read off a diff directly.
- 'ambiguous' — the versions differ, so EVERY difference may be the TOOL rather
  than the domain, and none of it can be reported as domain progress. This is
  not hypothetical: a control in this project went fail -> pass between two real
  scans purely because the scanner learned to read Group Policy Preferences. The
  value had been set correctly the whole time and the domain never changed.
  Both version pairs are named and the verdict is stamped on every entry.

The payload, in order:
- attribution: the above, with a plain-language summary and caveats (a different
  GPO count, unreadable GPOs, a narrowed scan, reversed arguments)
- scans: both scan_ids, timestamps, versions and read coverage
- regressions, FIRST because a regression matters more: pass -> fail/unknown/
  error, or a rollout moving backwards (enforced -> audit -> not_started), which
  counts even when result stays 'pass'
- improvements: fail/unknown -> pass, or a rollout advancing. error -> pass is
  deliberately NOT an improvement — the earlier scan could not read the setting,
  so "it passes now" is not evidence that anything was fixed
- other_changes: verdict moves that are neither, each saying why
- unchanged: a count
- catalog_changes: controls added to or removed from the catalog, reported
  separately and NEVER counted as improvements or regressions. 'comparable' says
  whether absence from a findings list really means absence from the catalog
- evidence_changes: same verdict, moved grounds — a different value, a different
  GPO delivering it, a changed delivery mechanism (policy -> preference tattoos,
  which is a weaker statement), a changed evidence source, or a conflict
  appearing or clearing
- counts_delta: before/after/delta per count key

Refuses with a clear error, not a crash, if the two scans are of different
domains (base_dn mismatch) or if a file is not a scan payload — an HTML report
from write_hardening_report is not a scan and cannot be diffed."""

TEST_CONNECTION_DESC = """Test the LDAP connection and return server information.

Validates Active Directory connectivity and reports server status."""

HEALTH_DESC = """Health check for the Active Directory MCP server.

Returns server status and LDAP connectivity information."""

GET_SCHEMA_INFO_DESC = """Get schema information for all available tools.

Returns the operation catalogue and attribute/permission metadata for each tool
group."""


# --------------------------------------------------------------------------- #
# System-tool handlers (formerly hand-written on the two server classes).
# --------------------------------------------------------------------------- #

def _handle_test_connection(tools: "Tools", args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return tools.ldap.test_connection()
    except Exception as e:  # pragma: no cover - defensive
        return {"success": False, "error": str(e)}


def _handle_health(tools: "Tools", args: Dict[str, Any]) -> Dict[str, Any]:
    health_info: Dict[str, Any] = {
        "status": "ok",
        "server": "ActiveDirectoryMCP",
        "timestamp": datetime.now().isoformat(),
        "ldap_connection": "unknown",
    }
    try:
        connection_info = tools.ldap.test_connection()
        health_info["ldap_connection"] = (
            "connected" if connection_info.get("connected") else "disconnected"
        )
        health_info["ldap_server"] = connection_info.get("server", "unknown")
    except Exception as e:
        health_info["ldap_connection"] = "error"
        health_info["ldap_error"] = str(e)
        health_info["status"] = "degraded"
    return health_info


def _handle_schema_info(tools: "Tools", args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "server": "ActiveDirectoryMCP",
        "version": "0.1.0",
        "tools": {
            "user_tools": tools.user.get_schema_info(),
            "group_tools": tools.group.get_schema_info(),
            "computer_tools": tools.computer.get_schema_info(),
            "ou_tools": tools.ou.get_schema_info(),
            "security_tools": tools.security.get_schema_info(),
            "gpo_tools": tools.gpo.get_schema_info(),
            "hardening_tools": tools.hardening.get_schema_info(),
        },
    }


# --------------------------------------------------------------------------- #
# The single tool registry.
# --------------------------------------------------------------------------- #

TOOLS: List[ToolSpec] = [
    # ----- User management -----
    ToolSpec(
        "list_users",
        LIST_USERS_DESC,
        {
            "type": "object",
            "properties": {
                "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
                "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
        },
        lambda t, a: t.user.list_users(a.get("ou"), a.get("filter_criteria"), a.get("attributes")),
    ),
    ToolSpec(
        "get_user",
        GET_USER_DESC,
        {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username (sAMAccountName) to search for"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
            "required": ["username"],
        },
        lambda t, a: t.user.get_user(a["username"], a.get("attributes")),
    ),
    ToolSpec(
        "create_user",
        CREATE_USER_DESC,
        {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username (sAMAccountName)"},
                "password": {"type": "string", "description": "User password"},
                "first_name": {"type": "string", "description": "User's first name"},
                "last_name": {"type": "string", "description": "User's last name"},
                "email": {"type": "string", "description": "User's email address"},
                "ou": {"type": "string", "description": "Organizational Unit DN to create user in"},
                "additional_attributes": {"type": "object", "description": "Additional attributes to set"},
            },
            "required": ["username", "password", "first_name", "last_name"],
        },
        lambda t, a: t.user.create_user(
            a["username"], a["password"], a["first_name"], a["last_name"],
            a.get("email"), a.get("ou"), a.get("additional_attributes"),
        ),
    ),
    ToolSpec(
        "modify_user",
        MODIFY_USER_DESC,
        {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username to modify"},
                "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
            },
            "required": ["username", "attributes"],
        },
        lambda t, a: t.user.modify_user(a["username"], a["attributes"]),
    ),
    ToolSpec(
        "delete_user",
        DELETE_USER_DESC,
        {
            "type": "object",
            "properties": {"username": {"type": "string", "description": "Username to delete"}},
            "required": ["username"],
        },
        lambda t, a: t.user.delete_user(a["username"]),
    ),
    ToolSpec(
        "enable_user",
        ENABLE_USER_DESC,
        {
            "type": "object",
            "properties": {"username": {"type": "string", "description": "Username to enable"}},
            "required": ["username"],
        },
        lambda t, a: t.user.enable_user(a["username"]),
    ),
    ToolSpec(
        "disable_user",
        DISABLE_USER_DESC,
        {
            "type": "object",
            "properties": {"username": {"type": "string", "description": "Username to disable"}},
            "required": ["username"],
        },
        lambda t, a: t.user.disable_user(a["username"]),
    ),
    ToolSpec(
        "reset_user_password",
        RESET_USER_PASSWORD_DESC,
        {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username to reset password for"},
                "new_password": {"type": "string", "description": "New password (auto-generated if not provided)"},
                "force_change": {"type": "boolean", "description": "Force user to change password at next logon", "default": True},
            },
            "required": ["username"],
        },
        lambda t, a: t.user.reset_password(a["username"], a.get("new_password"), a.get("force_change", True)),
    ),
    ToolSpec(
        "get_user_groups",
        GET_USER_GROUPS_DESC,
        {
            "type": "object",
            "properties": {"username": {"type": "string", "description": "Username to get groups for"}},
            "required": ["username"],
        },
        lambda t, a: t.user.get_user_groups(a["username"]),
    ),
    # ----- Group management -----
    ToolSpec(
        "list_groups",
        LIST_GROUPS_DESC,
        {
            "type": "object",
            "properties": {
                "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
                "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
        },
        lambda t, a: t.group.list_groups(a.get("ou"), a.get("filter_criteria"), a.get("attributes")),
    ),
    ToolSpec(
        "get_group",
        GET_GROUP_DESC,
        {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Group name (sAMAccountName) to search for"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
            "required": ["group_name"],
        },
        lambda t, a: t.group.get_group(a["group_name"], a.get("attributes")),
    ),
    ToolSpec(
        "create_group",
        CREATE_GROUP_DESC,
        {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Group name (sAMAccountName)"},
                "display_name": {"type": "string", "description": "Display name for the group"},
                "description": {"type": "string", "description": "Group description"},
                "ou": {"type": "string", "description": "Organizational Unit DN to create group in"},
                "group_scope": {"type": "string", "description": "Group scope (Global, DomainLocal, Universal)", "default": "Global"},
                "group_type": {"type": "string", "description": "Group type (Security, Distribution)", "default": "Security"},
                "additional_attributes": {"type": "object", "description": "Additional attributes to set"},
            },
            "required": ["group_name"],
        },
        lambda t, a: t.group.create_group(
            a["group_name"], a.get("display_name"), a.get("description"), a.get("ou"),
            a.get("group_scope", "Global"), a.get("group_type", "Security"), a.get("additional_attributes"),
        ),
    ),
    ToolSpec(
        "modify_group",
        MODIFY_GROUP_DESC,
        {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Group name to modify"},
                "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
            },
            "required": ["group_name", "attributes"],
        },
        lambda t, a: t.group.modify_group(a["group_name"], a["attributes"]),
    ),
    ToolSpec(
        "delete_group",
        DELETE_GROUP_DESC,
        {
            "type": "object",
            "properties": {"group_name": {"type": "string", "description": "Group name to delete"}},
            "required": ["group_name"],
        },
        lambda t, a: t.group.delete_group(a["group_name"]),
    ),
    ToolSpec(
        "add_group_member",
        ADD_GROUP_MEMBER_DESC,
        {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Group name to add member to"},
                "member_dn": {"type": "string", "description": "Distinguished name of member to add"},
            },
            "required": ["group_name", "member_dn"],
        },
        lambda t, a: t.group.add_member(a["group_name"], a["member_dn"]),
    ),
    ToolSpec(
        "remove_group_member",
        REMOVE_GROUP_MEMBER_DESC,
        {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Group name to remove member from"},
                "member_dn": {"type": "string", "description": "Distinguished name of member to remove"},
            },
            "required": ["group_name", "member_dn"],
        },
        lambda t, a: t.group.remove_member(a["group_name"], a["member_dn"]),
    ),
    ToolSpec(
        "get_group_members",
        GET_GROUP_MEMBERS_DESC,
        {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Group name to get members for"},
                "recursive": {"type": "boolean", "description": "Include members of nested groups", "default": False},
            },
            "required": ["group_name"],
        },
        lambda t, a: t.group.get_members(a["group_name"], a.get("recursive", False)),
    ),
    # ----- Computer management -----
    ToolSpec(
        "list_computers",
        LIST_COMPUTERS_DESC,
        {
            "type": "object",
            "properties": {
                "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
                "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
        },
        lambda t, a: t.computer.list_computers(a.get("ou"), a.get("filter_criteria"), a.get("attributes")),
    ),
    ToolSpec(
        "get_computer",
        GET_COMPUTER_DESC,
        {
            "type": "object",
            "properties": {
                "computer_name": {"type": "string", "description": "Computer name (sAMAccountName) to search for"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
            "required": ["computer_name"],
        },
        lambda t, a: t.computer.get_computer(a["computer_name"], a.get("attributes")),
    ),
    ToolSpec(
        "create_computer",
        CREATE_COMPUTER_DESC,
        {
            "type": "object",
            "properties": {
                "computer_name": {"type": "string", "description": "Computer name (without $ suffix)"},
                "description": {"type": "string", "description": "Computer description"},
                "ou": {"type": "string", "description": "Organizational Unit DN to create computer in"},
                "dns_hostname": {"type": "string", "description": "DNS hostname"},
                "additional_attributes": {"type": "object", "description": "Additional attributes to set"},
            },
            "required": ["computer_name"],
        },
        lambda t, a: t.computer.create_computer(
            a["computer_name"], a.get("description"), a.get("ou"),
            a.get("dns_hostname"), a.get("additional_attributes"),
        ),
    ),
    ToolSpec(
        "modify_computer",
        MODIFY_COMPUTER_DESC,
        {
            "type": "object",
            "properties": {
                "computer_name": {"type": "string", "description": "Computer name to modify"},
                "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
            },
            "required": ["computer_name", "attributes"],
        },
        lambda t, a: t.computer.modify_computer(a["computer_name"], a["attributes"]),
    ),
    ToolSpec(
        "delete_computer",
        DELETE_COMPUTER_DESC,
        {
            "type": "object",
            "properties": {"computer_name": {"type": "string", "description": "Computer name to delete"}},
            "required": ["computer_name"],
        },
        lambda t, a: t.computer.delete_computer(a["computer_name"]),
    ),
    ToolSpec(
        "enable_computer",
        ENABLE_COMPUTER_DESC,
        {
            "type": "object",
            "properties": {"computer_name": {"type": "string", "description": "Computer name to enable"}},
            "required": ["computer_name"],
        },
        lambda t, a: t.computer.enable_computer(a["computer_name"]),
    ),
    ToolSpec(
        "disable_computer",
        DISABLE_COMPUTER_DESC,
        {
            "type": "object",
            "properties": {"computer_name": {"type": "string", "description": "Computer name to disable"}},
            "required": ["computer_name"],
        },
        lambda t, a: t.computer.disable_computer(a["computer_name"]),
    ),
    ToolSpec(
        "reset_computer_password",
        RESET_COMPUTER_PASSWORD_DESC,
        {
            "type": "object",
            "properties": {"computer_name": {"type": "string", "description": "Computer name to reset password for"}},
            "required": ["computer_name"],
        },
        lambda t, a: t.computer.reset_computer_password(a["computer_name"]),
    ),
    ToolSpec(
        "get_stale_computers",
        GET_STALE_COMPUTERS_DESC,
        {
            "type": "object",
            "properties": {"days": {"type": "integer", "description": "Number of days to consider stale", "default": 90}},
        },
        lambda t, a: t.computer.get_stale_computers(a.get("days", 90)),
    ),
    # ----- Organizational Unit management -----
    ToolSpec(
        "list_organizational_units",
        LIST_ORGANIZATIONAL_UNITS_DESC,
        {
            "type": "object",
            "properties": {
                "parent_ou": {"type": "string", "description": "Parent OU DN to search in"},
                "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
                "recursive": {"type": "boolean", "description": "Search recursively in sub-OUs", "default": True},
            },
        },
        lambda t, a: t.ou.list_ous(a.get("parent_ou"), a.get("filter_criteria"), a.get("attributes"), a.get("recursive", True)),
    ),
    ToolSpec(
        "get_organizational_unit",
        GET_ORGANIZATIONAL_UNIT_DESC,
        {
            "type": "object",
            "properties": {
                "ou_dn": {"type": "string", "description": "Distinguished name of the OU"},
                "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
            },
            "required": ["ou_dn"],
        },
        lambda t, a: t.ou.get_ou(a["ou_dn"], a.get("attributes")),
    ),
    ToolSpec(
        "create_organizational_unit",
        CREATE_ORGANIZATIONAL_UNIT_DESC,
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name of the OU"},
                "parent_ou": {"type": "string", "description": "Parent OU DN"},
                "description": {"type": "string", "description": "OU description"},
                "managed_by": {"type": "string", "description": "DN of user/group managing this OU"},
                "additional_attributes": {"type": "object", "description": "Additional attributes to set"},
            },
            "required": ["name"],
        },
        lambda t, a: t.ou.create_ou(
            a["name"], a.get("parent_ou"), a.get("description"),
            a.get("managed_by"), a.get("additional_attributes"),
        ),
    ),
    ToolSpec(
        "modify_organizational_unit",
        MODIFY_ORGANIZATIONAL_UNIT_DESC,
        {
            "type": "object",
            "properties": {
                "ou_dn": {"type": "string", "description": "OU distinguished name to modify"},
                "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
            },
            "required": ["ou_dn", "attributes"],
        },
        lambda t, a: t.ou.modify_ou(a["ou_dn"], a["attributes"]),
    ),
    ToolSpec(
        "delete_organizational_unit",
        DELETE_ORGANIZATIONAL_UNIT_DESC,
        {
            "type": "object",
            "properties": {
                "ou_dn": {"type": "string", "description": "OU distinguished name to delete"},
                "force": {"type": "boolean", "description": "Force deletion even if OU contains objects", "default": False},
            },
            "required": ["ou_dn"],
        },
        lambda t, a: t.ou.delete_ou(a["ou_dn"], a.get("force", False)),
    ),
    ToolSpec(
        "move_organizational_unit",
        MOVE_ORGANIZATIONAL_UNIT_DESC,
        {
            "type": "object",
            "properties": {
                "ou_dn": {"type": "string", "description": "OU distinguished name to move"},
                "new_parent_dn": {"type": "string", "description": "New parent OU distinguished name"},
            },
            "required": ["ou_dn", "new_parent_dn"],
        },
        lambda t, a: t.ou.move_ou(a["ou_dn"], a["new_parent_dn"]),
    ),
    ToolSpec(
        "get_organizational_unit_contents",
        GET_ORGANIZATIONAL_UNIT_CONTENTS_DESC,
        {
            "type": "object",
            "properties": {
                "ou_dn": {"type": "string", "description": "OU distinguished name"},
                "object_types": {"type": "array", "items": {"type": "string"}, "description": "Types of objects to include"},
            },
            "required": ["ou_dn"],
        },
        lambda t, a: t.ou.get_ou_contents(a["ou_dn"], a.get("object_types")),
    ),
    # ----- Security and audit (read-only reporting) -----
    ToolSpec(
        "get_domain_info",
        GET_DOMAIN_INFO_DESC,
        {"type": "object", "properties": {}},
        lambda t, a: t.security.get_domain_info(),
    ),
    ToolSpec(
        "get_privileged_groups",
        GET_PRIVILEGED_GROUPS_DESC,
        {"type": "object", "properties": {}},
        lambda t, a: t.security.get_privileged_groups(),
    ),
    ToolSpec(
        "get_user_permissions",
        GET_USER_PERMISSIONS_DESC,
        {
            "type": "object",
            "properties": {"username": {"type": "string", "description": "Username to analyze permissions for"}},
            "required": ["username"],
        },
        lambda t, a: t.security.get_user_permissions(a["username"]),
    ),
    ToolSpec(
        "get_inactive_users",
        GET_INACTIVE_USERS_DESC,
        {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Number of days to consider inactive", "default": 90},
                "include_disabled": {"type": "boolean", "description": "Include disabled accounts in results", "default": False},
            },
        },
        lambda t, a: t.security.get_inactive_users(a.get("days", 90), a.get("include_disabled", False)),
    ),
    ToolSpec(
        "get_password_policy_violations",
        GET_PASSWORD_POLICY_VIOLATIONS_DESC,
        {
            "type": "object",
            "properties": {
                "include_disabled": {"type": "boolean", "description": "Include disabled accounts in results", "default": False},
            },
        },
        lambda t, a: t.security.get_password_policy_violations(a.get("include_disabled", False)),
    ),
    ToolSpec(
        "audit_admin_accounts",
        AUDIT_ADMIN_ACCOUNTS_DESC,
        {"type": "object", "properties": {}},
        lambda t, a: t.security.audit_admin_accounts(),
    ),
    ToolSpec(
        "check_password_policy",
        CHECK_PASSWORD_POLICY_DESC,
        {"type": "object", "properties": {}},
        lambda t, a: t.security.check_password_policy(),
    ),
    # ----- Group Policy (read-only) -----
    ToolSpec(
        "get_gpos",
        GET_GPOS_DESC,
        {
            "type": "object",
            "properties": {"name_filter": {"type": "string", "description": "Optional substring to match against GPO display name"}},
        },
        lambda t, a: t.gpo.get_gpos(a.get("name_filter")),
    ),
    ToolSpec(
        "get_gpo",
        GET_GPO_DESC,
        {
            "type": "object",
            "properties": {"identifier": {"type": "string", "description": "GPO GUID (with or without braces) or exact display name"}},
            "required": ["identifier"],
        },
        lambda t, a: t.gpo.get_gpo(a["identifier"]),
    ),
    ToolSpec(
        "get_linked_gpos",
        GET_LINKED_GPOS_DESC,
        {
            "type": "object",
            "properties": {"target_dn": {"type": "string", "description": "DN of the OU/domain/site to inspect"}},
            "required": ["target_dn"],
        },
        lambda t, a: t.gpo.get_linked_gpos(a["target_dn"]),
    ),
    ToolSpec(
        "get_gpo_contents",
        GET_GPO_CONTENTS_DESC,
        {
            "type": "object",
            "properties": {
                "identifier": {"type": "string", "description": "GPO GUID (with or without braces) or exact display name"},
                "include_registry": {"type": "boolean", "description": "Parse Registry.pol files", "default": True},
                "max_value_chars": {"type": "integer", "description": "Truncate values longer than this", "default": 6000},
                "summary": {"type": "boolean", "description": "Omit registry entries and full AppLocker rule XML; return per-rule digests and section names only", "default": False},
            },
            "required": ["identifier"],
        },
        lambda t, a: t.gpo.get_gpo_contents(
            a["identifier"], a.get("include_registry", True), a.get("max_value_chars", 6000),
            a.get("summary", False),
        ),
    ),
    # ----- Hardening scan (read-only) -----
    ToolSpec(
        "scan_hardening",
        SCAN_HARDENING_DESC,
        {
            "type": "object",
            "properties": {
                "control_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Evaluate only these control ids (e.g. "
                                   "DEVORE-03-LDAP-SERVER-SIGNING). Omit for the "
                                   "whole catalog.",
                },
                "include_not_applicable": {
                    "type": "boolean",
                    "description": "Include findings whose control did not apply. "
                                   "Controls flagged needs_baseline_value are "
                                   "always included either way.",
                    "default": False,
                },
            },
        },
        lambda t, a: t.hardening.scan_hardening(
            a.get("control_ids"), a.get("include_not_applicable", False),
        ),
    ),
    ToolSpec(
        "write_hardening_report",
        WRITE_HARDENING_REPORT_DESC,
        {
            "type": "object",
            "properties": {
                "output_path": {
                    "type": "string",
                    "description": "Where to write the .html report. '~' is "
                                   "expanded; a relative path resolves against "
                                   "the server's working directory. Missing "
                                   "parent directories are created. An existing "
                                   "file is overwritten only if it is a previous "
                                   "ADitor report.",
                },
                "control_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Report on only these control ids (e.g. "
                                   "DEVORE-03-LDAP-SERVER-SIGNING). Omit for the "
                                   "whole catalog.",
                },
            },
            "required": ["output_path"],
        },
        lambda t, a: t.hardening.write_hardening_report(
            a.get("output_path"), a.get("control_ids"),
        ),
    ),
    ToolSpec(
        "write_hardening_scan",
        WRITE_HARDENING_SCAN_DESC,
        {
            "type": "object",
            "properties": {
                "output_path": {
                    "type": "string",
                    "description": "Where to write the .json scan. '~' is "
                                   "expanded; a relative path resolves against "
                                   "the server's working directory. Missing "
                                   "parent directories are created. An existing "
                                   "file is overwritten only if it is a previous "
                                   "ADitor scan.",
                },
                "control_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Scan only these control ids (e.g. "
                                   "DEVORE-03-LDAP-SERVER-SIGNING). Omit for the "
                                   "whole catalog, which is what a scan meant "
                                   "for diffing should normally do.",
                },
            },
            "required": ["output_path"],
        },
        lambda t, a: t.hardening.write_hardening_scan(
            a.get("output_path"), a.get("control_ids"),
        ),
    ),
    ToolSpec(
        "diff_hardening_scans",
        DIFF_HARDENING_SCANS_DESC,
        {
            "type": "object",
            "properties": {
                "before_path": {
                    "type": "string",
                    "description": "The earlier scan's .json file, as written by "
                                   "write_hardening_scan.",
                },
                "after_path": {
                    "type": "string",
                    "description": "The later scan's .json file. Both must be "
                                   "scans of the same domain.",
                },
            },
            "required": ["before_path", "after_path"],
        },
        lambda t, a: t.hardening.diff_hardening_scans(
            a.get("before_path"), a.get("after_path"),
        ),
    ),
    # ----- System -----
    ToolSpec(
        "test_connection",
        TEST_CONNECTION_DESC,
        {"type": "object", "properties": {}},
        _handle_test_connection,
    ),
    ToolSpec(
        "health",
        HEALTH_DESC,
        {"type": "object", "properties": {}},
        _handle_health,
    ),
    ToolSpec(
        "get_schema_info",
        GET_SCHEMA_INFO_DESC,
        {"type": "object", "properties": {}},
        _handle_schema_info,
    ),
]


def tool_names() -> List[str]:
    """Return the list of tool names in registry order."""
    return [spec.name for spec in TOOLS]
