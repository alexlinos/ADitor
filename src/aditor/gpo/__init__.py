"""Group Policy domain logic that needs no directory connection.

This package holds the DC-free half of ADitor's Group Policy support: pure
functions that turn bytes and attribute strings from SYSVOL/LDAP into plain
data structures. They are deliberately separate from ``aditor.tools.gpo``
(the MCP tool class, which owns LDAP/SMB I/O) so they can be unit-tested
offline and reused by any caller — the OU tools today, the Phase-2 hardening
scanner later.
"""

from .parsers import (
    APPLOCKER_ENFORCEMENT,
    REG_TYPES,
    applocker_rule_digest,
    decode_gpo_status,
    decode_version,
    extract_applocker,
    normalize_guid,
    parse_gp_link,
    parse_ini,
    parse_registry_pol,
    summarize_applocker,
    summarize_gpo_contents,
)

__all__ = [
    "APPLOCKER_ENFORCEMENT",
    "REG_TYPES",
    "applocker_rule_digest",
    "decode_gpo_status",
    "decode_version",
    "extract_applocker",
    "normalize_guid",
    "parse_gp_link",
    "parse_ini",
    "parse_registry_pol",
    "summarize_applocker",
    "summarize_gpo_contents",
]
