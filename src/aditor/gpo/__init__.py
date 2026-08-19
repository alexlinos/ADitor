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
    REGISTRY_XML_ACTIONS,
    REGISTRY_XML_DEFAULT_ACTION,
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

__all__ = [
    "APPLOCKER_ENFORCEMENT",
    "REG_TYPES",
    "REGISTRY_XML_ACTIONS",
    "REGISTRY_XML_DEFAULT_ACTION",
    "REGISTRY_XML_DRIFT_CORRECTING_ACTIONS",
    "REGISTRY_XML_WRITE_ACTIONS",
    "applocker_rule_digest",
    "decode_gpo_status",
    "decode_version",
    "extract_applocker",
    "normalize_guid",
    "normalize_registry_key",
    "parse_gp_link",
    "parse_ini",
    "parse_registry_pol",
    "parse_registry_xml",
    "parse_security_template_registry_values",
    "summarize_applocker",
    "summarize_gpo_contents",
]
