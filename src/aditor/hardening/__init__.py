"""ADitor's hardening scan engine.

Three pieces, deliberately layered so the logic is testable offline:

* :mod:`aditor.hardening.catalog` — the declarative control catalog
  (``controls.json``), its model, and a validating loader.
* :mod:`aditor.hardening.evaluator` — pure functions that turn parsed GPO
  content plus a control into a finding (result, rollout state, evidence,
  conflicts). No LDAP, no SMB, no clock.
* :mod:`aditor.tools.hardening` — the orchestration behind the
  ``scan_hardening`` MCP tool: read GPOs, hand them to the evaluator, add the
  provenance header.

``SCAN_ENGINE_VERSION`` is the version of the *scan logic*, reported in every
scan's provenance header alongside the catalog version, so a stored report can
always say which engine and which baseline produced it.
"""

SCAN_ENGINE_VERSION = "1.0.0"

from .catalog import (  # noqa: E402  (re-exported for callers' convenience)
    Catalog,
    CatalogError,
    Control,
    build_catalog,
    load_catalog,
)

__all__ = [
    "SCAN_ENGINE_VERSION",
    "Catalog",
    "CatalogError",
    "Control",
    "build_catalog",
    "load_catalog",
]
