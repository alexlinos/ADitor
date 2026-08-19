"""ADitor's hardening scan engine.

Four pieces, deliberately layered so the logic is testable offline:

* :mod:`aditor.hardening.catalog` — the declarative control catalog
  (``controls.json``), its model, and a validating loader.
* :mod:`aditor.hardening.evaluator` — pure functions that turn parsed GPO
  content plus a control into a finding (result, rollout state, evidence,
  conflicts). No LDAP, no SMB, no clock.
* :mod:`aditor.hardening.report` — pure rendering of a scan payload into one
  self-contained HTML file, ordered by actionability. Consumes the scan and adds
  nothing to it; the JSON stays the source of truth.
* :mod:`aditor.tools.hardening` — the orchestration behind the
  ``scan_hardening`` and ``write_hardening_report`` MCP tools: read GPOs, hand
  them to the evaluator, add the provenance header.

``SCAN_ENGINE_VERSION`` is the version of the *scan logic* and
``REPORT_FORMAT_VERSION`` the version of the rendered layout. Both are reported
in a scan's provenance header alongside the catalog version, so a stored report
can always say which engine, which renderer and which baseline produced it.
"""

SCAN_ENGINE_VERSION = "1.2.0"

from .catalog import (  # noqa: E402  (re-exported for callers' convenience)
    Catalog,
    CatalogError,
    Control,
    build_catalog,
    load_catalog,
)
from .evaluator import (  # noqa: E402
    GpoLink,
    GpoSnapshot,
    evaluate_control,
    evaluate_controls,
)
from .report import (  # noqa: E402
    REPORT_FORMAT_VERSION,
    ReportPathError,
    headline_counts,
    render_report,
    write_report,
)

__all__ = [
    "SCAN_ENGINE_VERSION",
    "REPORT_FORMAT_VERSION",
    "Catalog",
    "CatalogError",
    "Control",
    "GpoLink",
    "GpoSnapshot",
    "ReportPathError",
    "build_catalog",
    "load_catalog",
    "evaluate_control",
    "evaluate_controls",
    "headline_counts",
    "render_report",
    "write_report",
]
