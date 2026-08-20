"""ADitor's hardening scan engine.

Six pieces, deliberately layered so the logic is testable offline:

* :mod:`aditor.hardening.catalog` — the declarative control catalog
  (``controls.json``), its model, and a validating loader.
* :mod:`aditor.hardening.evaluator` — pure functions that turn parsed GPO
  content plus a control into a finding (result, rollout state, evidence,
  conflicts). No LDAP, no SMB, no clock.
* :mod:`aditor.hardening.report` — pure rendering of a scan payload into one
  self-contained HTML file, ordered by actionability. Consumes the scan and adds
  nothing to it; the JSON stays the source of truth.
* :mod:`aditor.hardening.scanfile` — storing that same JSON payload on disk and
  reading it back, with the report tool's path guards.
* :mod:`aditor.hardening.diff` — comparing two stored scans. Its first job is to
  say whether a difference is the *domain's* or the *tool's*; see that module's
  docstring for why that distinction is the whole feature.
* :mod:`aditor.tools.hardening` — the orchestration behind the
  ``scan_hardening``, ``write_hardening_report``, ``write_hardening_scan`` and
  ``diff_hardening_scans`` MCP tools: read GPOs, hand them to the evaluator, add
  the provenance header.

``SCAN_ENGINE_VERSION`` is the version of the *scan logic* and
``REPORT_FORMAT_VERSION`` the version of the rendered layout. Both are reported
in a scan's provenance header alongside the catalog version, so a stored report
can always say which engine, which renderer and which baseline produced it — and
so a diff of two stored scans can say whether the engine or the baseline moved
underneath it.
"""

SCAN_ENGINE_VERSION = "1.3.0"

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
    group_findings,
    headline_counts,
    render_report,
    write_report,
)
from .scanfile import (  # noqa: E402
    SCAN_FILE_FORMAT_VERSION,
    SCAN_FILE_MARKER,
    ScanFileError,
    read_scan,
    write_scan,
)
from .diff import (  # noqa: E402
    DIFF_FORMAT_VERSION,
    ScanDiffError,
    diff_scan_files,
    diff_scans,
)

__all__ = [
    "SCAN_ENGINE_VERSION",
    "REPORT_FORMAT_VERSION",
    "SCAN_FILE_FORMAT_VERSION",
    "SCAN_FILE_MARKER",
    "DIFF_FORMAT_VERSION",
    "Catalog",
    "CatalogError",
    "Control",
    "GpoLink",
    "GpoSnapshot",
    "ReportPathError",
    "ScanDiffError",
    "ScanFileError",
    "build_catalog",
    "load_catalog",
    "evaluate_control",
    "evaluate_controls",
    "diff_scan_files",
    "diff_scans",
    "group_findings",
    "headline_counts",
    "read_scan",
    "render_report",
    "write_report",
    "write_scan",
]
