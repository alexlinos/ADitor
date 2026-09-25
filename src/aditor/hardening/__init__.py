"""ADitor's hardening scan engine.

Seven pieces, deliberately layered so the logic is testable offline:

* :mod:`aditor.hardening.catalog` — the declarative control catalog
  (``controls.json``), its model, and a validating loader.
* :mod:`aditor.hardening.evaluator` — pure functions that turn parsed GPO
  content plus a control into a finding (result, rollout state, evidence,
  conflicts). No LDAP, no SMB, no clock.
* :mod:`aditor.hardening.report` — pure rendering of a scan payload into one
  self-contained HTML file, ordered by actionability. Consumes the scan and adds
  nothing to it; the JSON stays the source of truth.
* :mod:`aditor.hardening.scanfile` — storing that same JSON payload on disk and
  reading it back, with the report's path guards.
* :mod:`aditor.hardening.snapshot` — putting one scan's ``scan.json`` and
  ``report.html`` in one dated folder, from a single payload so the two cannot
  disagree.
* :mod:`aditor.hardening.diff` — comparing two stored scans. Its first job is to
  say whether a difference is the *domain's* or the *tool's*; see that module's
  docstring for why that distinction is the whole feature.
* :mod:`aditor.hardening.collect` — the one piece that touches the directory:
  read GPOs over LDAP and SYSVOL, hand them to the evaluator, add the provenance
  header. ``aditor scan`` and the desktop app both run it.

``SCAN_ENGINE_VERSION`` is the version of the *scan logic* and
``REPORT_FORMAT_VERSION`` the version of the rendered layout. Both are reported
in a scan's provenance header alongside the catalog version, so a stored report
can always say which engine, which renderer and which baseline produced it — and
so a diff of two stored scans can say whether the engine or the baseline moved
underneath it.
"""

SCAN_ENGINE_VERSION = "1.3.0"
