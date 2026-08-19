"""Render a hardening scan into a single self-contained HTML report.

**The JSON is the source of truth; this module only renders it.** Everything
below is a pure function of the dict :func:`aditor.tools.hardening.HardeningTools`
already produces — no LDAP, no SMB, no clock, no catalog lookups. Nothing is
derived that the scan does not already state, so a saved report and the JSON it
came from can never disagree.

**No new dependency.** The page is assembled with ``string.Template`` and
f-strings out of the standard library. Phase 1 spent a work package removing
needless dependencies and the discipline is deliberate: a template engine buys
nothing here that a handful of small ``_render_*`` functions do not, and the
catalog already made the same call (JSON over YAML) for the same reason.

**Everything interpolated is escaped.** GPO display names, registry data, DNs and
SMB error strings are *directory* content — attacker-influenceable text — and this
file gets opened in a browser. Every value goes through :func:`_esc`
(``html.escape`` with ``quote=True``), including the catalog's own prose, so no
future edit can introduce an unescaped hole. URLs additionally have to pass
:func:`_safe_url` before becoming an ``href``.

**Self-contained.** One ``.html`` file: inline CSS, no external stylesheet, no
CDN, no web font, no image, and no JavaScript at all. It opens correctly from a
``file://`` path, survives being emailed or dropped in a ticket, and makes no
network request when opened. The only outbound references are the citation
hyperlinks, which are inert until a reader clicks them. ``<details>`` provides
the collapsing without script.

**PDF is deliberately not built** (see ``docs/HARDENING_CATALOG.md``): a browser
can print this file if a PDF is ever wanted, which is cheaper than dragging a
renderer and its native dependencies into the packaging.

Ordering is by **actionability, not catalog order**, because the report's job is
to drive action rather than to be admired. See :data:`SECTIONS`:

1. Read failures and ``error`` findings — first, and before any verdict section.
   Per the evaluator, one unreadable GPO turns an unset key into an ``error``, so
   the affected verdicts are *unknown, not clean*, and a reader who misses that
   misreads the whole report.
2. ``fail`` findings, with expected versus every found value, its source GPO, the
   catalog's remediation, and the phasing caveat.
3. Conflicts — cross-referenced rather than owned, because a conflict on a
   *passing* control is the dangerous one.
4. ``os-default`` findings as hardening *opportunities* — never as enforcement.
5. Unscored (``needs_baseline_value``) controls, explicitly not judged.
6. Passes last, compact.
"""

from __future__ import annotations

import html
import os
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import SCAN_ENGINE_VERSION

# Version of the *report layout*. Bumped when the rendered structure changes, so
# a stored report can say which renderer produced it alongside which engine and
# which catalog scored it.
REPORT_FORMAT_VERSION = "1.0.0"

# The string that identifies a file as one of our reports. ``write_report``
# refuses to overwrite an existing file that does not carry it, so a mistyped
# output path cannot silently destroy someone's document.
REPORT_MARKER = "aditor-hardening-report"

# How much of an existing file to search for the marker before refusing it.
_MARKER_SCAN_BYTES = 8192

# Suffixes ``write_report`` accepts. A path guard as much as a formality: it
# stops ``write_hardening_report("controls.json")`` from ever being attempted.
HTML_SUFFIXES = (".html", ".htm")

# Placeholder for a value the scan did not provide.
_ABSENT = "&mdash;"

# --- section model --------------------------------------------------------- #
#
# Each finding lands in exactly one of these, chosen by _section_for in this
# order. Conflicts are the one cross-cut: a finding with a conflict is listed in
# the conflicts section *as well as* in its verdict section, because a conflict
# on a pass is precisely the case a verdict-only reading gets wrong.

SECTION_UNKNOWN = "unknown"
SECTION_FAIL = "failures"
SECTION_CONFLICTS = "conflicts"
SECTION_OPPORTUNITIES = "opportunities"
SECTION_NOT_JUDGED = "not-judged"
SECTION_PASSES = "passes"
SECTION_NOT_APPLICABLE = "not-applicable"

# id, heading, lede. The order here is the order in the document.
SECTIONS: Tuple[Tuple[str, str, str], ...] = (
    (SECTION_UNKNOWN, "Unknown — the scan could not decide",
     "These controls were not judged because the scan could not read what it "
     "needed. <strong>They are unknown, not clean.</strong> An unreadable GPO "
     "could set any of these keys to anything, including a value below the "
     "Windows default, so no verdict is issued. Fix the read failures above and "
     "re-scan before treating any of this as evidence."),
    (SECTION_FAIL, "Failures — act on these",
     "Each failure below shows what the baseline expects, every value actually "
     "found and which GPO set it, and the catalog's remediation. "
     "<strong>Read the rollout guidance before changing anything:</strong> "
     "several of these controls are audit-first-then-enforce, and jumping "
     "straight to enforcement is how a hardening project causes an outage."),
    (SECTION_CONFLICTS, "Conflicts — precedence unresolved",
     "Two or more GPOs set the same key to different values. This scan "
     "deliberately does not resolve policy precedence, so which value actually "
     "applies is <strong>unproven</strong> — confirm the effective value with "
     "<code>gpresult</code> / RSoP before acting on any single GPO's setting. "
     "Findings here also appear in their verdict section: a conflict on a "
     "passing control is the one most likely to be misread."),
    (SECTION_OPPORTUNITIES, "Hardening opportunities — at the Windows default",
     "No GPO sets these keys. The verdict rests on a Microsoft-documented "
     "Windows default, so the value is <em>assumed</em>, not configured. "
     "<strong>Nothing in Group Policy holds it there</strong> and nothing would "
     "stop a future GPO from lowering it. Configure the policy explicitly to "
     "make the value enforced and auditable."),
    (SECTION_NOT_JUDGED, "Not judged — no baseline value to score against",
     "These controls were <strong>not evaluated at all</strong>. The source does "
     "not state their exact expected value, and this tool never guesses one, so "
     "no verdict is issued. <strong>They are not passes.</strong> Their state is "
     "unknown until the value is sourced from a Microsoft Security Baseline or "
     "CIS Benchmark."),
    (SECTION_PASSES, "Passes",
     "Evidence retained, kept out of the way. Each row expands to the full "
     "expected-versus-found evidence. A pass is a statement about the value this "
     "scan read, not a guarantee that precedence leaves it effective — check the "
     "conflicts section."),
    (SECTION_NOT_APPLICABLE, "Not applicable",
     "The control's own definition puts it out of scope for what this scan "
     "found. No verdict is claimed either way."),
)

_SECTION_LEDES = {section_id: lede for section_id, _title, lede in SECTIONS}
_SECTION_TITLES = {section_id: title for section_id, title, _lede in SECTIONS}

# Human labels for the raw enum values the scan emits.
_RESULT_LABELS = {
    "pass": "Pass",
    "fail": "Fail",
    "error": "Unknown",
    "not_applicable": "Not applicable",
}
_STATE_LABELS = {
    "not_started": "not started",
    "audit": "audit",
    "enforced": "enforced",
}
_SOURCE_LABELS = {
    "gpo": "configured by Group Policy",
    "os-default": "Windows default (assumed, not enforced by Group Policy)",
    "not-configured": "no GPO sets this key",
    "unknown": "not established by this scan",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                   "informational": 4}

# The standing disclaimer. Restated in the document because a saved report gets
# read without the tool that produced it.
_PRECEDENCE_DISCLAIMER = (
    "Policy precedence (RSoP) is <strong>not resolved</strong> by this scan. "
    "Every GPO that sets a control's key is reported with its link path and "
    "enforced flag, and disagreements are flagged as conflicts, rather than "
    "guessing which GPO wins. Where a finding carries a conflict, confirm the "
    "effective value with <code>gpresult</code> / RSoP before acting on it."
)

_READ_FAILURE_LEDE = (
    "<strong>This scan is incomplete.</strong> The GPOs listed below could not "
    "be read, so no statement in this report about a key they might set is "
    "proven. Where a control's key was not found in any GPO that <em>was</em> "
    "read, the finding is reported as <em>unknown</em> rather than as a pass — an "
    "unreadable GPO could set that key to anything. Verdicts for the affected "
    "controls are <strong>unknown, not clean</strong>. Fix the read failures and "
    "re-scan."
)

_NO_READ_FAILURE_NOTE = (
    "Every GPO in the domain was read successfully, so \"no GPO sets this key\" "
    "is a statement this scan is entitled to make."
)

# Rendered when a failing control's catalog entry carries no phasing guidance at
# all. This is a *catalog gap*, reported as one — the renderer never invents
# rollout prose, because advice this tool made up could cause the outage the
# phasing fields exist to prevent.
_PHASING_GAP_NOTE = (
    "<strong>Catalog gap:</strong> this control states no interim step and no "
    "audit-before-enforce evidence, so this report has no phased-rollout "
    "guidance to give you for it. That is a gap in the catalog, not a statement "
    "that the change is safe to apply domain-wide. Pilot it before rolling it "
    "out, and raise the gap so the catalog can be sourced properly."
)


# --------------------------------------------------------------------------- #
# Escaping — every value in the document goes through here
# --------------------------------------------------------------------------- #

def _esc(value: Any, absent: str = _ABSENT) -> str:
    """HTML-escape any value for insertion into text or an attribute.

    ``quote=True`` so the same function is safe in both positions; there is
    deliberately no "trusted" variant, because the one place a second variant
    gets used by accident is on a GPO display name.

    ``None`` and the empty string become ``absent`` (an em dash by default) —
    already-escaped markup this module owns, never caller data.
    """
    if value is None:
        return absent
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    if not text:
        return absent
    return html.escape(text, quote=True)


def _esc_value(value: Any) -> str:
    """Escape a *found or expected* registry value, preserving its repr.

    ``repr`` rather than ``str`` so ``2`` and ``"2"`` are distinguishable in the
    evidence: a security template writing the string ``"2"`` where the baseline
    expects the number ``2`` is exactly the sort of detail an auditor is reading
    for. Lists render as a comma-separated set of reprs, which is how the ``in``
    operator's ``final_expected`` reads best.
    """
    if value is None:
        return _ABSENT
    if isinstance(value, (list, tuple)):
        if not value:
            return _ABSENT
        return _esc(", ".join(repr(item) for item in value))
    return _esc(repr(value))


def _safe_url(url: Any) -> Optional[str]:
    """Return an escaped ``href`` only for an http(s) URL, else ``None``.

    Citations come from the catalog, which this repo controls, but a renderer
    that will happily emit whatever string it is handed as an ``href`` is one
    catalog edit away from a ``javascript:`` link in a document people open in a
    browser. Anything else is rendered as plain text instead.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    lowered = text.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        return None
    return html.escape(text, quote=True)


def _link(url: Any, label: Any = None) -> str:
    """A citation link — or the citation as inert escaped text when unsafe.

    An unsafe URL is *shown* rather than dropped: silently swallowing a citation
    hides a broken catalog entry, and the whole point of the citation is that a
    reader can check it. It just never becomes an ``href``.
    """
    href = _safe_url(url)
    text = _esc(label if label is not None else url)
    if href is not None:
        return (f'<a href="{href}" rel="noreferrer noopener" '
                f'target="_blank">{text}</a>')
    if url in (None, ""):
        return text
    return (f'{text} <span class="cite-bad">(citation URL not linked &mdash; it '
            f'is not an http(s) address: <code>{_esc(url)}</code>)</span>')


# --------------------------------------------------------------------------- #
# Classification — which section a finding belongs to
# --------------------------------------------------------------------------- #

def _section_for(finding: Dict[str, Any]) -> str:
    """Which single section owns this finding.

    Priority, not catalog order. ``error`` first because "we could not tell" has
    to outrank everything; ``fail`` next; then the unscored controls, which must
    never fall through into the passes; then os-default, whose verdict rests on
    an assumption rather than on Group Policy; then passes.

    An os-default finding that *failed* stays in the failures section — a
    documented default below the baseline floor is a real finding to act on, and
    its card still carries the "nothing enforces a default" framing.
    """
    result = finding.get("result")
    if result == "error":
        return SECTION_UNKNOWN
    if result == "fail":
        return SECTION_FAIL
    if finding.get("unscored_reason"):
        return SECTION_NOT_JUDGED
    if (finding.get("evidence") or {}).get("source") == "os-default":
        return SECTION_OPPORTUNITIES
    if result == "pass":
        return SECTION_PASSES
    return SECTION_NOT_APPLICABLE


def group_findings(findings: Sequence[Dict[str, Any]]
                   ) -> Dict[str, List[Dict[str, Any]]]:
    """Bucket findings into :data:`SECTIONS`, severity-ordered within a bucket.

    The conflicts bucket is populated independently of the others: a finding
    carrying a conflict appears both there and in its verdict section.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {
        section_id: [] for section_id, _t, _l in SECTIONS}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        grouped[_section_for(finding)].append(finding)
        if finding.get("conflict"):
            grouped[SECTION_CONFLICTS].append(finding)

    for bucket in grouped.values():
        bucket.sort(key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity")), 99),
            str(f.get("control_id") or "")))
    return grouped


# --------------------------------------------------------------------------- #
# Small building blocks
# --------------------------------------------------------------------------- #

def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{_esc(kind, "none")}">{text}</span>'


def _rows(pairs: Sequence[Tuple[str, str]]) -> str:
    """A definition table from (already-escaped) label/value pairs."""
    body = "".join(f"<tr><th scope=\"row\">{label}</th><td>{value}</td></tr>"
                   for label, value in pairs if value is not None)
    return f'<table class="kv">{body}</table>' if body else ""


def _notes_list(notes: Any, css_class: str = "notes") -> str:
    """The evaluator's ``evidence.notes`` — its own words, escaped."""
    items = [f"<li>{_esc(note)}</li>" for note in (notes or [])
             if str(note or "").strip()]
    if not items:
        return ""
    return f'<ul class="{css_class}">{"".join(items)}</ul>'


def _links_text(links: Any) -> str:
    """Link paths for one GPO: where it is linked and how."""
    if not links:
        return '<span class="muted">not linked anywhere this scan could see</span>'
    parts = []
    for link in links:
        if not isinstance(link, dict):
            continue
        flags = []
        if link.get("enforced"):
            flags.append("enforced")
        if not link.get("link_enabled", True):
            flags.append("link disabled")
        if link.get("block_inheritance"):
            flags.append("blocks inheritance")
        suffix = f' <span class="flags">({_esc(", ".join(flags))})</span>' if flags else ""
        parts.append(f'<li><code>{_esc(link.get("target_dn"))}</code>{suffix}</li>')
    return f'<ul class="links">{"".join(parts)}</ul>' if parts else ""


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #

def _render_provenance(scan: Dict[str, Any], counts: Dict[str, Any]) -> str:
    """The audit header: what ran, against which baseline, when, and where.

    A report that cannot state "against which baseline, when, which domain" is
    folklore rather than evidence, so this renders in the document itself and not
    only in the JSON.
    """
    baseline = scan.get("baseline") or {}
    unreadable = _as_int(scan.get("gpos_unreadable"))

    pairs: List[Tuple[str, str]] = [
        ("Tool", _esc(scan.get("tool", "scan_hardening"))),
        ("Scan engine version", _esc(scan.get("tool_version"))),
        ("Report format version", _esc(REPORT_FORMAT_VERSION)),
        ("Catalog version", _esc(scan.get("catalog_version"))),
        ("Catalog source", _esc(scan.get("catalog_source"))),
        ("Scan timestamp (UTC)", _esc(scan.get("timestamp"))),
        ("Domain", _esc(scan.get("domain"))),
        ("Base DN", f'<code>{_esc(scan.get("base_dn"))}</code>'),
        ("GPOs scanned", _esc(scan.get("gpos_scanned"))),
        ("GPOs unreadable",
         f'<strong class="bad">{_esc(unreadable)}</strong>' if unreadable
         else _esc(scan.get("gpos_unreadable", 0))),
        ("Controls evaluated", _esc(counts.get("total"))),
        ("Controls scored", _esc(counts.get("scored"))),
        ("Read-only scan", _esc(scan.get("read_only", True))),
        ("Not-applicable findings included",
         _esc(scan.get("include_not_applicable", False))),
    ]
    if baseline.get("primary_source"):
        pairs.append(("Primary baseline source",
                      _esc(baseline.get("primary_source"))))
    if baseline.get("value_policy"):
        pairs.append(("Value policy", _esc(baseline.get("value_policy"))))
    if baseline.get("pending_value_source"):
        pairs.append(("Pending value sources",
                      _esc(baseline.get("pending_value_source"))))

    catalog_notes = _notes_list(scan.get("catalog_notes"), "notes small")
    notes_block = (f'<details class="prov-notes"><summary>Catalog notes</summary>'
                   f'{catalog_notes}</details>' if catalog_notes else "")

    return (
        '<section class="provenance" id="provenance">'
        '<h2>Provenance</h2>'
        f'{_rows(pairs)}'
        f'<p class="disclaimer">{_PRECEDENCE_DISCLAIMER}</p>'
        f'{notes_block}'
        '</section>'
    )


def _render_counts(counts: Dict[str, Any]) -> str:
    """The headline numbers, in actionability order."""
    tiles = [
        ("Unknown", counts.get("error"), "unknown"),
        ("Failures", counts.get("fail"), "fail"),
        ("Conflicts", counts.get("conflicts"), "conflict"),
        ("At OS default", counts.get("os_default"), "osdefault"),
        ("Not judged", counts.get("needs_baseline_value"), "notjudged"),
        ("Passes", counts.get("pass"), "pass"),
    ]
    cells = "".join(
        f'<li class="tile tile-{kind}">'
        f'<span class="tile-n">{_esc(value, "0")}</span>'
        f'<span class="tile-l">{_esc(label)}</span></li>'
        for label, value, kind in tiles)

    reconcile = (
        f'{_esc(counts.get("rendered"), "0")} of '
        f'{_esc(counts.get("total"), "0")} findings rendered; '
        f'{_esc(counts.get("hidden"), "0")} hidden by the not-applicable filter. '
        f'Of the passes, {_esc(counts.get("os_default_pass"), "0")} rest on a '
        f'documented Windows default rather than on any GPO — "at OS default" '
        f'counts every finding judged against a default, which can also be a '
        f'failure or an unknown, so it is not a number to subtract from passes.'
    )
    return (
        '<section class="summary" id="summary">'
        '<h2>Headline counts</h2>'
        f'<ul class="tiles">{cells}</ul>'
        f'<p class="small muted">{reconcile}</p>'
        '</section>'
    )


def _render_read_failures(scan: Dict[str, Any],
                          read_errors: Sequence[Dict[str, Any]]) -> str:
    """The unmissable read-failure banner, rendered before any verdict.

    Deliberately the first thing after the title — ahead of the provenance
    table, the counts and every verdict section. A reader who does not see this
    reads the rest of the report as a clean bill of health it is not entitled to
    give.
    """
    if not read_errors:
        return (f'<p class="ok-banner" id="read-failures">'
                f'<strong>All GPOs read.</strong> {_esc(_NO_READ_FAILURE_NOTE)}'
                f'</p>')

    rows = "".join(
        '<tr>'
        f'<td>{_esc((error or {}).get("display_name"))}</td>'
        f'<td><code>{_esc((error or {}).get("gpo_dn"))}</code></td>'
        f'<td class="err">{_esc((error or {}).get("error"))}</td>'
        '</tr>'
        for error in read_errors if isinstance(error, dict))

    scanned = _as_int(scan.get("gpos_scanned"))
    return (
        '<section class="alert" id="read-failures">'
        '<h2>&#9888; GPO read failures — this scan is incomplete</h2>'
        f'<p class="alert-count">{len(read_errors)} of {_esc(scanned, "?")} '
        f'GPO(s) could not be read.</p>'
        f'<p>{_READ_FAILURE_LEDE}</p>'
        '<table class="grid"><thead><tr>'
        '<th>GPO display name</th><th>GPO DN</th><th>Read error</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
        '</section>'
    )


# --------------------------------------------------------------------------- #
# Finding cards
# --------------------------------------------------------------------------- #

def _render_expected(finding: Dict[str, Any]) -> str:
    """The baseline side of the evidence: what the control asserts."""
    evidence = finding.get("evidence") or {}
    expected = evidence.get("expected")
    if not isinstance(expected, dict):
        return ('<p class="muted">This control asserts no expected value — see '
                '"not judged" below.</p>')

    pairs = [
        ("Operator", f'<code>{_esc(expected.get("operator"))}</code>'),
        ("Interim (audit step)", _esc_value(expected.get("interim"))),
        ("Final (enforced)", _esc_value(expected.get("final"))),
    ]
    if expected.get("os_default") is not None:
        pairs.append(("Documented Windows default",
                      _esc_value(expected.get("os_default"))))
    if expected.get("value_source"):
        pairs.append(("Where the value comes from",
                      _esc(expected.get("value_source"))))
    return _rows(pairs)


def _render_found(finding: Dict[str, Any]) -> str:
    """Every value found, with the GPO that set it and that GPO's link path."""
    evidence = finding.get("evidence") or {}
    found = evidence.get("found") or []
    source = evidence.get("source")

    if not found:
        os_default = evidence.get("os_default") or {}
        if source == "os-default" and os_default.get("applied"):
            return (
                '<p class="found-none osdefault">'
                '<strong>No GPO sets this key.</strong> Judged against the '
                f'documented Windows default {_esc_value(os_default.get("value"))} '
                '— an assumed value. <strong>Nothing in Group Policy holds it '
                'there.</strong>'
                f'{_cite("Default documented by", os_default.get("value_source"))}'
                '</p>')
        if os_default and not os_default.get("applied"):
            return (
                '<p class="found-none bad">'
                '<strong>No GPO that could be read sets this key</strong>, and '
                'the scan could not read every GPO, so the documented default '
                f'{_esc_value(os_default.get("value"))} was <strong>not '
                'applied</strong>: '
                f'{_esc(os_default.get("not_applied_reason"))}</p>')
        label = _SOURCE_LABELS.get(str(source), "no value found")
        return (f'<p class="found-none">No value found — '
                f'<em>{_esc(label)}</em>.</p>')

    rows = []
    for match in found:
        if not isinstance(match, dict):
            continue
        state = match.get("rollout_state")
        rows.append(
            '<tr>'
            f'<td class="val"><code>{_esc_value(match.get("value"))}</code></td>'
            f'<td>{_esc(match.get("type_name"))}</td>'
            f'<td>{_STATE_LABELS.get(str(state), _esc(state))}</td>'
            f'<td>{_esc(match.get("gpo_display_name"))}'
            f'<br><code class="dn">{_esc(match.get("gpo_dn"))}</code>'
            f'<br><span class="small muted">read from '
            f'{_esc(match.get("source_file"))}</span></td>'
            f'<td>{"<strong>yes</strong>" if match.get("enforced_link") else "no"}'
            f'{_links_text(match.get("links"))}</td>'
            '</tr>')

    return (
        '<table class="grid found"><thead><tr>'
        '<th>Value found</th><th>Type</th><th>Rollout step</th>'
        '<th>Set by GPO</th><th>Enforced link / link path</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    )


def _cite(label: str, text: Any) -> str:
    if not text:
        return ""
    return f'<span class="cite"><em>{_esc(label)}:</em> {_esc(text)}</span>'


def _render_conflict(finding: Dict[str, Any]) -> str:
    """Both GPO names, both values, and the precedence-unresolved warning."""
    conflict = finding.get("conflict")
    if not isinstance(conflict, dict):
        return ""

    rows = "".join(
        '<tr>'
        f'<td>{_esc((s or {}).get("gpo_display_name"))}'
        f'<br><code class="dn">{_esc((s or {}).get("gpo_dn"))}</code></td>'
        f'<td class="val"><code>{_esc_value((s or {}).get("value"))}</code></td>'
        f'<td>{_STATE_LABELS.get(str((s or {}).get("rollout_state")), _ABSENT)}</td>'
        f'<td>{"<strong>yes</strong>" if (s or {}).get("enforced_link") else "no"}</td>'
        '</tr>'
        for s in (conflict.get("settings") or []))

    return (
        '<div class="block conflict">'
        f'<h4>Conflict &mdash; {_esc(conflict.get("kind"))}</h4>'
        f'<p>{_esc(conflict.get("detail"))}</p>'
        '<table class="grid"><thead><tr>'
        '<th>GPO</th><th>Value</th><th>Rollout step</th><th>Enforced link</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
        '<p class="warn"><strong>Precedence is unresolved.</strong> Confirm the '
        'effective value with <code>gpresult /h</code> or the Group Policy '
        'Results (RSoP) wizard against a representative machine before changing '
        'or trusting any of these settings.</p>'
        '</div>'
    )


def _render_remediation(finding: Dict[str, Any]) -> str:
    """The catalog's remediation text. Never this module's own words.

    The renderer states only what the catalog states — ``remediation``,
    ``caveats``, ``missing_note`` — because remediation prose a report invented
    is advice nobody sourced, and for these controls bad advice causes lockouts.
    """
    remediation = finding.get("remediation")
    if not remediation:
        return ('<div class="block remediation gap"><h4>Remediation</h4>'
                '<p class="warn"><strong>Catalog gap:</strong> this control '
                'carries no remediation text. Nothing is improvised here — raise '
                'the gap so the catalog can state the fix.</p></div>')
    return ('<div class="block remediation"><h4>Remediation</h4>'
            f'<p>{_esc(remediation)}</p></div>')


def _caveat_items(caveats: Sequence[Any]) -> str:
    """The catalog's caveats, in catalog order, all of them.

    Every caveat is rendered rather than a subset this module picked out. Which
    caveats matter for a rollout is a judgement the catalog author already made
    when writing them, and a renderer that filtered on a prefix would silently
    drop the unprefixed ones — Part 4's "remediate SERVICE ACCOUNTS before
    disabling RC4 on devices" is exactly that shape, and it is the warning whose
    omission causes the outage.

    The catalog's convention of leading a load-bearing caveat with an all-caps
    label (``PHASED:``, ``AUDIT-FIRST:``, ``TATTOOING:``) is used only for
    emphasis, never to decide what is shown.
    """
    items: List[str] = []
    for caveat in caveats or ():
        text = str(caveat or "").strip()
        if not text:
            continue
        lead = text.split(":", 1)[0]
        flagged = (len(lead) >= 3 and len(lead) <= 40
                   and lead == lead.upper() and any(c.isalpha() for c in lead))
        css = "flagged" if flagged else ""
        items.append(f'<li class="{css}">{_esc(text)}</li>')
    if not items:
        return ""
    return f'<ul class="notes caveats">{"".join(items)}</ul>'


def _render_phasing(finding: Dict[str, Any]) -> str:
    """Rollout order: the interim step first, and why, before enforcement.

    This is the part of a failure card that most needs to be right. Several
    controls are audit-first-then-enforce and telling a reader to jump to the
    final value is actively dangerous advice: Devore Part 1 documents account
    lockouts from refusing NTLM before every device was ready, and Part 4 warns
    to remediate service accounts before removing RC4 domain-wide. So where the
    control carries an ``interim_expected``, the interim step is recommended
    *first*, with the catalog's ``audit_before_enforce`` as the evidence to
    gather; where it does not, the report says plainly that the catalog states no
    interim step rather than implying a phased path that nobody sourced; and
    where the catalog carries no rollout guidance at all, that is reported as a
    catalog gap rather than papered over with invented advice.

    Every sentence about *this* control's values comes from the scan
    (``expected.interim`` / ``expected.final``) or the catalog
    (``audit_before_enforce``, ``caveats``). The fixed prose only explains why
    the order matters, which is a property of phased rollouts and not a claim
    about any particular control.
    """
    evidence = finding.get("evidence") or {}
    expected = evidence.get("expected") or {}
    if not isinstance(expected, dict):
        expected = {}
    interim = expected.get("interim")
    final = expected.get("final")
    audit_before = finding.get("audit_before_enforce")
    caveats = [c for c in (finding.get("caveats") or []) if str(c or "").strip()]
    state = finding.get("rollout_state")

    parts: List[str] = []
    if state:
        parts.append('<p class="phase-now">Rollout state reported by this scan: '
                     f'<strong>{_esc(_STATE_LABELS.get(str(state), state))}'
                     '</strong>.</p>')

    if interim is not None:
        parts.append(
            '<p class="phase-step"><strong>Step 1 &mdash; reach the interim '
            f'value {_esc_value(interim)} first.</strong> This control is '
            'audit-first-then-enforce: the interim step makes the setting '
            'observable across the estate without refusing anything yet, which '
            'is what stops the enforcement step causing an outage.</p>')
        parts.append(
            '<p class="phase-step"><strong>Step 2 &mdash; only then move to the '
            f'final value {_esc_value(final)}.</strong> Do not skip step 1. '
            'Enforcing before every device and service account is ready is how '
            'this class of change produces authentication failures and account '
            'lockouts instead of hardening.</p>')
    elif final is not None:
        parts.append(
            '<p class="phase-step">The catalog states a single target value '
            f'{_esc_value(final)} and <strong>no interim step</strong> for this '
            'control. That is the catalog\'s position, not a statement that the '
            'change is safe to make everywhere at once &mdash; read the caveats '
            'below.</p>')

    if audit_before:
        parts.append(
            '<p class="phase-audit"><strong>Gather this evidence before '
            f'enforcing:</strong> {_esc(audit_before)}</p>')
    elif interim is not None:
        parts.append(
            '<p class="phase-audit muted">The catalog states no '
            'audit-before-enforce evidence for this control, so this report does '
            'not tell you what to look for. Treat that as a catalog gap.</p>')

    caveat_items = _caveat_items(caveats)
    if caveat_items:
        parts.append('<p class="phase-label"><strong>Caveats from the catalog '
                     '&mdash; read all of them:</strong></p>' + caveat_items)

    if interim is None and not audit_before and not caveats:
        parts.append(f'<p class="warn">{_PHASING_GAP_NOTE}</p>')

    return ('<div class="block phasing"><h4>Rollout order &mdash; read before '
            f'changing anything</h4>{"".join(parts)}</div>')


def _render_source(finding: Dict[str, Any]) -> str:
    source = finding.get("source")
    if not isinstance(source, dict):
        return ""
    part = source.get("part")
    label = f"Devore AD Hardening Series, Part {part}" if part else "Source"
    return (f'<p class="source small">Source: {_link(source.get("url"), label)}'
            f'</p>')


def _render_not_judged(finding: Dict[str, Any]) -> str:
    """An unscored control, framed so it cannot be read as a pass."""
    return (
        '<div class="block notjudged">'
        '<h4>Not judged &mdash; this is not a pass</h4>'
        '<p><strong>No verdict was issued for this control.</strong> '
        f'Reason: <code>{_esc(finding.get("unscored_reason"))}</code>. '
        'The source does not state this control\'s exact expected value, and '
        'this tool never guesses one, so the setting\'s actual state is '
        '<strong>unknown</strong>. Source the value from a Microsoft Security '
        'Baseline or CIS Benchmark to activate the control.</p>'
        + _notes_list((finding.get("evidence") or {}).get("notes"),
                      "notes gap")
        + '</div>'
    )


def _card_badges(finding: Dict[str, Any], section_id: str) -> str:
    result = str(finding.get("result") or "")
    evidence = finding.get("evidence") or {}
    state = finding.get("rollout_state")

    badges = [_badge(_esc(str(finding.get("severity") or "").upper()),
                     f"sev-{str(finding.get('severity') or 'none').lower()}")]
    if section_id == SECTION_NOT_JUDGED:
        badges.append(_badge("NOT JUDGED", "notjudged"))
    else:
        badges.append(_badge(_esc(_RESULT_LABELS.get(result, result or "?")),
                             f"result-{result or 'none'}"))
    if state:
        badges.append(_badge(f'rollout: {_esc(_STATE_LABELS.get(str(state), state))}',
                             f"state-{state}"))
    badges.append(_badge(_esc(_SOURCE_LABELS.get(str(evidence.get("source")),
                                                 str(evidence.get("source")))),
                         f"src-{str(evidence.get('source') or 'none').replace('-', '')}"))
    if finding.get("conflict"):
        badges.append(_badge("CONFLICT", "conflict"))
    return f'<p class="badges">{"".join(badges)}</p>'


def _render_card(finding: Dict[str, Any], section_id: str) -> str:
    """One finding, rendered for the section it is in."""
    evidence = finding.get("evidence") or {}
    control_id = str(finding.get("control_id") or "")
    anchor = f"{section_id}-{control_id}".lower().replace(" ", "-")

    identity = _rows([
        ("Policy", _esc(finding.get("friendly_policy"))),
        ("Registry key",
         f'<code>{_esc(evidence.get("registry_key"))}</code>'),
        ("Registry type", _esc(evidence.get("registry_type"))),
        ("Scope", _esc(finding.get("scope"))),
        ("Check type", _esc(finding.get("check_type"))),
        ("GPOs searched", _esc(evidence.get("gpos_searched"))),
    ])

    body: List[str] = [identity]

    if section_id == SECTION_NOT_JUDGED:
        body.append(_render_not_judged(finding))
        body.append(_render_remediation(finding))
        body.append(_render_phasing(finding))
    else:
        body.append('<div class="block"><h4>Expected (baseline)</h4>'
                    + _render_expected(finding) + '</div>')
        body.append('<div class="block"><h4>Found (this scan)</h4>'
                    + _render_found(finding) + '</div>')
        if finding.get("error"):
            body.append('<div class="block err-block"><h4>Why this is '
                        'unknown</h4><p>'
                        + _esc(finding.get("error")) + '</p></div>')
        body.append(_render_conflict(finding))
        if section_id in (SECTION_FAIL, SECTION_UNKNOWN, SECTION_OPPORTUNITIES):
            body.append(_render_remediation(finding))
            body.append(_render_phasing(finding))

    notes = _notes_list(evidence.get("notes"), "notes")
    if notes:
        body.append('<details class="block scan-notes"><summary>Scan notes '
                    f'({len((evidence.get("notes") or []))})</summary>{notes}'
                    '</details>')
    body.append(_render_source(finding))

    return (
        f'<article class="card card-{_esc(section_id, "none")}" id="{_esc(anchor)}">'
        f'<h3><span class="cid">{_esc(control_id)}</span> '
        f'{_esc(finding.get("title"))}</h3>'
        f'{_card_badges(finding, section_id)}'
        f'{"".join(body)}'
        '</article>'
    )


def _render_pass_row(finding: Dict[str, Any]) -> str:
    """A pass, compact: one always-visible line plus expandable evidence.

    The summary line stays visible when the document is printed, which a
    ``<details>``-only treatment would not guarantee; the evidence is retained
    but out of the way, which is what a report driving action needs.
    """
    evidence = finding.get("evidence") or {}
    found = evidence.get("found") or []
    values = ", ".join(repr(m.get("value")) for m in found
                       if isinstance(m, dict)) if found else None
    state = finding.get("rollout_state")
    conflict = ' <span class="badge badge-conflict">CONFLICT</span>' if \
        finding.get("conflict") else ""

    detail_body = (
        '<div class="pass-detail">'
        '<div class="block"><h4>Expected (baseline)</h4>'
        + _render_expected(finding) + '</div>'
        '<div class="block"><h4>Found (this scan)</h4>'
        + _render_found(finding) + '</div>'
        + _render_conflict(finding)
        + _notes_list(evidence.get("notes"), "notes small")
        + _render_source(finding)
        + '</div>')

    return (
        '<details class="pass-row">'
        '<summary>'
        f'<span class="cid">{_esc(finding.get("control_id"))}</span> '
        f'<span class="pass-title">{_esc(finding.get("title"))}</span> '
        f'<span class="badge badge-state-{_esc(state, "none")}">rollout: '
        f'{_esc(_STATE_LABELS.get(str(state), state))}</span> '
        f'<span class="pass-val">found {_esc(values, "no value (see evidence)")}'
        f'</span>{conflict}'
        '</summary>'
        f'{detail_body}'
        '</details>'
    )


def _render_section(section_id: str, findings: Sequence[Dict[str, Any]],
                    extra: str = "") -> str:
    """One document section. Rendered even when empty, so absence is explicit."""
    title = _SECTION_TITLES[section_id]
    lede = _SECTION_LEDES[section_id]
    count = len(findings)

    if not findings and not extra:
        body = '<p class="muted empty">None.</p>'
    elif section_id == SECTION_PASSES:
        body = extra + "".join(_render_pass_row(f) for f in findings)
    else:
        body = extra + "".join(_render_card(f, section_id) for f in findings)

    return (
        f'<section class="section section-{section_id}" id="{section_id}">'
        f'<h2>{title} <span class="count">({count})</span></h2>'
        f'<p class="lede">{lede}</p>'
        f'{body}'
        '</section>'
    )


def _render_toc(grouped: Dict[str, List[Dict[str, Any]]],
                read_errors: Sequence[Any]) -> str:
    items = []
    if read_errors:
        items.append('<li><a href="#read-failures"><strong>GPO read failures '
                     '&mdash; scan incomplete</strong></a></li>')
    for section_id, title, _lede in SECTIONS:
        items.append(f'<li><a href="#{section_id}">{title}</a> '
                     f'<span class="count">({len(grouped[section_id])})</span></li>')
    items.append('<li><a href="#provenance">Provenance</a></li>')
    return f'<nav class="toc"><h2>Contents</h2><ol>{"".join(items)}</ol></nav>'


# --------------------------------------------------------------------------- #
# Page assembly
# --------------------------------------------------------------------------- #

_PAGE = Template("""<!DOCTYPE html>
<!-- $marker : generated by ADitor. Self-contained: inline CSS, no scripts, no
     external assets. Safe to email, attach to a ticket, or print to PDF. -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="$marker report-format/$report_version engine/$engine_version">
<meta name="robots" content="noindex, nofollow">
<title>$title</title>
<style>
$css
</style>
</head>
<body>
<main>
<header class="doc-head">
<p class="kicker">$marker</p>
<h1>Active Directory hardening report</h1>
<p class="sub">$subtitle</p>
</header>
$read_failures
$provenance
$counts
$toc
$sections
<footer class="doc-foot">
<p>Generated by ADitor &mdash; scan engine $engine_version, report format
$report_version, catalog $catalog_version. This scan is read-only and changed
nothing.</p>
<p>$precedence</p>
<p class="small muted">This file is self-contained: it loads no stylesheet,
script, font or image, and needs no network access to read. The JSON scan output
is the source of truth; this document renders it and adds nothing to it.</p>
</footer>
</main>
</body>
</html>
""")

_CSS = """
:root{--ink:#16191d;--muted:#5d646d;--line:#d8dde3;--bg:#ffffff;
--panel:#f6f8fa;--bad:#a3131f;--bad-bg:#fdecee;--warn:#8a5300;
--warn-bg:#fff6e5;--ok:#1c6435;--ok-bg:#eef7f1;--info:#1b4a7a;
--info-bg:#eef4fb;}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,
Arial,sans-serif}
main{max-width:64rem;margin:0 auto;padding:1.5rem 1.25rem 4rem}
h1{font-size:1.85rem;margin:.2rem 0 .3rem}
h2{font-size:1.3rem;margin:2rem 0 .5rem;padding-bottom:.3rem;
border-bottom:2px solid var(--line)}
h3{font-size:1.08rem;margin:0 0 .5rem}
h4{font-size:.9rem;text-transform:uppercase;letter-spacing:.04em;
color:var(--muted);margin:0 0 .4rem}
p{margin:.5rem 0}
code{font:.86em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
background:var(--panel);border:1px solid var(--line);border-radius:3px;
padding:0 .25em;word-break:break-all}
a{color:var(--info)}
.muted{color:var(--muted)}
.small{font-size:.85rem}
.bad{color:var(--bad)}
.err{color:var(--bad);word-break:break-word}
.warn{background:var(--warn-bg);border-left:4px solid var(--warn);
padding:.6rem .8rem;margin:.6rem 0}
.doc-head{border-bottom:3px solid var(--ink);padding-bottom:.8rem}
.kicker{font:.72rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;
letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:0}
.sub{color:var(--muted);margin:.2rem 0 0}
/* Read-failure banner: first thing after the title, deliberately loud. */
.alert{background:var(--bad-bg);border:2px solid var(--bad);
border-radius:6px;padding:.9rem 1.1rem;margin:1.2rem 0}
.alert h2{border:0;margin:0 0 .3rem;color:var(--bad);font-size:1.2rem}
.alert-count{font-weight:700;margin:0 0 .4rem}
.ok-banner{background:var(--ok-bg);border-left:4px solid var(--ok);
padding:.6rem .8rem;margin:1.2rem 0;font-size:.92rem}
.disclaimer{background:var(--info-bg);border-left:4px solid var(--info);
padding:.6rem .8rem}
table{border-collapse:collapse;width:100%;margin:.4rem 0}
.kv th{text-align:left;vertical-align:top;width:15rem;font-weight:600;
padding:.28rem .6rem .28rem 0;border-bottom:1px solid var(--line);
color:var(--muted);font-size:.88rem}
.kv td{vertical-align:top;padding:.28rem 0;border-bottom:1px solid var(--line);
font-size:.92rem}
.grid{font-size:.88rem}
.grid th{text-align:left;background:var(--panel);border:1px solid var(--line);
padding:.35rem .5rem}
.grid td{border:1px solid var(--line);padding:.35rem .5rem;vertical-align:top}
.grid .val{white-space:nowrap}
.dn{font-size:.82em}
.tiles{display:flex;flex-wrap:wrap;gap:.6rem;list-style:none;padding:0;
margin:.6rem 0}
.tile{flex:1 1 8rem;border:1px solid var(--line);border-radius:6px;
padding:.55rem .7rem;background:var(--panel)}
.tile-n{display:block;font-size:1.5rem;font-weight:700;line-height:1.1}
.tile-l{display:block;font-size:.78rem;text-transform:uppercase;
letter-spacing:.04em;color:var(--muted)}
.tile-unknown,.tile-fail{background:var(--bad-bg);border-color:var(--bad)}
.tile-conflict,.tile-osdefault,.tile-notjudged{background:var(--warn-bg);
border-color:var(--warn)}
.tile-pass{background:var(--ok-bg);border-color:var(--ok)}
.toc ol{margin:.4rem 0;padding-left:1.4rem}
.toc li{margin:.15rem 0}
.count{color:var(--muted);font-weight:400;font-size:.85em}
.lede{background:var(--panel);border-left:4px solid var(--line);
padding:.6rem .8rem;font-size:.93rem}
.section-unknown>.lede,.section-failures>.lede{background:var(--bad-bg);
border-left-color:var(--bad)}
.section-conflicts>.lede,.section-opportunities>.lede,
.section-not-judged>.lede{background:var(--warn-bg);
border-left-color:var(--warn)}
.card{border:1px solid var(--line);border-left-width:5px;border-radius:5px;
padding:.9rem 1rem;margin:.9rem 0;page-break-inside:avoid}
.card-unknown,.card-failures{border-left-color:var(--bad)}
.card-conflicts,.card-opportunities,.card-not-judged{
border-left-color:var(--warn)}
.card-passes,.card-not-applicable{border-left-color:var(--line)}
.cid{font:.8em/1 ui-monospace,SFMono-Regular,Menlo,monospace;
color:var(--muted)}
.badges{margin:.2rem 0 .7rem}
.badge{display:inline-block;font-size:.72rem;font-weight:700;
text-transform:uppercase;letter-spacing:.04em;border-radius:3px;
padding:.12rem .4rem;margin:0 .3rem .3rem 0;border:1px solid var(--line);
background:var(--panel);color:var(--muted)}
.badge-result-fail,.badge-result-error,.badge-sev-critical,.badge-sev-high{
background:var(--bad-bg);border-color:var(--bad);color:var(--bad)}
.badge-result-pass{background:var(--ok-bg);border-color:var(--ok);
color:var(--ok)}
.badge-conflict,.badge-notjudged,.badge-srcosdefault,.badge-sev-medium{
background:var(--warn-bg);border-color:var(--warn);color:var(--warn)}
.block{margin:.8rem 0}
.remediation p,.phasing p{margin:.35rem 0}
.remediation{background:var(--info-bg);border-left:4px solid var(--info);
padding:.6rem .8rem}
.phasing{background:var(--warn-bg);border-left:4px solid var(--warn);
padding:.6rem .8rem}
.conflict{background:var(--warn-bg);border:1px solid var(--warn);
border-radius:5px;padding:.6rem .8rem}
.notjudged{background:var(--warn-bg);border:1px solid var(--warn);
border-radius:5px;padding:.6rem .8rem}
.err-block{background:var(--bad-bg);border-left:4px solid var(--bad);
padding:.6rem .8rem}
.found-none{background:var(--panel);border:1px dashed var(--line);
padding:.5rem .7rem}
.found-none.osdefault{background:var(--warn-bg);border-color:var(--warn)}
.found-none.bad{background:var(--bad-bg);border-color:var(--bad)}
.notes{margin:.3rem 0;padding-left:1.2rem;font-size:.88rem}
.notes li{margin:.2rem 0}
.caveats li.flagged{font-weight:700}
.phase-now{font-size:.9rem;color:var(--muted)}
.phase-audit{border-top:1px dotted var(--warn);padding-top:.4rem}
.links{margin:.2rem 0 0;padding-left:1.1rem;font-size:.85em}
.flags{color:var(--warn);font-weight:600}
.cite{display:block;margin-top:.3rem;font-size:.85rem;color:var(--muted)}
.cite-bad{color:var(--bad);font-size:.85em}
details{margin:.4rem 0}
summary{cursor:pointer}
.pass-row{border:1px solid var(--line);border-radius:4px;padding:.35rem .6rem;
margin:.3rem 0;font-size:.9rem;page-break-inside:avoid}
.pass-row>summary{list-style-position:outside}
.pass-title{font-weight:600}
.pass-val{color:var(--muted);font-size:.85em}
.pass-detail{border-top:1px solid var(--line);margin-top:.4rem;
padding-top:.4rem}
.scan-notes>summary{font-size:.85rem;color:var(--muted)}
.source{color:var(--muted);word-break:break-all}
.doc-foot{margin-top:2.5rem;border-top:2px solid var(--line);
padding-top:.8rem;font-size:.88rem;color:var(--muted)}
.empty{font-style:italic}
@media print{
body{font-size:11pt}
main{max-width:none;padding:0}
.card,.pass-row,.alert,.section{page-break-inside:avoid}
a{text-decoration:none;color:inherit}
}
"""


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _subtitle(scan: Dict[str, Any], counts: Dict[str, Any]) -> str:
    domain = _esc(scan.get("domain"), "unknown domain")
    timestamp = _esc(scan.get("timestamp"), "unknown time")
    return (f"{domain} &middot; scanned {timestamp} &middot; "
            f"catalog {_esc(scan.get('catalog_version'))} &middot; "
            f"{_esc(counts.get('total'), '0')} controls evaluated")


def render_report(scan_result: Dict[str, Any]) -> str:
    """Render a ``scan_hardening`` payload into one self-contained HTML document.

    Args:
        scan_result: The scan payload — ``scan`` (provenance), ``counts``,
            ``findings`` and ``gpo_read_errors``. Every key is optional and
            missing ones render as "absent" rather than raising: a report is the
            wrong place to discover a ``KeyError``, and an empty or partial scan
            must still produce a readable document.

    Returns:
        The complete HTML document as a string. No file I/O — see
        :func:`write_report`.
    """
    if not isinstance(scan_result, dict):
        scan_result = {}

    scan = scan_result.get("scan") if isinstance(
        scan_result.get("scan"), dict) else {}
    counts = scan_result.get("counts") if isinstance(
        scan_result.get("counts"), dict) else {}
    findings = scan_result.get("findings")
    findings = [f for f in findings if isinstance(f, dict)] if isinstance(
        findings, list) else []
    read_errors = scan_result.get("gpo_read_errors")
    read_errors = [e for e in read_errors if isinstance(e, dict)] if isinstance(
        read_errors, list) else []

    grouped = group_findings(findings)

    unknown_extra = ""
    unknown_ids = scan_result.get("unknown_control_ids") or []
    if unknown_ids:
        unknown_extra = (
            '<p class="warn"><strong>Control ids that matched nothing in the '
            'catalog and were therefore not scanned:</strong> '
            + ", ".join(f"<code>{_esc(cid)}</code>" for cid in unknown_ids)
            + '. They are reported rather than silently dropped.</p>')

    sections = "".join(
        _render_section(section_id, grouped[section_id],
                        extra=unknown_extra if section_id == SECTION_UNKNOWN
                        else "")
        for section_id, _title, _lede in SECTIONS)

    title = ("AD hardening report — "
             f"{str(scan.get('domain') or 'unknown domain')} — "
             f"{str(scan.get('timestamp') or 'unknown time')}")

    return _PAGE.substitute(
        marker=REPORT_MARKER,
        css=_CSS,
        title=_esc(title),
        subtitle=_subtitle(scan, counts),
        read_failures=_render_read_failures(scan, read_errors),
        provenance=_render_provenance(scan, counts),
        counts=_render_counts(counts),
        toc=_render_toc(grouped, read_errors),
        sections=sections,
        engine_version=_esc(scan.get("tool_version") or SCAN_ENGINE_VERSION),
        report_version=_esc(REPORT_FORMAT_VERSION),
        catalog_version=_esc(scan.get("catalog_version")),
        precedence=_PRECEDENCE_DISCLAIMER,
    )


# --------------------------------------------------------------------------- #
# Writing the file — the one side effect in this module
# --------------------------------------------------------------------------- #

class ReportPathError(ValueError):
    """The requested output path cannot be written to safely.

    Raised *before* anything is written, with a message saying what to do
    instead. Writing the file is this module's only side effect, so refusing a
    doubtful path loudly beats overwriting something a reader cared about.
    """


def _validate_output_path(output_path: Any) -> Path:
    """Resolve and vet an output path without touching the filesystem's contents.

    Guards, in order: a usable string; an ``.html``/``.htm`` suffix (which also
    stops a report being written over a ``.json`` or a ``.py`` by typo); the path
    is not an existing directory; and, if the file already exists, it carries
    :data:`REPORT_MARKER` — so re-running the tool over its own output is fine
    while clobbering an unrelated document is refused.
    """
    if not isinstance(output_path, str) or not output_path.strip():
        raise ReportPathError(
            "output_path must be a non-empty file path ending in .html")

    path = Path(os.path.expanduser(output_path.strip()))
    if not path.is_absolute():
        path = Path.cwd() / path

    if path.suffix.lower() not in HTML_SUFFIXES:
        raise ReportPathError(
            f"output_path must end in {' or '.join(HTML_SUFFIXES)} (got "
            f"{path.suffix or 'no suffix'!r}); this report is a single HTML "
            f"file, and requiring the suffix is what stops it being written "
            f"over a file of another kind")

    if path.is_dir():
        raise ReportPathError(
            f"output_path {str(path)!r} is a directory; give the full file name "
            f"to write, e.g. {str(path / 'hardening-report.html')!r}")

    if path.exists():
        if not path.is_file():
            raise ReportPathError(
                f"output_path {str(path)!r} exists and is not a regular file; "
                f"refusing to write to it")
        try:
            with path.open("rb") as handle:
                head = handle.read(_MARKER_SCAN_BYTES)
        except OSError as exc:
            raise ReportPathError(
                f"output_path {str(path)!r} exists but could not be read to "
                f"check whether it is a previous report: {exc}") from exc
        if REPORT_MARKER.encode("ascii") not in head:
            raise ReportPathError(
                f"output_path {str(path)!r} already exists and is not an ADitor "
                f"hardening report (it does not carry the "
                f"{REPORT_MARKER!r} marker); refusing to overwrite it. Choose a "
                f"new file name, or delete that file first if you meant to "
                f"replace it")
    return path


def write_report(scan_result: Dict[str, Any], output_path: Any) -> Tuple[Path, int]:
    """Render ``scan_result`` and write it to ``output_path``.

    Parent directories are created when missing; anything that cannot be created
    or written fails with a :class:`ReportPathError` naming the path, rather than
    a bare ``OSError`` from somewhere in the middle of the write.

    Returns:
        ``(path, bytes_written)``.

    Raises:
        ReportPathError: the path is unusable, would clobber a non-report file,
            or could not be created/written.
    """
    path = _validate_output_path(output_path)
    document = render_report(scan_result)
    payload = document.encode("utf-8")

    parent = path.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReportPathError(
                f"could not create the directory {str(parent)!r} for the "
                f"report: {exc}") from exc
    elif not parent.is_dir():
        raise ReportPathError(
            f"the parent path {str(parent)!r} is not a directory, so "
            f"{str(path)!r} cannot be written")

    try:
        path.write_bytes(payload)
    except OSError as exc:
        raise ReportPathError(
            f"could not write the report to {str(path)!r}: {exc}") from exc
    return path, len(payload)


def headline_counts(scan_result: Dict[str, Any]) -> Dict[str, int]:
    """The numbers a caller wants back without re-reading the file.

    Copied straight out of the scan's own ``counts`` — the JSON stays the source
    of truth, and this function deliberately computes nothing the scan did not
    already state.
    """
    counts = scan_result.get("counts") if isinstance(
        scan_result.get("counts"), dict) else {}
    scan = scan_result.get("scan") if isinstance(
        scan_result.get("scan"), dict) else {}
    return {
        "error": _as_int(counts.get("error")),
        "fail": _as_int(counts.get("fail")),
        "conflicts": _as_int(counts.get("conflicts")),
        "os_default": _as_int(counts.get("os_default")),
        "os_default_pass": _as_int(counts.get("os_default_pass")),
        "needs_baseline_value": _as_int(counts.get("needs_baseline_value")),
        "pass": _as_int(counts.get("pass")),
        "not_applicable": _as_int(counts.get("not_applicable")),
        "scored": _as_int(counts.get("scored")),
        "total": _as_int(counts.get("total")),
        "rendered": _as_int(counts.get("rendered")),
        "hidden": _as_int(counts.get("hidden")),
        "gpos_scanned": _as_int(scan.get("gpos_scanned")),
        "gpos_unreadable": _as_int(scan.get("gpos_unreadable")),
    }
