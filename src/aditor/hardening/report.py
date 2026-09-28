"""Render a hardening scan into a single self-contained HTML report.

**The JSON is the source of truth; this module only renders it.** Everything
below is a pure function of the dict :meth:`aditor.hardening.collect.Scanner.scan`
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

**Delivery is shown, not just the value.** Every found value carries a
"Delivered by" cell naming the mechanism that put it there, and a preference item
additionally shows its action plus the caveats that follow: the value *tattoos*
(it survives its GPO being unlinked, where a policy value reverts), an action of
``C`` will not correct drift, and item-level targeting may narrow who gets it. A
pass held only by a preference is badged ``BY PREFERENCE`` on the compact
always-visible row, because that is the line a reader skims. None of this is
inferred — it all comes from the scan's own ``delivery`` and ``preference``
fields.

**PDF is deliberately not built** (see ``docs/HARDENING_CATALOG.md``): a browser
can print this file if a PDF is ever wanted, which is cheaper than dragging a
renderer and its native dependencies into the packaging.

Ordering is by **actionability, not catalog order**, because the report's job is
to drive action rather than to be admired. See :data:`SECTIONS`:

The document leads with the read-failure banner, one results tile per reader
group, and a "Start here" box: a one-line status and the first few things to
do, each linking to its card. It ends with "About this scan" (the provenance).
Each card shows its verdict (found versus target), the fix, the rollout steps
and every caveat in the open, and collapses the evidence tables: a first-time
reader needs what to do, an auditor needs the evidence, and nothing
safety-related is ever collapsed, because a closed ``<details>`` also prints
closed.

The findings are grouped by what the reader does with them (:data:`GROUPS`),
each group holding sections (:data:`SECTIONS`):

1. **Fix** — ``fail`` findings, with expected versus every found value, its
   source GPO, the catalog's remediation and the phasing caveat; then
   ``os-default`` findings as settings to lock in, never as enforcement.
2. **Check by hand** — ``error`` and ``unknown`` findings, then conflicts. An
   ``unknown`` card states its reason and the command that settles it in the
   open. Conflicts are cross-referenced rather than owned, because a conflict
   on a *passing* control is the dangerous one; a
   ``policy-preference-disagreement`` is rendered with each side's delivery
   mechanism, because that conflict must *not* be settled by comparing link
   precedence. The read-failure banner, above everything, is what says a scan
   is incomplete.
3. **Not covered yet** — unscored (``needs_baseline_value``) controls, as
   compact rows badged "not checked — not a pass", then not-applicable ones.
4. **Good** — passes, compact.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import SCAN_ENGINE_VERSION
from .catalog import SEVERITY_RANK

# Version of the *report layout*. Bumped when the rendered structure changes, so
# a stored report can say which renderer produced it alongside which engine and
# which catalog scored it.
REPORT_FORMAT_VERSION = "1.5.0"

# The string that identifies a file as one of our reports.
REPORT_MARKER = "aditor-hardening-report"

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

# id, heading, lede. The order here is the order in the document. The ledes
# are written for a first-time reader: what the section means and what to do,
# in two or three sentences. Detail lives on the cards.
SECTIONS: Tuple[Tuple[str, str, str], ...] = (
    (SECTION_FAIL, "Failures",
     "These settings are weaker than the baseline recommends. <strong>Fix them "
     "in the order each card shows:</strong> several need an audit step first, "
     "and skipping it can lock users out."),
    (SECTION_OPPORTUNITIES, "At the Windows default — not locked in",
     "No GPO sets these. They are judged against the documented Windows "
     "default, so <strong>nothing in Group Policy holds them there</strong> and "
     "a future GPO could weaken them. Set each one in a GPO to lock it in."),
    (SECTION_UNKNOWN, "Unknown",
     "The scan couldn't confirm these settings. <strong>Treat them as "
     "unconfirmed, not as passes.</strong> A GPO couldn't be read, a "
     "directory query failed, or the setting is normally made directly in the "
     "registry, where Group Policy can't show it. Each card says which, and "
     "how to check."),
    (SECTION_CONFLICTS, "Conflicts — GPOs disagree",
     "Two or more GPOs set the same setting to different values, and this scan "
     "doesn't work out which one wins. <strong>Check the value a machine "
     "actually gets</strong> with <code>gpresult /h report.html</code> before "
     "changing any of them. These findings also appear in their own section."),
    (SECTION_NOT_JUDGED, "Not checked yet — no target value",
     "The published guidance doesn't give an exact value to check these "
     "against, and this tool doesn't guess, so <strong>they were not checked "
     "and are not passes.</strong> Each row expands to its guidance."),
    (SECTION_NOT_APPLICABLE, "Not applicable",
     "These didn't apply to what the scan found, so there is no verdict "
     "either way."),
    (SECTION_PASSES, "Passes",
     "These meet the baseline. Each row expands to its evidence. If a pass "
     "also appears under Conflicts, check it there before relying on it."),
)

# The four groups a reader works through, each holding one or more sections.
# id, heading, intro, section ids. The document follows this order, and
# SECTIONS is listed in the same order.
GROUPS: Tuple[Tuple[str, str, str, Tuple[str, ...]], ...] = (
    ("fix", "Fix",
     "Settings to change: they are weaker than the baseline, or only hold "
     "because of a Windows default.",
     (SECTION_FAIL, SECTION_OPPORTUNITIES)),
    ("check", "Check by hand",
     "The scan couldn't settle these. They are not passes.",
     (SECTION_UNKNOWN, SECTION_CONFLICTS)),
    ("not-covered", "Not covered yet",
     "Settings this scan doesn't check yet. They are not passes, and there is "
     "nothing to change from this report.",
     (SECTION_NOT_JUDGED, SECTION_NOT_APPLICABLE)),
    ("good", "Good",
     "Settings that meet the baseline.",
     (SECTION_PASSES,)),
)

_SECTION_LEDES = {section_id: lede for section_id, _title, lede in SECTIONS}
_SECTION_TITLES = {section_id: title for section_id, title, _lede in SECTIONS}

# Human labels for the raw enum values the scan emits.
_RESULT_LABELS = {
    "pass": "Pass",
    "fail": "Fail",
    # Two distinct ways of not knowing, both rendered as "Unknown" because the
    # reader's takeaway is identical: no verdict was issued. Which one it was is
    # spelled out on the card, where there is room to say it properly.
    "unknown": "Unknown",
    "error": "Unknown",
    "not_applicable": "Not applicable",
}
_STATE_LABELS = {
    "not_started": "not started",
    "audit": "audit (step 1 of 2)",
    "enforced": "enforced",
}
_SOURCE_LABELS = {
    "gpo": "set by Group Policy",
    "os-default": "Windows default — not set by any GPO",
    "not-configured": "no GPO sets this",
    "unknown": "not confirmed by this scan",
    "directory": "read from the directory",
}
# The catalog's operators, as a reader would say them.
_OPERATOR_WORDS = {
    "equals": "exactly",
    "gte": "at least",
    "in": "one of",
    "present": "present",
    "absent": "absent",
}
# How the GPO put the value there. Shown per found value because the mechanism
# changes what a "pass" is worth: a policy value reverts when the GPO stops
# applying, a preference value tattoos and stays.
_DELIVERY_LABELS = {
    "security-template": "security template (policy)",
    "registry-pol": "administrative template (policy)",
    "registry-preference": "Group Policy preference",
}
_PREFERENCE_TATTOO_WARNING = (
    "Preference &mdash; <strong>tattoos</strong>: the value stays in the "
    "registry if this GPO is unlinked or deleted, where a policy value would "
    "revert."
)
_PREFERENCE_CREATE_WARNING = (
    "Action <code>C</code> (Create) writes the value only when it is absent, so "
    "<strong>drift is not corrected</strong>."
)
_PREFERENCE_FILTER_WARNING = (
    "Carries item-level targeting (<code>&lt;Filters&gt;</code>), so it may "
    "apply to only some of the machines this GPO reaches. <strong>Not "
    "evaluated</strong> by this scan."
)
# Worst first. Shared with the scan diff, which orders its regression and
# improvement lists the same way — one definition so the two cannot drift.
_SEVERITY_ORDER = SEVERITY_RANK

# The standing disclaimer. Restated in the document because a saved report gets
# read without the tool that produced it.
_PRECEDENCE_DISCLAIMER = (
    "This scan doesn't work out which GPO wins when several set the same "
    "setting (policy precedence, RSoP). It reports every GPO that sets it, "
    "with its link path, and flags disagreements as conflicts. For a "
    "conflict, check the effective value with <code>gpresult /h</code> before "
    "acting."
)

_READ_FAILURE_LEDE = (
    "<strong>This scan is incomplete.</strong> The GPOs below couldn't be read, "
    "and any of them could set any setting in this report. So a setting not "
    "found in the GPOs that <em>were</em> read is reported as "
    "<em>unknown</em>, not as a pass. Those verdicts are <strong>unknown, not "
    "clean</strong>. Fix the read failures and scan again."
)

# Rendered when a failing control's catalog entry carries no phasing guidance at
# all. This is a *catalog gap*, reported as one — the renderer never invents
# rollout prose, because advice this tool made up could cause the outage the
# phasing fields exist to prevent.
_PHASING_GAP_NOTE = (
    "<strong>Catalog gap:</strong> the catalog gives no rollout guidance for "
    "this setting. That doesn't mean it's safe to apply everywhere at once: "
    "pilot it first, and report the gap so it can be sourced."
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

    ``unknown`` shares the section with ``error``. They arise differently — a
    read failure versus a control a GPO scan structurally cannot see — but they
    make the same claim, which is that no verdict was issued, and a reader who
    needs "what did this scan fail to establish?" wants one place to look. The
    card says which case it is.
    """
    result = finding.get("result")
    if result in ("error", "unknown"):
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
    """A definition table from (already-escaped) label/value pairs.

    Scrollable like the evidence tables: these carry registry keys, DNs and
    citation URLs, any one of which can be longer than a narrow viewport.
    """
    body = "".join(f"<tr><th scope=\"row\">{label}</th><td>{value}</td></tr>"
                   for label, value in pairs if value is not None)
    return _scrollable(f'<table class="kv">{body}</table>') if body else ""


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
        ("Scan id", f'<code>{_esc(scan.get("scan_id"))}</code>'),
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
        '<h2>About this scan</h2>'
        f'{_rows(pairs)}'
        f'<p class="disclaimer">{_PRECEDENCE_DISCLAIMER}</p>'
        f'{notes_block}'
        '</section>'
    )


def _group_findings(grouped: Dict[str, List[Dict[str, Any]]],
                    section_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """The distinct findings across ``section_ids``, in section order.

    Distinct because a conflict is listed in its verdict section and in the
    conflicts section, and a group should count it once.
    """
    seen, out = set(), []
    for section_id in section_ids:
        for finding in grouped.get(section_id, []):
            if id(finding) not in seen:
                seen.add(id(finding))
                out.append(finding)
    return out


def _render_counts(counts: Dict[str, Any],
                   grouped: Dict[str, List[Dict[str, Any]]]) -> str:
    """The headline numbers: one tile per group, broken down by section.

    Every number counts what the named group or section lists, so a reader who
    clicks through finds exactly that many. ``counts`` supplies only the
    breakdowns a section count cannot show — how the unknowns split, and how
    many findings the not-applicable filter hid.
    """
    kinds = {"fix": "fail", "check": "unknown", "not-covered": "notjudged",
             "good": "pass"}
    cells = []
    for group_id, heading, _intro, section_ids in GROUPS:
        total = len(_group_findings(grouped, section_ids))
        parts = " &middot; ".join(
            f"{len(grouped.get(section_id, []))} "
            f"{_esc(_TILE_PARTS[section_id][len(grouped.get(section_id, [])) != 1])}"
            for section_id in section_ids)
        cells.append(
            f'<li class="tile tile-{kinds[group_id]}">'
            f'<a href="#group-{group_id}">'
            f'<span class="tile-n">{total}</span>'
            f'<span class="tile-l">{_esc(heading)}</span>'
            f'<span class="tile-s">{parts}</span></a></li>')

    notes: List[str] = []
    unread = _as_int(counts.get("error"))
    unseen = _as_int(counts.get("unknown"))
    if unread or unseen:
        notes.append(f"Of the {unread + unseen} unknown, {unread} couldn't be "
                     f"read and {unseen} can't be seen in Group Policy at all.")
    hidden = _as_int(counts.get("hidden"))
    if hidden:
        notes.append(f"{hidden} not-applicable finding(s) are hidden.")
    note = f'<p class="small muted">{_esc(" ".join(notes))}</p>' if notes else ""
    return (
        '<section class="summary" id="summary">'
        '<h2>Results</h2>'
        f'<ul class="tiles">{"".join(cells)}</ul>'
        f'{note}'
        '</section>'
    )


# The per-section breakdown under each group tile.
# (one, many)
_TILE_PARTS = {
    SECTION_FAIL: ("failure", "failures"),
    SECTION_OPPORTUNITIES: ("at Windows default", "at Windows default"),
    SECTION_UNKNOWN: ("unknown", "unknown"),
    SECTION_CONFLICTS: ("conflict", "conflicts"),
    SECTION_NOT_JUDGED: ("not checked", "not checked"),
    SECTION_NOT_APPLICABLE: ("not applicable", "not applicable"),
    SECTION_PASSES: ("pass", "passes"),
}

# How many items "Start here" lists before pointing at the rest.
START_HERE_LIMIT = 5


def _next_step(finding: Dict[str, Any], section_id: str) -> str:
    """The one next action for a finding, from the scan's own fields.

    Never new advice: it names a value the catalog already states (the step 1
    or target value) or points at the card, where the full guidance is.
    """
    if section_id == SECTION_UNKNOWN:
        if finding.get("error") and _is_directory(finding):
            return "the directory query failed; the card says why"
        if finding.get("error"):
            return "fix the read failure above, then scan again"
        return "check it by hand; the card gives the command"
    if section_id == SECTION_CONFLICTS:
        return ("GPOs disagree; check which one wins with "
                "<code>gpresult /h</code>")
    if section_id == SECTION_OPPORTUNITIES:
        return "set it in a GPO to lock it in"
    if _is_directory(finding):
        count = len((finding.get("evidence") or {}).get("found") or [])
        return f"fix the {count} listed on the card"
    expected = (finding.get("evidence") or {}).get("expected") or {}
    if not isinstance(expected, dict) or expected.get("operator") in (
            "present", "absent"):
        return "see the card"
    interim, final = expected.get("interim"), expected.get("final")
    state = finding.get("rollout_state")
    if interim is not None and state not in ("audit", "enforced"):
        return f"step 1: set it to {_esc_value(interim)} (audit mode)"
    if interim is not None and state == "audit":
        return f"step 2: set it to {_esc_value(final)}"
    return f"set it to {_esc_value(final)}"


def _render_start_here(grouped: Dict[str, List[Dict[str, Any]]],
                       read_errors: Sequence[Any]) -> str:
    """Where you stand in one line, then the first few things to do.

    Failures first, worst severity first, then settings resting on a Windows
    default, then the ones to check by hand. Each item links to its card,
    where the full guidance is. Every value comes from the scan.
    """
    totals = {group_id: len(_group_findings(grouped, section_ids))
              for group_id, _h, _i, section_ids in GROUPS}
    lines: List[str] = []
    if read_errors:
        lines.append(
            '<p class="warn"><strong>This scan is incomplete:</strong> '
            f'{len(read_errors)} GPO(s) couldn\'t be read (see above). Fix '
            'that and scan again before relying on the rest.</p>')
    lines.append(
        f'<p class="stand">{totals["fix"]} to fix &middot; {totals["check"]} '
        f'to check by hand &middot; {totals["not-covered"]} not covered yet '
        f'&middot; {totals["good"]} good</p>')

    todo: List[Tuple[Dict[str, Any], str]] = []
    listed = set()
    for section_id in (SECTION_FAIL, SECTION_OPPORTUNITIES, SECTION_UNKNOWN,
                       SECTION_CONFLICTS):
        for finding in grouped.get(section_id, []):
            if id(finding) not in listed:
                listed.add(id(finding))
                todo.append((finding, section_id))

    if not todo:
        lines.append('<p><strong>Nothing to fix or check.</strong></p>')
    else:
        shown = todo[:START_HERE_LIMIT]
        items = []
        for finding, section_id in shown:
            anchor = str(finding.get("control_id") or "").lower().replace(" ", "-")
            severity = str(finding.get("severity") or "none").lower()
            items.append(
                f'<li>{_badge(_esc(severity.upper()), f"sev-{severity}")}'
                f'<a href="#{_esc(anchor)}">{_esc(finding.get("title"))}</a>'
                f'<br><span class="next">Next: '
                f'{_next_step(finding, section_id)}</span></li>')
        lines.append(f'<ol class="start-list">{"".join(items)}</ol>')
        more = len(todo) - len(shown)
        if more > 0:
            lines.append(f'<p class="small muted">and {more} more below.</p>')
        if any(((f.get("evidence") or {}).get("expected") or {}).get("interim")
               is not None for f, _s in shown):
            lines.append(
                '<p class="small"><strong>Before changing anything:</strong> '
                'some of these need an audit step first. Each card shows the '
                'order. Don\'t skip step 1.</p>')

    return ('<section class="start" id="start-here"><h2>Start here</h2>'
            f'{"".join(lines)}</section>')


def _render_read_failures(scan: Dict[str, Any],
                          read_errors: Sequence[Dict[str, Any]]) -> str:
    """The unmissable read-failure banner, rendered before any verdict.

    Deliberately the first thing after the title — ahead of the counts and
    every verdict section. A reader who does not see this
    reads the rest of the report as a clean bill of health it is not entitled to
    give.
    """
    if not read_errors:
        scanned = scan.get("gpos_scanned")
        what = f"All {_esc(scanned)} GPOs" if scanned is not None else "All GPOs"
        return (f'<p class="ok-banner" id="read-failures">'
                f'<strong>{what} were read.</strong></p>')

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
        + _scrollable(
            '<table class="grid"><thead><tr>'
            '<th>GPO display name</th><th>GPO DN</th><th>Read error</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')
        + '</section>'
    )


# --------------------------------------------------------------------------- #
# Finding cards
# --------------------------------------------------------------------------- #

def _is_directory(finding: Dict[str, Any]) -> bool:
    return finding.get("check_type") == "directory-state"


def _render_expected(finding: Dict[str, Any]) -> str:
    """The baseline side of the evidence: what the control asserts."""
    evidence = finding.get("evidence") or {}
    expected = evidence.get("expected")
    if _is_directory(finding) and isinstance(expected, dict):
        return _rows([
            ("Expected", "nothing found by the directory query"),
            ("Where the rule comes from", _esc(expected.get("value_source"))),
        ])
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


def _render_delivery(match: Dict[str, Any]) -> str:
    """How this value was delivered, plus the caveats that follow from it.

    A pass delivered by a Group Policy *preference* is a materially different
    statement from one delivered by policy, so the mechanism gets its own cell
    rather than being buried in prose: the value tattoos, action ``C`` will not
    correct drift, and item-level targeting may narrow who gets it. All three
    come from the scan's own ``delivery`` / ``preference`` fields — nothing here
    is inferred.
    """
    delivery = match.get("delivery")
    label = _DELIVERY_LABELS.get(str(delivery), _esc(delivery))
    parts = [f'<span class="delivery">{label}</span>']

    preference = match.get("preference")
    if isinstance(preference, dict):
        action = preference.get("action")
        action_name = preference.get("action_name")
        shown = f"{action} ({action_name})" if action_name else str(action)
        parts.append(f'<br><span class="small">action '
                     f'<code>{_esc(shown)}</code></span>')
        parts.append(f'<br><span class="small pref-note">'
                     f'{_PREFERENCE_TATTOO_WARNING}</span>')
        if action == "C":
            parts.append(f'<br><span class="small pref-note">'
                         f'{_PREFERENCE_CREATE_WARNING}</span>')
        if preference.get("has_filters"):
            parts.append(f'<br><span class="small pref-note">'
                         f'{_PREFERENCE_FILTER_WARNING}</span>')
    return "".join(parts)


def _render_directory_found(finding: Dict[str, Any]) -> str:
    """The objects a directory query found: name, kind, why, and DN."""
    found = [m for m in ((finding.get("evidence") or {}).get("found") or [])
             if isinstance(m, dict)]
    if finding.get("result") == "error":
        return ('<p class="found-none bad"><strong>Not read</strong> &mdash; '
                'the directory query failed, so this setting is unconfirmed. '
                f'{_esc(finding.get("error"))}</p>')
    if not found:
        return ('<p class="found-none">Nothing found &mdash; the directory '
                'query returned no matching objects that the bind account can '
                'read.</p>')
    rows = "".join(
        '<tr>'
        f'<td>{_esc(m.get("value"))}</td>'
        f'<td>{_esc(m.get("object_class"))}</td>'
        f'<td>{_esc(m.get("detail"))}</td>'
        f'<td><code class="dn">{_esc(m.get("dn"))}</code></td>'
        '</tr>' for m in found)
    return _scrollable(
        '<table class="grid found"><thead><tr><th>Name</th><th>Type</th>'
        f'<th>Why it is listed</th><th>DN</th></tr></thead><tbody>{rows}'
        '</tbody></table>')


def _render_found(finding: Dict[str, Any]) -> str:
    """Every value found, with the GPO that set it and that GPO's link path."""
    if _is_directory(finding):
        return _render_directory_found(finding)
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
            f'<td class="delivery-cell">{_render_delivery(match)}</td>'
            f'<td>{"<strong>yes</strong>" if match.get("enforced_link") else "no"}'
            f'{_links_text(match.get("links"))}</td>'
            '</tr>')

    return _scrollable(
        '<table class="grid found"><thead><tr>'
        '<th>Value found</th><th>Type</th><th>Rollout step</th>'
        '<th>Set by GPO</th><th>Delivered by</th>'
        '<th>Enforced link / link path</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    )


def _scrollable(table: str) -> str:
    """Wrap a table so it scrolls instead of the page body.

    These tables carry DNs, registry values, citation URLs and the delivery
    caveats, and they are read on laptops, on phones and in print. Without the
    wrapper the widest of them pushes the whole document into horizontal scroll,
    which makes every other section harder to read; with it, only the table
    scrolls. Every table in the document goes through here — a reader should
    never have to discover which ones were exempt.
    """
    return f'<div class="table-wrap">{table}</div>'


def _conflict_delivery(setting: Dict[str, Any]) -> str:
    """The delivery mechanism for one conflicting setting.

    Load-bearing in a ``policy-preference-disagreement``: without it the table
    reads as two GPOs to compare by link precedence, which is precisely the
    wrong way to settle this particular conflict.
    """
    delivery = setting.get("delivery")
    if not delivery:
        return _ABSENT
    label = _DELIVERY_LABELS.get(str(delivery), _esc(delivery))
    action = setting.get("preference_action")
    if action:
        return f'{label}<br><span class="small">action <code>{_esc(action)}</code></span>'
    return label


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
        f'<td>{_conflict_delivery(s or {})}</td>'
        f'<td>{"<strong>yes</strong>" if (s or {}).get("enforced_link") else "no"}</td>'
        '</tr>'
        for s in (conflict.get("settings") or []))

    return (
        '<div class="block conflict">'
        f'<h5>Conflict &mdash; {_esc(conflict.get("kind"))}</h5>'
        f'<p>{_esc(conflict.get("detail"))}</p>'
        + _scrollable(
            '<table class="grid"><thead><tr>'
            '<th>GPO</th><th>Value</th><th>Rollout step</th>'
            '<th>Delivered by</th><th>Enforced link</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')
        +
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
        return ('<div class="block remediation gap"><h5>Remediation</h5>'
                '<p class="warn"><strong>Catalog gap:</strong> this control '
                'carries no remediation text. Nothing is improvised here — raise '
                'the gap so the catalog can state the fix.</p></div>')
    return ('<div class="block remediation"><h5>Remediation</h5>'
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

    step1_done = state in ("audit", "enforced")
    step2_done = state == "enforced"

    def done(flag: bool) -> str:
        return ' <span class="done">&#10003; Done.</span>' if flag else ""

    parts: List[str] = []
    if interim is not None:
        parts.append(
            '<p class="phase-step"><strong>Step 1: set it to '
            f'{_esc_value(interim)} first</strong> (audit mode). This makes the '
            'setting visible on every machine without blocking anything yet.'
            f'{done(step1_done)}</p>')
        parts.append(
            '<p class="phase-step"><strong>Step 2: only then set it to '
            f'{_esc_value(final)}.</strong> Don\'t skip step 1: enforcing before '
            'every device and service account is ready can cause sign-in '
            f'failures and account lockouts.{done(step2_done)}</p>')
    elif final is not None:
        parts.append(
            f'<p class="phase-step"><strong>Set it to {_esc_value(final)}.'
            '</strong> The catalog gives no audit step for this one. That '
            'doesn\'t make it safe to apply everywhere at once, so read the '
            f'warnings below.{done(step2_done)}</p>')

    if audit_before:
        parts.append(
            '<p class="phase-audit"><strong>Before enforcing, check:</strong> '
            f'{_esc(audit_before)}</p>')
    elif interim is not None:
        parts.append(
            '<p class="phase-audit muted">The catalog doesn\'t say what to check '
            'before enforcing. Treat that as a catalog gap, and pilot it '
            'first.</p>')

    caveat_items = _caveat_items(caveats)
    if caveat_items:
        parts.append('<p class="phase-label"><strong>Watch out for:</strong></p>'
                     + caveat_items)

    if interim is None and not audit_before and not caveats:
        parts.append(f'<p class="warn">{_PHASING_GAP_NOTE}</p>')

    return ('<div class="block phasing"><h5>How to roll it out safely</h5>'
            f'{"".join(parts)}</div>')


def _render_source(finding: Dict[str, Any]) -> str:
    source = finding.get("source")
    if not isinstance(source, dict):
        return ""
    part = source.get("part")
    label = f"Devore AD Hardening Series, Part {part}" if part else "Source"
    return (f'<p class="source small">Source: {_link(source.get("url"), label)}'
            f'</p>')


def _render_not_judged(finding: Dict[str, Any]) -> str:
    """An unscored control, framed so it cannot be read as a pass.

    Carries the evidence notes (the catalog's reason there is no target
    value), so the row that holds this block does not print them again.
    """
    return (
        '<div class="block notjudged">'
        '<h5>Not checked &mdash; this is not a pass</h5>'
        '<p>The published guidance doesn\'t give an exact value for this '
        'setting, and this tool doesn\'t guess one, so its state is '
        '<strong>unknown</strong>. It can be checked once a target value is '
        'sourced, for example from a Microsoft Security Baseline. Reason code: '
        f'<code>{_esc(finding.get("unscored_reason"))}</code>.</p>'
        + _notes_list((finding.get("evidence") or {}).get("notes"),
                      "notes gap")
        + '</div>'
    )


def _render_unknown_reason(finding: Dict[str, Any]) -> str:
    """Why an ``unknown`` finding was not judged — always visible, never folded.

    The reason and the command that settles it are the entire value of this
    finding, so they are rendered open on the card rather than left inside the
    collapsed scan-notes block. A reader who has to click to discover that a row
    is not a pass will read it as one.
    """
    notes = (finding.get("evidence") or {}).get("notes")
    return (
        '<div class="block err-block">'
        '<h5>Why this is unknown &mdash; this is not a pass</h5>'
        '<p>Group Policy doesn\'t show this setting\'s value, so the scan '
        'can\'t confirm it either way. Use the check below to settle it.</p>'
        + _notes_list(notes, "notes")
        + '</div>'
    )


def _card_badges(finding: Dict[str, Any], section_id: str) -> str:
    result = str(finding.get("result") or "")
    evidence = finding.get("evidence") or {}
    state = finding.get("rollout_state")

    badges = [_badge(_esc(str(finding.get("severity") or "").upper()),
                     f"sev-{str(finding.get('severity') or 'none').lower()}")]
    if section_id == SECTION_NOT_JUDGED:
        badges.append(_badge("NOT CHECKED &mdash; NOT A PASS", "notjudged"))
    else:
        badges.append(_badge(_esc(_RESULT_LABELS.get(result, result or "?")),
                             f"result-{result or 'none'}"))
    if state:
        badges.append(_badge(f'stage: {_esc(_STATE_LABELS.get(str(state), state))}',
                             f"state-{state}"))
    source = evidence.get("source")
    # "Set by Group Policy" is the normal case; badge only the exceptions. A
    # not-checked row already says it has no verdict.
    if source != "gpo" and section_id != SECTION_NOT_JUDGED:
        badges.append(_badge(_esc(_SOURCE_LABELS.get(str(source), str(source))),
                             f"src-{str(source or 'none').replace('-', '')}"))
    if finding.get("conflict"):
        badges.append(_badge("CONFLICT", "conflict"))
    return f'<p class="badges">{"".join(badges)}</p>'


def _target_text(expected: Any) -> str:
    """The baseline, in words: "at least 5 (step 1: at least 3)"."""
    if not isinstance(expected, dict):
        return "no target value"
    operator = expected.get("operator")
    words = _OPERATOR_WORDS.get(str(operator), str(operator or ""))
    if operator in ("present", "absent"):
        return f"setting {_esc(words)}"
    text = f"{_esc(words)} {_esc_value(expected.get('final'))}"
    if expected.get("interim") is not None:
        text += f" (step 1: {_esc(words)} {_esc_value(expected.get('interim'))})"
    return text


def _render_glance(finding: Dict[str, Any]) -> str:
    """Found versus target in two lines — the card's always-visible verdict.

    Built only from the scan's own ``found`` and ``expected``; the full tables
    sit in the evidence block below.
    """
    evidence = finding.get("evidence") or {}
    found = [m for m in (evidence.get("found") or []) if isinstance(m, dict)]
    if _is_directory(finding):
        if finding.get("result") == "error":
            found_text = "not confirmed &mdash; the directory query failed"
        elif found:
            names = ", ".join(_esc(m.get("value")) for m in found[:5])
            more = f" and {len(found) - 5} more" if len(found) > 5 else ""
            found_text = f"{len(found)} listed: {names}{more}"
        else:
            found_text = "none"
        return ('<p class="glance">'
                f'<span><strong>Found:</strong> {found_text}</span>'
                '<span><strong>Target:</strong> none</span></p>')
    if found:
        shown = [f'<code>{_esc_value(m.get("value"))}</code> in '
                 f'{_esc(m.get("gpo_display_name"))}' for m in found[:3]]
        if len(found) > 3:
            shown.append(f"and {len(found) - 3} more")
        found_text = "; ".join(shown)
    else:
        os_default = evidence.get("os_default") or {}
        if evidence.get("source") == "os-default" and os_default.get("applied"):
            found_text = ("no GPO sets it; the Windows default is "
                          f'<code>{_esc_value(os_default.get("value"))}</code>')
        else:
            found_text = _esc(_SOURCE_LABELS.get(str(evidence.get("source")),
                                                 "no value found"))
    return (
        '<p class="glance">'
        f'<span><strong>Found:</strong> {found_text}</span>'
        f'<span><strong>Target:</strong> {_target_text(evidence.get("expected"))}'
        '</span></p>')


def _render_evidence(finding: Dict[str, Any], notes_shown: bool) -> str:
    """Everything the verdict rests on, collapsed: a first-time reader needs
    the verdict and the fix, an auditor needs this.

    Nothing safety-related lives here. Rollout steps, caveats, conflicts and
    the reason an unknown is unknown stay open on the card, because most
    browsers print a closed ``<details>`` closed.
    """
    evidence = finding.get("evidence") or {}
    if _is_directory(finding):
        targets = evidence.get("directory_targets") or []
        identity = _rows([
            ("Directory check",
             f'<code>{_esc(evidence.get("directory_check"))}</code>'),
            ("Checked", _esc(", ".join(targets)) if targets else None),
            ("Scope", _esc(finding.get("scope"))),
            ("Check type", _esc(finding.get("check_type"))),
        ])
    else:
        identity = None
    identity = identity or _rows([
        ("Policy", _esc(finding.get("friendly_policy"))),
        ("Registry key",
         f'<code>{_esc(evidence.get("registry_key"))}</code>'),
        ("Registry type", _esc(evidence.get("registry_type"))),
        ("Scope", _esc(finding.get("scope"))),
        ("Check type", _esc(finding.get("check_type"))),
        ("GPOs searched", _esc(evidence.get("gpos_searched"))),
    ])
    parts = [identity,
             '<div class="block"><h5>Expected (baseline)</h5>'
             + _render_expected(finding) + '</div>',
             '<div class="block"><h5>Found (this scan)</h5>'
             + _render_found(finding) + '</div>']
    notes = "" if notes_shown else _notes_list(evidence.get("notes"), "notes")
    if notes:
        parts.append('<div class="block scan-notes"><h5>Scan notes</h5>'
                     f'{notes}</div>')
    return ('<details class="block evidence"><summary>Evidence and technical '
            f'detail</summary>{"".join(parts)}</details>')


def _render_card(finding: Dict[str, Any], section_id: str) -> str:
    """One finding: verdict, then what to do, then the evidence (collapsed)."""
    control_id = str(finding.get("control_id") or "")
    # Anchor on the control id alone: a card's anchor must NOT move when its
    # verdict changes, or a link from a ticket breaks exactly when the finding
    # changes — which is the moment someone follows it. The section survives as
    # the card's class.
    anchor = control_id.lower().replace(" ", "-")

    body: List[str] = [_render_glance(finding)]
    # True when the evidence notes are already rendered open on the card, so
    # the evidence block does not repeat them.
    notes_shown = False

    if finding.get("error"):
        body.append('<div class="block err-block"><h5>Why this is '
                    'unknown</h5><p>'
                    + _esc(finding.get("error")) + '</p></div>')
    elif finding.get("result") == "unknown":
        body.append(_render_unknown_reason(finding))
        notes_shown = True
    body.append(_render_conflict(finding))
    if section_id in (SECTION_FAIL, SECTION_UNKNOWN, SECTION_OPPORTUNITIES):
        body.append(_render_remediation(finding))
        body.append(_render_phasing(finding))
    body.append(_render_evidence(finding, notes_shown))
    body.append(_render_source(finding))

    return (
        f'<article class="card card-{_esc(section_id, "none")}" id="{_esc(anchor)}">'
        f'<h4 class="card-title"><span class="cid">{_esc(control_id)}</span> '
        f'{_esc(finding.get("title"))}</h4>'
        f'{_card_badges(finding, section_id)}'
        f'{"".join(body)}'
        '</article>'
    )


def _render_not_judged_row(finding: Dict[str, Any]) -> str:
    """An unscored control, compact: one line that says it is not a pass,
    expanding to its reason and rollout guidance.

    The "not a pass" badge is on the summary line, so it stays visible when
    the row is collapsed and when the page is printed.
    """
    control_id = str(finding.get("control_id") or "")
    anchor = control_id.lower().replace(" ", "-")
    return (
        f'<details class="pass-row notjudged-row card-{SECTION_NOT_JUDGED}" '
        f'id="{_esc(anchor)}">'
        '<summary>'
        f'<span class="cid">{_esc(control_id)}</span> '
        f'<span class="pass-title">{_esc(finding.get("title"))}</span> '
        f'{_card_badges(finding, SECTION_NOT_JUDGED)}'
        '</summary>'
        '<div class="pass-detail">'
        + _render_not_judged(finding)
        + _render_remediation(finding)
        + _render_phasing(finding)
        + _render_source(finding)
        + '</div></details>'
    )


def _delivered_by_preference(found: Sequence[Any]) -> bool:
    """Whether **every** found value came from a Group Policy preference item.

    ``all``, not ``any``, and the difference is the whole point of the badge. It
    exists because a preference *tattoos* and may not correct drift, so a pass
    that depends on one is a weaker guarantee about ongoing state. If a policy
    *also* delivers a compliant value, the pass does not depend on the
    preference — the evaluator already treats that as two mechanisms agreeing,
    not as a conflict — and badging it would tell the reader the pass is weaker
    than it is. In a pass, every found value met at least the interim step (the
    verdict follows the least compliant of them), so "every found value" is
    "every compliant found value".

    An empty ``found`` is **not** badged: a pass with no found value rests on a
    documented OS default or on an ``absent`` assertion, neither of which
    involves a preference at all. ``all()`` over an empty sequence is ``True``,
    so this has to be said explicitly rather than left to the built-in.
    """
    matches = [match for match in found or () if isinstance(match, dict)]
    if not matches:
        return False
    return all(match.get("delivery") == "registry-preference"
               for match in matches)


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
    # A pass held ONLY by a preference is a weaker pass, and the compact row is
    # where a reader skims. Say so on the always-visible line, not only inside
    # the expanded evidence. A pass a policy also delivers is not weaker and is
    # deliberately not badged — see _delivered_by_preference.
    preference = (' <span class="badge badge-preference">BY PREFERENCE</span>'
                  if _delivered_by_preference(found) else "")

    detail_body = (
        '<div class="pass-detail">'
        '<div class="block"><h5>Expected (baseline)</h5>'
        + _render_expected(finding) + '</div>'
        '<div class="block"><h5>Found (this scan)</h5>'
        + _render_found(finding) + '</div>'
        + _render_conflict(finding)
        + _notes_list(evidence.get("notes"), "notes small")
        + _render_source(finding)
        + '</div>')

    found_text = ("none" if _is_directory(finding)
                  else _esc(values, "no value (see evidence)"))
    return (
        '<details class="pass-row">'
        '<summary>'
        f'<span class="cid">{_esc(finding.get("control_id"))}</span> '
        f'<span class="pass-title">{_esc(finding.get("title"))}</span> '
        f'<span class="badge badge-state-{_esc(state, "none")}">stage: '
        f'{_esc(_STATE_LABELS.get(str(state), state))}</span> '
        f'<span class="pass-val">found {found_text}'
        f'</span>{preference}{conflict}'
        '</summary>'
        f'{detail_body}'
        '</details>'
    )


def _render_section(section_id: str, findings: Sequence[Dict[str, Any]],
                    extra: str = "") -> str:
    """One section inside a group. Rendered even when empty, so absence is
    explicit — but an empty section skips its intro."""
    title = _SECTION_TITLES[section_id]
    count = len(findings)

    if not findings and not extra:
        return (f'<section class="section section-{section_id}" '
                f'id="{section_id}"><h3>{title} <span class="count">(0)</span>'
                '</h3><p class="muted empty">None.</p></section>')
    if section_id == SECTION_PASSES:
        body = extra + "".join(_render_pass_row(f) for f in findings)
    elif section_id == SECTION_NOT_JUDGED:
        body = extra + "".join(_render_not_judged_row(f) for f in findings)
    else:
        body = extra + "".join(_render_card(f, section_id) for f in findings)

    return (
        f'<section class="section section-{section_id}" id="{section_id}">'
        f'<h3>{title} <span class="count">({count})</span></h3>'
        f'<p class="lede">{_SECTION_LEDES[section_id]}</p>'
        f'{body}'
        '</section>'
    )


def _render_group(group_id: str, heading: str, intro: str, sections: str,
                  total: int) -> str:
    """A reader group: its heading and intro, then its sections."""
    return (f'<div class="group group-{group_id}" id="group-{group_id}">'
            f'<h2>{_esc(heading)} <span class="count">({total})</span></h2>'
            f'<p class="group-intro">{_esc(intro)}</p>{sections}</div>')


def _render_toc(grouped: Dict[str, List[Dict[str, Any]]],
                read_errors: Sequence[Any]) -> str:
    items = []
    if read_errors:
        items.append('<li><a href="#read-failures"><strong>GPO read failures '
                     '&mdash; scan incomplete</strong></a></li>')
    items.append('<li><a href="#start-here">Start here</a></li>')
    for group_id, heading, _intro, section_ids in GROUPS:
        subs = "".join(
            f'<li><a href="#{section_id}">{_SECTION_TITLES[section_id]}</a> '
            f'<span class="count">({len(grouped[section_id])})</span></li>'
            for section_id in section_ids)
        total = len(_group_findings(grouped, section_ids))
        items.append(f'<li><a href="#group-{group_id}">{_esc(heading)}</a> '
                     f'<span class="count">({total})</span><ol>{subs}</ol></li>')
    items.append('<li><a href="#provenance">About this scan</a></li>')
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
$counts
$start_here
$toc
$sections
$provenance
<footer class="doc-foot">
<p>Generated by ADitor &mdash; scan engine $engine_version, report format
$report_version, catalog $catalog_version. This scan is read-only and changed
nothing.</p>
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
h3{font-size:1.15rem;margin:1.6rem 0 .5rem}
h4{font-size:1.08rem;margin:0 0 .5rem}
h5{font-size:.9rem;text-transform:uppercase;letter-spacing:.04em;
color:var(--muted);margin:0 0 .4rem}
.group>h2{font-size:1.5rem;margin-top:2.6rem;border-bottom-width:3px}
.group-intro{color:var(--muted);margin:.3rem 0 1rem}
.start{border:2px solid var(--info);border-radius:6px;padding:.8rem 1.1rem;
margin:1.2rem 0;background:var(--info-bg)}
.start h2{border:0;margin:0 0 .4rem}
.stand{font-weight:600;margin:.2rem 0 .6rem}
.start-list{margin:.4rem 0;padding-left:1.4rem}
.start-list li{margin:.45rem 0}
.start-list .badge{margin-right:.4rem}
.next{font-size:.92rem;color:var(--muted)}
.tile-s{display:block;font-size:.75rem;color:var(--muted);margin-top:.2rem}
.toc ol ol{margin:.1rem 0 .3rem;font-size:.92rem}
p{margin:.5rem 0}
code{font:.86em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
background:var(--panel);border:1px solid var(--line);border-radius:3px;
padding:0 .25em;word-break:break-all}
a{color:var(--info)}
.muted{color:var(--muted)}
.small{font-size:.85rem}
/* Delivery mechanism, per found value. The pref-note caveats are inline
   rather than .warn blocks because they live inside a table cell. */
.delivery{font-weight:600}
.pref-note{display:inline-block;margin-top:.2rem;padding-left:.4rem;
border-left:3px solid var(--warn)}
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
font-size:.92rem;overflow-wrap:anywhere}
/* Every table scrolls inside its own box, and long registry keys, DNs and
   citation URLs break rather than set a wide floor; the page body never
   scrolls sideways. */
.table-wrap{overflow-x:auto}
.grid{font-size:.88rem}
.grid .delivery-cell{min-width:11rem}
.grid th{text-align:left;background:var(--panel);border:1px solid var(--line);
padding:.35rem .5rem}
.grid td{border:1px solid var(--line);padding:.35rem .5rem;vertical-align:top}
.grid .val{white-space:nowrap}
.dn{font-size:.82em}
.tiles{display:flex;flex-wrap:wrap;gap:.6rem;list-style:none;padding:0;
margin:.6rem 0}
.tile{flex:1 1 8rem;border:1px solid var(--line);border-radius:6px;
padding:.55rem .7rem;background:var(--panel)}
.tile a{display:block;color:inherit;text-decoration:none}
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
.badge-result-fail,.badge-result-error,.badge-result-unknown,
.badge-sev-critical,.badge-sev-high{
background:var(--bad-bg);border-color:var(--bad);color:var(--bad)}
.badge-result-pass{background:var(--ok-bg);border-color:var(--ok);
color:var(--ok)}
.badge-conflict,.badge-notjudged,.badge-srcosdefault,.badge-sev-medium,
.badge-preference{
background:var(--warn-bg);border-color:var(--warn);color:var(--warn)}
.block{margin:.8rem 0}
/* The card's always-visible verdict: found versus target. */
.glance{background:var(--panel);border-radius:4px;padding:.5rem .7rem;
margin:.5rem 0 .8rem}
.glance span{display:block}
.done{color:var(--ok);font-weight:700}
.evidence>summary{font-size:.9rem;font-weight:600;color:var(--muted)}
.notjudged-row .badges{display:inline;margin:0}
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


def friendly_time(timestamp: Any) -> str:
    """``2026-08-24T18:40:04.123+00:00`` as ``2026-08-24 18:40 UTC``.

    Falls back to the raw value, so an unexpected timestamp is still shown.
    """
    try:
        moment = datetime.fromisoformat(str(timestamp))
    except ValueError:
        return str(timestamp)
    if moment.utcoffset() is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def _subtitle(scan: Dict[str, Any], counts: Dict[str, Any]) -> str:
    domain = _esc(scan.get("domain"), "unknown domain")
    timestamp = (_esc(friendly_time(scan.get("timestamp")))
                 if scan.get("timestamp") else "unknown time")
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
        _render_group(
            group_id, heading, intro,
            "".join(_render_section(section_id, grouped[section_id],
                                    extra=unknown_extra
                                    if section_id == SECTION_UNKNOWN else "")
                    for section_id in section_ids),
            len(_group_findings(grouped, section_ids)))
        for group_id, heading, intro, section_ids in GROUPS)

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
        counts=_render_counts(counts, grouped),
        start_here=_render_start_here(grouped, read_errors),
        toc=_render_toc(grouped, read_errors),
        sections=sections,
        engine_version=_esc(scan.get("tool_version") or SCAN_ENGINE_VERSION),
        report_version=_esc(REPORT_FORMAT_VERSION),
        catalog_version=_esc(scan.get("catalog_version")),
    )


# --------------------------------------------------------------------------- #
# Writing the file — the one side effect in this module
# --------------------------------------------------------------------------- #

class ReportPathError(ValueError):
    """The report file could not be written."""


def write_report(scan_result: Dict[str, Any], output_path: Any) -> Tuple[Path, int]:
    """Render ``scan_result`` and write it to ``output_path``.

    The only caller is :func:`aditor.hardening.snapshot.write_snapshot`, which
    writes into a folder it has just created, so there is nothing to clobber.

    Returns:
        ``(path, bytes_written)``.

    Raises:
        ReportPathError: the file could not be written.
    """
    path = Path(output_path)
    payload = render_report(scan_result).encode("utf-8")
    try:
        path.write_bytes(payload)
    except OSError as exc:
        raise ReportPathError(
            f"could not write the report to '{path}': {exc}") from exc
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
        "unknown": _as_int(counts.get("unknown")),
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
