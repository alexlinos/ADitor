"""Render the app's data-derived HTML, with everything escaped.

The window's chrome — the four tabs, the forms, the buttons — is static HTML in
``web/index.html``. **Everything derived from data is rendered here, in Python.**
Not in JavaScript, and the reason is the one :mod:`aditor.hardening.report`
already states: GPO display names, DNs, registry values and LDAP error strings
are *directory* content, which is attacker-influenceable text, and this window
is a browser. Rendering in Python puts every one of those values through
:func:`esc` in a module that a test can call directly, instead of scattering
``textContent`` versus ``innerHTML`` decisions across a script file where the
next edit gets it wrong.

:func:`esc` is deliberately a local copy of the report's escaper rather than an
import of its private ``_esc``: same discipline, ``html.escape(quote=True)``,
no "trusted" variant, because the one place a trusted variant gets used by
accident is on a GPO display name.

The JS side does ``element.innerHTML = fragment`` and nothing else. There is no
templating engine and no framework, per ``REPLATFORM_BRIEF.md``: the same
standard-library-only discipline as the self-contained report.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Sequence

from ..hardening.diff import ATTRIBUTION_AMBIGUOUS

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Imported for annotations only. This module is a *renderer*: it consumes
    # the shapes these classes describe and calls no method on them beyond
    # attribute access, so importing them at runtime would buy nothing and
    # would make the renderer depend on the whole package.
    from .connection import ConnectionTestResult
    from .endpoint import ExposureAssessment
    from .history import SnapshotEntry
    from .scanning import ScanResult

_ABSENT = "&mdash;"


def esc(value: Any, absent: str = _ABSENT) -> str:
    """HTML-escape any value, for text or attribute position.

    ``quote=True`` so one function is safe in both. ``None`` and the empty
    string become ``absent``, which is markup this module owns and never caller
    data.
    """
    if value is None:
        return absent
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    if not text:
        return absent
    return html.escape(text, quote=True)


def _list(items: Iterable[Any], css: str = "") -> str:
    entries = [f"<li>{esc(item)}</li>" for item in items
               if str(item or "").strip()]
    if not entries:
        return ""
    attribute = f' class="{esc(css, "")}"' if css else ""
    return f"<ul{attribute}>{''.join(entries)}</ul>"


def _ordered(items: Iterable[Any]) -> str:
    entries = [f"<li>{esc(item)}</li>" for item in items
               if str(item or "").strip()]
    return f"<ol class=\"steps\">{''.join(entries)}</ol>" if entries else ""


def _rows(pairs: Sequence[Any]) -> str:
    """A definition table from (label, already-escaped value) pairs."""
    body = "".join(
        f"<tr><th>{esc(label)}</th><td>{value}</td></tr>"
        for label, value in pairs)
    return f'<table class="facts">{body}</table>' if body else ""


def _banner(kind: str, title: str, body: str = "") -> str:
    """The one banner shape: a state word, a headline, optional body markup.

    ``kind`` is one of ``ok``, ``warn``, ``bad``, ``info`` — a CSS class, never
    caller data, but escaped anyway so that stays true.
    """
    return (f'<div class="banner banner-{esc(kind, "info")}">'
            f'<p class="banner-title">{esc(title)}</p>{body}</div>')


def _code_block(text: Any, language: str = "") -> str:
    label = f'<span class="code-lang">{esc(language)}</span>' if language else ""
    return (f'<div class="code">{label}'
            f'<pre><code>{esc(text, "")}</code></pre></div>')


# --------------------------------------------------------------------------- #
# 1. Connection
# --------------------------------------------------------------------------- #

def render_connection_result(result: "ConnectionTestResult") -> str:
    """The Test-connection outcome, with the real LDAP error always shown.

    On failure the domain controller's own error text is rendered in a
    monospaced block under the headline. ADitor's reading of it (headline, fix)
    sits around it, but the error is never replaced by the reading: the
    classifier can be wrong about a message it has not seen, and the message
    cannot.
    """
    if result.ok:
        details = result.details or {}
        body = _rows([
            ("Server", esc(details.get("server"))),
            ("Port", esc(details.get("port"))),
            ("TLS", esc(details.get("ssl"))),
            ("Bound as", f'<code>{esc(details.get("bind_account"))}</code>'),
            ("Base DN read", esc(details.get("search_test"))),
        ])
        warnings = "".join(
            _banner("warn", "Worth fixing", f"<p>{esc(item)}</p>")
            for item in result.warnings)
        return _banner("ok", result.headline, body) + warnings

    parts: List[str] = []
    if result.error:
        parts.append(
            '<p class="label">What the domain controller reported</p>'
            + _code_block(result.error))
    if result.fix:
        parts.append(f'<p class="fix">{esc(result.fix)}</p>')
    return _banner("bad", result.headline, "".join(parts))


# --------------------------------------------------------------------------- #
# 2. Scan
# --------------------------------------------------------------------------- #

#: The headline tiles, in reading order: what needs attention first, passes
#: last. Same ordering principle as the report — actionability, not catalog
#: order. ``key`` indexes the scan's own ``counts`` block; nothing is derived.
_TILES = (
    ("fail", "Failed", "bad"),
    ("error", "Errors", "bad"),
    ("unknown", "Unknown", "warn"),
    ("conflicts", "Conflicts", "warn"),
    ("os_default", "At OS default", "warn"),
    ("needs_baseline_value", "Not scored", "muted"),
    ("pass", "Passed", "ok"),
    ("total", "Controls evaluated", "muted"),
)


def render_counts(counts: Dict[str, Any]) -> str:
    """The headline tiles, straight out of one scan's ``counts`` block."""
    tiles = "".join(
        f'<li class="tile tile-{esc(kind, "muted")}">'
        f'<span class="tile-n">{esc(counts.get(key), "0")}</span>'
        f'<span class="tile-l">{esc(label)}</span></li>'
        for key, label, kind in _TILES)
    return f'<ul class="tiles">{tiles}</ul>'


def render_scan_result(result: "ScanResult") -> str:
    """The Scan screen's outcome panel.

    Every number here is read from the ``write_hardening_snapshot`` response —
    one scan, its own counts. ``scans_run`` is displayed for exactly that
    reason: it is the tool asserting that it ran once, and showing it makes the
    guarantee visible rather than merely true.
    """
    if not result.ok:
        return _banner(
            "bad", "The scan did not complete.",
            _code_block(result.error) +
            "<p>Nothing was written. Fix the problem above and scan again.</p>")

    payload = result.payload
    scan = payload.get("scan")
    scan = scan if isinstance(scan, dict) else {}
    unreadable = int(scan.get("gpos_unreadable") or 0)

    parts = [
        _banner("ok", "Scan complete.",
                f'<p>{esc(payload.get("snapshot_name"))} — '
                f'{esc(scan.get("gpos_scanned"), "0")} Group Policy '
                f'object(s) read.</p>'),
        render_counts(result.counts),
    ]

    if unreadable:
        parts.append(_banner(
            "warn", f"{unreadable} Group Policy object(s) could not be read.",
            "<p>Any of them could set any of these keys to anything, so the "
            "affected controls are reported as unknown rather than as clean. "
            "The report lists which ones and why.</p>"))

    parts.append(_rows([
        ("Snapshot folder", f'<code>{esc(payload.get("snapshot_dir"))}</code>'),
        ("Scans run", esc(payload.get("scans_run"), "0")),
        ("Scan id", f'<code>{esc(scan.get("scan_id"))}</code>'),
        ("Scan time (UTC)", esc(scan.get("timestamp"))),
        ("Domain", esc(scan.get("domain"))),
        ("Base DN", f'<code>{esc(scan.get("base_dn"))}</code>'),
        ("Catalog version", esc(scan.get("catalog_version"))),
        ("Scan engine version", esc(scan.get("tool_version"))),
    ]))
    parts.append(_banner(
        "info", "This folder contains directory content.",
        "<p>Both files embed this domain's Group Policy names, registry "
        "values and distinguished names. Treat the folder accordingly when "
        "attaching it to a ticket or sharing it.</p>"))
    return "".join(parts)


# --------------------------------------------------------------------------- #
# 3. History
# --------------------------------------------------------------------------- #

def render_history(entries: Sequence["SnapshotEntry"],
                   directory: Any = "") -> str:
    """The snapshot archive as a table, newest first.

    Two radio columns rather than checkboxes: a diff has a *before* and an
    *after*, and a pair of checkboxes leaves the app guessing which is which
    from the order they were clicked. Guessing that wrong inverts every
    regression into an improvement.
    """
    if not entries:
        return _banner(
            "info", "No scans yet.",
            f'<p>Snapshots will appear here once you run a scan. They are '
            f'stored in <code>{esc(directory, "")}</code>.</p>')

    rows: List[str] = []
    for entry in entries:
        counts = entry.counts or {}
        if entry.readable:
            summary = (
                f'<span class="pill pill-bad">{esc(counts.get("fail"), "0")}'
                f' fail</span>'
                f'<span class="pill pill-warn">'
                f'{esc(counts.get("conflicts"), "0")} conflict</span>'
                f'<span class="pill pill-ok">{esc(counts.get("pass"), "0")}'
                f' pass</span>')
            meta = (f'{esc(entry.gpos_scanned, "0")} GPOs'
                    + (f' &middot; <strong class="bad">'
                       f'{esc(entry.gpos_unreadable)} unreadable</strong>'
                       if entry.gpos_unreadable else ""))
        else:
            summary = ('<span class="pill pill-bad">unreadable</span>')
            meta = esc(entry.error)

        report_button = (
            f'<button type="button" class="ghost" data-open-report='
            f'"{esc(entry.name, "")}">Open report</button>'
            if entry.has_report else
            '<span class="muted">no report</span>')

        rows.append(
            f"<tr>"
            f'<td class="pick"><input type="radio" name="diff-before" '
            f'value="{esc(entry.name, "")}" aria-label="Use '
            f'{esc(entry.name, "")} as the earlier scan"></td>'
            f'<td class="pick"><input type="radio" name="diff-after" '
            f'value="{esc(entry.name, "")}" aria-label="Use '
            f'{esc(entry.name, "")} as the later scan"></td>'
            f"<td><div class=\"snap-name\">{esc(entry.timestamp or entry.name)}"
            f'</div><div class="muted mono">{esc(entry.name)}</div></td>'
            f"<td>{summary}</td>"
            f'<td class="muted">{meta}</td>'
            f'<td class="muted mono">{esc(entry.catalog_version)} / '
            f'{esc(entry.engine_version)}</td>'
            f'<td class="right">{report_button}</td>'
            f"</tr>")

    return (
        '<table class="history">'
        '<thead><tr><th title="The earlier scan">Before</th>'
        '<th title="The later scan">After</th>'
        "<th>Scan time (UTC)</th><th>Result</th><th>Coverage</th>"
        "<th>Catalog / engine</th><th></th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>")


# --------------------------------------------------------------------------- #
# 4. Diff — attribution first, and loudly when it is ambiguous
# --------------------------------------------------------------------------- #

#: Shown next to every count in an ambiguous diff. Criterion: an ambiguous
#: attribution must never be rendered as a bare improvement count.
_AMBIGUOUS_QUALIFIER = "not attributable to the domain"


def render_diff(diff: Dict[str, Any]) -> str:
    """The diff, led by its attribution.

    ``attribution`` is the diff payload's first key because every number below
    it depends on it, and this renderer keeps that order. When the verdict is
    ``ambiguous`` the app **repeats why** — the version delta and the diff's own
    summary paragraph — and every total is labelled
    "not attributable to the domain" rather than presented as a count of
    improvements. A UI that showed "3 improvements" for two scans taken on
    different scanner versions would be reporting the tool's progress as the
    domain's, which is the failure this whole feature exists to prevent.
    """
    attribution = diff.get("attribution")
    attribution = attribution if isinstance(attribution, dict) else {}
    verdict = str(attribution.get("verdict") or "")
    ambiguous = verdict == ATTRIBUTION_AMBIGUOUS

    totals = diff.get("totals")
    totals = totals if isinstance(totals, dict) else {}
    scans = diff.get("scans")
    scans = scans if isinstance(scans, dict) else {}

    parts = [_render_attribution(attribution, ambiguous),
             _render_scan_pair(scans),
             _render_totals(totals, ambiguous)]

    for key, heading, kind in (("regressions", "Regressions", "bad"),
                               ("improvements", "Improvements", "ok"),
                               ("other_changes", "Other changes", "warn"),
                               ("evidence_changes",
                                "Same verdict, different evidence", "muted")):
        entries = diff.get(key)
        if isinstance(entries, list) and entries:
            parts.append(_render_change_list(heading, kind, entries, ambiguous))

    catalog = diff.get("catalog_changes")
    if isinstance(catalog, dict):
        parts.append(_render_catalog_changes(catalog))

    notes = diff.get("notes")
    if isinstance(notes, list) and notes:
        parts.append(
            '<details class="notes"><summary>How to read this diff</summary>'
            + _list(notes) + "</details>")
    return "".join(parts)


def _render_attribution(attribution: Dict[str, Any], ambiguous: bool) -> str:
    reason = attribution.get("reason")
    summary = attribution.get("summary")
    caveats = attribution.get("caveats")
    caveats = caveats if isinstance(caveats, list) else []

    if ambiguous:
        body = [
            '<p class="banner-lede">These two scans were not produced by the '
            "same version of ADitor, so the differences below may be the "
            "scanner or the control catalog rather than the domain. None of "
            "this can be reported as progress.</p>",
            f'<p class="reason">What moved: {esc(reason)}</p>',
            f"<p>{esc(summary)}</p>",
        ]
        if caveats:
            body.append('<p class="label">Also worth knowing</p>'
                        + _list(caveats))
        return _banner("bad", "Attribution: ambiguous", "".join(body))

    body = [f"<p>{esc(summary)}</p>"]
    if caveats:
        body.append('<p class="label">Caveats — read these anyway</p>'
                    + _list(caveats))
    return _banner(
        "ok", "Attribution: the domain",
        f'<p class="reason">{esc(reason)}</p>' + "".join(body))


def _render_scan_pair(scans: Dict[str, Any]) -> str:
    before = scans.get("before")
    after = scans.get("after")
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    return _rows([
        ("Domain", esc(scans.get("domain"))),
        ("Base DN", f'<code>{esc(scans.get("base_dn"))}</code>'),
        ("Earlier scan", f'{esc(before.get("timestamp"))} '
                         f'<code>{esc(before.get("scan_id"))}</code>'),
        ("Later scan", f'{esc(after.get("timestamp"))} '
                       f'<code>{esc(after.get("scan_id"))}</code>'),
        ("Catalog version", f'{esc(before.get("catalog_version"))} &rarr; '
                            f'{esc(after.get("catalog_version"))}'),
        ("Engine version", f'{esc(before.get("engine_version"))} &rarr; '
                           f'{esc(after.get("engine_version"))}'),
    ])


def _render_totals(totals: Dict[str, Any], ambiguous: bool) -> str:
    """The counts — always carrying the attribution qualifier when ambiguous."""
    figures = (("regressions", "Regressions", "bad"),
               ("improvements", "Improvements", "ok"),
               ("other_changes", "Other changes", "warn"),
               ("evidence_changes", "Evidence changed", "muted"),
               ("unchanged", "Unchanged", "muted"),
               ("controls_compared", "Controls compared", "muted"))
    qualifier = (f'<span class="tile-q">{esc(_AMBIGUOUS_QUALIFIER)}</span>'
                 if ambiguous else "")
    tiles = "".join(
        f'<li class="tile tile-{esc(kind, "muted")}'
        f'{" tile-unattributed" if ambiguous else ""}">'
        f'<span class="tile-n">{esc(totals.get(key), "0")}</span>'
        f'<span class="tile-l">{esc(label)}</span>'
        f'{qualifier if key in ("regressions", "improvements") else ""}'
        f"</li>"
        for key, label, kind in figures)
    heading = ("Differences &mdash; ambiguous attribution, see above"
               if ambiguous else "Differences")
    return (f'<h3 class="section">{heading}</h3>'
            f'<ul class="tiles">{tiles}</ul>')


def _render_change_list(heading: str, kind: str,
                        entries: Sequence[Dict[str, Any]],
                        ambiguous: bool) -> str:
    cards: List[str] = []
    for entry in entries:
        entry = entry if isinstance(entry, dict) else {}
        result = entry.get("result")
        result = result if isinstance(result, dict) else {}
        rollout = entry.get("rollout_state")
        rollout = rollout if isinstance(rollout, dict) else {}
        notes = entry.get("notes")
        notes = notes if isinstance(notes, list) else []
        cards.append(
            f'<article class="change change-{esc(kind, "muted")}">'
            f'<header><code>{esc(entry.get("control_id"))}</code>'
            f'<span class="sev">{esc(entry.get("severity"))}</span></header>'
            f'<p class="change-title">{esc(entry.get("title"))}</p>'
            f'<p class="change-move">Result '
            f'<code>{esc(result.get("before"))}</code> &rarr; '
            f'<code>{esc(result.get("after"))}</code>'
            f' &middot; rollout <code>{esc(rollout.get("before"))}</code>'
            f' &rarr; <code>{esc(rollout.get("after"))}</code></p>'
            + (_list(notes, "change-notes") if notes else "")
            + "</article>")
    suffix = (f' <span class="qualifier">({esc(_AMBIGUOUS_QUALIFIER)})</span>'
              if ambiguous else "")
    return (f'<h3 class="section">{esc(heading)} '
            f'<span class="count">{len(entries)}</span>{suffix}</h3>'
            + "".join(cards))


def _render_catalog_changes(catalog: Dict[str, Any]) -> str:
    added = catalog.get("added")
    removed = catalog.get("removed")
    added = added if isinstance(added, list) else []
    removed = removed if isinstance(removed, list) else []
    if not added and not removed:
        return ""
    def ids(entries: Sequence[Any]) -> List[str]:
        out = []
        for entry in entries:
            if isinstance(entry, dict):
                out.append(str(entry.get("control_id") or entry))
            else:
                out.append(str(entry))
        return out
    body = []
    if added:
        body.append('<p class="label">Added to the catalog</p>'
                    + _list(ids(added)))
    if removed:
        body.append('<p class="label">Removed from the catalog</p>'
                    + _list(ids(removed)))
    note = str(catalog.get("note") or
               "A control present in one scan and not the other has no "
               "before-and-after verdict, so it is never counted as an "
               "improvement or a regression.")
    return _banner("info", "Catalog changes",
                   "".join(body) + f"<p>{esc(note)}</p>")


# --------------------------------------------------------------------------- #
# 5. Connect Claude Code / Codex
# --------------------------------------------------------------------------- #

def render_server_status(status: Dict[str, Any]) -> str:
    running = bool(status.get("running"))
    kind = "ok" if running else "muted"
    title = ("Server running" if running else "Server stopped")
    body = [_rows([
        ("Endpoint", f'<code>{esc(status.get("url"))}</code>'),
        ("Bound to", f'<code>{esc(status.get("bind"))}</code>'),
        ("Process id", esc(status.get("pid"))),
        ("Uptime", (f'{esc(status.get("uptime_seconds"), "0")} s'
                    if running else _ABSENT)),
        ("Config file", f'<code>{esc(status.get("config_path"))}</code>'),
    ])]
    output = status.get("recent_output")
    if isinstance(output, list) and output:
        body.append(
            '<details class="server-log"><summary>Server output</summary>'
            + _code_block("\n".join(str(line) for line in output))
            + "</details>")
    exit_code = status.get("exit_code")
    if not running and exit_code not in (None, 0):
        body.append(f'<p class="fix">The server exited with code '
                    f'{esc(exit_code)}. The output above says why.</p>')
    return _banner(kind, title, "".join(body))


def render_exposure(exposure: "ExposureAssessment") -> str:
    """Same-machine or on the network — and what remote actually costs.

    The exposure warning is rendered **whenever the bind is not loopback**, and
    a test asserts that. It is the paragraph that stops "open the port" reading
    as routine setup, and it is the paragraph a later tidy-up would delete for
    being long.
    """
    parts = [_banner("ok" if exposure.loopback else "warn",
                     exposure.headline, f"<p>{esc(exposure.detail)}</p>")]
    if exposure.warning:
        parts.append(_banner(
            "bad", "Exposing this port puts a privileged AD API on the network",
            f"<p>{esc(exposure.warning)}</p>"))
    if exposure.recommendation:
        parts.append(f'<p class="fix">{esc(exposure.recommendation)}</p>')
    if exposure.firewall_command:
        parts.append(
            '<p class="label">If it must be remote — scope the rule to one '
            "source address</p>"
            + _code_block(exposure.firewall_command, "PowerShell")
            + f'<p class="fix">{esc(exposure.firewall_note)}</p>')
    return "".join(parts)


def render_snippets(snippet_data: Dict[str, Any]) -> str:
    """The two client cards, each built from the live endpoint's own URL."""
    parts: List[str] = []
    note = snippet_data.get("trailing_slash_note")
    if note:
        parts.append(_banner("info", "Use Copy, do not retype",
                             f"<p>{esc(note)}</p>"))

    for key in ("claude_code", "codex"):
        client = snippet_data.get(key)
        if not isinstance(client, dict):
            continue
        body = [_ordered(client.get("steps") or [])]
        command = client.get("command")
        if command:
            body.append('<p class="label">Or run this</p>'
                        + _code_block(command, "Command"))
            body.append('<p class="label">Or paste this</p>')
        body.append(_code_block(client.get("snippet"),
                                str(client.get("format") or "").upper()))
        locations = client.get("locations") or []
        if locations:
            body.append('<p class="label">Where the config file lives on '
                        "Windows</p>" + _list(locations, "mono"))
        parts.append(
            f'<section class="client-card">'
            f'<header><h3>{esc(client.get("label"))}</h3>'
            f'<button type="button" class="ghost" data-copy="{esc(key, "")}">'
            f'Copy snippet</button></header>'
            f'<div class="client-body">{"".join(body)}</div></section>')
    return "".join(parts)


def render_credential_store(store_name: str, available: bool,
                            where: str = "",
                            detail: str = "") -> str:
    """Where the password goes — or that there is nowhere, so nothing is saved."""
    if available:
        return _banner(
            "ok", f"Passwords are kept in {store_name}.",
            (f"<p>{esc(where)}</p>" if where else "")
            + "<p>ADitor never writes the password to its own settings file or "
              "to any other file. The settings file holds the placeholder "
              "<code>${AD_MCP_PASSWORD}</code>, which is filled in from the "
              "credential store at the moment it is needed.</p>")
    return _banner(
        "bad", "There is nowhere safe to keep the password on this machine.",
        f"<p>{esc(detail or store_name)}</p>"
        "<p>ADitor will not save the password to a file instead, so this "
        "connection cannot be saved. You can still test the connection and run "
        "scans by entering the password each time.</p>")


def render_error(message: Any) -> str:
    """A refusal, rendered the same way everywhere."""
    return _banner("bad", "That did not work.", f"<p>{esc(message)}</p>")


def render_notice(title: Any, message: Any = "", kind: str = "info") -> str:
    return _banner(kind, title, f"<p>{esc(message)}</p>" if message else "")


__all__ = [
    "esc",
    "render_connection_result",
    "render_counts",
    "render_credential_store",
    "render_diff",
    "render_error",
    "render_exposure",
    "render_history",
    "render_notice",
    "render_scan_result",
    "render_server_status",
    "render_snippets",
]
