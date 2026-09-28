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
templating engine and no framework: the same
standard-library-only discipline as the self-contained report.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Sequence

from ..hardening.diff import ATTRIBUTION_AMBIGUOUS
from ..hardening.report import friendly_time

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Imported for annotations only. This module is a *renderer*: it consumes
    # the shapes these classes describe and calls no method on them beyond
    # attribute access, so importing them at runtime would buy nothing and
    # would make the renderer depend on the whole package.
    from .connection import ConnectionTestResult
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
# 1b. The certificate chain — fingerprint first, and nothing that trusts it
# --------------------------------------------------------------------------- #
#
# Read :mod:`aditor.app.certificates` before editing anything below. The short
# version: this panel exists because the Connection screen says "install the
# issuing CA" without saying how, and it must close that gap **without**
# offering a button that does the installing. Every certificate on it arrived
# over the connection that is failing, so the panel's job is to hand the
# operator a file, a command and a fingerprint to check — not a verdict.
#
# Three properties here are pinned by tests in
# ``tests/test_app_certificate_panel.py`` and are not stylistic:
#
#   * no rendered button installs or trusts anything;
#   * the out-of-band instruction cannot be rendered without the fingerprint
#     next to it, because the instruction is meaningless alone and the
#     fingerprint is unexplained alone. They are emitted by one function and
#     that function is the only reference to the constant;
#   * "could not check" never renders like "checked and fine".

#: The sentence the safety of this whole panel rests on. Rendered beside every
#: single certificate, never once at the top: an operator scrolling to the
#: anchor and copying its fingerprint must meet the instruction there, not have
#: passed it four cards ago.
OUT_OF_BAND_INSTRUCTION = (
    "Confirm this SHA-256 fingerprint out of band before trusting this "
    "certificate. Read it off the certification authority itself — "
    "'certutil -store Root' on the CA server, the Certification Authority "
    "console, or Keychain Access on a machine that already trusts it — and "
    "compare every group. ADitor read this certificate over the same "
    "connection that is failing to verify, so it corroborates nothing on its "
    "own: if anything is intercepting that connection, this is the "
    "interceptor's certificate and it will look exactly this legitimate.")

# Where each certificate sits in the chain. The anchor is called out because it
# is the one a trust store would need, and the leaf is called out because
# installing *it* as a root is a common and useless mistake.
def _position_label(index: int, total: int) -> str:
    if total <= 1:
        return "The only certificate the server sent"
    if index == 0:
        return "Server certificate — the domain controller's own"
    if index == total - 1:
        return "Chain anchor — the certificate a trust store would need"
    return "Intermediate certification authority"


def _fingerprint_block(facts: Any) -> str:
    """The fingerprint and the out-of-band instruction, together or not at all.

    One function, and the **only** reference to
    :data:`OUT_OF_BAND_INSTRUCTION` in this module — asserted over the AST by
    ``tests/test_app_certificate_panel.py``. That is the mechanism, not a
    convention: the instruction without a fingerprint beside it is advice the
    operator cannot act on, and a fingerprint without the instruction is a hex
    string that reads like a receipt. Rendering either alone is the failure
    mode, so neither has a code path of its own.
    """
    return (f'<div class="fingerprint">'
            f'<p class="fp-label">SHA-256 fingerprint</p>'
            f'<p class="fp-value"><code>{esc(facts.fingerprint)}</code></p>'
            f'<p class="fp-verify">{esc(OUT_OF_BAND_INSTRUCTION)}</p>'
            f"</div>")


def _certificate_card(facts: Any, position: str = "",
                      exportable: bool = False) -> str:
    """One certificate: what it claims, then the fingerprint block.

    ``subject`` and ``issuer`` are directory- and attacker-influenceable text
    arriving from a socket ADitor does not trust, which is the whole reason this
    renderer is in Python — see the module docstring. Everything goes through
    :func:`esc`.
    """
    flags = []
    if facts.self_issued:
        flags.append("self-issued")
    if facts.is_ca:
        flags.append("certification authority")
    flag_line = (f'<p class="cert-flags">{esc(", ".join(flags))}</p>'
                 if flags else "")
    export = (
        f'<button type="button" class="secondary" '
        f'data-export-ca="{esc(facts.fingerprint_hex, "")}">'
        f"Export CA certificate</button>" if exportable else "")
    return (
        f'<article class="cert-card">'
        f'<header><p class="cert-position">{esc(position)}</p>'
        f'<p class="cert-name">{esc(facts.label)}</p>'
        f"{flag_line}"
        f"</header>"
        + _rows([
            ("Subject", f'<code>{esc(facts.subject)}</code>'),
            ("Issuer", f'<code>{esc(facts.issuer)}</code>'),
            ("Valid from", esc(_stamp(facts.not_before))),
            ("Valid to", esc(_stamp(facts.not_after))),
            ("Serial", f'<code>{esc(facts.serial)}</code>'),
            ("Source", esc(facts.source_label)),
        ])
        + _fingerprint_block(facts)
        + (f'<div class="actions actions-left">{export}</div>' if export else "")
        + "</article>")


def _stamp(value: Any) -> str:
    try:
        return value.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:                       # pragma: no cover - defensive
        return str(value)


def _expiry_alerts(certificates: Sequence[Any]) -> str:
    """The expiry banners — deliberately not shaped like the trust banners.

    An expired domain controller certificate produces a *different* LDAPS
    failure from an untrusted one, and an operator who reads it as a trust
    problem will spend an hour installing a CA that was never the issue. So
    these carry their own wrapper class, their own headline, and the sentence
    that says installing a CA will not fix it.
    """
    parts: List[str] = []
    for facts in certificates:
        if not facts.needs_expiry_attention():
            continue
        days = facts.days_until_expiry()
        if facts.is_expired():
            title = (f"Expired {abs(days)} day(s) ago: "
                     f"{facts.label}")
            body = (
                "<p>This certificate's validity period has ended. That is a "
                "different failure from an untrusted issuer, and installing a "
                "CA certificate will not fix it — the certificate has to be "
                "reissued on the server that presented it.</p>")
            kind = "bad"
        elif facts.is_not_yet_valid():
            title = f"Not valid yet: {facts.label}"
            body = (
                "<p>This certificate's validity period has not started. "
                "Either it was just issued and this machine's clock is behind "
                "the server's, or the clocks genuinely disagree. Fix the time "
                "first; installing a CA certificate will not help.</p>")
            kind = "bad"
        else:
            title = f"Expires in {days} day(s): {facts.label}"
            body = (
                "<p>Inside the 30-day window. When it lapses, LDAPS will fail "
                "with an expiry error rather than a trust error, and the fix "
                "will be a reissue on the server — not anything to do with "
                "this machine's trust store. Get it renewed now.</p>")
            kind = "warn"
        parts.append(
            '<div class="expiry-alert">'
            + _banner(kind, title,
                      body + _rows([
                          ("Valid to", esc(_stamp(facts.not_after))),
                          ("Certificate", f'<code>{esc(facts.subject)}</code>'),
                      ]))
            + "</div>")
    return "".join(parts)


#: Rendered classes per corroboration outcome. Three entries, because there are
#: three outcomes; ``unavailable`` has its own so it can never be styled, read
#: or grepped as agreement.
_CORROBORATION_KIND = {
    "agree": "ok",
    "disagree": "bad",
    "unavailable": "warn",
}

_CORROBORATION_TITLE_PREFIX = {
    "agree": "Corroborated by Active Directory",
    "disagree": "Warning — Active Directory disagrees",
    "unavailable": "Not corroborated — could not check",
}


def _corroboration_panel(corroboration: Any) -> str:
    """Agree / disagree / could-not-check, kept visibly distinct.

    The three outcomes get three CSS classes, three title prefixes and three
    banner kinds. "Unavailable" reads as an open question, because that is what
    it is: an attacker who can make the directory read fail would otherwise get
    a clean-looking panel for free.
    """
    outcome = str(getattr(corroboration, "outcome", "") or "unavailable")
    kind = _CORROBORATION_KIND.get(outcome, "warn")
    prefix = _CORROBORATION_TITLE_PREFIX.get(outcome,
                                             "Not corroborated — could not "
                                             "check")
    body = [f"<p>{esc(corroboration.headline)}</p>",
            f"<p>{esc(corroboration.detail)}</p>"]
    if getattr(corroboration, "reason", ""):
        body.append('<p class="label">Why it could not be checked</p>'
                    f"<p>{esc(corroboration.reason)}</p>")
    if outcome == "agree" and not getattr(corroboration, "independent", False):
        body.append(
            '<p class="fix">Both sources came down the same unauthenticated '
            "connection, so this agreement is weaker than it looks. Confirm "
            "the fingerprint out of band anyway.</p>")
    return (f'<div class="corroboration corroboration-{esc(outcome, "")}">'
            + _banner(kind, prefix, "".join(body)) + "</div>")


def _directory_panel(directory: Any) -> str:
    """What the directory published, per container, including what failed."""
    rows = "".join(
        f"<tr><th>{esc(item.label)}</th>"
        f'<td>{esc(item.count, "0") if item.ok else "not read"}</td>'
        f'<td class="muted">{esc(item.error or item.dn)}</td></tr>'
        for item in getattr(directory, "containers", ()) or ())
    table = (f'<table class="facts"><thead><tr><th>Container</th>'
             f"<th>Certificates</th><th>Detail</th></tr></thead>"
             f"<tbody>{rows}</tbody></table>" if rows else "")
    if not getattr(directory, "ok", False):
        return _banner(
            "warn", "Active Directory's own CA list could not be read.",
            f"<p>{esc(directory.error)}</p>"
            "<p>Without it the chain above is corroborated by nothing except "
            "itself. If certificate validation is on and this failed for the "
            "same certificate reason the connection did, that is expected — "
            "the corroboration is only available once either the root is "
            "trusted or you knowingly clear 'Validate certificate' for one "
            "diagnostic pass.</p>" + table)
    certificates = getattr(directory, "certificates", ()) or ()
    if not certificates:
        return _banner(
            "warn", "Active Directory publishes no CA certificates.",
            "<p>The configuration naming context was read and held none. That "
            "is normal in a domain with no enterprise certification "
            "authority — and it means there is nothing here to check the "
            "chain against.</p>" + table)
    cards = "".join(_certificate_card(facts,
                                      "Published in Active Directory",
                                      exportable=True)
                    for facts in certificates)
    return (_banner("info",
                    f"Active Directory publishes {len(certificates)} CA "
                    f"certificate(s).",
                    "<p>These came from the forest's configuration naming "
                    "context over the LDAP connection, not from the TLS "
                    "handshake.</p>" + table)
            + cards)


def _guidance_panel(machine: Any, steps: Sequence[Any]) -> str:
    """The platform-specific steps, in order, each with a copyable command."""
    body = [f"<p>{esc(machine.headline)}</p>",
            f'<p class="muted">How ADitor worked that out: '
            f"{esc(machine.evidence)}.</p>"]
    items: List[str] = []
    for index, step in enumerate(steps or (), start=1):
        command = ""
        if step.command:
            command = (
                _code_block(step.command, "Command")
                + f'<button type="button" class="ghost" '
                  f'data-copy-text="{esc(step.command, "")}">Copy '
                  f"command</button>")
        note = f"<p>{esc(step.note)}</p>" if step.note else ""
        items.append(
            f'<li class="step">'
            f'<p class="step-label"><span class="step-n">{index}</span> '
            f"{esc(step.label)}</p>"
            f"{note}"
            f"{command}</li>")
    return (_banner("info" if machine.manual_import_is_the_fix else "warn",
                    f"On this machine ({machine.system})",
                    "".join(body))
            + (f'<ol class="trust-steps">{"".join(items)}</ol>'
               if items else ""))


#: The label on the download button. Deliberately says what it does -- fetches
#: a file -- and not what the operator then does with it. "Download" and "save"
#: are not on the forbidden-verb list in
#: ``tests/test_app_certificate_panel.py`` because writing a file is the one
#: thing this app is allowed to do with a certificate; "trust", "install" and
#: "import" are, and remain, not.
DOWNLOAD_ISSUER_LABEL = "Download the issuing CA certificate"


def _download_issuer_prompt(report: Any) -> str:
    """The offer to fetch the CA certificate, when there is nothing to export.

    Shown when the controller sent no CA of its own, which is the ordinary case
    for an autoenrolled domain controller certificate and the case where the
    instructions below would otherwise begin with a path the operator has to go
    and find by hand.
    """
    return _banner(
        "info", "ADitor can fetch the issuing CA certificate for you.",
        "<p>The controller did not send it, but Active Directory publishes it, "
        "and the certificate the controller <em>did</em> send names the "
        "directory object it lives in. ADitor will read it and save it as a "
        "<code>.crt</code> file here — that is all: it does not add it to any "
        "trust store, and the commands below stay yours to run.</p>"
        "<p><strong>What makes the file the right one.</strong> More than one "
        "CA certificate is normally published, including retired ones, and "
        "installing the wrong one leaves the same error behind while looking "
        "like a fix. So ADitor does not pick by name: it offers a certificate "
        "only if that certificate&rsquo;s key <em>signed the one the "
        "controller presented</em>. Anything else is discarded and counted "
        "below.</p>"
        "<p class=\"muted\">The read is made with certificate validation off, "
        "because the certificate needed to validate it is the one being "
        "fetched. That is why the signature check exists, and why the "
        "fingerprint still has to be confirmed out of band before you install "
        "anything.</p>"
        f'<div class="actions actions-left">'
        f'<button type="button" class="primary" data-download-issuer="1">'
        f"{esc(DOWNLOAD_ISSUER_LABEL)}</button></div>")


def _issuer_panel(fetch: Any) -> str:
    """What the issuer fetch found, including what it refused to offer."""
    if fetch is None:
        return ""
    outcome = str(getattr(fetch, "outcome", "") or "")
    kind = {"found": "ok", "no_match": "bad"}.get(outcome, "warn")
    body = [f"<p>{esc(fetch.detail)}</p>"]

    rows = "".join(
        f"<tr><th>{esc(item.facts.label)}</th>"
        f'<td>{"signed it" if item.verified else "no"}</td>'
        f'<td class="muted"><code>{esc(item.facts.fingerprint)}</code></td>'
        f"<td class=\"muted\">{esc(item.reason)}</td></tr>"
        for item in getattr(fetch, "candidates", ()) or ())
    if rows:
        body.append(
            '<p class="label">Every certificate that was considered</p>'
            '<table class="facts"><thead><tr><th>Certificate</th>'
            "<th>Signed the presented certificate?</th>"
            "<th>SHA-256 fingerprint</th><th>Why</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")
    if getattr(fetch, "error", ""):
        body.append('<p class="label">What the directory said</p>'
                    + _code_block(fetch.error))
    if getattr(fetch, "unchecked", 0):
        body.append(
            f'<p class="fix">{esc(fetch.unchecked)} certificate(s) could not '
            f"be checked at all. That is not the same as ruling them out, and "
            f"none of them were offered.</p>")
    if outcome == "found":
        body.append(
            '<p class="fix">This proves the two certificates belong together. '
            "It does not prove either is legitimate — the connection it came "
            "over was not authenticated. Confirm the fingerprint above with "
            "whoever runs the certification authority before you install "
            "it.</p>")
    return _banner(kind, fetch.headline, "".join(body))


def render_certificate_panel(report: Any, fetch: Any = None) -> str:
    """The whole Certificate panel: chain, corroboration, guidance, export.

    Ordered by what the operator has to do first. Expiry alerts lead, because
    an expired certificate makes the rest of the panel a distraction. Then the
    chain with its fingerprints, then the corroboration, then the
    machine-specific steps, then the export.

    There is no button here that installs or trusts a certificate, and
    ``tests/test_app_certificate_panel.py`` asserts that over the rendered
    markup rather than trusting this paragraph.
    """
    chain = report.chain
    parts: List[str] = []

    if not chain.ok:
        parts.append(_banner(
            "bad", "The certificate chain could not be read.",
            '<p class="label">What happened</p>' + _code_block(chain.error)
            + f"<p>Nothing was reached on "
              f"<code>{esc(chain.host)}:{esc(chain.port)}</code>. That is a "
              f"connectivity or port problem rather than a trust one — port "
              f"636 speaks TLS from the first byte, port 389 does not.</p>"))
        parts.append(_corroboration_panel(report.corroboration))
        parts.append(_directory_panel(report.directory))
        return "".join(parts)

    parts.append(_expiry_alerts(
        tuple(chain.certificates)
        + tuple(getattr(report.directory, "certificates", ()) or ())))

    exportable = {facts.fingerprint_hex for facts in report.exportable}
    total = len(chain.certificates)
    parts.append(
        f'<h3 class="section">What '
        f"<code>{esc(chain.host)}:{esc(chain.port)}</code> presented "
        f'<span class="count">{total}</span></h3>')
    parts.append(_banner(
        "warn", "Read with certificate validation off — this proves nothing.",
        "<p>Every value below is what the server said about itself, over a "
        "connection this machine has not authenticated. It is here to be "
        "checked against the certification authority, not believed.</p>"))
    if chain.leaf_only:
        parts.append(_banner(
            "warn", "The server sent only its own certificate.",
            "<p>No CA certificates came with it, so the chain has no visible "
            "anchor — which is normal for an autoenrolled controller "
            "certificate rather than a fault in itself. The issuing CA has to "
            "come from somewhere else, and ADitor can fetch it: see "
            f"<strong>{esc(DOWNLOAD_ISSUER_LABEL)}</strong> below.</p>"))
    parts.extend(
        _certificate_card(facts, _position_label(index, total),
                          exportable=facts.fingerprint_hex in exportable)
        for index, facts in enumerate(chain.certificates))

    parts.append('<h3 class="section">Does Active Directory agree?</h3>')
    parts.append(_corroboration_panel(report.corroboration))
    parts.append(_directory_panel(report.directory))

    parts.append('<h3 class="section">Get the CA certificate</h3>')
    if fetch is not None:
        parts.append(_issuer_panel(fetch))
    if not report.export_path and not exportable:
        # Nothing in the chain can be exported, so the instructions below would
        # otherwise open on a path the operator has to go and find.
        parts.append(_download_issuer_prompt(report))

    parts.append('<h3 class="section">What to do on this machine</h3>')
    parts.append(_guidance_panel(report.machine, report.steps))

    if report.export_path:
        parts.append(_banner(
            "ok", "Certificate exported.",
            f"<p>Written to <code>{esc(report.export_path)}</code>. ADitor has "
            f"not installed it and will not: the commands above are yours to "
            f"run, and the elevation prompt is where you decide.</p>"))
    else:
        hint = ("<strong>Export CA certificate</strong> on the certificate "
                "you have verified" if exportable else
                f"<strong>{esc(DOWNLOAD_ISSUER_LABEL)}</strong> above")
        parts.append(_banner(
            "info", "Save a CA certificate to fill the path into the "
                    "commands above.",
            f"<p>Use {hint}. ADitor writes a <code>.crt</code> file and "
            "nothing else — it does not add it to any trust store.</p>"))
    return "".join(parts)


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

    Every number here is read from the one scan's payload — its own counts.
    ``scans_run`` is displayed for exactly that reason: showing that it ran
    once makes the guarantee visible rather than merely true.
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

    directory_errors = payload.get("directory_errors") or []
    if directory_errors:
        parts.append(_banner(
            "warn", f"{len(directory_errors)} directory check(s) could not "
                    f"run.",
            "<p>Their queries failed, so these controls are reported as "
            "unknown rather than as clean: "
            + esc(", ".join(str(c) for c in directory_errors))
            + ". The report says why.</p>"))

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
        "values, distinguished names, and the names of the accounts and group "
        "members the directory checks list. Treat the folder accordingly when "
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
                f'{esc(counts.get("conflicts"), "0")} '
                f'{"conflict" if counts.get("conflicts") == 1 else "conflicts"}'
                f'</span>'
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
            f"<td><div class=\"snap-name\">"
            f"{esc(friendly_time(entry.timestamp) if entry.timestamp else entry.name)}"
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
        "<th>Scan time</th><th>Result</th><th>Coverage</th>"
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

    why = (f'<details class="notes"><summary>Why this matters</summary>'
           f'<p>{esc(summary)}</p></details>' if summary else "")
    if ambiguous:
        body = [
            '<p class="banner-lede">These scans were made by different versions '
            "of ADitor, so a difference below may come from the tool rather than "
            "the domain. Treat this comparison as a new starting point, not as "
            "progress.</p>",
            f'<p class="reason">What changed: {esc(reason)}</p>',
        ]
        if caveats:
            body.append('<p class="label">Also worth knowing</p>'
                        + _list(caveats))
        return _banner("bad", "Different ADitor versions", "".join(body) + why)

    body = ['<p class="banner-lede">Both scans used the same ADitor version, '
            "so the differences below are changes in the domain.</p>"]
    if caveats:
        body.append('<p class="label">Read these anyway</p>' + _list(caveats))
    return _banner("ok", "Same ADitor version", "".join(body) + why)


def _render_scan_pair(scans: Dict[str, Any]) -> str:
    before = scans.get("before")
    after = scans.get("after")
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    return _rows([
        ("Domain", esc(scans.get("domain"))),
        ("Base DN", f'<code>{esc(scans.get("base_dn"))}</code>'),
        ("Earlier scan", f'{esc(friendly_time(before.get("timestamp")))} '
                         f'<code>{esc(before.get("scan_id"))}</code>'),
        ("Later scan", f'{esc(friendly_time(after.get("timestamp")))} '
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
    body = []
    if added:
        entries = sorted((e for e in added if isinstance(e, dict)),
                         key=lambda e: (_ADDED_ORDER.get(str(e.get("result")), 9),
                                        str(e.get("control_id") or "")))
        tally = ", ".join(
            f"{n} {label}" for label, n in _tally(entries) if n)
        body.append(f'<p class="label">Added to the catalog: {len(added)}'
                    + (f" ({esc(tally)})" if tally else "") + "</p>"
                    + '<ul class="added">' + "".join(
                        f'<li><span class="pill pill-{_ADDED_PILL.get(str(e.get("result")), "muted")}">'
                        f'{esc(_ADDED_LABEL.get(str(e.get("result")), e.get("result")))}'
                        f'</span> <code>{esc(e.get("control_id"))}</code> '
                        f'{esc(e.get("title"))}</li>' for e in entries)
                    + "</ul>"
                    + "<p>These are new checks, so they have no earlier result to "
                      "compare with. A failure here is a first finding, not a "
                      "regression &mdash; open the later scan's report for "
                      "what to do.</p>")
    if removed:
        ids = [str(e.get("control_id") if isinstance(e, dict) else e)
               for e in removed]
        body.append('<p class="label">Removed from the catalog</p>'
                    + _list(ids))
    note = str(catalog.get("note") or
               "A control present in one scan and not the other has no "
               "before-and-after verdict, so it is never counted as an "
               "improvement or a regression.")
    return _banner("info", "Catalog changes",
                   "".join(body) + f"<p>{esc(note)}</p>")


#: How an added control's first result is shown, worst first.
_ADDED_ORDER = {"fail": 0, "error": 1, "unknown": 2, "pass": 3,
                "not_applicable": 4}
_ADDED_LABEL = {"fail": "fail", "error": "unknown", "unknown": "unknown",
                "pass": "pass", "not_applicable": "not checked"}
_ADDED_PILL = {"fail": "bad", "error": "warn", "unknown": "warn", "pass": "ok"}


def _tally(entries: Sequence[Dict[str, Any]]) -> List[Any]:
    counts: Dict[str, int] = {}
    for entry in entries:
        label = _ADDED_LABEL.get(str(entry.get("result")), "other")
        counts[label] = counts.get(label, 0) + 1
    return [(label, counts.get(label, 0))
            for label in ("fail", "unknown", "pass", "not checked", "other")]


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
    "OUT_OF_BAND_INSTRUCTION",
    "esc",
    "render_certificate_panel",
    "render_connection_result",
    "render_counts",
    "render_credential_store",
    "render_diff",
    "render_error",
    "render_history",
    "render_notice",
    "render_scan_result",
]
