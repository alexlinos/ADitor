"""Tests for the self-contained HTML hardening report.

**Offline by construction.** The renderer is a pure function of a scan payload,
so there is no LDAP, no SMB, no server, no keychain and no domain controller
anywhere in this file. The only side effect exercised is writing a file, and that
happens under ``tmp_path``.

**Fixture hygiene.** Every payload is synthesized. GPO GUIDs are obvious
placeholders (``11111111-...``), DNs follow the repo's ``DC=test,DC=local``
convention, and no real SID, domain, DC hostname or file path appears. That
matters more here than anywhere else in the suite: a rendered report *embeds* the
domain's GPO display names and registry values, which is exactly the
environmental detail this repo keeps out of git.

The load-bearing tests, in the order the review cares about:

* ``TestSelfContained`` — one file, no external asset of any kind, no script, and
  it survives an empty scan, an all-pass scan and a mixed scan.
* ``TestEscaping`` — a GPO display name containing ``<script>``, ``&`` and quotes
  is escaped everywhere it appears. Directory data is untrusted and this file
  gets opened in a browser.
* ``TestOrdering`` — actionability order, and the read-failure banner ahead of
  every verdict section.
* ``TestUnreadableGpos`` — the affected verdicts read as unknown, never clean.
* ``TestOsDefaultFraming`` and ``TestNotJudged`` — the two framings that must not
  be mistakable for a pass.
"""

import html
import re

import pytest
from aditor.hardening.catalog import build_catalog, load_catalog
from aditor.hardening.evaluator import GpoLink, GpoSnapshot, evaluate_controls
from aditor.hardening.report import (
    GROUPS,
    REPORT_FORMAT_VERSION,
    REPORT_MARKER,
    SECTION_CONFLICTS,
    SECTION_FAIL,
    SECTION_NOT_APPLICABLE,
    SECTION_NOT_JUDGED,
    SECTION_OPPORTUNITIES,
    SECTION_PASSES,
    SECTION_UNKNOWN,
    SECTIONS,
    START_HERE_LIMIT,
    _delivered_by_preference,
    group_findings,
    headline_counts,
    render_report,
    write_report,
)

BASE_DN = "DC=test,DC=local"
GUID_A = "11111111-1111-1111-1111-111111111111"
GUID_B = "22222222-2222-2222-2222-222222222222"
GUID_C = "33333333-3333-3333-3333-333333333333"

# A GPO display name an attacker who can rename a GPO would choose. Directory
# content is untrusted input to this renderer.
HOSTILE_NAME = "Evil <script>alert(\"xss\")</script> & 'quoted' GPO"

LM_KEY = r"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"
LM_CONTROL = "DEVORE-01-NTLM-LMCOMPATIBILITYLEVEL"
CLIENT_SIGNING_CONTROL = "DEVORE-03-LDAP-CLIENT-SIGNING"
UNSCORED_CONTROL = "DEVORE-08-NTLM-BLOCK-INCOMING"


# --------------------------------------------------------------------------- #
# Synthesized inputs
# --------------------------------------------------------------------------- #

def gpo_dn(guid):
    return f"CN={{{guid}}},CN=Policies,CN=System,{BASE_DN}"


def template_entry(key, value, type_name="REG_DWORD"):
    return {"key": key, "type": 4, "type_name": type_name, "value": value}


def snapshot(guid, display_name, entries=(), links=(), read_error=None,
             pol_entries=(), preference_entries=()):
    return GpoSnapshot(
        dn=gpo_dn(guid),
        display_name=display_name,
        guid=guid,
        security_template_entries=list(entries),
        registry_pol_entries=list(pol_entries),
        registry_xml_entries=list(preference_entries),
        links=tuple(links),
        read_error=read_error,
    )


# The live-observed KDC preference item, already parsed (the value is 0x38, so
# parse_registry_xml has decoded it to 56 by the time the evaluator sees it).
KDC_CONTROL = "DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"


def preference_entry(value=56, action="U", has_filters=False,
                     key=r"SYSTEM\CurrentControlSet\Services\Kdc",
                     value_name="DefaultDomainSupportedEncTypes",
                     type_name="REG_DWORD"):
    return {"hive": "HKEY_LOCAL_MACHINE", "key": key,
            "value_name": value_name, "type": 4, "type_name": type_name,
            "value": value, "action": action, "order": 1,
            "has_filters": has_filters, "disabled": False}


def kdc_pol_entry(value=56):
    return {"key": r"System\CurrentControlSet\services\KDC",
            "value": "DefaultDomainSupportedEncTypes",
            "type": "REG_DWORD", "data": value}


def provenance(catalog, gpos_scanned=2, gpos_unreadable=0):
    """A synthesized scan header, shaped exactly like the tool's own."""
    header = {
        "tool": "scan_hardening",
        "tool_version": "1.1.0",
        "scan_id": "0123456789abcdef0123456789abcdef",
        "timestamp": "2026-08-19T09:30:00+00:00",
        "domain": "test.local",
        "base_dn": BASE_DN,
        "gpos_scanned": gpos_scanned,
        "gpos_unreadable": gpos_unreadable,
        "include_not_applicable": True,
        "read_only": True,
        "precedence": "Precedence is not resolved.",
    }
    header.update(catalog.provenance())
    header["catalog_notes"] = list(catalog.notes)
    return header


def scan_payload(gpos, catalog=None, include_not_applicable=True,
                 read_errors=(), unknown_control_ids=(), control_ids=None,
                 directory=None):
    """Build the payload ``scan_hardening`` would return, using the real engine.

    The findings come from the real evaluator over the real shipped catalog, so
    these tests render the same shapes production renders rather than a
    hand-written approximation of them.
    """
    catalog = catalog or load_catalog()
    controls, _unknown = catalog.select(control_ids)
    if directory is None:  # every directory query ran and found nothing
        directory = {c.id: {"objects": [], "notes": [], "error": None}
                     for c in controls if c.check_type == "directory-state"}
    findings, counts = evaluate_controls(
        controls, gpos, include_not_applicable=include_not_applicable,
        directory=directory)
    return {
        "scan": provenance(catalog, gpos_scanned=len(gpos),
                           gpos_unreadable=len(read_errors)),
        "counts": counts,
        "findings": findings,
        "unscored_control_ids": [c.id for c in controls if not c.scored],
        "unknown_control_ids": list(unknown_control_ids),
        "gpo_read_errors": list(read_errors),
    }


# --------------------------------------------------------------------------- #
# HTML helpers — string slicing, no parser dependency
# --------------------------------------------------------------------------- #

def sections_of(document):
    """Split the document into ``{section_id: html}``, in document order."""
    starts = [(m.start(), m.group(1)) for m in
              re.finditer(r'<section class="section section-([a-z-]+)"', document)]
    out = {}
    for index, (offset, section_id) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(document)
        out[section_id] = document[offset:end]
    return out


def card_of(document, section_id, control_id):
    """The one ``<article>`` for ``control_id`` inside ``section_id``.

    The anchor is the control id alone — deliberately not section-qualified, so a
    link to a finding survives the finding changing verdict. ``section_id`` is
    still checked, via the card's class.
    """
    anchor = f'id="{control_id}"'.lower()
    start = document.lower().index(anchor)
    # A card is an <article>; a not-checked finding is a compact <details> row.
    start = max(document.rfind("<article", 0, start),
                document.rfind("<details", 0, start))
    closing = ("</article>" if document.startswith("<article", start)
               else "</details>")
    return document[start:document.index(closing, start)]


def pass_row_of(document, control_id):
    section = sections_of(document)[SECTION_PASSES]
    start = section.index(control_id)
    start = section.rindex("<details", 0, start)
    return section[start:section.index("</details>", start)]


def visible_text(document):
    """Tag-stripped text, for assertions about what a reader actually sees."""
    return re.sub(r"<[^>]+>", " ", document)


# --------------------------------------------------------------------------- #
# Scans used across the tests
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.fixture
def mixed_scan(catalog):
    """A failure, a conflict (with an enforced override), and unscored controls.

    Two GPOs disagree on ``LmCompatibilityLevel`` (1 vs 5) and the higher one is
    linked with enforcement, which is the conflict shape most likely to be
    misread. No GPO sets the LDAP client signing key, so that control lands on
    its documented Windows default.
    """
    return scan_payload([
        snapshot(GUID_A, HOSTILE_NAME, entries=[template_entry(LM_KEY, 1)],
                 links=[GpoLink(target_dn=BASE_DN)]),
        snapshot(GUID_B, "Override GPO", entries=[template_entry(LM_KEY, 5)],
                 links=[GpoLink(target_dn=f"OU=Domain Controllers,{BASE_DN}",
                                enforced=True)]),
    ], catalog=catalog)


@pytest.fixture
def unreadable_scan(catalog):
    """One GPO read, one that could not be read at all."""
    read_errors = [{
        "gpo_dn": gpo_dn(GUID_C),
        "display_name": HOSTILE_NAME,
        "error": "SMB read failed: STATUS_ACCESS_DENIED on <policy> path",
    }]
    return scan_payload([
        snapshot(GUID_A, "Readable GPO", entries=[template_entry(LM_KEY, 5)],
                 links=[GpoLink(target_dn=BASE_DN)]),
        snapshot(GUID_C, HOSTILE_NAME,
                 read_error="SMB read failed: STATUS_ACCESS_DENIED"),
    ], catalog=catalog, read_errors=read_errors)


@pytest.fixture
def all_pass_scan(catalog):
    """Every scored control set to its final expected value by one GPO."""
    entries, pol_entries = [], []
    for control in catalog.controls:
        if not control.scored or not control.registry_key:
            continue
        value = control.final_expected
        if isinstance(value, list):
            value = value[0]
        if control.check_type == "gpo-security-template":
            entries.append(template_entry(control.registry_key, value,
                                          control.registry_type or "REG_DWORD"))
        else:
            pol_entries.append({"key": control.registry_key_path,
                                "value": control.registry_value_name,
                                "type": 4, "data": value})
    return scan_payload([
        snapshot(GUID_A, "Everything Configured", entries=entries,
                 pol_entries=pol_entries, links=[GpoLink(target_dn=BASE_DN)]),
    ], catalog=catalog)


@pytest.fixture
def empty_scan(catalog):
    """A scan that found nothing at all: no GPOs, no findings, zero counts."""
    return {
        "scan": provenance(catalog, gpos_scanned=0),
        "counts": {},
        "findings": [],
        "unscored_control_ids": [],
        "unknown_control_ids": [],
        "gpo_read_errors": [],
    }


# --------------------------------------------------------------------------- #
# 1. Self-contained, and never crashing
# --------------------------------------------------------------------------- #

class TestSelfContained:
    """One file, no external anything, and no JavaScript to read it."""

    FORBIDDEN = ("<script", "src=", "<link ", "@import", "url(", "<iframe",
                 "<object", "<embed", "onerror=", "onload=", "onclick=",
                 "javascript:")

    @pytest.mark.parametrize("fixture_name",
                             ["empty_scan", "all_pass_scan", "mixed_scan",
                              "unreadable_scan"])
    def test_no_external_assets_and_no_script(self, fixture_name, request):
        """Empty, all-pass, mixed and unreadable scans all render, all inert."""
        document = render_report(request.getfixturevalue(fixture_name))

        assert document.startswith("<!DOCTYPE html>")
        assert '<meta charset="utf-8">' in document
        assert document.rstrip().endswith("</html>")
        for token in self.FORBIDDEN:
            assert token not in document, f"{fixture_name} emitted {token!r}"

    def test_css_is_inline(self, mixed_scan):
        document = render_report(mixed_scan)
        assert document.count("<style>") == 1
        assert "font:16px/1.5" in document

    def test_carries_the_report_marker_and_versions(self, mixed_scan):
        document = render_report(mixed_scan)
        assert REPORT_MARKER in document[:4096]
        assert REPORT_FORMAT_VERSION in document

    def test_tags_are_balanced(self, mixed_scan):
        """A malformed document is not a report; check every tag closes."""
        from html.parser import HTMLParser

        void = {"meta", "br", "hr", "img", "input", "link", "area", "base",
                "col", "source", "track", "wbr"}

        class Balance(HTMLParser):
            def __init__(self):
                super().__init__()
                self.stack, self.errors = [], []

            def handle_starttag(self, tag, attrs):
                if tag not in void:
                    self.stack.append(tag)

            def handle_endtag(self, tag):
                if not self.stack or self.stack[-1] != tag:
                    self.errors.append((tag, list(self.stack[-3:])))
                else:
                    self.stack.pop()

        checker = Balance()
        checker.feed(render_report(mixed_scan))
        assert checker.errors == []
        assert checker.stack == []

    def test_empty_scan_still_names_every_section(self, empty_scan):
        document = render_report(empty_scan)
        rendered = sections_of(document)
        assert set(rendered) == {section_id for section_id, _t, _l in SECTIONS}
        assert document.count(">None.<") == len(SECTIONS)

    @pytest.mark.parametrize("payload", [{}, None, {"findings": "nonsense"},
                                         {"findings": [None, 7]},
                                         {"counts": [], "scan": "no"}])
    def test_garbage_payloads_do_not_crash(self, payload):
        """A renderer that raises on a partial payload is a renderer nobody trusts."""
        document = render_report(payload)
        assert document.startswith("<!DOCTYPE html>")


# --------------------------------------------------------------------------- #
# 2. Escaping — acceptance criterion 3
# --------------------------------------------------------------------------- #

class TestEscaping:
    """Directory data is untrusted; this file is opened in a browser."""

    def test_hostile_gpo_display_name_is_escaped(self, mixed_scan):
        document = render_report(mixed_scan)

        # The raw markup never appears...
        assert "<script>alert" not in document
        assert "<script" not in document
        # ...and the escaped form does, so the name is still readable evidence.
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in document
        assert "Evil &lt;script&gt;" in document

    def test_ampersand_and_quotes_are_escaped(self, mixed_scan):
        document = render_report(mixed_scan)
        assert "&amp; &#x27;quoted&#x27; GPO" in document
        # No bare ampersand introduced anywhere: every & starts an entity.
        bare = re.findall(r"&(?!#?\w+;)", document)
        assert bare == []

    def test_escaped_in_every_place_the_name_appears(self, mixed_scan):
        """Found-value table, conflict table and the conflict detail prose."""
        document = render_report(mixed_scan)
        card = card_of(document, SECTION_FAIL, LM_CONTROL)
        assert card.count("Evil &lt;script&gt;") >= 2  # found row + conflict row
        assert "<script" not in card

    def test_read_error_text_is_escaped(self, unreadable_scan):
        """SMB error strings quote directory paths back at us."""
        document = render_report(unreadable_scan)
        assert "STATUS_ACCESS_DENIED on &lt;policy&gt; path" in document
        assert "on <policy> path" not in document

    def test_registry_values_from_the_directory_are_escaped(self, catalog):
        """A string value in a GPO is directory content too."""
        hostile_value = '<img src=x onerror=alert(1)>'
        payload = scan_payload([
            snapshot(GUID_A, "String Value GPO",
                     entries=[template_entry(LM_KEY, hostile_value,
                                             "REG_SZ")],
                     links=[GpoLink(target_dn=BASE_DN)]),
        ], catalog=catalog, control_ids=[LM_CONTROL])
        document = render_report(payload)

        # No tag is produced: the value is inert text, entity-encoded.
        assert "<img" not in document
        assert "&lt;img src=x onerror=alert(1)&gt;" in document

    def test_unsafe_citation_urls_are_not_turned_into_links(self, catalog):
        """A non-http citation renders as text, never as an href."""
        raw = {
            "catalog_version": "test-1",
            "controls": [{
                "id": "TEST-JS-URL",
                "title": "Synthetic control with an unsafe citation",
                "source": {"part": 1, "url": "javascript:alert(1)"},
                "scope": "all",
                "check_type": "gpo-security-template",
                "severity": "low",
                "status": "active",
                "operator": "equals",
                "registry_key": r"HKLM\Software\Test\Value",
                "final_expected": 1,
                "missing_result": "fail",
                "remediation": "Synthetic remediation.",
            }],
        }
        payload = scan_payload([], catalog=build_catalog(raw, "<test>"))
        document = render_report(payload)

        # Never an href...
        assert 'href="javascript' not in document
        # The only anchors in the document are in-page links (tiles, contents).
        hrefs = re.findall(r'<a href="([^"]*)"', document)
        assert hrefs and all(href.startswith("#") for href in hrefs), hrefs
        # ...but shown as inert text, because silently dropping a citation hides
        # a broken catalog entry.
        assert "citation URL not linked" in document
        assert "javascript:alert(1)" in visible_text(document)


# --------------------------------------------------------------------------- #
# 3. Ordering — actionability, not catalog order
# --------------------------------------------------------------------------- #

class TestOrdering:

    # Group order: Fix, Check by hand, Not covered yet, Good.
    EXPECTED_ORDER = [SECTION_FAIL, SECTION_OPPORTUNITIES, SECTION_UNKNOWN,
                      SECTION_CONFLICTS, SECTION_NOT_JUDGED,
                      SECTION_NOT_APPLICABLE, SECTION_PASSES]

    def test_sections_appear_in_actionability_order(self, mixed_scan):
        document = render_report(mixed_scan)
        assert list(sections_of(document)) == self.EXPECTED_ORDER

    def test_read_failure_banner_precedes_every_verdict_section(
            self, unreadable_scan):
        """Acceptance 4: the warning comes before anything that reads as a verdict."""
        document = render_report(unreadable_scan)
        banner = document.index('<section class="alert" id="read-failures"')

        for section_id in self.EXPECTED_ORDER:
            assert banner < document.index(f'id="{section_id}"'), section_id
        # Ahead of the headline counts and the provenance table too: a reader who
        # sees "2 failures, 14 passes" first has already misread the report.
        assert banner < document.index('id="summary"')
        assert banner < document.index('id="provenance"')

    def test_failures_are_severity_ordered_within_the_section(self, mixed_scan):
        section = sections_of(render_report(mixed_scan))[SECTION_FAIL]
        severities = re.findall(r'badge badge-sev-([a-z]+)"', section)
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                "informational": 4}
        assert severities == sorted(severities, key=lambda s: rank[s])

    def test_conflicts_cross_reference_rather_than_own(self, mixed_scan):
        """A conflicting finding appears in both its verdict section and conflicts."""
        grouped = group_findings(mixed_scan["findings"])
        conflicted = {f["control_id"] for f in grouped[SECTION_CONFLICTS]}
        failing = {f["control_id"] for f in grouped[SECTION_FAIL]}
        assert LM_CONTROL in conflicted
        assert LM_CONTROL in failing

        document = render_report(mixed_scan)
        assert card_of(document, SECTION_FAIL, LM_CONTROL)
        assert card_of(document, SECTION_CONFLICTS, LM_CONTROL)

    def test_table_of_contents_leads_with_the_read_failures(
            self, unreadable_scan):
        document = render_report(unreadable_scan)
        toc = document[document.index('<nav class="toc"'):
                       document.index("</nav>")]
        assert toc.index('href="#read-failures"') < toc.index('href="#unknown"')


# --------------------------------------------------------------------------- #
# 4. Unreadable GPOs — acceptance criterion 4
# --------------------------------------------------------------------------- #

class TestUnreadableGpos:

    def test_banner_names_the_gpo_and_the_error(self, unreadable_scan):
        document = render_report(unreadable_scan)
        banner = document[document.index('id="read-failures"'):
                          document.index('id="provenance"')]
        assert "could not be read" in banner
        assert gpo_dn(GUID_C) in banner
        assert "STATUS_ACCESS_DENIED" in banner
        assert "1 of 2 GPO(s) could not be read" in banner

    def test_banner_says_the_affected_verdicts_are_unknown_not_clean(
            self, unreadable_scan):
        document = render_report(unreadable_scan)
        banner = document[document.index('id="read-failures"'):
                          document.index('id="provenance"')]
        assert "This scan is incomplete" in banner
        assert "unknown, not clean" in banner

    def test_affected_control_is_unknown_rather_than_a_pass(
            self, unreadable_scan):
        """WP2: an unset key plus an unreadable GPO is an error, not a default pass."""
        document = render_report(unreadable_scan)
        rendered = sections_of(document)

        assert CLIENT_SIGNING_CONTROL in rendered[SECTION_UNKNOWN]
        assert CLIENT_SIGNING_CONTROL not in rendered[SECTION_PASSES]
        assert CLIENT_SIGNING_CONTROL not in rendered[SECTION_OPPORTUNITIES]

        card = card_of(document, SECTION_UNKNOWN, CLIENT_SIGNING_CONTROL)
        assert "Unknown" in card
        assert "was <strong>not\napplied</strong>" in card or \
            "not <strong>applied</strong>" in card or "not applied" in card
        assert "Why this is unknown" in card

    def test_provenance_highlights_the_unreadable_count(self, unreadable_scan):
        document = render_report(unreadable_scan)
        provenance_block = document[document.index('id="provenance"'):
                                    document.index('<footer')]
        assert "GPOs unreadable" in provenance_block
        assert '<strong class="bad">1</strong>' in provenance_block

    def test_clean_scan_says_so_instead(self, mixed_scan):
        document = render_report(mixed_scan)
        assert '<section class="alert"' not in document
        assert "GPOs were read." in document


# --------------------------------------------------------------------------- #
# 5. Failure cards — acceptance criterion 5
# --------------------------------------------------------------------------- #

class TestFailureCard:

    @pytest.fixture
    def card(self, mixed_scan):
        return card_of(render_report(mixed_scan), SECTION_FAIL, LM_CONTROL)

    def test_shows_severity_and_verdict(self, card):
        assert 'badge badge-sev-high">HIGH<' in card
        assert ">Fail<" in card

    def test_shows_expected_interim_and_final(self, card):
        assert "Interim (audit step)" in card
        assert "Final (enforced)" in card
        assert ">3<" in card and ">5<" in card

    def test_shows_every_found_value_with_its_gpo_dn_and_link_path(self, card):
        assert card.count("<tr>") >= 3  # header + one row per finding value
        assert gpo_dn(GUID_A) in card
        assert gpo_dn(GUID_B) in card
        assert f"OU=Domain Controllers,{BASE_DN}" in card
        assert "GptTmpl.inf [Registry Values]" in card

    def test_shows_the_catalogs_remediation_verbatim(self, card, catalog):
        remediation = catalog.by_id(LM_CONTROL).remediation
        assert "Remediation" in card
        # The catalog's own words, escaped but not paraphrased.
        assert "Set every client and member server to" in card
        assert remediation.split(".")[0][:40] in card.replace("&gt;", ">")

    def test_carries_the_phasing_caveat_interim_first(self, card):
        """Advising a jump straight to enforcement is the dangerous failure mode."""
        assert "How to roll it out safely" in card
        step_one = card.index("Step 1")
        step_two = card.index("Step 2")
        assert step_one < step_two
        assert "Step 1: set it to 3 first" in card
        assert "Step 2: only then set it to 5." in card
        assert "Don&#x27;t skip step 1" in card or "Don't skip step 1" in card

    def test_carries_the_catalogs_audit_before_enforce_evidence(self, card):
        assert "Before enforcing, check:" in card
        assert "LmPackageName = &#x27;NTLM V1&#x27;" in card

    def test_carries_every_catalog_caveat_including_unprefixed_ones(
            self, card, catalog):
        """All of them: Part 4's service-account warning carries no prefix."""
        for caveat in catalog.by_id(LM_CONTROL).caveats:
            assert caveat.split(":")[0][:30].replace("'", "&#x27;") in card
        assert 'class="flagged"' in card  # the IN STAGES: caveat is emphasised

    def test_rc4_control_surfaces_the_service_account_warning(self, catalog):
        """Part 4: remediate service accounts before disabling RC4 domain-wide.

        The failing fixture is a GPO that sets the value *wrongly* (0x26, which
        re-enables RC4) rather than an empty domain: since P2-WP5 an empty domain
        makes this control ``unknown``, because its documented remediation writes
        the registry directly on the DCs and leaves no GPO trace. A wrong value
        that a GPO really does deliver is still a failure, and that is the card
        this test is about.
        """
        payload = scan_payload(
            [snapshot(GUID_A, "Enc Types By Policy",
                      pol_entries=[kdc_pol_entry(value=38)],
                      links=[GpoLink(target_dn=BASE_DN)])],
            catalog=catalog, control_ids=[KDC_CONTROL])
        document = render_report(payload)
        assert KDC_CONTROL in sections_of(document)[SECTION_FAIL]
        card = card_of(document, SECTION_FAIL, KDC_CONTROL)
        assert "How to roll it out safely" in card
        assert "too aggressive for most" in card

    def test_missing_note_from_the_catalog_is_shown(self, catalog):
        """The catalog's words on what an unset key means, not the renderer's."""
        payload = scan_payload(
            [snapshot(GUID_A, "Empty GPO", links=[GpoLink(target_dn=BASE_DN)])],
            catalog=catalog, control_ids=[LM_CONTROL])
        card = card_of(render_report(payload), SECTION_FAIL, LM_CONTROL)
        assert "No GPO sets the level" in card

    def test_thin_catalog_guidance_is_reported_as_a_gap_not_improvised(self):
        """A control with no interim, no audit evidence and no caveats."""
        raw = {
            "catalog_version": "test-1",
            "controls": [{
                "id": "TEST-NO-GUIDANCE",
                "title": "Synthetic control with no rollout guidance",
                "source": {"part": 1, "url": "https://example.invalid/doc"},
                "scope": "all",
                "check_type": "gpo-security-template",
                "severity": "high",
                "status": "active",
                "operator": "equals",
                "registry_key": r"HKLM\Software\Test\NoGuidance",
                "final_expected": 1,
                "missing_result": "fail",
                "remediation": "Set the value to 1.",
            }],
        }
        payload = scan_payload([], catalog=build_catalog(raw, "<test>"))
        card = card_of(render_report(payload), SECTION_FAIL, "TEST-NO-GUIDANCE")
        assert "Catalog gap:" in card
        assert "report the gap" in card
        assert "no rollout guidance" in card

    def test_missing_remediation_is_a_reported_gap(self, monkeypatch,
                                                  mixed_scan):
        """The renderer never writes remediation prose of its own."""
        for finding in mixed_scan["findings"]:
            finding["remediation"] = ""
        document = render_report(mixed_scan)
        assert "carries no remediation text" in document
        assert "Nothing is improvised here" in document


# --------------------------------------------------------------------------- #
# 6. Conflicts
# --------------------------------------------------------------------------- #

class TestConflicts:

    @pytest.fixture
    def section(self, mixed_scan):
        return sections_of(render_report(mixed_scan))[SECTION_CONFLICTS]

    def test_names_both_gpos_and_both_values(self, section):
        assert "Evil &lt;script&gt;" in section
        assert "Override GPO" in section
        assert gpo_dn(GUID_A) in section
        assert gpo_dn(GUID_B) in section
        assert ">1<" in section and ">5<" in section

    def test_says_precedence_is_unresolved_and_to_use_gpresult(self, section):
        assert "Precedence is unresolved" in section
        assert "gpresult" in section
        assert "RSoP" in section

    def test_flags_the_enforced_override_shape(self, section):
        assert "enforced-override" in section
        # 1 on the domain root, 5 enforced on the DC OU: workstations really
        # get 1, so it's a split between parts of the domain, not an override.
        assert "linked to different parts of the domain" in section
        assert "likely overridden" not in section

    def test_conflict_on_a_pass_is_still_surfaced(self, catalog):
        """Two GPOs disagree but the worst value still passes: the risky case."""
        payload = scan_payload([
            snapshot(GUID_A, "GPO Three", entries=[template_entry(LM_KEY, 3)],
                     links=[GpoLink(target_dn=BASE_DN)]),
            snapshot(GUID_B, "GPO Five", entries=[template_entry(LM_KEY, 5)],
                     links=[GpoLink(target_dn=BASE_DN)]),
        ], catalog=catalog, control_ids=[LM_CONTROL])
        document = render_report(payload)
        rendered = sections_of(document)

        assert LM_CONTROL in rendered[SECTION_PASSES]
        assert LM_CONTROL in rendered[SECTION_CONFLICTS]
        assert "CONFLICT" in pass_row_of(document, LM_CONTROL)


# --------------------------------------------------------------------------- #
# 7. os-default framing — acceptance criterion 6
# --------------------------------------------------------------------------- #

class TestOsDefaultFraming:

    @pytest.fixture
    def card(self, mixed_scan):
        return card_of(render_report(mixed_scan), SECTION_OPPORTUNITIES,
                       CLIENT_SIGNING_CONTROL)

    def test_lands_in_opportunities_not_in_passes(self, mixed_scan):
        rendered = sections_of(render_report(mixed_scan))
        assert CLIENT_SIGNING_CONTROL in rendered[SECTION_OPPORTUNITIES]
        assert CLIENT_SIGNING_CONTROL not in rendered[SECTION_PASSES]

    def test_section_frames_it_as_an_opportunity(self, mixed_scan):
        section = sections_of(render_report(mixed_scan))[SECTION_OPPORTUNITIES]
        assert "At the Windows default" in section
        assert "Nothing in Group Policy holds it there" in section
        assert "assumed" in section

    def test_card_says_no_gpo_sets_the_key_and_nothing_holds_it(self, card):
        assert "No GPO sets this key" in card
        assert "Nothing in Group Policy holds it\nthere" in card or \
            "Nothing in Group Policy holds it there" in card.replace("\n", " ")
        assert "an assumed value" in card

    def test_never_claims_group_policy_enforces_the_value(self, card):
        """Every mention of enforcement in this card must be a denial of it."""
        for match in re.finditer(r"enforced by (?:Group Policy|a GPO)", card):
            preceding = card[max(0, match.start() - 5):match.start()]
            assert preceding.endswith("not "), preceding
        for match in re.finditer(r"Group Policy enforces", card):
            preceding = card[max(0, match.start() - 12):match.start()]
            assert "Nothing in " in preceding, preceding

    def test_rollout_state_is_never_enforced(self, card):
        assert "stage: audit" in card
        assert "stage: enforced" not in card
        assert "badge-state-enforced" not in card

    def test_cites_the_document_that_states_the_default(self, card):
        assert "Default documented by" in card
        assert "Default values table" in card

    def test_os_default_failure_stays_in_the_failures_section(self):
        """A documented default below the floor is a real finding, framed honestly."""
        raw = {
            "catalog_version": "test-1",
            "controls": [{
                "id": "TEST-LOW-DEFAULT",
                "title": "Synthetic control whose OS default is below the floor",
                "source": {"part": 3, "url": "https://example.invalid/doc"},
                "scope": "all",
                "check_type": "gpo-security-template",
                "severity": "high",
                "status": "active",
                "operator": "gte",
                "registry_key": r"HKLM\Software\Test\LowDefault",
                "final_expected": 2,
                "os_default": 0,
                "os_default_source": "Synthetic: states the default is 0.",
                "missing_result": "fail",
                "remediation": "Set the value to 2.",
                "caveats": ["Synthetic caveat."],
            }],
        }
        payload = scan_payload([], catalog=build_catalog(raw, "<test>"))
        document = render_report(payload)
        rendered = sections_of(document)

        assert "TEST-LOW-DEFAULT" in rendered[SECTION_FAIL]
        assert "TEST-LOW-DEFAULT" not in rendered[SECTION_PASSES]
        card = card_of(document, SECTION_FAIL, "TEST-LOW-DEFAULT")
        assert "No GPO sets this key" in card


# --------------------------------------------------------------------------- #
# 8. Unscored controls — acceptance criterion 6
# --------------------------------------------------------------------------- #

class TestNotJudged:

    @pytest.fixture
    def card(self, mixed_scan):
        return card_of(render_report(mixed_scan), SECTION_NOT_JUDGED,
                       UNSCORED_CONTROL)

    def test_lands_in_its_own_section_never_in_passes(self, mixed_scan):
        rendered = sections_of(render_report(mixed_scan))
        assert UNSCORED_CONTROL in rendered[SECTION_NOT_JUDGED]
        assert UNSCORED_CONTROL not in rendered[SECTION_PASSES]
        assert UNSCORED_CONTROL not in rendered[SECTION_NOT_APPLICABLE]

    def test_badge_says_not_judged_and_never_pass(self, card):
        assert ">NOT CHECKED &mdash; NOT A PASS<" in card
        assert ">Pass<" not in card
        assert "badge-result-pass" not in card

    def test_states_plainly_that_it_is_not_a_pass(self, card):
        assert "this is not a pass" in card
        assert "its state is <strong>unknown</strong>" in card
        assert "doesn&#x27;t guess" in card or "doesn't guess" in card

    def test_shows_the_baseline_gap_reason(self, card, catalog):
        """The catalog's baseline_gap, reaching the report via evidence.notes."""
        gap = catalog.by_id(UNSCORED_CONTROL).baseline_gap
        assert gap[:50] in card
        assert "needs_baseline_value" in card

    def test_section_lede_forbids_reading_them_as_passes(self, mixed_scan):
        section = sections_of(render_report(mixed_scan))[SECTION_NOT_JUDGED]
        assert "they were not checked" in section
        assert "are not passes." in section


# --------------------------------------------------------------------------- #
# 9. Passes, compact
# --------------------------------------------------------------------------- #

class TestPasses:

    def test_passes_are_compact_but_keep_their_evidence(self, all_pass_scan):
        document = render_report(all_pass_scan)
        section = sections_of(document)[SECTION_PASSES]
        assert section.count('<details class="pass-row">') >= 10

        row = pass_row_of(document, LM_CONTROL)
        # Visible without expanding: id, title, rollout state, found value.
        summary = row[:row.index("</summary>")]
        assert LM_CONTROL in summary
        assert "stage: enforced" in summary
        assert "found 5" in summary
        # Retained behind the disclosure: the full evidence.
        assert "Expected (baseline)" in row
        assert gpo_dn(GUID_A) in row

    def test_passes_come_last(self, all_pass_scan):
        order = list(sections_of(render_report(all_pass_scan)))
        assert order.index(SECTION_PASSES) > order.index(SECTION_FAIL)
        assert order.index(SECTION_PASSES) > order.index(SECTION_NOT_JUDGED)

    def test_all_pass_scan_has_no_failures(self, all_pass_scan):
        rendered = sections_of(render_report(all_pass_scan))
        assert ">None.<" in rendered[SECTION_FAIL]
        assert ">None.<" in rendered[SECTION_UNKNOWN]


# --------------------------------------------------------------------------- #
# 10. Provenance — acceptance criterion 4 / 7
# --------------------------------------------------------------------------- #

class TestProvenance:

    def test_header_states_engine_catalog_time_domain_and_gpo_counts(
            self, mixed_scan):
        document = render_report(mixed_scan)
        block = document[document.index('id="provenance"'):
                         document.index('<footer')]

        for label in ("Scan engine version", "Catalog version",
                      "Report format version", "Scan timestamp (UTC)",
                      "Domain", "Base DN", "GPOs scanned", "GPOs unreadable",
                      "Controls evaluated", "Controls scored"):
            assert label in block, label
        assert "1.1.0" in block
        assert mixed_scan["scan"]["catalog_version"] in block
        assert "2026-08-19T09:30:00+00:00" in block
        assert "test.local" in block
        assert BASE_DN in block

    def test_standing_precedence_disclaimer_is_in_the_document(self, mixed_scan):
        document = render_report(mixed_scan)
        provenance = document[document.index('id="provenance"'):]
        assert "doesn't work out which GPO wins" in provenance.replace(
            "&#x27;", "'")
        assert "gpresult" in document

    def test_each_tile_counts_what_its_group_lists(self, mixed_scan,
                                                   all_pass_scan):
        """A tile that disagreed with its section is how "12 passes" sat over
        a list of 11: an os-default pass is listed under "At the Windows
        default", not under Passes. Every tile, and every per-section number
        under it, counts what the document lists."""
        for payload in (mixed_scan, all_pass_scan):
            document = render_report(payload)
            summary = document[document.index('id="summary"'):
                               document.index('id="start-here"')]
            grouped = group_findings(payload["findings"])
            for group_id, _h, _i, sections in GROUPS:
                distinct = {id(f) for s in sections for f in grouped[s]}
                tile = re.search(rf'href="#group-{group_id}"><span '
                                 rf'class="tile-n">(\d+)<', summary)
                assert tile, group_id
                assert int(tile.group(1)) == len(distinct), group_id
                cell = summary[tile.start():summary.index("</li>", tile.start())]
                for section_id in sections:
                    assert f">{len(grouped[section_id])} " in cell.replace(
                        "&middot; ", ">"), section_id

    def test_unknown_control_ids_are_reported_not_dropped(self, catalog):
        payload = scan_payload([], catalog=catalog,
                               unknown_control_ids=["NOT-A-CONTROL"])
        document = render_report(payload)
        assert "matched nothing in the" in document
        assert "NOT-A-CONTROL" in document

    def test_title_names_the_domain_and_the_timestamp(self, mixed_scan):
        document = render_report(mixed_scan)
        title = document[document.index("<title>"):document.index("</title>")]
        assert "test.local" in title
        assert "2026-08-19T09:30:00+00:00" in title


# --------------------------------------------------------------------------- #
# 11. Writing the file — the only side effect
# --------------------------------------------------------------------------- #

class TestWriteReport:

    def test_writes_a_self_contained_file(self, tmp_path, mixed_scan):
        target = tmp_path / "report.html"
        path, size = write_report(mixed_scan, str(target))

        assert path == target
        assert size == target.stat().st_size
        text = target.read_text(encoding="utf-8")
        assert text.startswith("<!DOCTYPE html>")
        assert REPORT_MARKER in text
        assert "About this scan" in text


# --------------------------------------------------------------------------- #
# 12. Headline counts — copied from the scan, never recomputed
# --------------------------------------------------------------------------- #

class TestHeadlineCounts:

    def test_counts_come_straight_from_the_scan(self, mixed_scan):
        headline = headline_counts(mixed_scan)
        counts = mixed_scan["counts"]

        for key in ("fail", "error", "conflicts", "os_default",
                    "os_default_pass", "needs_baseline_value", "pass",
                    "scored", "total", "rendered", "hidden"):
            assert headline[key] == counts[key], key
        assert headline["gpos_scanned"] == 2
        assert headline["gpos_unreadable"] == 0

    def test_missing_counts_become_zero_rather_than_raising(self):
        assert headline_counts({}) == {
            key: 0 for key in headline_counts({})}


# --------------------------------------------------------------------------- #
# Sample generator
# --------------------------------------------------------------------------- #
#
# `examples/hardening-report-sample.html` is committed so the report's design can
# be reviewed without running anything. It is regenerated from *these* synthetic
# fixtures and never from a real scan:
#
#     python tests/test_hardening_report.py examples/hardening-report-sample.html
#
# That constraint is not cosmetic. A rendered report embeds the domain's GPO
# display names, registry values and DNs, so a sample taken from a live scan
# would commit exactly the environmental detail this repo keeps out of git.

def sample_scan(first_gpo=HOSTILE_NAME):
    """The richest synthetic scan: a read failure, a conflict, and passes.

    The escaping tests use the hostile GPO name; the published sample passes a
    plain one, since people read it as a showcase.
    """
    catalog = load_catalog()
    read_errors = [{
        "gpo_dn": gpo_dn(GUID_C),
        "display_name": "Unreadable Sample GPO",
        "error": "SMB read failed: STATUS_ACCESS_DENIED",
    }]
    return scan_payload([
        snapshot(GUID_A, first_gpo, entries=[template_entry(LM_KEY, 1)],
                 links=[GpoLink(target_dn=BASE_DN)]),
        snapshot(GUID_B, "Sample Override GPO",
                 entries=[
                     template_entry(LM_KEY, 5),
                     template_entry(r"MACHINE\System\CurrentControlSet\Services"
                                    r"\NTDS\Parameters\LDAPServerIntegrity", 2),
                 ],
                 links=[GpoLink(target_dn=f"OU=Domain Controllers,{BASE_DN}",
                                enforced=True)]),
        snapshot(GUID_C, "Unreadable Sample GPO",
                 links=[GpoLink(target_dn=BASE_DN)],
                 read_error="SMB read failed: STATUS_ACCESS_DENIED"),
    ], catalog=catalog, read_errors=read_errors, directory={
        # One directory-state failure and two passes, so the sample shows
        # what a directory finding looks like.
        "DEVORE-07-UNCONSTRAINED-DELEGATION": {"objects": [{
            "value": "APPSRV01$", "dn": f"CN=APPSRV01,CN=Computers,{BASE_DN}",
            "object_class": "computer",
            "detail": "computer trusted for delegation to any service"}],
            "notes": [], "error": None},
        "DEVORE-04-SPN-ACCOUNTS-AES": {"objects": [], "notes": [],
                                       "error": None},
        "DEVORE-07-EMPTY-PRIVILEGED-GROUPS": {"objects": [], "notes": [],
                                              "error": None},
    })


if __name__ == "__main__":  # pragma: no cover - a maintenance utility
    import sys

    destination = sys.argv[1] if len(sys.argv) > 1 else \
        "examples/hardening-report-sample.html"
    written, size = write_report(sample_scan("Sample Workstation Baseline GPO"),
                                 destination)
    print(f"wrote {size} bytes of synthetic sample report to {written}")


class TestStableAnchorsAndScanId:
    """Two guarantees the diffing work depends on.

    A card's anchor must not move when its verdict moves, and a scan must be
    nameable, not just timestamped.
    """

    def test_a_card_anchor_does_not_move_when_the_verdict_changes(self, catalog):
        """The anchor is the whole point: a link from a ticket must survive.

        Previously anchors were ``{section}-{control_id}``, so the anchor changed
        exactly when the finding changed — breaking the link at the moment someone
        would follow it.
        """
        control_id = "DEVORE-06-LLMNR-DISABLE"
        compliant = scan_payload([
            snapshot("11111111-1111-1111-1111-111111111111", "LLMNR off",
                     entries=[template_entry(
                         r"MACHINE\Software\Policies\Microsoft\Windows NT"
                         r"\DNSClient\EnableMulticast", 0)])],
            catalog=catalog)
        breached = scan_payload([
            snapshot("11111111-1111-1111-1111-111111111111", "LLMNR on",
                     entries=[template_entry(
                         r"MACHINE\Software\Policies\Microsoft\Windows NT"
                         r"\DNSClient\EnableMulticast", 1)])],
            catalog=catalog)

        passing = render_report(compliant)
        failing = render_report(breached)

        anchor = f'id="{control_id.lower()}"'
        assert anchor in passing.lower()
        assert anchor in failing.lower()
        # and the anchor is not section-qualified in either direction
        for document in (passing, failing):
            assert f'id="passes-{control_id.lower()}"' not in document.lower()
            assert f'id="failures-{control_id.lower()}"' not in document.lower()

    def test_the_section_survives_as_the_card_class(self, mixed_scan):
        """Dropping the section from the id must not lose the section."""
        document = render_report(mixed_scan)
        assert 'class="card card-failures"' in document

    def test_the_scan_id_is_rendered_in_provenance(self, mixed_scan):
        """A saved report must be able to name which scan produced it."""
        document = render_report(mixed_scan)
        assert "Scan id" in document
        assert mixed_scan["scan"]["scan_id"] in document


class TestDeliveryIsRendered:
    """A pass held by a preference must not look like a policy-enforced pass.

    The scan already records how each value was delivered; the report's job is
    to put that in front of the reader. A "Delivered by" cell, the item's
    action, and the tattoo/drift/targeting caveats all come straight from the
    payload — the renderer derives nothing.
    """

    def preference_payload(self, **entry_kwargs):
        return scan_payload(
            [snapshot(GUID_A, "Enc Types By Preference",
                      preference_entries=[preference_entry(**entry_kwargs)],
                      links=[GpoLink(target_dn=BASE_DN)])],
            control_ids=[KDC_CONTROL])

    def test_the_found_table_names_the_delivery_mechanism(self):
        document = render_report(self.preference_payload())

        row = pass_row_of(document, KDC_CONTROL)
        assert "Delivered by" in row
        assert "Group Policy preference" in row

    def test_the_preference_action_is_shown(self):
        row = pass_row_of(render_report(self.preference_payload(action="R")),
                          KDC_CONTROL)

        assert "R (Replace)" in row

    def test_the_tattoo_caveat_is_visible_to_a_reader(self):
        row = pass_row_of(render_report(self.preference_payload()), KDC_CONTROL)

        assert "tattoos" in visible_text(row)
        assert "if this GPO is unlinked" in visible_text(row)

    def test_a_create_action_says_drift_is_not_corrected(self):
        row = pass_row_of(render_report(self.preference_payload(action="C")),
                          KDC_CONTROL)

        assert "drift is not corrected" in visible_text(row)

    def test_an_update_action_makes_no_drift_claim(self):
        row = pass_row_of(render_report(self.preference_payload(action="U")),
                          KDC_CONTROL)

        assert "drift is not corrected" not in visible_text(row)

    def test_item_level_targeting_is_disclosed(self):
        row = pass_row_of(
            render_report(self.preference_payload(has_filters=True)),
            KDC_CONTROL)

        assert "item-level targeting" in visible_text(row)
        assert "Not evaluated" in visible_text(row)

    def test_an_unfiltered_item_makes_no_targeting_claim(self):
        row = pass_row_of(render_report(self.preference_payload()), KDC_CONTROL)

        assert "item-level targeting" not in visible_text(row)

    def test_a_preference_pass_is_badged_on_the_compact_row(self):
        """The skim-level signal: this pass is held by a preference."""
        row = pass_row_of(render_report(self.preference_payload()), KDC_CONTROL)

        assert "BY PREFERENCE" in row

    def test_a_policy_pass_is_not_badged_and_shows_no_preference_caveats(self):
        payload = scan_payload(
            [snapshot(GUID_A, "Enc Types By Policy",
                      pol_entries=[kdc_pol_entry()],
                      links=[GpoLink(target_dn=BASE_DN)])],
            control_ids=[KDC_CONTROL])

        row = pass_row_of(render_report(payload), KDC_CONTROL)

        assert "BY PREFERENCE" not in row
        assert "administrative template (policy)" in row
        assert "tattoos" not in visible_text(row)

    def test_a_security_template_pass_names_its_delivery(self):
        payload = scan_payload(
            [snapshot(GUID_A, "LM Policy", entries=[template_entry(LM_KEY, 5)],
                      links=[GpoLink(target_dn=BASE_DN)])],
            control_ids=[LM_CONTROL])

        row = pass_row_of(render_report(payload), LM_CONTROL)

        assert "security template (policy)" in row

    def test_a_failing_preference_value_still_shows_its_delivery(self):
        payload = scan_payload(
            [snapshot(GUID_A, "Enc Types By Preference",
                      preference_entries=[preference_entry(value=38)],
                      links=[GpoLink(target_dn=BASE_DN)])],
            control_ids=[KDC_CONTROL])

        card = card_of(render_report(payload), SECTION_FAIL, KDC_CONTROL)

        assert "Group Policy preference" in card
        assert "tattoos" in visible_text(card)

    def test_a_deleting_preference_appears_in_the_scan_notes(self):
        payload = scan_payload(
            [snapshot(GUID_A, "Undo Enc Types",
                      preference_entries=[preference_entry(action="D")],
                      links=[GpoLink(target_dn=BASE_DN)])],
            control_ids=[KDC_CONTROL])

        card = card_of(render_report(payload), SECTION_FAIL, KDC_CONTROL)

        assert "DELETE this value" in visible_text(card)
        assert "Undo Enc Types" in card


class TestWideEvidenceTablesScrollThemselves:
    """The Delivered by column widened the evidence tables.

    A table that overflows the page pushes the whole document into horizontal
    scroll and makes every other section harder to read, so the found and
    conflict tables get their own scroll container. Still no script and still one
    file.
    """

    @pytest.fixture
    def document(self):
        payload = scan_payload([
            snapshot(GUID_A, "Enc Types By Preference",
                     preference_entries=[preference_entry(has_filters=True)],
                     links=[GpoLink(target_dn=BASE_DN)]),
            snapshot(GUID_B, "Enc Types By Policy",
                     pol_entries=[kdc_pol_entry(38)],
                     links=[GpoLink(target_dn=BASE_DN)]),
        ], control_ids=[KDC_CONTROL])
        return render_report(payload)

    def test_every_evidence_table_sits_in_a_scroll_container(self, document):
        tables = re.findall(r'(.{24})<table class="grid', document)

        assert tables, "the document should contain evidence tables"
        assert all(chunk == '<div class="table-wrap">' for chunk in tables), \
            tables

    def test_the_scroll_container_is_css_only(self, document):
        assert ".table-wrap{overflow-x:auto}" in document
        assert "<script" not in document.lower()

    def test_the_read_failure_table_scrolls_too(self, unreadable_scan):
        document = render_report(unreadable_scan)
        tables = re.findall(r'(.{24})<table class="grid', document)

        assert tables, "the banner should contain a read-failure table"
        assert all(chunk == '<div class="table-wrap">' for chunk in tables), \
            tables


class TestKeyValueTablesNeverScrollThePage:
    """The identity, expected and provenance tables are wide too.

    Their right-hand cells carry registry keys, DNs and bare citation URLs --
    unbroken runs of 200 characters -- which set a min-content width far past a
    phone-sized column and put the whole document into horizontal scroll. Long
    values break, and the table scrolls in its own box if it still has to. This
    is the pre-existing .kv shape, not anything the delivery column introduced.
    """

    @pytest.fixture
    def document(self, mixed_scan):
        return render_report(mixed_scan)

    def test_every_key_value_table_sits_in_a_scroll_container(self, document):
        tables = re.findall(r'(.{24})<table class="kv"', document)

        assert tables, "the document should contain key/value tables"
        assert all(chunk == '<div class="table-wrap">' for chunk in tables), \
            tables

    def test_the_provenance_header_is_one_of_them(self, document):
        provenance = document[document.index('id="provenance"'):]

        assert provenance.index('<div class="table-wrap">') < \
            provenance.index('<table class="kv">')

    def test_long_values_break_instead_of_widening_the_table(self, document):
        # overflow-wrap:anywhere, not break-word: only "anywhere" lets a long
        # token shrink the cell's min-content width, which is what forces the
        # page wide in the first place.
        assert "overflow-wrap:anywhere}" in document
        assert re.search(r"\.kv td\{[^}]*overflow-wrap:anywhere", document), \
            "the wrapping rule has to be on the .kv value cell"

    def test_the_offending_value_is_a_real_shape_not_a_hypothetical(self,
                                                                    document):
        # The widest .kv value in a real report is the catalog's value_source,
        # rendered as plain text rather than inside <code>, so the code
        # word-break rule never reaches it. If this run stops producing an
        # unbroken run this long, the rules above are no longer load-bearing
        # and someone should find out why before deleting them.
        cells = [cell for table in
                 re.findall(r'<table class="kv">.*?</table>', document, re.S)
                 for cell in re.findall(r"<td>(.*?)</td>", table, re.S)]
        runs = [max((len(word) for word in visible_text(cell).split()),
                    default=0) for cell in cells]

        assert max(runs, default=0) > 120, max(runs, default=0)

    def test_still_one_file_with_no_script(self, document):
        assert "<script" not in document.lower()
        assert "<link" not in document.lower()


class TestPolicyVersusPreferenceConflictIsRendered:
    """The conflict a reader must not try to settle with link precedence."""

    @pytest.fixture
    def document(self):
        payload = scan_payload([
            snapshot(GUID_A, "Enc Types By Policy",
                     pol_entries=[kdc_pol_entry(56)],
                     links=[GpoLink(target_dn=BASE_DN)]),
            snapshot(GUID_B, "Enc Types By Preference",
                     preference_entries=[preference_entry(value=38)],
                     links=[GpoLink(target_dn=BASE_DN)]),
        ], control_ids=[KDC_CONTROL])
        return render_report(payload)

    def test_the_conflict_section_carries_the_finding(self, document):
        section = sections_of(document)[SECTION_CONFLICTS]

        assert KDC_CONTROL in section
        assert "policy-preference-disagreement" in section

    def test_each_side_of_the_conflict_names_its_delivery(self, document):
        section = sections_of(document)[SECTION_CONFLICTS]

        assert "administrative template (policy)" in section
        assert "Group Policy preference" in section

    def test_the_reader_is_told_link_precedence_does_not_settle_it(self,
                                                                  document):
        text = visible_text(sections_of(document)[SECTION_CONFLICTS])

        assert "client-side extensions" in text
        assert "not on link precedence" in text

    def test_the_finding_also_lands_in_the_failures_section(self, document):
        card = card_of(document, SECTION_FAIL, KDC_CONTROL)

        assert "38" in card
        assert "56" in card


# --------------------------------------------------------------------------- #
# P2-WP5 — an `unknown` result that is neither a read failure nor an error
# --------------------------------------------------------------------------- #

DIAG_CONTROL = "DEVORE-03-LDAP-DIAG-LOGGING"
DIAG_REG_QUERY = ('reg query &quot;HKLM\\SYSTEM\\CurrentControlSet\\Services'
                  '\\NTDS\\Diagnostics&quot; /v &quot;16 LDAP Interface '
                  'Events&quot;')


class TestUnknownVerdictThatIsNotAReadFailure:
    """Acceptance 7: the new ``unknown`` result renders correctly.

    Every GPO was read successfully, nothing errored, and the control still has
    no verdict — because its documented remediation writes the registry directly
    on the domain controllers and leaves no GPO trace. The report has to make
    that legible without the reader mistaking the row for a pass.
    """

    @pytest.fixture
    def payload(self, catalog):
        return scan_payload(
            [snapshot(GUID_A, "Some Unrelated Policy",
                      links=[GpoLink(target_dn=BASE_DN)])],
            catalog=catalog, control_ids=[DIAG_CONTROL])

    @pytest.fixture
    def document(self, payload):
        return render_report(payload)

    def test_it_lands_in_the_unknown_section(self, document):
        rendered = sections_of(document)

        assert DIAG_CONTROL in rendered[SECTION_UNKNOWN]

    def test_it_is_in_no_other_section(self, document):
        rendered = sections_of(document)

        for section_id in (SECTION_PASSES, SECTION_FAIL, SECTION_OPPORTUNITIES,
                           SECTION_NOT_JUDGED, SECTION_NOT_APPLICABLE,
                           SECTION_CONFLICTS):
            assert DIAG_CONTROL not in rendered[section_id], section_id

    def test_the_card_cannot_be_mistaken_for_a_pass(self, document):
        card = card_of(document, SECTION_UNKNOWN, DIAG_CONTROL)
        text = visible_text(card)

        assert "badge-result-unknown" in card
        assert "Unknown" in text
        assert "this is not a pass" in text
        assert "can't confirm it either way" in text
        assert "Pass" not in text

    def test_the_card_carries_the_reg_query_command_in_the_open(self, document):
        """Not folded into the collapsed notes: the command is the deliverable."""
        card = card_of(document, SECTION_UNKNOWN, DIAG_CONTROL)
        reason = card[card.index("Why this is unknown"):]

        assert DIAG_REG_QUERY in reason
        assert "Scan notes" not in card, \
            "the notes are rendered open here, so the collapsed copy is dropped"

    def test_the_card_says_why_group_policy_cannot_answer_it(self, document):
        text = visible_text(card_of(document, SECTION_UNKNOWN, DIAG_CONTROL))

        assert "direct registry write on the domain controllers" in text
        assert "no trace in Group Policy" in text

    def test_the_card_still_carries_remediation_and_rollout_guidance(
            self, document):
        card = card_of(document, SECTION_UNKNOWN, DIAG_CONTROL)

        assert "Remediation" in card
        assert "How to roll it out safely" in card
        assert "NOT SET THROUGH GROUP POLICY" in card  # the catalog's own caveat

    def test_it_is_not_reported_as_a_read_failure(self, document):
        """The distinction acceptance 7 asks for: nothing failed to read."""
        assert "GPOs were read." in document
        assert '<section class="alert"' not in document

    def test_the_section_lede_explains_both_kinds_of_unknown(self, document):
        lede = visible_text(sections_of(document)[SECTION_UNKNOWN])

        assert "A GPO couldn't be read" in lede
        assert "Group Policy can't show it" in lede
        assert "unconfirmed, not as passes" in lede

    def test_the_headline_tile_counts_it_as_unknown(self, document):
        summary = document[document.index('id="summary"'):
                           document.index('<nav class="toc"')]
        text = visible_text(summary)

        flat = re.sub(r"\s+", " ", html.unescape(text))
        assert "1 Check by hand 1 unknown" in flat, flat
        assert "0 Good 0 passes" in flat, flat

    def test_the_tile_breakdown_separates_unread_from_unseeable(self, document):
        text = re.sub(r"\s+", " ", visible_text(document))

        assert ("Of the 1 unknown, 0 couldn't be read and 1 can't be seen in "
                "Group Policy at all") in html.unescape(text)

    def test_the_table_of_contents_counts_it(self, document):
        toc = document[document.index('<nav class="toc"'):
                       document.index("</nav>")]
        entry = toc[toc.index('href="#unknown"'):]

        assert "(1)" in entry[:80]

    def test_the_headline_counts_expose_it_separately_from_error(self, payload):
        headline = headline_counts(payload)

        assert headline["unknown"] == 1
        assert headline["error"] == 0
        assert headline["pass"] == 0
        assert headline["fail"] == 0

    def test_grouping_puts_unknown_and_error_in_one_section(self, catalog):
        """Both mean "no verdict", so a reader has one place to look."""
        payload = scan_payload(
            [snapshot(GUID_A, "Some Unrelated Policy",
                      links=[GpoLink(target_dn=BASE_DN)]),
             snapshot(GUID_C, "Unreadable Policy",
                      read_error="STATUS_ACCESS_DENIED")],
            catalog=catalog,
            control_ids=[DIAG_CONTROL, CLIENT_SIGNING_CONTROL])
        grouped = group_findings(payload["findings"])
        ids = {f["control_id"]: f["result"]
               for f in grouped[SECTION_UNKNOWN]}

        assert ids == {DIAG_CONTROL: "unknown",
                       CLIENT_SIGNING_CONTROL: "error"}

    def test_a_gpo_delivered_value_on_the_same_control_renders_as_a_pass(
            self, catalog):
        """The field changes only the absent case, in the report too."""
        payload = scan_payload(
            [snapshot(GUID_A, "NTDS Diagnostics",
                      pol_entries=[{
                          "key": r"SYSTEM\CurrentControlSet\Services\NTDS"
                                 r"\Diagnostics",
                          "value": "16 LDAP Interface Events",
                          "type": "REG_DWORD", "data": 3}],
                      links=[GpoLink(target_dn=BASE_DN)])],
            catalog=catalog, control_ids=[DIAG_CONTROL])
        document = render_report(payload)

        assert DIAG_CONTROL in sections_of(document)[SECTION_PASSES]
        assert DIAG_CONTROL not in sections_of(document)[SECTION_UNKNOWN]


class TestByPreferenceBadgeIsOnlyForPreferenceOnlyPasses:
    """Fix 2: the badge said "only" in the docs and "any" in the code.

    The badge exists because a preference tattoos and may not correct drift, so
    a pass that *depends* on one is a weaker statement about ongoing state. Where
    a policy also delivers a compliant value the pass does not depend on the
    preference — the evaluator treats that as two mechanisms agreeing — and
    labelling it weaker misleads the reader in the one place they skim.

    The mixed-delivery case was the one nothing pinned.
    """

    POL_KEY = r"System\CurrentControlSet\services\KDC"

    def payload(self, *gpos):
        return scan_payload(list(gpos), control_ids=[KDC_CONTROL])

    def preference_gpo(self, guid=GUID_A, name="Enc Types By Preference"):
        return snapshot(guid, name, preference_entries=[preference_entry(56)],
                        links=[GpoLink(target_dn=BASE_DN)])

    def policy_gpo(self, guid=GUID_B, name="Enc Types By Policy"):
        return snapshot(guid, name, pol_entries=[kdc_pol_entry(56)],
                       links=[GpoLink(target_dn=BASE_DN)])

    def test_a_preference_only_pass_is_badged(self):
        row = pass_row_of(render_report(self.payload(self.preference_gpo())),
                          KDC_CONTROL)

        assert "BY PREFERENCE" in row

    def test_a_mixed_policy_and_preference_pass_is_not_badged(self):
        """Two mechanisms agreeing: the pass is not preference-dependent."""
        document = render_report(
            self.payload(self.policy_gpo(), self.preference_gpo()))
        row = pass_row_of(document, KDC_CONTROL)

        assert "BY PREFERENCE" not in row

    def test_the_mixed_pass_is_still_a_pass_with_both_values_in_evidence(self):
        """Guards against "fixed" by suppressing the finding instead."""
        document = render_report(
            self.payload(self.policy_gpo(), self.preference_gpo()))
        row = pass_row_of(document, KDC_CONTROL)

        assert "Group Policy preference" in row
        assert "administrative template (policy)" in row
        assert "tattoos" in visible_text(row), \
            "the tattoo caveat still belongs in the expanded evidence"

    def test_two_preferences_agreeing_are_still_badged(self):
        """Every found value is a preference, so the pass does depend on them."""
        row = pass_row_of(render_report(self.payload(
            self.preference_gpo(),
            self.preference_gpo(guid=GUID_B, name="Second Preference"))),
            KDC_CONTROL)

        assert "BY PREFERENCE" in row

    def test_a_policy_only_pass_is_not_badged(self):
        row = pass_row_of(render_report(self.payload(self.policy_gpo())),
                          KDC_CONTROL)

        assert "BY PREFERENCE" not in row

    def test_a_pass_with_no_found_value_is_not_badged(self):
        """An os-default pass has no found values; ``all([])`` must not badge it."""
        payload = scan_payload(
            [snapshot(GUID_A, "Unrelated Policy",
                      links=[GpoLink(target_dn=BASE_DN)])],
            control_ids=[CLIENT_SIGNING_CONTROL])
        document = render_report(payload)

        assert "BY PREFERENCE" not in document

    def test_the_helper_is_unit_pinned_in_both_directions(self):
        """The predicate itself, away from the rendering."""
        preference = {"delivery": "registry-preference"}
        policy = {"delivery": "registry-pol"}

        assert _delivered_by_preference([preference]) is True
        assert _delivered_by_preference([preference, preference]) is True
        assert _delivered_by_preference([preference, policy]) is False
        assert _delivered_by_preference([policy, preference]) is False
        assert _delivered_by_preference([policy]) is False
        assert _delivered_by_preference([]) is False
        assert _delivered_by_preference(None) is False
        assert _delivered_by_preference(["not a dict"]) is False


class TestKeyScopedDeleteIsVisibleInTheReport:
    """Fix 3 through the renderer: the disclosure has to reach the reader.

    The finding is a pass — this scan does not resolve precedence — so the row is
    a compact pass row, which is exactly where a "another GPO deletes the key
    under this value" note would be easiest to lose.
    """

    KDC_PREF_KEY = r"SYSTEM\CurrentControlSet\Services\Kdc"

    def key_delete_entry(self, key=None):
        """A parsed key-scoped delete: no value name, `deletes_key` set."""
        return {"hive": "HKEY_LOCAL_MACHINE", "key": key or self.KDC_PREF_KEY,
                "value_name": None, "type": None, "type_name": None,
                "value": None, "action": "D", "order": 1,
                "has_filters": False, "disabled": False, "deletes_key": True}

    @pytest.fixture
    def document(self):
        payload = scan_payload([
            snapshot(GUID_A, "Enc Types By Preference",
                     preference_entries=[preference_entry(56)],
                     links=[GpoLink(target_dn=BASE_DN)]),
            snapshot(GUID_B, "Undo Enc Types",
                     preference_entries=[self.key_delete_entry()],
                     links=[GpoLink(target_dn=BASE_DN)]),
        ], control_ids=[KDC_CONTROL])
        return render_report(payload)

    def test_the_pass_row_discloses_the_key_delete(self, document):
        text = visible_text(pass_row_of(document, KDC_CONTROL))

        assert "DELETE a registry KEY" in text
        assert "Undo Enc Types" in text

    def test_the_reader_is_told_what_decides_the_outcome(self, document):
        text = visible_text(pass_row_of(document, KDC_CONTROL))

        assert "another GPO is removing the key underneath the value" in text
        assert "client-side extensions run" in text
        assert "not on link precedence" in text

    def test_the_deleted_key_is_named(self, document):
        row = pass_row_of(document, KDC_CONTROL)

        assert "Kdc" in row


# --------------------------------------------------------------------------- #
# Start here, and the four reader groups
# --------------------------------------------------------------------------- #

RISK_BADGES = ("logging-only", "low", "pilot", "can-lock-out")


def start_here_of(document):
    return document[document.index('id="start-here"'):
                    document.index('<nav class="toc"')]


class TestStartHere:

    def test_it_sits_between_the_results_and_the_contents(self, mixed_scan):
        document = render_report(mixed_scan)
        assert (document.index('id="summary"') < document.index('id="start-here"')
                < document.index('<nav class="toc"'))

    def test_the_read_failure_banner_still_comes_first(self, unreadable_scan):
        document = render_report(unreadable_scan)
        assert document.index('id="read-failures"') < document.index(
            'id="start-here"')
        assert "This scan is incomplete" in start_here_of(document)

    def test_it_lists_the_safest_changes_first(self, mixed_scan):
        """Logging-only and low-risk changes can go in straight away and give
        the risky ones their evidence, so they lead; severity breaks ties."""
        box = start_here_of(render_report(mixed_scan))
        ranks = [list(RISK_BADGES).index(risk)
                 for risk in re.findall(r'badge-risk-([a-z-]+)', box)]
        assert ranks and ranks == sorted(ranks)
        assert "Safest first" in box

    def test_a_risky_failure_gives_its_step_one(self, catalog):
        payload = scan_payload([
            snapshot(GUID_A, "Baseline", entries=[template_entry(LM_KEY, 1)],
                     links=[GpoLink(target_dn=BASE_DN)])],
            catalog=catalog, control_ids=[LM_CONTROL])
        box = start_here_of(render_report(payload))

        assert 'href="#devore-01-ntlm-lmcompatibilitylevel"' in box
        assert "Next: step 1: set it to 3" in box
        assert "Can lock people out" in box
        assert "audit mode" not in box
        assert "some of these need an audit step first" in box
        assert "skip step 1" in box

    def test_every_item_links_to_a_card_in_the_document(self, mixed_scan):
        document = render_report(mixed_scan)
        for anchor in re.findall(r'<li>.*?href="#([^"]+)"',
                                 start_here_of(document)):
            assert f'id="{anchor}"' in document, anchor

    def test_it_lists_at_most_the_limit_and_says_how_many_more(self, catalog):
        """Every scored control failing: far more than the box should list."""
        entries, pol_entries = [], []
        for control in catalog.controls:
            if not control.scored or not control.registry_key:
                continue
            if control.check_type == "gpo-security-template":
                entries.append(template_entry(control.registry_key, 0,
                                              control.registry_type
                                              or "REG_DWORD"))
            else:
                pol_entries.append({"key": control.registry_key_path,
                                    "value": control.registry_value_name,
                                    "type": 4, "data": 0})
        payload = scan_payload([
            snapshot(GUID_A, "Everything Wrong", entries=entries,
                     pol_entries=pol_entries,
                     links=[GpoLink(target_dn=BASE_DN)]),
        ], catalog=catalog)
        box = start_here_of(render_report(payload))
        listed = box.count("<li>")
        assert listed == START_HERE_LIMIT
        assert "more below." in box

    def test_an_all_pass_scan_has_nothing_to_do(self, all_pass_scan):
        box = start_here_of(render_report(all_pass_scan))
        assert "Nothing to fix or check." in box
        assert "<li>" not in box


class TestGroups:

    def test_the_groups_cover_every_section_once_in_document_order(self):
        in_groups = [s for _g, _h, _i, sections in GROUPS for s in sections]
        assert in_groups == [section_id for section_id, _t, _l in SECTIONS]

    def test_each_group_wraps_its_own_sections(self, mixed_scan):
        document = render_report(mixed_scan)
        positions = {section_id: document.index(f'id="{section_id}"')
                     for section_id, _t, _l in SECTIONS}
        starts = [document.index(f'id="group-{g}"') for g, _h, _i, _s in GROUPS]
        for index, (_g, _h, _i, sections) in enumerate(GROUPS):
            end = starts[index + 1] if index + 1 < len(starts) else len(document)
            for section_id in sections:
                assert starts[index] < positions[section_id] < end, section_id

    def test_a_conflict_is_counted_once_in_its_group(self, mixed_scan):
        """It is listed under Failures and under Conflicts; the Fix and Check
        tiles each count it, but neither counts it twice."""
        summary = render_report(mixed_scan)
        summary = summary[summary.index('id="summary"'):
                          summary.index('id="start-here"')]
        grouped = group_findings(mixed_scan["findings"])
        check = {id(f) for s in (SECTION_UNKNOWN, SECTION_CONFLICTS)
                 for f in grouped[s]}
        tile = re.search(r'href="#group-check"><span class="tile-n">(\d+)<',
                         summary)
        assert int(tile.group(1)) == len(check)


class TestLessToReadUpFront:
    """Spencer's "information overload": say each thing once, fold what
    nobody acts on, and keep safety text open."""

    @pytest.fixture
    def document(self):
        return render_report(sample_scan("Sample Workstation Baseline GPO"))

    def test_each_card_leads_with_why_it_matters(self, document, catalog):
        why = catalog.by_id(LM_CONTROL).why_it_matters
        card = document[document.index('id="devore-01-ntlm-lmcompatibilitylevel"'):]
        card = card[:card.index("</article>")]
        assert html.escape(why, quote=True) in card
        assert card.index(html.escape(why, quote=True)) < card.index('class="glance"')

    def test_a_note_on_several_cards_is_said_once_under_how_aditor_decides(
            self, document):
        note = "A pass means nothing the bind account can read matched."
        method = document[document.index('id="method"'):]
        assert document.count(note) == 1
        assert note in method

    def test_labelled_warnings_stay_open_and_the_rest_fold(self, document):
        card = document[document.index('id="devore-01-ntlm-lmcompatibilitylevel"'):]
        card = card[:card.index("</article>")]
        folded = card[card.index("More notes"):] if "More notes" in card else ""
        assert "IN STAGES:" in card and "IN STAGES:" not in folded
        assert "TATTOOING:" in card and "TATTOOING:" not in folded

    def test_notes_on_how_a_value_is_judged_fold(self, document):
        card = document[document.index('id="devore-08-ntlm-audit-incoming"'):]
        card = card[:card.index("</article>")]
        folded = card[card.index("More notes"):]
        for label in ("MINIMUM, NOT EXACT LEVEL:", "INFERRED, NOT CITED:",
                      "WATCH OUT:"):
            assert label in folded

    def test_a_logging_only_change_says_it_is_safe(self, document):
        card = document[document.index('id="devore-08-ntlm-audit-incoming"'):]
        assert "only turns on logging" in card[:card.index("</article>")]

    def test_nothing_to_do_groups_fold_but_keep_their_counts(self, document):
        assert '<details class="group group-not-covered"' in document
        assert '<details class="group group-good"' in document
        assert '<div class="group group-fix"' in document
        tiles = document[document.index('id="summary"'):
                         document.index('id="start-here"')]
        assert "Not covered yet" in tiles

    def test_the_summary_shows_rollout_progress(self, document):
        assert re.search(r"Rollout:</strong> \d+ enforced &middot; \d+ at step 1 "
                         r"&middot; \d+ not started, of \d+", document)


class TestMicrosoftDeadlines:

    def card(self, timestamp):
        payload = sample_scan("Sample Workstation Baseline GPO")
        payload["scan"]["timestamp"] = timestamp
        document = render_report(payload)
        card = document[document.index('id="devore-01-ntlm-lmcompatibilitylevel"'):]
        return card[:card.index("</article>")]

    def test_a_coming_deadline_says_when(self):
        card = self.card("2026-09-30T12:00:00+00:00")
        assert "Microsoft changes this default: October 2026." in card
        assert "support.microsoft.com" in card

    def test_a_passed_deadline_says_it_already_happened(self):
        card = self.card("2026-11-02T12:00:00+00:00")
        assert "Microsoft already changed this default: October 2026." in card


class TestUnknownBecauseAGpoWasUnread:
    """A pass held back by an unreadable GPO must say so, not claim Group
    Policy can't show the setting."""

    @pytest.fixture
    def card(self):
        document = render_report(sample_scan("Sample Workstation Baseline GPO"))
        card = document[document.index('id="devore-03-ldap-server-signing"'):]
        return card[:card.index("</article>")]

    def test_it_names_the_real_reason_and_the_real_next_step(self, card):
        assert "couldn't be read and could set a weaker value" in card
        assert "Group Policy doesn't show this setting" not in card
        assert "Next:</strong> fix the read failure above" in card

    def test_an_enforced_setting_drops_the_warnings_about_getting_there(self,
                                                                         card):
        opened = card[:card.index("How to fix it")]
        assert "Before enforcing" not in opened
        assert "AUDIT FIRST" not in opened
        assert "catalog doesn't say what to check" not in card
