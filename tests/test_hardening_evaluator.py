"""Tests for the pure hardening evaluator.

Offline by construction: the evaluator is a pure function of GPO snapshots and
controls, so there is no LDAP, no SMB and no domain controller anywhere in this
file.

**Fixture hygiene.** Every fixture is synthesized, not captured. ``GptTmpl.inf``
content is hand-written text run through the real ``parse_ini`` +
``parse_security_template_registry_values``; ``Registry.pol`` blobs are built by
``build_preg`` from the WP3 test helpers. GPO GUIDs are obvious placeholders
(``11111111-...``), DNs follow the repo's ``DC=test,DC=local`` convention, and no
real SID, domain, DC hostname or file path appears.

The centrepiece is ``TestLiveVerifiedLdapCase``: the two ``[Registry Values]``
lines a real GPO was observed to contain must satisfy *both* LDAP controls. That
reproduces the live-verified case entirely offline.

Three further classes pin the accuracy fixes, each of which changes a verdict:
``TestOsDefault`` and ``TestLdapClientSigningOnTheShippedCatalog`` (an unset key
with a documented Windows default is judged against it, and labelled so it never
reads as GPO-enforced), ``TestSmbSigningOnTheShippedCatalog`` (the newly active
SMB controls, spelled the way real GPOs spell the service names), and
``TestNtlmAuditFloorOnTheShippedCatalog`` (auditing configured *off* must fail
rather than pass as "the policy is configured").

``TestUnreadableGposCannotProduceAnOsDefaultPass`` pins the review fix that
matters most: an empty match list means "no GPO *that we read* sets this key", so
a scan with any unreadable GPO must not conclude the Windows default is effective.
It reported ``pass`` / ``audit`` / ``source: os-default`` off a scan that read
nothing at all.
"""

import dataclasses

import pytest
from aditor.gpo.parsers import (
    parse_ini,
    parse_registry_pol,
    parse_registry_xml,
    parse_security_template_registry_values,
)
from aditor.hardening.catalog import build_catalog, load_catalog
from aditor.hardening.evaluator import (
    DELIVERIES,
    DELIVERY_REGISTRY_POL,
    DELIVERY_REGISTRY_PREFERENCE,
    DELIVERY_SECURITY_TEMPLATE,
    EVIDENCE_SOURCE_GPO,
    EVIDENCE_SOURCE_NOT_CONFIGURED,
    EVIDENCE_SOURCE_OS_DEFAULT,
    EVIDENCE_SOURCE_UNKNOWN,
    NON_WRITE_DELETE,
    NON_WRITE_KEY_DELETE,
    RESULT_ERROR,
    RESULT_FAIL,
    RESULT_NOT_APPLICABLE,
    RESULT_PASS,
    RESULT_UNKNOWN,
    RESULTS,
    STATE_AUDIT,
    STATE_ENFORCED,
    STATE_NOT_STARTED,
    UNSCORED_NEEDS_BASELINE_VALUE,
    GpoLink,
    GpoSnapshot,
    OperatorError,
    evaluate_control,
    evaluate_controls,
    find_matches,
    find_preference_key_deletes,
    find_preference_non_writes,
    satisfies,
)

from tests.test_gpo_parsers import build_preg, dword

GUID_SIGNING = "11111111-1111-1111-1111-111111111111"
GUID_CONFLICT = "22222222-2222-2222-2222-222222222222"
GUID_ENFORCED = "33333333-3333-3333-3333-333333333333"
BASE_DN = "DC=test,DC=local"
DC_OU = f"OU=Domain Controllers,{BASE_DN}"


def gpo_dn(guid):
    return f"CN={{{guid}}},CN=Policies,CN=System,{BASE_DN}"


# --- fixture builders ------------------------------------------------------

def gpttmpl(*registry_lines):
    """Hand-written GptTmpl.inf bytes, UTF-16LE with a BOM as SYSVOL stores it."""
    text = (
        "[Unicode]\n"
        "Unicode=yes\n"
        "[Registry Values]\n"
        + "".join(line + "\n" for line in registry_lines)
        + "[Version]\n"
        "signature=\"$CHICAGO$\"\n"
        "Revision=1\n"
    )
    return b"\xff\xfe" + text.encode("utf-16-le")


def template_gpo(guid, name, *registry_lines, links=None, read_error=None):
    """A GPO snapshot whose settings come from a synthesized GptTmpl.inf."""
    sections = parse_ini(gpttmpl(*registry_lines))
    return GpoSnapshot(
        dn=gpo_dn(guid),
        display_name=name,
        guid=guid,
        security_template_entries=parse_security_template_registry_values(
            sections.get("Registry Values")),
        links=links if links is not None else (GpoLink(DC_OU),),
        read_error=read_error,
    )


def pol_gpo(guid, name, *records, links=None):
    """A GPO snapshot whose settings come from a synthesized Registry.pol blob."""
    entries, _truncated = parse_registry_pol(build_preg(records))
    return GpoSnapshot(
        dn=gpo_dn(guid),
        display_name=name,
        guid=guid,
        registry_pol_entries=entries,
        links=links if links is not None else (GpoLink(BASE_DN),),
    )


def control(**overrides):
    """A single-control catalog, built through the real loader."""
    raw = {
        "id": "TEST-01",
        "title": "A test control",
        "source": {"part": 1, "url": "https://example.invalid/part-1"},
        "scope": "all",
        "check_type": "gpo-security-template",
        "severity": "high",
        "status": "active",
        "operator": "equals",
        "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Test\\Flag",
        "registry_type": "REG_DWORD",
        "final_expected": 2,
        "missing_result": "fail",
        "remediation": "Set the flag to 2 in a GPO linked to the DC OU.",
    }
    raw.update(overrides)
    raw = {k: v for k, v in raw.items() if v is not None or k in ("registry_key",)}
    return build_catalog({"catalog_version": "test-1",
                          "controls": [raw]}).controls[0]


def line(key, type_code, data):
    return f"MACHINE\\{key}={type_code},{data}"


TEST_FLAG_LINE = "MACHINE\\System\\CurrentControlSet\\Services\\Test\\Flag=4,{}"



def clean_directory(catalog):
    """Every directory query in ``catalog`` run, and none found anything."""
    return {c.id: {"objects": [], "notes": [], "error": None}
            for c in catalog.controls if c.check_type == "directory-state"}

class TestSatisfies:
    """The five catalog operators."""

    @pytest.mark.parametrize("found,expected,result", [
        (2, 2, True), (1, 2, False), ("2", 2, True), (2, "2", True),
        ("0x38", 56, True), ("Always", "always", True), ([1, 2], [1, 2], True),
    ])
    def test_equals(self, found, expected, result):
        assert satisfies("equals", found, expected) is result

    @pytest.mark.parametrize("found,expected,result", [
        (5, 3, True), (3, 3, True), (2, 3, False), ("5", 3, True),
    ])
    def test_gte(self, found, expected, result):
        assert satisfies("gte", found, expected) is result

    def test_gte_on_a_non_numeric_value_is_an_operator_error(self):
        with pytest.raises(OperatorError, match="not numeric"):
            satisfies("gte", "not-a-number", 3)

    @pytest.mark.parametrize("found,result", [(1, True), (2, True), (3, False)])
    def test_in(self, found, result):
        assert satisfies("in", found, [1, 2]) is result

    def test_in_accepts_a_scalar_expected_value(self):
        assert satisfies("in", 1, 1) is True

    @pytest.mark.parametrize("operator", ["present", "absent"])
    def test_presence_operators_are_decided_by_the_caller(self, operator):
        assert satisfies(operator, None, None) is True

    def test_unknown_operator_raises(self):
        with pytest.raises(OperatorError, match="unsupported operator"):
            satisfies("approximately", 1, 1)

    def test_missing_expected_value_raises(self):
        with pytest.raises(OperatorError, match="no expected value"):
            satisfies("equals", 1, None)


class TestFindMatches:
    """Key matching across the two namespaces and both check types."""

    def test_security_template_key_matches_the_catalog_spelling(self):
        gpo = template_gpo(GUID_SIGNING, "Test Policy", TEST_FLAG_LINE.format(2))

        matches = find_matches(control(), [gpo])

        assert len(matches) == 1
        assert matches[0]["value"] == 2
        assert matches[0]["gpo_dn"] == gpo_dn(GUID_SIGNING)
        assert matches[0]["source_file"] == "GptTmpl.inf [Registry Values]"

    def test_registry_pol_key_and_value_name_are_rejoined(self):
        gpo = pol_gpo(GUID_SIGNING, "Test Policy",
                      ("Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
                       "EnableMulticast", 4, dword(0)))

        matches = find_matches(
            control(check_type="gpo-registry-pol", final_expected=0,
                    registry_key="HKLM\\Software\\Policies\\Microsoft"
                                 "\\Windows NT\\DNSClient\\EnableMulticast"),
            [gpo])

        assert len(matches) == 1
        assert matches[0]["value"] == 0
        assert matches[0]["source_file"] == "Registry.pol"

    def test_a_registry_pol_setting_is_not_matched_by_a_template_control(self):
        """Check types are not interchangeable: the entry must be the right kind."""
        gpo = pol_gpo(GUID_SIGNING, "Test Policy",
                      ("System\\CurrentControlSet\\Services\\Test", "Flag", 4,
                       dword(2)))

        assert find_matches(control(), [gpo]) == []

    def test_unrelated_settings_are_not_matched(self):
        gpo = template_gpo(GUID_SIGNING, "Test Policy",
                           "MACHINE\\System\\CurrentControlSet\\Services\\Other"
                           "\\Flag=4,2")

        assert find_matches(control(), [gpo]) == []

    def test_a_control_with_no_registry_key_matches_nothing(self):
        """The needs_baseline_value case: no key is known, so nothing matches."""
        gpo = template_gpo(GUID_SIGNING, "Test Policy", TEST_FLAG_LINE.format(2))

        assert find_matches(TestUnscoredControls().gap_control(), [gpo]) == []

    def test_every_gpo_setting_the_key_is_returned_not_just_the_first(self):
        gpos = [template_gpo(GUID_SIGNING, "First", TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Second", TEST_FLAG_LINE.format(1))]

        matches = find_matches(control(), gpos)

        assert [m["gpo_display_name"] for m in matches] == ["First", "Second"]


class TestResults:
    """pass / fail / not_applicable / error, each with evidence."""

    def test_a_compliant_setting_passes_and_reads_as_enforced(self):
        gpo = template_gpo(GUID_SIGNING, "Require Test Flag",
                           TEST_FLAG_LINE.format(2))

        finding = evaluate_control(control(interim_expected=1), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["conflict"] is None
        assert finding["scored"] is True

    def test_a_non_compliant_setting_fails_with_the_value_found(self):
        gpo = template_gpo(GUID_SIGNING, "Weak Test Flag",
                           TEST_FLAG_LINE.format(0))

        finding = evaluate_control(control(interim_expected=1), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["found"][0]["value"] == 0
        assert finding["evidence"]["expected"]["final"] == 2

    def test_an_interim_value_is_a_pass_in_the_audit_state(self):
        """A domain correctly mid-rollout must not read as failing."""
        gpo = template_gpo(GUID_SIGNING, "Negotiate Test Flag",
                           TEST_FLAG_LINE.format(1))

        finding = evaluate_control(control(operator="gte", interim_expected=1), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT

    def test_evidence_names_the_source_gpo_dn_and_its_link_path(self):
        gpo = template_gpo(GUID_SIGNING, "Require Test Flag",
                           TEST_FLAG_LINE.format(2),
                           links=(GpoLink(DC_OU, enforced=True),))

        evidence = evaluate_control(control(), [gpo])["evidence"]

        found = evidence["found"][0]
        assert found["gpo_dn"] == gpo_dn(GUID_SIGNING)
        assert found["gpo_display_name"] == "Require Test Flag"
        assert found["links"] == [{"target_dn": DC_OU, "enforced": True,
                                   "link_enabled": True,
                                   "block_inheritance": False}]
        assert found["enforced_link"] is True
        assert evidence["gpos_searched"] == 1

    def test_evidence_carries_the_type_name_the_gpo_declared(self):
        gpo = template_gpo(GUID_SIGNING, "Require Test Flag",
                           TEST_FLAG_LINE.format(2))

        finding = evaluate_control(control(), [gpo])

        assert finding["evidence"]["found"][0]["type_name"] == "REG_DWORD"

    def test_a_missing_key_fails_when_that_is_the_controls_semantics(self):
        finding = evaluate_control(control(), [template_gpo(GUID_SIGNING, "Other")])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["found"] == []
        assert finding["evidence"]["found_count"] == 0

    def test_a_missing_key_is_not_applicable_when_the_control_says_so(self):
        finding = evaluate_control(
            control(missing_result="not_applicable",
                    missing_note="Only applies where named pipes are retained."),
            [template_gpo(GUID_SIGNING, "Other")])

        assert finding["result"] == RESULT_NOT_APPLICABLE
        assert "named pipes" in " ".join(finding["evidence"]["notes"])

    def test_the_missing_note_explains_the_verdict(self):
        finding = evaluate_control(
            control(missing_note="Nothing sets the flag, so it is not enforced."),
            [])

        assert finding["evidence"]["notes"][0].startswith("Nothing sets the flag")

    def test_no_gpos_at_all_still_produces_a_finding(self):
        finding = evaluate_control(control(), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["gpos_searched"] == 0

    def test_an_uncomparable_value_is_an_error_not_a_verdict(self):
        gpo = template_gpo(GUID_SIGNING, "Broken Test Flag",
                           "MACHINE\\System\\CurrentControlSet\\Services\\Test"
                           "\\Flag=1,\"not a number\"")

        finding = evaluate_control(control(operator="gte", final_expected=3), [gpo])

        assert finding["result"] == RESULT_ERROR
        assert finding["rollout_state"] is None
        assert "not numeric" in finding["error"]
        assert finding["evidence"]["found"][0]["value"] == "not a number"

    def test_a_finding_carries_the_controls_identity_and_remediation(self):
        finding = evaluate_control(control(), [])

        assert finding["control_id"] == "TEST-01"
        assert finding["severity"] == "high"
        assert finding["check_type"] == "gpo-security-template"
        assert finding["source"]["url"].startswith("https://")
        assert "Set the flag" in finding["remediation"]

    def test_unreadable_gpos_are_disclosed_in_the_evidence(self):
        """"Not configured" and "could not read it" must not look the same."""
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Unreadable",
                             read_error="SYSVOL read failed")]

        notes = evaluate_control(control(), gpos)["evidence"]["notes"]

        assert any("could not be read" in note for note in notes)


class TestPresenceOperators:

    def presence_control(self, **overrides):
        raw = dict(operator="present", final_expected=None,
                   presence_rollout_state="audit", missing_result="fail")
        raw.update(overrides)
        return control(**raw)

    def test_a_configured_setting_passes_without_judging_its_value(self):
        gpo = template_gpo(GUID_SIGNING, "Audit Test Flag",
                           TEST_FLAG_LINE.format(7))

        finding = evaluate_control(self.presence_control(), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT
        assert finding["evidence"]["found"][0]["value"] == 7

    def test_the_presence_only_caveat_is_spelled_out_in_the_evidence(self):
        """The value is reported un-judged, and the finding says so."""
        gpo = template_gpo(GUID_SIGNING, "Audit Test Flag",
                           TEST_FLAG_LINE.format(0))

        notes = evaluate_control(self.presence_control(), [gpo])["evidence"]["notes"]

        assert any("asserts only that the policy is configured" in note
                   for note in notes)

    def test_an_unconfigured_presence_control_fails(self):
        finding = evaluate_control(self.presence_control(), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED

    def test_absent_passes_when_nothing_sets_the_key(self):
        finding = evaluate_control(
            control(operator="absent", final_expected=None,
                    missing_result="fail"),
            [template_gpo(GUID_SIGNING, "Other")])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED

    def test_absent_fails_when_a_gpo_sets_the_key(self):
        gpo = template_gpo(GUID_SIGNING, "Sets The Flag", TEST_FLAG_LINE.format(1))

        finding = evaluate_control(
            control(operator="absent", final_expected=None, missing_result="fail"),
            [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"][0]["gpo_dn"] == gpo_dn(GUID_SIGNING)


class TestOsDefault:
    """Unset is not the same as insecure — but an assumed value must say so.

    A control that documents a Windows default (``os_default``) is judged
    against that default when no GPO sets its key. The point of the field is
    accuracy in *both* directions: the domain is not reported as unsigned when
    the OS already negotiates signing, and the finding never reads as though a
    GPO enforced anything.
    """

    DEFAULT_SOURCE = ("Microsoft, 'Network security: LDAP client signing "
                      "requirements' — effective default: Negotiate signing.")

    def default_control(self, **overrides):
        raw = dict(operator="gte", interim_expected=1, final_expected=2,
                   os_default=1, value_source=self.DEFAULT_SOURCE,
                   os_default_source=self.DEFAULT_SOURCE,
                   missing_result="fail")
        raw.update(overrides)
        if raw.get("os_default") is None:
            raw.pop("os_default_source", None)
        return control(**raw)

    def test_an_unset_key_is_judged_against_the_documented_default(self):
        finding = evaluate_control(self.default_control(),
                                  [template_gpo(GUID_SIGNING, "Unrelated Policy")])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT
        assert finding["scored"] is True

    def test_the_evidence_marks_the_value_as_assumed_not_configured(self):
        finding = evaluate_control(self.default_control(), [])

        evidence = finding["evidence"]
        assert evidence["source"] == EVIDENCE_SOURCE_OS_DEFAULT
        assert evidence["os_default"] == {
            "value": 1,
            "source": "os-default",
            "applied": True,
            "enforced_by_gpo": False,
            "meets_final_expected": False,
            "rollout_state_capped": False,
            "value_source": self.DEFAULT_SOURCE,
        }
        assert evidence["expected"]["os_default"] == 1

    def test_a_finding_resting_on_a_default_never_reads_as_gpo_enforced(self):
        """The accuracy requirement: no GPO is credited with this value."""
        finding = evaluate_control(self.default_control(),
                                  [template_gpo(GUID_SIGNING, "Unrelated Policy")])

        assert finding["evidence"]["found"] == []
        assert finding["evidence"]["found_count"] == 0
        assert finding["rollout_state"] != STATE_ENFORCED
        assert any("not a configured one" in note
                   for note in finding["evidence"]["notes"])
        assert any("Nothing in Group Policy enforces it" in note
                   for note in finding["evidence"]["notes"])

    def test_a_default_that_does_not_meet_the_floor_still_fails(self):
        """The field is not a free pass: a weak default fails, labelled."""
        finding = evaluate_control(self.default_control(os_default=0), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT

    def test_a_weak_default_respects_a_conditional_controls_semantics(self):
        """Knowing the default cannot make a control apply that says it does not.

        A control whose ``missing_result`` is ``not_applicable`` has declared
        that an unset key means "does not apply here". A documented default that
        falls below the floor must not silently upgrade that to a failure.
        """
        finding = evaluate_control(
            self.default_control(os_default=0, missing_result="not_applicable",
                                 missing_note="Only applies where X is retained."),
            [])

        assert finding["result"] == RESULT_NOT_APPLICABLE
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT

    def test_a_strong_default_also_respects_a_conditional_controls_semantics(self):
        """The other half of the same rule, which used to be missing.

        ``missing_result: not_applicable`` was honoured only when the default fell
        *below* the floor. A default that met the floor returned a scored ``pass``
        — making a control apply that its author said does not, which is exactly
        what the rule's own docstring forbade.
        """
        finding = evaluate_control(
            self.default_control(os_default=1, missing_result="not_applicable",
                                 missing_note="Only applies where X is retained."),
            [])

        assert finding["result"] == RESULT_NOT_APPLICABLE
        assert finding["result"] != RESULT_PASS
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT
        assert any("cannot make a control apply" in note
                   for note in finding["evidence"]["notes"])

    def test_a_conditional_control_reports_the_default_for_information(self):
        """Out of scope is not a reason to hide what the default is."""
        finding = evaluate_control(
            self.default_control(os_default=2, missing_result="not_applicable",
                                 missing_note="Only applies where X is retained."),
            [])

        assert finding["result"] == RESULT_NOT_APPLICABLE
        assert finding["evidence"]["os_default"]["value"] == 2
        assert finding["evidence"]["os_default"]["applied"] is True

    @pytest.mark.parametrize("os_default,expected", [
        (0, RESULT_FAIL), (1, RESULT_PASS), (2, RESULT_PASS)])
    def test_a_fail_missing_result_still_judges_the_default_on_its_merits(
            self, os_default, expected):
        """The two-sided rule must not change the ``missing_result: fail`` case."""
        finding = evaluate_control(self.default_control(os_default=os_default), [])

        assert finding["result"] == expected

    def test_a_default_that_meets_the_final_step_is_capped_at_audit(self):
        """Nothing enforces a default, so no default may read as ``enforced``.

        This test previously asserted the opposite (``STATE_ENFORCED``), which
        contradicted the catalog-wide
        ``test_a_control_with_an_os_default_is_judged_against_it_instead`` in
        ``TestShippedCatalogAgainstAnEmptyDomain`` — whose docstring already said
        "nothing enforces a default" and which passed only because the one shipped
        ``os_default`` (1) happens to sit below its ``final_expected`` (2). Both now
        assert the same rule, and this one exercises it directly instead of relying
        on the catalog's current numbers to never change.

        The result is still ``pass``: the default does meet the target. It is the
        *rollout state* that must not claim Group Policy holds it there.
        """
        finding = evaluate_control(self.default_control(os_default=2), [])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT
        assert finding["rollout_state"] != STATE_ENFORCED

    def test_the_cap_is_recorded_in_the_evidence_not_just_applied(self):
        """A reader must be able to see that the state was capped, and why."""
        finding = evaluate_control(self.default_control(os_default=2), [])

        os_default = finding["evidence"]["os_default"]
        assert os_default["rollout_state_capped"] is True
        assert os_default["meets_final_expected"] is True
        assert os_default["enforced_by_gpo"] is False
        assert any("capped at 'audit'" in note
                   for note in finding["evidence"]["notes"])

    def test_a_default_above_the_final_step_is_also_capped(self):
        """The cap is on the state, not on an exact equality with the target."""
        finding = evaluate_control(self.default_control(os_default=5), [])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT

    def test_a_default_below_the_final_step_is_not_marked_capped(self):
        """The shipped case: 1 against a final of 2 reaches audit on its own."""
        finding = evaluate_control(self.default_control(), [])

        assert finding["rollout_state"] == STATE_AUDIT
        assert finding["evidence"]["os_default"]["rollout_state_capped"] is False
        assert finding["evidence"]["os_default"]["meets_final_expected"] is False
        assert not any("capped at 'audit'" in note
                       for note in finding["evidence"]["notes"])

    def test_the_cap_holds_for_the_equals_operator(self):
        """``equals`` reaches ``enforced`` by a different path; cap it too."""
        finding = evaluate_control(
            self.default_control(operator="equals", interim_expected=1,
                                 final_expected=2, os_default=2), [])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT

    def test_the_cap_holds_for_the_in_operator(self):
        """``in`` was untested against ``os_default`` entirely."""
        finding = evaluate_control(
            self.default_control(operator="in", interim_expected=None,
                                 final_expected=[2, 3], os_default=3), [])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT

    def test_the_in_operator_fails_a_default_outside_the_option_set(self):
        finding = evaluate_control(
            self.default_control(operator="in", interim_expected=None,
                                 final_expected=[2, 3], os_default=0), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT

    def test_the_equals_operator_fails_a_default_that_does_not_match(self):
        finding = evaluate_control(
            self.default_control(operator="equals", interim_expected=None,
                                 final_expected=2, os_default=0), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT

    def test_a_control_without_a_default_keeps_the_old_unset_behaviour(self):
        """Absent ``os_default`` must change nothing."""
        finding = evaluate_control(self.default_control(os_default=None), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED
        assert finding["evidence"]["os_default"] is None

    def test_a_gpo_value_overrides_the_default_downwards(self):
        """A GPO that lowers the setting must beat the optimistic default."""
        gpo = template_gpo(GUID_SIGNING, "Legacy Exception", TEST_FLAG_LINE.format(0))

        finding = evaluate_control(self.default_control(), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO
        assert finding["evidence"]["os_default"] is None
        assert finding["evidence"]["found"][0]["value"] == 0
        assert finding["evidence"]["expected"]["os_default"] == 1

    def test_a_gpo_value_overrides_the_default_upwards(self):
        gpo = template_gpo(GUID_SIGNING, "Require Signing", TEST_FLAG_LINE.format(2))

        finding = evaluate_control(self.default_control(), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO
        assert finding["evidence"]["found"][0]["gpo_dn"] == gpo_dn(GUID_SIGNING)

    def test_the_counts_separate_os_default_verdicts_from_configured_ones(self):
        """A summary must not lump assumed passes in with enforced ones."""
        gpo = template_gpo(GUID_SIGNING, "Require Signing", TEST_FLAG_LINE.format(2))
        assumed = self.default_control(id="TEST-ASSUMED")
        configured = self.default_control(id="TEST-CONFIGURED")

        _, both = evaluate_controls([assumed], [])
        _, neither = evaluate_controls([configured], [gpo])

        assert both["os_default"] == 1
        assert both[RESULT_PASS] == 1
        assert neither["os_default"] == 0
        assert neither[RESULT_PASS] == 1

    def test_os_default_pass_is_the_number_to_subtract_from_pass(self):
        """``os_default`` alone cannot be subtracted: it includes non-passes.

        The doc used to say "subtract it from pass". Since an os-default finding
        can be ``fail`` or ``not_applicable``, that would understate configured
        passes. ``os_default_pass`` is the subset that actually passed.
        """
        passing = self.default_control(id="TEST-ASSUMED-PASS", os_default=1)
        failing = self.default_control(id="TEST-ASSUMED-FAIL", os_default=0)

        _, counts = evaluate_controls([passing, failing], [])

        assert counts["os_default"] == 2
        assert counts["os_default_pass"] == 1
        assert counts[RESULT_PASS] == 1
        assert counts[RESULT_FAIL] == 1
        # The only subtraction that is correct.
        assert counts[RESULT_PASS] - counts["os_default_pass"] == 0

    def test_a_conditional_os_default_is_counted_but_is_not_a_pass(self):
        conditional = self.default_control(
            id="TEST-ASSUMED-NA", os_default=1, missing_result="not_applicable",
            missing_note="Only applies where X is retained.")

        _, counts = evaluate_controls([conditional], [],
                                      include_not_applicable=True)

        assert counts["os_default"] == 1
        assert counts["os_default_pass"] == 0
        assert counts[RESULT_NOT_APPLICABLE] == 1

    def test_the_counts_reconcile_with_the_filtered_findings_list(self):
        """The review's complaint: a count with zero rendered findings.

        ``counts.os_default == 1`` alongside an empty findings list looked like a
        bug. It is not — every count describes what was *evaluated* — but nothing
        said so. ``rendered`` and ``hidden`` now make the reconciliation explicit
        instead of leaving a reader to guess at the discrepancy.
        """
        hidden_control = self.default_control(
            id="TEST-HIDDEN", os_default=1, missing_result="not_applicable",
            missing_note="Only applies where X is retained.")

        findings, counts = evaluate_controls([hidden_control], [],
                                             include_not_applicable=False)

        assert findings == []
        assert counts["os_default"] == 1
        assert counts["total"] == 1
        assert counts["hidden"] == 1
        assert counts["rendered"] == 0
        assert counts["rendered"] == len(findings)
        assert counts["rendered"] + counts["hidden"] == counts["total"]

    def test_rendered_and_hidden_always_sum_to_total(self):
        gpo = template_gpo(GUID_SIGNING, "Require Signing", TEST_FLAG_LINE.format(2))
        controls = [
            self.default_control(id="TEST-PASS"),
            self.default_control(id="TEST-FAIL", os_default=0),
            self.default_control(id="TEST-NA", os_default=1,
                                 missing_result="not_applicable",
                                 missing_note="Only applies where X is retained."),
        ]

        findings, counts = evaluate_controls(controls, [gpo])

        assert counts["rendered"] == len(findings)
        assert counts["rendered"] + counts["hidden"] == counts["total"] == 3


def unreadable_gpo(guid, name="Unreadable Policy",
                   read_error="SMB access denied"):
    """A GPO whose content could not be read: no entries, and a read_error.

    This is the shape the tool layer produces when a SYSVOL read fails — the
    snapshot exists (it was found in the directory) but nothing could be parsed
    out of it.
    """
    return GpoSnapshot(dn=gpo_dn(guid), display_name=name, guid=guid,
                       security_template_entries=[], registry_pol_entries=[],
                       links=(GpoLink(DC_OU),), read_error=read_error)


class TestUnreadableGposCannotProduceAnOsDefaultPass:
    """"We could not look" is not "nothing sets this key".

    ``find_matches`` can only report keys it managed to read, so an empty match
    list conflates two very different claims. The os-default branch rests on the
    strong one — it concludes the Windows default is the *effective* value — so an
    unreadable GPO must invalidate it. Reporting ``pass`` / ``audit`` /
    ``source: os-default`` off a scan that read nothing is the exact failure this
    class exists to prevent.
    """

    def default_control(self, **overrides):
        raw = dict(operator="gte", interim_expected=1, final_expected=2,
                   os_default=1,
                   value_source="Microsoft, 'LDAP client signing requirements'.",
                   os_default_source=("Microsoft, 'LDAP client signing "
                                      "requirements', Default values table."),
                   missing_result="fail")
        raw.update(overrides)
        if raw.get("os_default") is None:
            raw.pop("os_default_source", None)
        return control(**raw)

    def test_all_gpos_unreadable_is_an_error_not_a_pass(self):
        """The reported defect: two unreadable GPOs and nothing else."""
        gpos = [unreadable_gpo(GUID_SIGNING), unreadable_gpo(GUID_CONFLICT)]

        finding = evaluate_control(self.default_control(), gpos)

        assert finding["result"] == RESULT_ERROR
        assert finding["result"] != RESULT_PASS
        assert finding["rollout_state"] is None

    def test_all_gpos_unreadable_does_not_assert_the_default_is_effective(self):
        gpos = [unreadable_gpo(GUID_SIGNING), unreadable_gpo(GUID_CONFLICT)]

        finding = evaluate_control(self.default_control(), gpos)
        evidence = finding["evidence"]

        assert evidence["source"] == EVIDENCE_SOURCE_UNKNOWN
        assert evidence["source"] != EVIDENCE_SOURCE_OS_DEFAULT
        assert evidence["source"] != EVIDENCE_SOURCE_NOT_CONFIGURED
        assert evidence["os_default"]["applied"] is False
        assert evidence["os_default"]["value"] == 1
        assert evidence["os_default"]["not_applied_reason"]

    def test_the_error_names_the_gpos_that_could_not_be_read(self):
        """An auditor must be able to act on this: which GPOs, and why."""
        gpos = [unreadable_gpo(GUID_SIGNING, read_error="SMB access denied")]

        finding = evaluate_control(self.default_control(), gpos)

        notes = " ".join(finding["evidence"]["notes"])
        assert gpo_dn(GUID_SIGNING) in notes
        assert "SMB access denied" in notes
        assert "1 of 1" in notes
        assert finding["evidence"]["gpos_searched"] == 1

    def test_partially_unreadable_also_refuses_the_default(self):
        """One unreadable GPO is enough, even when others read cleanly.

        The judgement call: the os-default branch concludes "the OS default is
        what is in effect", which requires knowing that *no* GPO sets the key.
        Reading 1 of 2 GPOs does not establish that — the unread one could set the
        value below the default — so the conservative rule is that any unreadable
        GPO blocks the branch.
        """
        gpos = [template_gpo(GUID_SIGNING, "Readable, Unrelated Policy"),
                unreadable_gpo(GUID_CONFLICT)]

        finding = evaluate_control(self.default_control(), gpos)

        assert finding["result"] == RESULT_ERROR
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_UNKNOWN
        assert finding["evidence"]["os_default"]["applied"] is False
        assert finding["evidence"]["gpos_searched"] == 2
        assert "1 of 2" in " ".join(finding["evidence"]["notes"])

    def test_a_readable_gpo_that_sets_the_key_still_wins(self):
        """An unreadable GPO must not suppress evidence we actually have.

        Where a readable GPO *does* set the key there is a real found value to
        report, so the verdict stands on it (with the unread GPOs noted) rather
        than collapsing to an error.
        """
        gpos = [template_gpo(GUID_SIGNING, "Require Signing",
                             TEST_FLAG_LINE.format(2)),
                unreadable_gpo(GUID_CONFLICT)]

        finding = evaluate_control(self.default_control(), gpos)

        assert finding["result"] == RESULT_PASS
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO
        assert finding["evidence"]["found"][0]["value"] == 2
        assert any("could not be read" in note
                   for note in finding["evidence"]["notes"])

    def test_a_control_without_a_default_keeps_its_missing_result(self):
        """Scope: this fix targets the unsound pass, not every unread GPO.

        Without ``os_default`` an unset key already returns ``missing_result``
        (never a pass), and the unread GPOs are already noted, so the verdict is
        left alone rather than turning every fail on an imperfectly-read domain
        into an error.
        """
        gpos = [unreadable_gpo(GUID_SIGNING)]

        finding = evaluate_control(self.default_control(os_default=None), gpos)

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED
        assert any("could not be read" in note
                   for note in finding["evidence"]["notes"])

    def test_the_shipped_ldap_client_control_refuses_to_pass(self):
        """The defect as reported, against the real shipped catalog control."""
        control_obj = load_catalog().by_id("DEVORE-03-LDAP-CLIENT-SIGNING")
        gpos = [unreadable_gpo(GUID_SIGNING), unreadable_gpo(GUID_CONFLICT)]

        findings, counts = evaluate_controls([control_obj], gpos)

        assert findings[0]["result"] == RESULT_ERROR
        assert findings[0]["evidence"]["source"] == EVIDENCE_SOURCE_UNKNOWN
        assert counts[RESULT_PASS] == 0
        assert counts[RESULT_ERROR] == 1
        assert counts["os_default"] == 0

    def test_an_unreadable_scan_is_never_hidden_from_the_report(self):
        """Why ``error`` and not ``not_applicable``: visibility.

        ``not_applicable`` findings are filtered out by default, which would hide
        the very thing the reader needs to see.
        """
        gpos = [unreadable_gpo(GUID_SIGNING)]

        findings, _ = evaluate_controls([self.default_control()], gpos,
                                        include_not_applicable=False)

        assert len(findings) == 1
        assert findings[0]["result"] == RESULT_ERROR


class TestConflictDetection:
    """The honest substitute for RSoP."""

    def test_two_gpos_with_different_values_are_flagged(self):
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Legacy App Exception",
                             TEST_FLAG_LINE.format(0))]

        finding = evaluate_control(control(interim_expected=1), gpos)

        assert finding["conflict"]["detected"] is True
        assert finding["conflict"]["kind"] == "value-disagreement"
        assert len(finding["conflict"]["settings"]) == 2

    def test_a_conflicting_non_compliant_value_denies_the_pass(self):
        """A 'pass' that another GPO silently overrides would be a lie."""
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Legacy App Exception",
                             TEST_FLAG_LINE.format(0))]

        finding = evaluate_control(control(interim_expected=1), gpos)

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert {s["value"] for s in finding["conflict"]["settings"]} == {2, 0}

    def test_both_source_gpos_appear_in_the_evidence(self):
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Legacy App Exception",
                             TEST_FLAG_LINE.format(0))]

        found = evaluate_control(control(), gpos)["evidence"]["found"]

        assert {f["gpo_dn"] for f in found} == {gpo_dn(GUID_SIGNING),
                                                gpo_dn(GUID_CONFLICT)}

    def test_an_enforced_conflicting_link_is_flagged_as_an_override(self):
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2),
                             links=(GpoLink(DC_OU),)),
                template_gpo(GUID_ENFORCED, "Domain Wide Exception",
                             TEST_FLAG_LINE.format(0),
                             links=(GpoLink(BASE_DN, enforced=True),))]

        finding = evaluate_control(control(interim_expected=1), gpos)

        assert finding["conflict"]["kind"] == "enforced-override"
        assert "Domain Wide Exception" in finding["conflict"]["detail"]
        assert finding["result"] == RESULT_FAIL

    def test_agreeing_gpos_are_not_a_conflict(self):
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Also Requires It",
                             TEST_FLAG_LINE.format(2))]

        finding = evaluate_control(control(), gpos)

        assert finding["conflict"] is None
        assert finding["result"] == RESULT_PASS
        assert finding["evidence"]["found_count"] == 2

    def test_two_compliant_but_different_values_still_conflict(self):
        """2 and 1 are both acceptable for a gte control — but not identical."""
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Negotiate Only",
                             TEST_FLAG_LINE.format(1))]

        finding = evaluate_control(control(operator="gte", interim_expected=1), gpos)

        assert finding["conflict"]["kind"] == "value-disagreement"
        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT

    def test_the_no_rsop_limit_is_stated_whenever_more_than_one_gpo_sets_the_key(self):
        gpos = [template_gpo(GUID_SIGNING, "First", TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Second", TEST_FLAG_LINE.format(2))]

        notes = evaluate_control(control(), gpos)["evidence"]["notes"]

        assert any("Precedence is not resolved" in note for note in notes)

    def test_a_single_gpo_cannot_conflict_with_itself(self):
        gpo = template_gpo(GUID_SIGNING, "Only One", TEST_FLAG_LINE.format(2))

        assert evaluate_control(control(), [gpo])["conflict"] is None


class TestUnscoredControls:
    """needs_baseline_value controls must be loud, never guessed at."""

    def gap_control(self):
        return build_catalog({"catalog_version": "test-1", "controls": [{
            "id": "TEST-GAP",
            "title": "A control the source never gave a value for",
            "source": {"part": 6, "url": "https://example.invalid/part-6"},
            "scope": "all",
            "check_type": "gpo-security-template",
            "severity": "high",
            "status": "needs_baseline_value",
            "operator": "present",
            "registry_key": None,
            "baseline_gap": "The post prints no registry path; source it from a "
                            "Microsoft Security Baseline.",
            "remediation": "Enable the policy once the exact value is sourced.",
        }]}).controls[0]

    def test_it_is_not_applicable_unscored_and_explains_itself(self):
        finding = evaluate_control(self.gap_control(), [])

        assert finding["result"] == RESULT_NOT_APPLICABLE
        assert finding["scored"] is False
        assert finding["unscored_reason"] == UNSCORED_NEEDS_BASELINE_VALUE
        assert finding["rollout_state"] is None
        assert "no registry path" in finding["evidence"]["notes"][0]
        assert "guessed" in finding["evidence"]["notes"][1]

    def test_no_expected_value_is_invented(self):
        finding = evaluate_control(self.gap_control(), [])

        assert finding["evidence"]["expected"] is None

    def test_it_is_not_evaluated_even_if_a_gpo_sets_something(self):
        gpo = template_gpo(GUID_SIGNING, "Sets Something",
                           TEST_FLAG_LINE.format(1))

        finding = evaluate_control(self.gap_control(), [gpo])

        assert finding["result"] == RESULT_NOT_APPLICABLE
        assert finding["evidence"]["found"] == []


class TestEvaluateControls:
    """Batch evaluation, counts, and the not_applicable filter."""

    def catalog_of(self, *controls):
        return list(controls)

    def test_counts_cover_every_outcome(self):
        gpos = [template_gpo(GUID_SIGNING, "Require Test Flag",
                             TEST_FLAG_LINE.format(2))]
        controls = [
            control(id="PASS-1"),
            control(id="FAIL-1",
                    registry_key="HKLM\\SYSTEM\\CurrentControlSet\\Services"
                                 "\\Test\\Other"),
            control(id="NA-1", missing_result="not_applicable",
                    registry_key="HKLM\\SYSTEM\\CurrentControlSet\\Services"
                                 "\\Test\\Third"),
        ]

        findings, counts = evaluate_controls(controls, gpos,
                                             include_not_applicable=True)

        assert counts["total"] == 3
        assert counts[RESULT_PASS] == 1
        assert counts[RESULT_FAIL] == 1
        assert counts[RESULT_NOT_APPLICABLE] == 1
        assert counts["scored"] == 3
        assert len(findings) == 3

    def test_not_applicable_findings_are_hidden_by_default(self):
        controls = [control(id="NA-1", missing_result="not_applicable")]

        findings, counts = evaluate_controls(controls, [])

        assert findings == []
        assert counts[RESULT_NOT_APPLICABLE] == 1
        assert counts["total"] == 1

    def test_needs_baseline_value_findings_are_never_hidden(self):
        """Excluded from scoring, but never from sight."""
        gap = TestUnscoredControls().gap_control()

        findings, counts = evaluate_controls([gap], [],
                                             include_not_applicable=False)

        assert [f["control_id"] for f in findings] == ["TEST-GAP"]
        assert counts["needs_baseline_value"] == 1
        assert counts["scored"] == 0

    def test_conflicts_are_counted(self):
        gpos = [template_gpo(GUID_SIGNING, "First", TEST_FLAG_LINE.format(2)),
                template_gpo(GUID_CONFLICT, "Second", TEST_FLAG_LINE.format(0))]

        _findings, counts = evaluate_controls([control()], gpos)

        assert counts["conflicts"] == 1

    def test_findings_keep_catalog_order(self):
        controls = [control(id="A-1"), control(id="B-2"), control(id="C-3")]

        findings, _counts = evaluate_controls(controls, [])

        assert [f["control_id"] for f in findings] == ["A-1", "B-2", "C-3"]


class TestLiveVerifiedLdapCase:
    """Acceptance criterion 7, reproduced offline.

    A real GPO's ``GptTmpl.inf`` was observed to contain exactly these two
    ``[Registry Values]`` lines. One GPO therefore satisfies two catalog
    controls, and both must evaluate to ``pass`` against the shipped catalog —
    which also exercises the ``MACHINE\\System`` vs ``HKLM\\SYSTEM`` key
    normalisation end to end.
    """

    LDAP_LINES = (
        "  MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
        "\\LdapEnforceChannelBinding=4,2",
        "  MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
        "\\LDAPServerIntegrity=4,2",
    )

    @pytest.fixture
    def signing_gpo(self):
        return template_gpo(GUID_SIGNING, "Example DC LDAP Signing",
                            *self.LDAP_LINES,
                            links=(GpoLink(DC_OU),))

    @pytest.mark.parametrize("control_id", ["DEVORE-03-LDAP-SERVER-SIGNING",
                                            "DEVORE-05-LDAP-CHANNEL-BINDING"])
    def test_one_gpo_passes_both_ldap_controls(self, signing_gpo, control_id):
        catalog = load_catalog()

        finding = evaluate_control(catalog.by_id(control_id), [signing_gpo])

        assert finding["result"] == RESULT_PASS, finding["evidence"]
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["conflict"] is None
        assert finding["evidence"]["found"][0]["value"] == 2
        assert finding["evidence"]["found"][0]["gpo_dn"] == gpo_dn(GUID_SIGNING)
        assert finding["evidence"]["found"][0]["links"][0]["target_dn"] == DC_OU

    def test_both_controls_pass_in_one_scan_of_the_shipped_catalog(self, signing_gpo):
        catalog = load_catalog()
        controls, unknown = catalog.select(["DEVORE-03-LDAP-SERVER-SIGNING",
                                            "DEVORE-05-LDAP-CHANNEL-BINDING"])

        findings, counts = evaluate_controls(controls, [signing_gpo])

        assert unknown == ()
        assert counts[RESULT_PASS] == 2
        assert counts[RESULT_FAIL] == 0
        assert counts["conflicts"] == 0
        assert {f["rollout_state"] for f in findings} == {STATE_ENFORCED}

    def test_the_interim_value_reads_as_audit_not_failure(self):
        """The same GPO mid-rollout: channel binding at 'When supported' (1)."""
        gpo = template_gpo(
            GUID_SIGNING, "Example DC LDAP Signing",
            "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
            "\\LdapEnforceChannelBinding=4,1")

        finding = evaluate_control(
            load_catalog().by_id("DEVORE-05-LDAP-CHANNEL-BINDING"), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT

    def test_a_second_gpo_disabling_signing_breaks_the_pass(self, signing_gpo):
        """The conflict case on the real control, not a synthetic one."""
        override = template_gpo(
            GUID_ENFORCED, "Legacy LDAP Exception",
            "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
            "\\LDAPServerIntegrity=4,0",
            links=(GpoLink(BASE_DN, enforced=True),))

        finding = evaluate_control(
            load_catalog().by_id("DEVORE-03-LDAP-SERVER-SIGNING"),
            [signing_gpo, override])

        assert finding["result"] == RESULT_FAIL
        assert finding["conflict"]["kind"] == "enforced-override"
        assert finding["evidence"]["found_count"] == 2

    def test_a_domain_with_no_ldap_signing_gpo_fails_both_controls(self):
        catalog = load_catalog()
        controls, _ = catalog.select(["DEVORE-03-LDAP-SERVER-SIGNING",
                                      "DEVORE-05-LDAP-CHANNEL-BINDING"])

        findings, counts = evaluate_controls(
            controls, [template_gpo(GUID_CONFLICT, "Unrelated Policy")])

        assert counts[RESULT_FAIL] == 2
        assert {f["rollout_state"] for f in findings} == {STATE_NOT_STARTED}


class TestLdapClientSigningOnTheShippedCatalog:
    """The live defect: a domain that sets nothing is not an unsigned domain.

    ``LdapClientIntegrity`` appeared in none of the real domain's GPOs, and the
    scan called that ``fail`` / ``not_started``. Windows defaults it to
    Negotiate (1), so the honest verdict is "at the OS default, not raised to
    Require" — and it must stay distinguishable from a domain that configured
    Require explicitly.
    """

    CLIENT_LINE = ("MACHINE\\System\\CurrentControlSet\\Services\\LDAP"
                   "\\LdapClientIntegrity=4,{}")

    @pytest.fixture
    def control_obj(self):
        return load_catalog().by_id("DEVORE-03-LDAP-CLIENT-SIGNING")

    def test_a_domain_that_sets_nothing_reflects_the_negotiate_default(
            self, control_obj):
        finding = evaluate_control(
            control_obj, [template_gpo(GUID_CONFLICT, "Unrelated Policy")])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_AUDIT
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT
        assert finding["evidence"]["os_default"]["value"] == 1
        assert finding["evidence"]["os_default"]["enforced_by_gpo"] is False

    def test_the_default_pass_cites_the_microsoft_document_it_rests_on(
            self, control_obj):
        finding = evaluate_control(control_obj, [])

        value_source = finding["evidence"]["os_default"]["value_source"]
        assert "learn.microsoft.com" in value_source
        assert "Negotiate signing" in value_source

    def test_an_explicit_require_is_distinguishable_from_the_default(
            self, control_obj):
        """Same pass, different evidence: configured and enforced, not assumed."""
        gpo = template_gpo(GUID_SIGNING, "Require LDAP Client Signing",
                           self.CLIENT_LINE.format(2))

        finding = evaluate_control(control_obj, [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO
        assert finding["evidence"]["os_default"] is None
        assert finding["evidence"]["found"][0]["gpo_dn"] == gpo_dn(GUID_SIGNING)

    def test_a_gpo_that_lowers_the_setting_to_none_still_fails(self, control_obj):
        """The default must not paper over a GPO that turned signing off."""
        gpo = template_gpo(GUID_ENFORCED, "Legacy LDAP Exception",
                           self.CLIENT_LINE.format(0),
                           links=(GpoLink(BASE_DN, enforced=True),))

        finding = evaluate_control(control_obj, [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO

    def test_channel_binding_has_no_default_and_still_fails_when_unset(self):
        """The deliberate contrast: no key by default means channel binding is off."""
        control_obj = load_catalog().by_id("DEVORE-05-LDAP-CHANNEL-BINDING")

        finding = evaluate_control(control_obj, [])

        assert control_obj.os_default is None
        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED


class TestSmbSigningOnTheShippedCatalog:
    """The SMB controls, now active, against the shapes a real GPO writes.

    Both were unscored while domains were configuring SMB signing all along, so
    the scan reported nothing about a control an auditor cares about. The keys
    are written with the service name cased differently in the wild
    (``LanmanWorkstation`` / ``LanManServer``) than in Microsoft's own
    documentation, and registry paths are case-insensitive, so key normalisation
    has to absorb that — these fixtures spell it the way the GPOs do.
    """

    CLIENT_LINE = ("MACHINE\\System\\CurrentControlSet\\Services"
                   "\\LanmanWorkstation\\Parameters\\RequireSecuritySignature=4,{}")
    SERVER_LINE = ("MACHINE\\System\\CurrentControlSet\\Services"
                   "\\LanManServer\\Parameters\\RequireSecuritySignature=4,{}")

    @pytest.mark.parametrize("control_id,line_template", [
        ("DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS", CLIENT_LINE),
        ("DEVORE-06-SMB-SERVER-SIGNING-ALWAYS", SERVER_LINE),
    ])
    def test_a_require_signing_gpo_passes(self, control_id, line_template):
        gpo = template_gpo(GUID_SIGNING, "SMB Signing", line_template.format(1))

        finding = evaluate_control(load_catalog().by_id(control_id), [gpo])

        assert finding["result"] == RESULT_PASS, finding["evidence"]
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["scored"] is True
        assert finding["evidence"]["found"][0]["value"] == 1
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO

    @pytest.mark.parametrize("service_casing", ["LanmanWorkstation",
                                                "LANMANWORKSTATION",
                                                "lanmanworkstation"])
    def test_the_client_key_matches_whatever_casing_the_gpo_used(self,
                                                                service_casing):
        """Registry paths are case-insensitive; the verdict must not depend on it."""
        gpo = template_gpo(
            GUID_SIGNING, "Example Client SMB Signing",
            f"MACHINE\\System\\CurrentControlSet\\Services\\{service_casing}"
            f"\\Parameters\\RequireSecuritySignature=4,1")

        finding = evaluate_control(
            load_catalog().by_id("DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS"), [gpo])

        assert finding["result"] == RESULT_PASS, finding["evidence"]

    def test_the_server_control_reads_the_server_key_not_the_client_one(self):
        """Two controls, two services: a client-only GPO must not pass the server."""
        gpo = template_gpo(GUID_SIGNING, "Example Client SMB Signing",
                           self.CLIENT_LINE.format(1))

        finding = evaluate_control(
            load_catalog().by_id("DEVORE-06-SMB-SERVER-SIGNING-ALWAYS"), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"] == []

    def test_signing_disabled_fails(self):
        gpo = template_gpo(GUID_SIGNING, "SMB Signing Off",
                           self.CLIENT_LINE.format(0))

        finding = evaluate_control(
            load_catalog().by_id("DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS"), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["found"][0]["value"] == 0

    def test_the_legacy_if_agrees_setting_does_not_satisfy_the_control(self):
        """EnableSecuritySignature is SMBv1-only and must not count as signing."""
        gpo = template_gpo(
            GUID_SIGNING, "Legacy SMB Signing",
            "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation"
            "\\Parameters\\EnableSecuritySignature=4,1")

        finding = evaluate_control(
            load_catalog().by_id("DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS"), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"] == []
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED

    def test_three_gpos_setting_signing_consistently_raise_no_conflict(self):
        """The live shape: client GPO, server GPO, and the DC policy agreeing."""
        catalog = load_catalog()
        gpos = [
            template_gpo(GUID_SIGNING, "Example Client SMB Signing",
                         self.CLIENT_LINE.format(1), links=(GpoLink(BASE_DN),)),
            template_gpo(GUID_CONFLICT, "Example Server SMB Signing",
                         self.SERVER_LINE.format(1), links=(GpoLink(BASE_DN),)),
            template_gpo(GUID_ENFORCED, "Domain Controllers Policy",
                         self.SERVER_LINE.format(1), links=(GpoLink(DC_OU),)),
        ]
        controls, _ = catalog.select(["DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS",
                                      "DEVORE-06-SMB-SERVER-SIGNING-ALWAYS"])

        findings, counts = evaluate_controls(controls, gpos)

        assert counts[RESULT_PASS] == 2
        assert counts[RESULT_FAIL] == 0
        assert counts["needs_baseline_value"] == 0
        assert counts["conflicts"] == 0
        server = next(f for f in findings
                      if f["control_id"] == "DEVORE-06-SMB-SERVER-SIGNING-ALWAYS")
        assert server["evidence"]["found_count"] == 2

    def test_a_domain_that_configures_no_smb_signing_now_fails_instead_of_hiding(self):
        """Previously unscored: the scan said nothing at all about these."""
        catalog = load_catalog()
        controls, _ = catalog.select(["DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS",
                                      "DEVORE-06-SMB-SERVER-SIGNING-ALWAYS"])

        findings, counts = evaluate_controls(
            controls, [template_gpo(GUID_CONFLICT, "Unrelated Policy")])

        assert counts[RESULT_FAIL] == 2
        assert counts["scored"] == 2
        assert counts["needs_baseline_value"] == 0
        assert all(f["evidence"]["expected"]["final"] == 1 for f in findings)


class TestNtlmAuditFloorOnTheShippedCatalog:
    """Acceptance 5: auditing configured *off* must not score as a pass.

    These three controls used ``operator: present``, so any configured value
    passed — including 0, which Microsoft documents as Disable / "no auditing".
    A summary line of "8 passed" that can include "auditing is disabled" is the
    plausible-wrong-answer class this tool exists to prevent, so the controls
    now assert a floor of >= 1 and report which enabled level is set as
    evidence rather than scoring it.
    """

    KEYS = {
        "DEVORE-08-NTLM-AUDIT-INCOMING":
            "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0"
            "\\AuditReceivingNTLMTraffic",
        "DEVORE-08-NTLM-AUDIT-OUTGOING":
            "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0"
            "\\RestrictSendingNTLMTraffic",
        "DEVORE-08-NTLM-AUDIT-INDOMAIN":
            "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters"
            "\\AuditNTLMInDomain",
    }

    def audit_gpo(self, control_id, value):
        return template_gpo(GUID_SIGNING, "NTLM Auditing",
                            f"{self.KEYS[control_id]}=4,{value}")

    @pytest.mark.parametrize("control_id", sorted(KEYS))
    def test_auditing_configured_off_fails(self, control_id):
        """The defect: value 0 used to pass as 'the policy is configured'."""
        finding = evaluate_control(load_catalog().by_id(control_id),
                                  [self.audit_gpo(control_id, 0)])

        assert finding["result"] == RESULT_FAIL, finding["evidence"]
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["found"][0]["value"] == 0
        assert finding["evidence"]["expected"]["final"] == 1

    @pytest.mark.parametrize("control_id", sorted(KEYS))
    @pytest.mark.parametrize("value", [1, 2])
    def test_any_enabled_auditing_level_passes(self, control_id, value):
        finding = evaluate_control(load_catalog().by_id(control_id),
                                  [self.audit_gpo(control_id, value)])

        assert finding["result"] == RESULT_PASS, finding["evidence"]
        assert finding["evidence"]["found"][0]["value"] == value

    @pytest.mark.parametrize("control_id", sorted(KEYS))
    def test_the_exact_level_is_reported_rather_than_scored(self, control_id):
        """1 vs 2 (domain accounts vs all accounts) is evidence, not a verdict."""
        control_obj = load_catalog().by_id(control_id)

        domain_accounts = evaluate_control(control_obj,
                                          [self.audit_gpo(control_id, 1)])
        all_accounts = evaluate_control(control_obj,
                                       [self.audit_gpo(control_id, 2)])

        assert domain_accounts["result"] == all_accounts["result"] == RESULT_PASS
        assert domain_accounts["evidence"]["found"][0]["value"] == 1
        assert all_accounts["evidence"]["found"][0]["value"] == 2
        assert any("FLOOR, NOT LEVEL" in caveat
                   for caveat in domain_accounts["caveats"])

    @pytest.mark.parametrize("control_id", sorted(KEYS))
    def test_unset_still_fails_as_no_auditing(self, control_id):
        """Microsoft: 'Not defined ... is the same as Disable'."""
        finding = evaluate_control(load_catalog().by_id(control_id), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED
        assert finding["evidence"]["os_default"] is None

    def test_a_domain_auditing_at_mixed_levels_is_not_reported_as_blocking(self):
        """The observed live shape (incoming 2, outgoing 1) passes as audited."""
        catalog = load_catalog()
        gpos = [self.audit_gpo("DEVORE-08-NTLM-AUDIT-INCOMING", 2),
                template_gpo(GUID_CONFLICT, "NTLM Outgoing Audit",
                             f"{self.KEYS['DEVORE-08-NTLM-AUDIT-OUTGOING']}=4,1")]
        controls, _ = catalog.select(["DEVORE-08-NTLM-AUDIT-OUTGOING",
                                      "DEVORE-08-NTLM-BLOCK-OUTGOING"])

        findings, counts = evaluate_controls(controls, gpos,
                                             include_not_applicable=True)

        audit = next(f for f in findings
                     if f["control_id"] == "DEVORE-08-NTLM-AUDIT-OUTGOING")
        block = next(f for f in findings
                     if f["control_id"] == "DEVORE-08-NTLM-BLOCK-OUTGOING")
        assert audit["result"] == RESULT_PASS
        assert block["result"] == RESULT_NOT_APPLICABLE
        assert block["scored"] is False
        assert block["unscored_reason"] == UNSCORED_NEEDS_BASELINE_VALUE
        assert block["evidence"]["registry_key"] is None
        assert counts["needs_baseline_value"] == 1
        assert any("NOT evidence that outgoing NTLM is blocked" in caveat
                   for caveat in audit["caveats"])

    def test_two_gpos_disagreeing_about_the_audit_level_follow_the_worst(self):
        """One GPO auditing, another switching it off: the off value wins."""
        control_obj = load_catalog().by_id("DEVORE-08-NTLM-AUDIT-INCOMING")
        key = self.KEYS["DEVORE-08-NTLM-AUDIT-INCOMING"]
        gpos = [template_gpo(GUID_SIGNING, "NTLM Auditing On", f"{key}=4,2"),
                template_gpo(GUID_CONFLICT, "NTLM Auditing Off", f"{key}=4,0")]

        finding = evaluate_control(control_obj, gpos)

        assert finding["result"] == RESULT_FAIL
        assert finding["conflict"]["kind"] == "value-disagreement"


class TestShippedCatalogAgainstSynthesizedGpos:
    """Every shipped active control, exercised once with a compliant GPO."""

    def compliant_gpo(self, control_obj):
        """A GPO that sets exactly this control's key to its final value."""
        value = control_obj.final_expected
        if control_obj.check_type == "gpo-security-template":
            key = "MACHINE\\" + control_obj.registry_key.split("\\", 1)[1]
            data = 1 if value is None else value
            return template_gpo(GUID_SIGNING, "Synthetic Compliant Policy",
                                f"{key}=4,{data}")
        key_path = control_obj.registry_key_path.split("\\", 1)[1]
        return pol_gpo(GUID_SIGNING, "Synthetic Compliant Policy",
                       (key_path, control_obj.registry_value_name, 4,
                        dword(1 if value is None else value)))

    @pytest.mark.parametrize("control_id", [
        c.id for c in load_catalog().scored_controls
        if c.check_type != "directory-state"])
    def test_every_active_control_can_pass(self, control_id):
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [self.compliant_gpo(control_obj)])

        assert finding["result"] == RESULT_PASS, finding["evidence"]
        assert finding["rollout_state"] in (STATE_ENFORCED, STATE_AUDIT)

    @pytest.mark.parametrize("control_id", [
        c.id for c in load_catalog().scored_controls
        if c.os_default is None and c.gpo_deliverable
        and c.check_type != "directory-state"])
    def test_every_active_control_reports_something_on_an_empty_domain(
            self, control_id):
        """For these controls a GPO *is* the delivery mechanism.

        So an empty domain really does establish that nothing sets the key, and
        the verdict stays the control's ``missing_result``. The two controls whose
        remediation bypasses Group Policy are excluded and covered by the next
        test — that exclusion is the whole point of ``gpo_deliverable``, and it is
        deliberately narrow.
        """
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [])

        assert finding["result"] in (RESULT_FAIL, RESULT_NOT_APPLICABLE)
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED
        assert finding["evidence"]["notes"]

    @pytest.mark.parametrize("control_id", [
        c.id for c in load_catalog().scored_controls if not c.gpo_deliverable])
    def test_a_control_a_gpo_scan_cannot_see_is_unknown_on_an_empty_domain(
            self, control_id):
        """The third empty-domain case: no GPO, and absence proves nothing."""
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [])

        assert finding["result"] == RESULT_UNKNOWN
        assert finding["rollout_state"] is None
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_UNKNOWN
        assert any("reg query" in note
                   for note in finding["evidence"]["notes"])

    @pytest.mark.parametrize("control_id", [
        c.id for c in load_catalog().scored_controls
        if c.os_default is not None])
    def test_a_control_with_an_os_default_is_judged_against_it_instead(
            self, control_id):
        """The other half of the empty-domain rule: no GPO, but a known default.

        ``rollout_state`` must stay below ``enforced``: nothing enforces a
        default, so a control whose documented default equals its final step must
        not read as "enforced" on a domain that configures nothing.

        This assertion used to hold only by luck — it passes trivially while the
        one shipped ``os_default`` (1) sits below its ``final_expected`` (2), and
        ``TestOsDefault`` simultaneously asserted the opposite for a default that
        *did* meet its target. The rule is now enforced in
        ``_os_default_finding``, which caps the state, so this test holds for any
        future catalog value; ``TestOsDefault.test_a_default_that_meets_the_final_
        step_is_capped_at_audit`` exercises the cap directly.
        """
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [])

        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_OS_DEFAULT
        assert finding["evidence"]["os_default"]["value"] == control_obj.os_default
        assert finding["evidence"]["found"] == []
        assert finding["rollout_state"] != STATE_ENFORCED

    def test_the_whole_catalog_evaluates_against_an_empty_domain(self):
        catalog = load_catalog()

        findings, counts = evaluate_controls(catalog.controls, [],
                                             directory=clean_directory(catalog),
                                             include_not_applicable=True)

        assert counts["total"] == len(catalog.controls)
        assert counts[RESULT_ERROR] == 0
        assert counts["needs_baseline_value"] == len(catalog.unscored_controls)
        assert counts["scored"] == len(catalog.scored_controls)
        assert len(findings) == len(catalog.controls)


# --------------------------------------------------------------------------- #
# Group Policy Preferences (Registry.xml) as a value source — P2-WP4
# --------------------------------------------------------------------------- #

KDC_CONTROL_ID = "DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"
KDC_PREFERENCE_KEY = r"SYSTEM\CurrentControlSet\Services\Kdc"


def registry_xml(*properties):
    """Hand-written Registry.xml bytes with one <Registry> item per argument.

    Each argument is either the ``<Properties>`` attribute string or a
    ``(attributes, item_attributes, children)`` triple. Nothing here was
    captured from a real domain: the value names are Microsoft-documented
    registry names, and no GUID, uid, timestamp or domain identifier appears.
    """
    items = []
    for spec in properties:
        attrs, item_attrs, children = (spec if isinstance(spec, tuple)
                                       else (spec, "", ""))
        items.append(f'<Registry name="Item"{item_attrs}>'
                     f'<Properties {attrs}/>{children}</Registry>')
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<RegistrySettings clsid="{A3CCFC41-0000-0000-0000-000000000002}">'
        + "".join(items) + '</RegistrySettings>'
    ).encode("utf-8")


def properties(key, name, value, *, action="U", reg_type="REG_DWORD",
               hive="HKEY_LOCAL_MACHINE", extra=""):
    """One <Properties> attribute string for a machine-side registry item."""
    return (f'action="{action}" displayDecimal="0" default="0" hive="{hive}" '
            f'key="{key}" name="{name}" type="{reg_type}" value="{value}" '
            f'{extra}')


def preference_gpo(guid, name, *specs, links=None, read_error=None):
    """A GPO snapshot whose only registry source is a Registry.xml.

    Built by running the *real* ``parse_registry_xml`` over hand-written XML, so
    these tests exercise the same decoding path the live scan does — including
    the hex value parse.
    """
    return GpoSnapshot(
        dn=gpo_dn(guid),
        display_name=name,
        guid=guid,
        registry_xml_entries=parse_registry_xml(registry_xml(*specs)),
        links=links if links is not None else (GpoLink(DC_OU),),
        read_error=read_error,
    )


def pol_control(**overrides):
    """A gpo-registry-pol control over the synthetic test flag key."""
    defaults = {
        "check_type": "gpo-registry-pol",
        "registry_key": r"HKLM\System\CurrentControlSet\Services\Test\Flag",
        "final_expected": 2,
    }
    defaults.update(overrides)
    return control(**defaults)


TEST_FLAG_PREFERENCE_KEY = r"SYSTEM\CurrentControlSet\Services\Test"


class TestPreferenceItemsAreAValueSource:
    """A gpo-registry-pol control matches a value delivered by preference.

    This is the false negative the work package exists to close: a registry
    value with no ADMX policy behind it can only be delivered by a preference
    item, so a scanner that reads Registry.pol alone reports the operator's
    hardening as missing.
    """

    def test_a_preference_item_satisfies_a_registry_pol_control(self):
        gpo = preference_gpo(GUID_SIGNING, "Test Flag By Preference",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["found_count"] == 1

    def test_the_found_value_is_the_hex_parse(self):
        """0x38 = 56. Decimal 38 would be 0x26, which is a different setting."""
        gpo = preference_gpo(GUID_SIGNING, "Enc Types By Preference",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000038"))

        matches = find_matches(pol_control(final_expected=56), [gpo])

        assert matches[0]["value"] == 56
        assert matches[0]["value"] != 38

    def test_the_full_hive_name_is_folded_onto_the_catalog_spelling(self):
        gpo = preference_gpo(GUID_SIGNING, "Test Flag By Preference",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        matches = find_matches(pol_control(), [gpo])

        assert matches[0]["registry_key"] == (
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Test\Flag")
        assert matches[0]["source_file"] == r"Preferences\Registry\Registry.xml"

    def test_a_preference_setting_a_different_key_is_not_matched(self):
        gpo = preference_gpo(GUID_SIGNING, "Something Else",
                             properties(r"SYSTEM\CurrentControlSet\Services"
                                        r"\Other", "Flag", "00000002"))

        assert find_matches(pol_control(), [gpo]) == []

    def test_a_preference_does_not_satisfy_a_security_template_control(self):
        """Scoped deliberately: a template control asserts a Security Option.

        WP4 widened the ``gpo-registry-pol`` value sources only. A
        ``gpo-security-template`` control asserts a ``[Registry Values]``
        setting, and widening that too was out of scope for this work package.
        """
        gpo = preference_gpo(GUID_SIGNING, "Test Flag By Preference",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        assert find_matches(control(), [gpo]) == []

    def test_a_non_compliant_preference_value_fails(self):
        gpo = preference_gpo(GUID_SIGNING, "Test Flag By Preference",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000000"))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"][0]["value"] == 0

    def test_a_reg_sz_preference_value_stays_a_string_in_the_evidence(self):
        gpo = preference_gpo(GUID_SIGNING, "Padding Check",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag", "1",
                                        reg_type="REG_SZ"))

        finding = evaluate_control(pol_control(final_expected=1), [gpo])

        # 'equals' compares numerically, so the string "1" still satisfies 1 —
        # but the evidence must show what the GPO actually writes.
        assert finding["result"] == RESULT_PASS
        assert finding["evidence"]["found"][0]["value"] == "1"
        assert finding["evidence"]["found"][0]["type_name"] == "REG_SZ"

    def test_several_preference_items_in_one_gpo_are_all_reported(self):
        gpo = preference_gpo(
            GUID_SIGNING, "Two Items",
            properties(TEST_FLAG_PREFERENCE_KEY, "Flag", "00000002"),
            properties(TEST_FLAG_PREFERENCE_KEY, "Flag", "00000002"))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["evidence"]["found_count"] == 2
        assert [match["preference"]["item_order"]
                for match in finding["evidence"]["found"]] == [1, 2]


class TestDeliveryIsRecordedOnEveryFoundValue:
    """``delivery`` says which mechanism put the value there."""

    def test_a_security_template_value_is_labelled_security_template(self):
        gpo = template_gpo(GUID_SIGNING, "Template Policy",
                           TEST_FLAG_LINE.format(2))

        finding = evaluate_control(control(), [gpo])

        assert finding["evidence"]["found"][0]["delivery"] == \
            DELIVERY_SECURITY_TEMPLATE
        assert finding["evidence"]["found"][0]["preference"] is None

    def test_a_registry_pol_value_is_labelled_registry_pol(self):
        gpo = pol_gpo(GUID_SIGNING, "Pol Policy",
                      (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                       dword(2)))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["evidence"]["found"][0]["delivery"] == \
            DELIVERY_REGISTRY_POL
        assert finding["evidence"]["found"][0]["preference"] is None

    def test_a_preference_value_is_labelled_registry_preference(self):
        gpo = preference_gpo(GUID_SIGNING, "Preference Policy",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["evidence"]["found"][0]["delivery"] == \
            DELIVERY_REGISTRY_PREFERENCE

    def test_every_found_value_carries_a_known_delivery(self):
        gpos = [
            pol_gpo(GUID_SIGNING, "Pol Policy",
                    (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                     dword(2))),
            preference_gpo(GUID_CONFLICT, "Preference Policy",
                           properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                      "00000002")),
        ]

        finding = evaluate_control(pol_control(), gpos)

        assert {match["delivery"] for match in finding["evidence"]["found"]} == {
            DELIVERY_REGISTRY_POL, DELIVERY_REGISTRY_PREFERENCE}
        assert all(match["delivery"] in DELIVERIES
                   for match in finding["evidence"]["found"])

    def test_the_preference_action_is_recorded_with_the_value(self):
        gpo = preference_gpo(GUID_SIGNING, "Preference Policy",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="R"))

        preference = evaluate_control(
            pol_control(), [gpo])["evidence"]["found"][0]["preference"]

        assert preference["action"] == "R"
        assert preference["action_name"] == "Replace"
        assert preference["corrects_drift"] is True
        assert preference["tattoos"] is True
        assert preference["has_filters"] is False

    def test_a_preference_pass_states_that_the_value_tattoos(self):
        gpo = preference_gpo(GUID_SIGNING, "Preference Policy",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        notes = evaluate_control(pol_control(), [gpo])["evidence"]["notes"]

        assert any("TATTOOS" in note for note in notes)

    def test_a_policy_only_finding_gains_no_preference_notes(self):
        """Existing verdicts must read exactly as they did before WP4."""
        gpo = pol_gpo(GUID_SIGNING, "Pol Policy",
                      (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                       dword(2)))

        notes = evaluate_control(pol_control(), [gpo])["evidence"]["notes"]

        assert notes == []


class TestPreferenceActionSemantics:
    """C/R/U/D are not interchangeable, and D is the dangerous one."""

    def test_a_delete_item_does_not_count_as_configuring_the_value(self):
        """The most damaging possible misread: a Delete reported as hardening."""
        gpo = preference_gpo(GUID_SIGNING, "Remove The Flag",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="D"))

        finding = evaluate_control(pol_control(), [gpo])

        assert find_matches(pol_control(), [gpo]) == []
        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"] == []
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED

    def test_a_delete_item_is_reported_in_the_notes_not_silently_dropped(self):
        gpo = preference_gpo(GUID_SIGNING, "Remove The Flag",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="D"))

        notes = evaluate_control(pol_control(), [gpo])["evidence"]["notes"]

        assert any("DELETE this value" in note for note in notes)
        assert any("Remove The Flag" in note for note in notes)

    def test_find_preference_non_writes_reports_the_delete(self):
        gpo = preference_gpo(GUID_SIGNING, "Remove The Flag",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="D"))

        non_writes = find_preference_non_writes(pol_control(), [gpo])

        assert len(non_writes) == 1
        assert non_writes[0]["reason"] == NON_WRITE_DELETE
        assert non_writes[0]["preference"]["action"] == "D"
        assert non_writes[0]["gpo_dn"] == gpo_dn(GUID_SIGNING)

    def test_a_delete_alongside_a_real_setting_still_passes_but_says_so(self):
        gpos = [
            pol_gpo(GUID_SIGNING, "Set The Flag",
                    (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                     dword(2))),
            preference_gpo(GUID_CONFLICT, "Remove The Flag",
                           properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                      "00000002", action="D")),
        ]

        finding = evaluate_control(pol_control(), gpos)

        assert finding["result"] == RESULT_PASS
        assert finding["evidence"]["found_count"] == 1
        assert any("working against each other" in note
                   for note in finding["evidence"]["notes"])

    def test_a_delete_does_not_break_an_absent_control(self):
        """For an 'absent' control a Delete is not a setting, so it still passes."""
        gpo = preference_gpo(GUID_SIGNING, "Remove The Flag",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="D"))

        finding = evaluate_control(pol_control(operator="absent",
                                              final_expected=None), [gpo])

        assert finding["result"] == RESULT_PASS
        assert any("DELETE this value" in note
                   for note in finding["evidence"]["notes"])

    def test_a_create_item_counts_but_is_flagged_as_not_correcting_drift(self):
        gpo = preference_gpo(GUID_SIGNING, "Create The Flag",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="C"))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_PASS
        preference = finding["evidence"]["found"][0]["preference"]
        assert preference["action"] == "C"
        assert preference["action_name"] == "Create"
        assert preference["corrects_drift"] is False
        assert any("does not correct drift" in note
                   for note in finding["evidence"]["notes"])

    @pytest.mark.parametrize("action,corrects", [("U", True), ("R", True),
                                                 ("C", False)])
    def test_drift_correction_is_recorded_per_action(self, action, corrects):
        gpo = preference_gpo(GUID_SIGNING, "The Flag",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action=action))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["evidence"]["found"][0]["preference"]["corrects_drift"] \
            is corrects

    def test_a_missing_action_attribute_is_treated_as_update(self):
        gpo = GpoSnapshot(
            dn=gpo_dn(GUID_SIGNING), display_name="No Action Attribute",
            guid=GUID_SIGNING,
            registry_xml_entries=parse_registry_xml(registry_xml(
                f'hive="HKEY_LOCAL_MACHINE" key="{TEST_FLAG_PREFERENCE_KEY}" '
                f'name="Flag" type="REG_DWORD" value="00000002"')),
            links=(GpoLink(DC_OU),))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["evidence"]["found"][0]["preference"]["action"] == "U"

    def test_a_disabled_item_writes_nothing_and_does_not_count(self):
        gpo = preference_gpo(
            GUID_SIGNING, "Switched Off",
            (properties(TEST_FLAG_PREFERENCE_KEY, "Flag", "00000002"),
             ' disabled="1"', ''))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"] == []
        assert any("are disabled and write nothing" in note
                   for note in finding["evidence"]["notes"])

    def test_an_unrecognised_action_is_not_counted_and_is_disclosed(self):
        """Whether it writes is unknown, and unknown is not a pass."""
        gpo = preference_gpo(GUID_SIGNING, "Odd Action",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002", action="Z"))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"] == []
        assert any("does not recognise" in note
                   for note in finding["evidence"]["notes"])

    def test_a_bare_key_creation_item_configures_nothing_either_way(self):
        gpo = preference_gpo(
            GUID_SIGNING, "Create The Key",
            f'action="C" hive="HKEY_LOCAL_MACHINE" '
            f'key="{TEST_FLAG_PREFERENCE_KEY}\\Flag"')

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"] == []
        assert finding["evidence"]["notes"] == [
            "No GPO in the domain sets this key."], \
            "a skipped key item must not produce a non-write note either"


class TestPreferenceItemLevelTargeting:
    """Filters are not resolved, so they must be disclosed, not implied away."""

    FILTER = ('<Filters><FilterGroup bool="AND" not="0" '
              'name="Placeholder Group"/></Filters>')

    def test_a_filtered_item_is_flagged_in_the_evidence(self):
        gpo = preference_gpo(
            GUID_SIGNING, "Filtered Preference",
            (properties(TEST_FLAG_PREFERENCE_KEY, "Flag", "00000002"), '',
             self.FILTER))

        finding = evaluate_control(pol_control(), [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["evidence"]["found"][0]["preference"]["has_filters"] \
            is True

    def test_a_filtered_item_says_coverage_is_not_domain_wide(self):
        gpo = preference_gpo(
            GUID_SIGNING, "Filtered Preference",
            (properties(TEST_FLAG_PREFERENCE_KEY, "Flag", "00000002"), '',
             self.FILTER))

        notes = evaluate_control(pol_control(), [gpo])["evidence"]["notes"]

        assert any("item-level targeting" in note for note in notes)
        assert any("not as domain-wide coverage" in note for note in notes)

    def test_an_unfiltered_item_makes_no_targeting_claim(self):
        gpo = preference_gpo(GUID_SIGNING, "Plain Preference",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        notes = evaluate_control(pol_control(), [gpo])["evidence"]["notes"]

        assert not any("item-level targeting" in note for note in notes)


class TestPolicyVersusPreferenceConflict:
    """A policy and a preference disagreeing is a conflict like any other."""

    def policy_and_preference(self, policy_value, preference_value,
                              enforced=False):
        return [
            pol_gpo(GUID_SIGNING, "Policy Sets The Flag",
                    (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                     dword(policy_value)),
                    links=(GpoLink(DC_OU, enforced=enforced),)),
            preference_gpo(GUID_CONFLICT, "Preference Sets The Flag",
                           properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                      f"{preference_value:08x}")),
        ]

    def test_the_disagreement_is_detected(self):
        finding = evaluate_control(pol_control(),
                                   self.policy_and_preference(2, 0))

        assert finding["conflict"]["detected"] is True
        assert finding["conflict"]["kind"] == "policy-preference-disagreement"

    def test_the_verdict_follows_the_least_compliant_value(self):
        finding = evaluate_control(pol_control(),
                                   self.policy_and_preference(2, 0))

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED

    def test_each_conflicting_setting_names_its_delivery(self):
        finding = evaluate_control(pol_control(),
                                   self.policy_and_preference(2, 0))

        assert {(setting["value"], setting["delivery"])
                for setting in finding["conflict"]["settings"]} == {
            (2, DELIVERY_REGISTRY_POL), (0, DELIVERY_REGISTRY_PREFERENCE)}
        preference_setting = next(
            s for s in finding["conflict"]["settings"]
            if s["delivery"] == DELIVERY_REGISTRY_PREFERENCE)
        assert preference_setting["preference_action"] == "U"

    def test_the_detail_explains_that_link_precedence_does_not_settle_it(self):
        detail = evaluate_control(
            pol_control(), self.policy_and_preference(2, 0))["conflict"]["detail"]

        assert "client-side extensions" in detail
        assert "not on link precedence" in detail
        assert "tattoos" in detail

    def test_the_conflict_detail_reaches_the_evidence_notes(self):
        finding = evaluate_control(pol_control(),
                                   self.policy_and_preference(2, 0))

        assert finding["conflict"]["detail"] in finding["evidence"]["notes"]

    def test_two_agreeing_mechanisms_are_not_a_conflict(self):
        finding = evaluate_control(pol_control(),
                                   self.policy_and_preference(2, 2))

        assert finding["conflict"] is None
        assert finding["result"] == RESULT_PASS

    def test_an_enforced_link_still_wins_the_conflict_kind(self):
        """An enforced link is the more urgent fact; delivery is added to it."""
        finding = evaluate_control(
            pol_control(), self.policy_and_preference(0, 2, enforced=True))

        assert finding["conflict"]["kind"] == "enforced-override"
        assert "client-side extensions" in finding["conflict"]["detail"]

    def test_two_preferences_disagreeing_is_a_plain_value_disagreement(self):
        """Both sides are preferences, so there is no policy-vs-preference."""
        gpos = [
            preference_gpo(GUID_SIGNING, "First Preference",
                           properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                      "00000002")),
            preference_gpo(GUID_CONFLICT, "Second Preference",
                           properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                      "00000000")),
        ]

        finding = evaluate_control(pol_control(), gpos)

        assert finding["conflict"]["kind"] == "value-disagreement"

    def test_two_policies_disagreeing_still_reads_exactly_as_before(self):
        gpos = [
            pol_gpo(GUID_SIGNING, "First Policy",
                    (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                     dword(2))),
            pol_gpo(GUID_CONFLICT, "Second Policy",
                    (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                     dword(0))),
        ]

        finding = evaluate_control(pol_control(), gpos)

        assert finding["conflict"]["kind"] == "value-disagreement"
        assert "client-side extensions" not in finding["conflict"]["detail"]


class TestLiveVerifiedKdcPreferenceCase:
    """The confirmed live case, reproduced end to end and entirely offline.

    A production domain sets ``DefaultDomainSupportedEncTypes`` to ``0x38`` —
    RC4 and DES disabled for Kerberos at the domain level — through a Registry
    *preference* item, because the value has no ADMX policy behind it. Before
    WP4 the scanner read only ``Registry.pol`` and reported
    ``DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES`` as ``fail`` on a domain
    where it is correctly configured.

    The GPO below has **no** ``Registry.pol`` and **no** ``GptTmpl.inf``: the
    preference item is the only registry source, exactly as observed. Both
    halves of the fix have to hold for this to pass — reading the file at all,
    and reading ``value="00000038"`` as 0x38 rather than as decimal 38.
    """

    def kdc_gpo(self, value="00000038", **kwargs):
        return preference_gpo(
            GUID_SIGNING, "DefaultDomainSupportedEncTypes",
            properties(KDC_PREFERENCE_KEY, "DefaultDomainSupportedEncTypes",
                       value),
            **kwargs)

    def test_the_control_passes_on_a_preference_only_gpo(self):
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)

        finding = evaluate_control(control_obj, [self.kdc_gpo()])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["found_count"] == 1

    def test_the_evidence_shows_56_and_names_the_delivery_mechanism(self):
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)

        found = evaluate_control(
            control_obj, [self.kdc_gpo()])["evidence"]["found"][0]

        assert found["value"] == 56
        assert found["delivery"] == DELIVERY_REGISTRY_PREFERENCE
        assert found["source_file"] == r"Preferences\Registry\Registry.xml"
        assert found["preference"]["action"] == "U"
        assert found["preference"]["tattoos"] is True

    def test_the_finding_still_says_the_value_is_not_policy_enforced(self):
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)

        notes = evaluate_control(
            control_obj, [self.kdc_gpo()])["evidence"]["notes"]

        assert any("TATTOOS" in note for note in notes)

    def test_reading_the_value_as_decimal_would_have_failed_the_control(self):
        """Pins the consequence of the hex/decimal error rather than the parse.

        38 decimal is 0x26 — AES128 plus RC4 plus DES-CBC-MD5. It is not merely
        a different number from 56, it is the RC4-enabled configuration the
        control exists to detect, and the catalog's ``equals 56`` rejects it.
        """
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)

        finding = evaluate_control(control_obj, [self.kdc_gpo(value="00000026")])

        assert finding["result"] == RESULT_FAIL
        assert finding["evidence"]["found"][0]["value"] == 38

    def test_a_domain_with_no_kdc_preference_is_unknown_not_a_failure(self):
        """P2-WP5 changed this verdict, and it is the same defect as WP4's.

        Devore's instruction for this control is to create the value on the
        domain controllers, so a domain that has done exactly that has no GPO
        naming the key. Reporting ``fail`` there was a confident claim the scan
        could not substantiate — the mirror image of the WP4 false pass. It is
        still not a pass; it is not a verdict at all.
        """
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)

        finding = evaluate_control(control_obj, [])

        assert finding["result"] == RESULT_UNKNOWN
        assert finding["result"] != RESULT_PASS
        assert finding["rollout_state"] is None
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_UNKNOWN

    def test_a_gpo_that_deletes_the_value_does_not_pass_the_control(self):
        """Still never a pass; now ``unknown`` and it says the GPO deletes it.

        A Delete item is not a match, so no value was read — and for this control
        no value read means no verdict. The delete is disclosed either way, which
        is the sentence that tells the reader what is going on.
        """
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)
        gpo = preference_gpo(
            GUID_SIGNING, "Undo Enc Types",
            properties(KDC_PREFERENCE_KEY, "DefaultDomainSupportedEncTypes",
                       "00000038", action="D"))

        finding = evaluate_control(control_obj, [gpo])

        assert finding["result"] == RESULT_UNKNOWN
        assert finding["result"] != RESULT_PASS
        assert any("DELETE this value" in note
                   for note in finding["evidence"]["notes"])

    def test_the_wpad_and_wintrust_shapes_from_the_same_domain(self):
        """The other two observed GPOs: a REG_DWORD 'C' and a REG_SZ pair.

        Not catalog controls, so this asserts the *parse and delivery* path over
        a synthetic control per key rather than a shipped verdict.
        """
        wpad = preference_gpo(
            GUID_SIGNING, "Disable WPAD",
            properties(r"SYSTEM\CurrentControlSet\Services"
                       r"\WinHttpAutoProxySvc", "Start", "00000004",
                       action="C"))
        wpad_finding = evaluate_control(
            pol_control(registry_key=r"HKLM\SYSTEM\CurrentControlSet\Services"
                                     r"\WinHttpAutoProxySvc\Start",
                        final_expected=4), [wpad])

        assert wpad_finding["result"] == RESULT_PASS
        assert wpad_finding["evidence"]["found"][0]["value"] == 4
        assert wpad_finding["evidence"]["found"][0]["preference"][
            "corrects_drift"] is False

        wintrust_key = r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
        wintrust = preference_gpo(
            GUID_CONFLICT, "CVE-2013-3900",
            f'action="C" hive="HKEY_LOCAL_MACHINE" key="{wintrust_key}"',
            properties(wintrust_key, "EnableCertPaddingCheck", "1",
                       reg_type="REG_SZ"),
            properties(r"SOFTWARE\WOW6432Node\Microsoft\Cryptography"
                       r"\Wintrust\Config", "EnableCertPaddingCheck", "1",
                       reg_type="REG_SZ"))
        wintrust_finding = evaluate_control(
            pol_control(registry_key=rf"HKLM\{wintrust_key}"
                                     r"\EnableCertPaddingCheck",
                        final_expected=1), [wintrust])

        assert wintrust_finding["result"] == RESULT_PASS
        assert wintrust_finding["evidence"]["found_count"] == 1, \
            "the WOW6432Node twin is a different key and must not double-count"
        assert wintrust_finding["evidence"]["found"][0]["value"] == "1"


class TestPreferencesDoNotDisturbTheRestOfTheEngine:
    """Regression cover: everything that has no preferences behaves as before."""

    def test_a_snapshot_defaults_to_no_preference_entries(self):
        assert GpoSnapshot(dn=gpo_dn(GUID_SIGNING)).registry_xml_entries == ()

    def test_find_preference_non_writes_is_empty_without_preferences(self):
        gpo = pol_gpo(GUID_SIGNING, "Pol Policy",
                      (r"System\CurrentControlSet\Services\Test", "Flag", 4,
                       dword(2)))

        assert find_preference_non_writes(pol_control(), [gpo]) == []

    def test_a_security_template_control_ignores_preferences_entirely(self):
        gpo = preference_gpo(GUID_SIGNING, "Preference Policy",
                             properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                        "00000002"))

        assert find_preference_non_writes(control(), [gpo]) == []

    def test_the_whole_catalog_still_evaluates_against_a_preference_only_gpo(self):
        catalog = load_catalog()
        gpo = preference_gpo(
            GUID_SIGNING, "DefaultDomainSupportedEncTypes",
            properties(KDC_PREFERENCE_KEY, "DefaultDomainSupportedEncTypes",
                       "00000038"))

        findings, counts = evaluate_controls(catalog.controls, [gpo],
                                             directory=clean_directory(catalog),
                                             include_not_applicable=True)

        assert counts["total"] == len(catalog.controls)
        assert counts[RESULT_ERROR] == 0
        kdc = next(f for f in findings if f["control_id"] == KDC_CONTROL_ID)
        assert kdc["result"] == RESULT_PASS

    def test_an_unreadable_gpo_report_is_unaffected_by_preferences(self):
        gpos = [preference_gpo(GUID_SIGNING, "Preference Policy",
                               properties(TEST_FLAG_PREFERENCE_KEY, "Flag",
                                          "00000002")),
                GpoSnapshot(dn=gpo_dn(GUID_ENFORCED), display_name="Broken",
                            read_error="SYSVOL read failed")]

        finding = evaluate_control(pol_control(), gpos)

        assert finding["result"] == RESULT_PASS
        assert any("could not be read" in note
                   for note in finding["evidence"]["notes"])


# --------------------------------------------------------------------------- #
# P2-WP5 — accuracy fixes
# --------------------------------------------------------------------------- #

DIAG_CONTROL_ID = "DEVORE-03-LDAP-DIAG-LOGGING"
DIAG_POL_KEY = r"SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
DIAG_VALUE_NAME = "16 LDAP Interface Events"


def diag_gpo(value, guid=GUID_SIGNING, name="NTDS Diagnostics"):
    """A GPO whose Registry.pol sets the LDAP Interface diagnostic level."""
    return pol_gpo(guid, name, (DIAG_POL_KEY, DIAG_VALUE_NAME, 4, dword(value)),
                   links=(GpoLink(DC_OU),))


class TestLdapDiagnosticLoggingIsAFloorNotAnExactValue:
    """Fix 1a: the NTDS diagnostic levels are 0-5 with increasing verbosity.

    A domain controller logging at level 3 produces everything level 2 produces
    and more — including the 2889 unsigned-bind events this control exists to
    generate. Asserting ``equals 2`` therefore failed a domain that was *more*
    compliant than the baseline asks for, which is the same "states more than the
    evidence supports" defect as the rest of this work package, pointing the
    other way.

    Levels and the default of 0 are Microsoft's: "How to configure Active
    Directory and LDS diagnostic event logging"
    (learn.microsoft.com/troubleshoot/windows-server/active-directory/
    configure-ad-and-lds-event-logging), cited in the control's ``value_source``.
    """

    @pytest.fixture
    def control_obj(self):
        return load_catalog().by_id(DIAG_CONTROL_ID)

    def test_the_shipped_control_asserts_a_floor(self, control_obj):
        assert control_obj.operator == "gte"
        assert control_obj.final_expected == 2

    @pytest.mark.parametrize("value", [2, 3, 4, 5])
    def test_any_level_at_or_above_two_passes(self, control_obj, value):
        finding = evaluate_control(control_obj, [diag_gpo(value)])

        assert finding["result"] == RESULT_PASS, finding["evidence"]
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["found"][0]["value"] == value

    @pytest.mark.parametrize("value", [0, 1])
    def test_a_level_below_two_still_fails(self, control_obj, value):
        finding = evaluate_control(control_obj, [diag_gpo(value)])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED

    def test_the_old_equals_two_assertion_would_have_failed_level_three(
            self, control_obj):
        """The defect, pinned as a counterfactual.

        The same fixture, the same evaluator, one field different: with the
        pre-fix ``equals`` the domain observed at level 3 scores ``fail``, and
        with the shipped ``gte`` it scores ``pass``. Without this assertion
        nothing stops a future edit restoring ``equals`` and re-introducing the
        false negative.
        """
        gpo = diag_gpo(3)
        old = dataclasses.replace(control_obj, operator="equals")

        assert evaluate_control(old, [gpo])["result"] == RESULT_FAIL
        assert evaluate_control(control_obj, [gpo])["result"] == RESULT_PASS

    def test_the_value_source_cites_the_microsoft_levels_document(
            self, control_obj):
        """The floor is a sourced judgement, not a loosened assertion."""
        assert "configure-ad-and-lds-event-logging" in control_obj.value_source

    def test_the_noisy_when_left_raised_caveat_is_kept(self, control_obj):
        assert any("noisy" in caveat for caveat in control_obj.caveats)


class TestAbsenceFromGpoIsNotAlwaysEvidence:
    """Fix 1b: a control a GPO scan cannot see reports ``unknown``, not ``fail``.

    Confirmed live. ``DEVORE-03-LDAP-DIAG-LOGGING`` reported ``fail`` /
    ``not-configured`` on a domain where the value *was* set — to 3, written
    directly on the domain controller, which is what Devore's own instruction for
    that control tells you to do. The catalog asserted a GPO check for a setting
    the source says to set locally, so the scanner issued a confident failure it
    could not substantiate, and an operator spent time on it.

    ``unknown`` is the honest verdict and the more actionable one: it says what
    the scan can and cannot see, and hands over the one command that settles it.
    """

    @pytest.fixture
    def control_obj(self):
        return load_catalog().by_id(DIAG_CONTROL_ID)

    def test_the_key_in_no_gpo_is_unknown_rather_than_a_failure(
            self, control_obj):
        finding = evaluate_control(control_obj, [])

        assert finding["result"] == RESULT_UNKNOWN
        assert finding["result"] != RESULT_FAIL
        assert finding["result"] != RESULT_PASS

    def test_rollout_state_is_null_not_not_started(self, control_obj):
        """``not_started`` would imply a value was read and found too low."""
        finding = evaluate_control(control_obj, [])

        assert finding["rollout_state"] is None

    def test_the_evidence_source_is_unknown_not_not_configured(
            self, control_obj):
        """"We cannot see it" is a different claim from "nothing sets it"."""
        finding = evaluate_control(control_obj, [])

        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_UNKNOWN
        assert finding["evidence"]["source"] != EVIDENCE_SOURCE_NOT_CONFIGURED
        assert finding["evidence"]["found"] == []
        assert finding["evidence"]["found_count"] == 0

    def test_a_note_gives_the_exact_reg_query_command(self, control_obj):
        """Acceptance 3. The exact string, because a paraphrase is not a command."""
        notes = evaluate_control(control_obj, [])["evidence"]["notes"]

        assert any(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS'
            '\\Diagnostics" /v "16 LDAP Interface Events"' in note
            for note in notes), notes

    def test_a_note_says_why_the_scan_cannot_see_it(self, control_obj):
        notes = " ".join(evaluate_control(control_obj, [])["evidence"]["notes"])

        assert "direct registry write on the domain controllers" in notes
        assert "no trace in Group Policy" in notes
        assert "NOT evidence that the value is unset" in notes

    def test_the_check_command_names_the_key_the_control_asserts(
            self, control_obj):
        """Derived from ``registry_key``, so the two can never disagree."""
        notes = " ".join(evaluate_control(control_obj, [])["evidence"]["notes"])

        assert control_obj.absence_check_command in notes
        assert control_obj.registry_value_name in control_obj.absence_check_command

    def test_the_finding_is_still_scored_and_carries_its_remediation(
            self, control_obj):
        """An unknown is a gap in the audit, not a control quietly dropped."""
        finding = evaluate_control(control_obj, [])

        assert finding["scored"] is True
        assert finding["unscored_reason"] is None
        assert finding["remediation"]

    # --- the field changes only the absent case ---------------------------

    @pytest.mark.parametrize("value,expected", [
        (3, RESULT_PASS), (2, RESULT_PASS), (0, RESULT_FAIL)])
    def test_a_gpo_delivered_value_is_scored_exactly_as_before(
            self, control_obj, value, expected):
        finding = evaluate_control(control_obj, [diag_gpo(value)])

        assert finding["result"] == expected
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO
        assert finding["rollout_state"] is not None

    def test_the_verified_kdc_preference_still_passes(self):
        """Acceptance 4: DEVORE-04 is GPO-delivered at 0x38 and must stay pass.

        The live domain delivers this value with a Registry preference item, so
        the control *is* found in a GPO and the new field must not touch it. If
        ``gpo_deliverable`` ever started suppressing found values, this is the
        test that fails.
        """
        control_obj = load_catalog().by_id(KDC_CONTROL_ID)
        gpo = preference_gpo(
            GUID_SIGNING, "DefaultDomainSupportedEncTypes",
            properties(KDC_PREFERENCE_KEY, "DefaultDomainSupportedEncTypes",
                       "00000038"))

        finding = evaluate_control(control_obj, [gpo])

        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_GPO
        assert finding["evidence"]["found"][0]["value"] == 56

    # --- narrowness -------------------------------------------------------

    def test_an_ordinary_control_still_fails_when_its_key_is_unset(self):
        """The narrowness that keeps the tool useful.

        For a control a GPO does deliver, absence from every GPO is strong
        evidence, and it must keep producing the control's ``missing_result``.
        Making every unset key ``unknown`` would gut the tool.
        """
        finding = evaluate_control(pol_control(), [])

        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED

    def test_a_synthetic_control_opts_in_through_the_catalog_only(self):
        """The behaviour is driven by the field, not by the control's identity."""
        opted_in = pol_control(id="TEST-DIRECT-WRITE", gpo_deliverable=False)

        assert evaluate_control(opted_in, [])["result"] == RESULT_UNKNOWN
        assert evaluate_control(pol_control(), [])["result"] == RESULT_FAIL

    # --- interaction with the other "we cannot be sure" branches ----------

    def test_an_unreadable_gpo_is_still_disclosed_on_an_unknown_finding(
            self, control_obj):
        gpos = [GpoSnapshot(dn=gpo_dn(GUID_ENFORCED), display_name="Broken",
                            read_error="SYSVOL read failed")]

        finding = evaluate_control(control_obj, gpos)

        assert finding["result"] == RESULT_UNKNOWN
        assert any("could not be read" in note
                   for note in finding["evidence"]["notes"])

    def test_it_takes_precedence_over_an_os_default(self):
        """A documented default cannot be assumed effective here either.

        The os-default branch concludes that the Windows default *is* the value
        in force, which needs "nothing sets this key" to be established. A
        documented direct-write remediation is precisely the case where absence
        from GPO does not establish it — the same reasoning that makes an
        unreadable GPO refuse the default.
        """
        both = pol_control(
            id="TEST-BOTH", operator="gte", final_expected=2, os_default=1,
            gpo_deliverable=False,
            value_source="Test doc: the compliant value is 2.",
            os_default_source="Test doc: the effective default is 1.")

        finding = evaluate_control(both, [])

        assert finding["result"] == RESULT_UNKNOWN
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_UNKNOWN
        assert finding["evidence"]["os_default"] is None


class TestUnknownFindingsInTheCounts:
    """Acceptance 7 (evaluator half): counted, never hidden, never a pass."""

    def controls(self):
        catalog = load_catalog()
        return [catalog.by_id(DIAG_CONTROL_ID), catalog.by_id(KDC_CONTROL_ID)]

    def test_unknown_has_its_own_count(self):
        _findings, counts = evaluate_controls(self.controls(), [])

        assert counts[RESULT_UNKNOWN] == 2
        assert counts[RESULT_FAIL] == 0
        assert counts[RESULT_PASS] == 0
        assert counts[RESULT_ERROR] == 0

    def test_an_unknown_finding_is_never_hidden(self):
        findings, counts = evaluate_controls(self.controls(), [],
                                             include_not_applicable=False)

        assert len(findings) == 2
        assert counts["hidden"] == 0
        assert counts["rendered"] == 2

    def test_every_result_is_a_known_result_value(self):
        catalog = load_catalog()
        findings, counts = evaluate_controls(catalog.controls, [],
                                             directory=clean_directory(catalog),
                                            include_not_applicable=True)

        assert all(f["result"] in RESULTS for f in findings)
        assert sum(counts[result] for result in RESULTS) == counts["total"]

    def test_the_shipped_catalog_on_an_empty_domain_reports_two_unknowns(self):
        """Pins the blast radius of the change against a real catalog."""
        catalog = load_catalog()

        _findings, counts = evaluate_controls(catalog.controls, [],
                                             directory=clean_directory(catalog),
                                             include_not_applicable=True)

        assert counts[RESULT_UNKNOWN] == 2
        assert counts[RESULT_ERROR] == 0
        assert counts["total"] == len(catalog.controls)


class TestKeyScopedDeletesAreDisclosed:
    """Fix 3: a GPP item deleting the KEY a hardened value lives in.

    ``<Properties action="D" hive="..." key="...\\Wintrust\\Config"/>`` names no
    value, so no value-path comparison can see it — which is how it stayed
    invisible to both ``find_matches`` and ``find_preference_non_writes``. A
    value could therefore read as configured while another GPO removed the key
    underneath it: the P2-WP4 false-pass class one level up.

    The evaluator does not resolve it, because it has no precedence model. It
    discloses it: names the GPO, says what happens if the control passes anyway,
    and points at client-side extension ordering as the thing that decides.
    """

    WINTRUST_KEY = r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
    WINTRUST_CONTROL_KEY = (r"HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust"
                            r"\Config\EnableCertPaddingCheck")

    def wintrust_control(self, **overrides):
        fields = {"registry_key": self.WINTRUST_CONTROL_KEY,
                  "final_expected": 1}
        fields.update(overrides)
        return pol_control(**fields)

    def key_delete_gpo(self, key=None, guid=GUID_CONFLICT,
                       name="Undo Wintrust", item_attrs=""):
        return preference_gpo(guid, name, (
            f'action="D" hive="HKEY_LOCAL_MACHINE" '
            f'key="{key or self.WINTRUST_KEY}"', item_attrs, ""))

    def value_gpo(self, guid=GUID_SIGNING, name="CVE-2013-3900"):
        return preference_gpo(guid, name, properties(
            self.WINTRUST_KEY, "EnableCertPaddingCheck", "1",
            reg_type="REG_SZ"))

    def test_the_key_delete_is_found(self):
        found = find_preference_key_deletes(self.wintrust_control(),
                                           [self.key_delete_gpo()])

        assert len(found) == 1
        assert found[0]["reason"] == NON_WRITE_KEY_DELETE
        assert found[0]["deleted_key"].endswith(self.WINTRUST_KEY)
        assert found[0]["delivery"] == DELIVERY_REGISTRY_PREFERENCE

    def test_it_is_not_counted_as_configuring_the_value(self):
        assert find_matches(self.wintrust_control(),
                           [self.key_delete_gpo()]) == []

    def test_a_passing_value_is_told_that_a_gpo_removes_the_key(self):
        """The false pass this closes: the value is set, the key is deleted."""
        finding = evaluate_control(self.wintrust_control(),
                                  [self.value_gpo(), self.key_delete_gpo()])

        assert finding["result"] == RESULT_PASS, \
            "precedence is not resolved, so the pass stands - but it is disclosed"
        notes = " ".join(finding["evidence"]["notes"])
        assert "DELETE a registry KEY that contains this control's value" in notes
        assert "Undo Wintrust" in notes
        assert "another GPO is removing the key underneath the value" in notes
        assert "client-side extensions run" in notes
        assert "not on link precedence" in notes

    def test_the_note_names_the_key_being_deleted(self):
        finding = evaluate_control(self.wintrust_control(),
                                   [self.value_gpo(), self.key_delete_gpo()])

        assert any(self.WINTRUST_KEY in note
                   for note in finding["evidence"]["notes"])

    def test_a_failing_control_is_told_too(self):
        """It is very often the explanation for the failure being read."""
        finding = evaluate_control(self.wintrust_control(),
                                   [self.key_delete_gpo()])

        assert finding["result"] == RESULT_FAIL
        assert any("DELETE a registry KEY" in note
                   for note in finding["evidence"]["notes"])

    def test_a_parent_key_delete_also_covers_the_value(self):
        """Deleting ...\\Wintrust takes ...\\Wintrust\\Config with it."""
        parent = r"SOFTWARE\Microsoft\Cryptography\Wintrust"

        found = find_preference_key_deletes(
            self.wintrust_control(), [self.key_delete_gpo(key=parent)])

        assert len(found) == 1

    def test_an_unrelated_key_delete_is_not_reported(self):
        found = find_preference_key_deletes(
            self.wintrust_control(),
            [self.key_delete_gpo(key=r"SOFTWARE\Something\Else")])

        assert found == []

    def test_a_sibling_key_with_a_shared_prefix_is_not_reported(self):
        """Path components, not string prefixes: ...\\Config != ...\\ConfigExtra."""
        found = find_preference_key_deletes(
            self.wintrust_control(),
            [self.key_delete_gpo(
                key=r"SOFTWARE\Microsoft\Cryptography\Wintrust\ConfigExtra")])

        assert found == []

    def test_a_disabled_key_delete_deletes_nothing_and_is_not_disclosed(self):
        """Saying a disabled item removes the key would be its own false claim."""
        gpo = self.key_delete_gpo(item_attrs=' disabled="1"')

        assert find_preference_key_deletes(self.wintrust_control(), [gpo]) == []
        finding = evaluate_control(self.wintrust_control(),
                                   [self.value_gpo(), gpo])
        assert not any("DELETE a registry KEY" in note
                       for note in finding["evidence"]["notes"])

    def test_the_hive_spelling_does_not_matter(self):
        """HKEY_LOCAL_MACHINE in the file, HKLM in the catalog."""
        found = find_preference_key_deletes(
            self.wintrust_control(),
            [self.key_delete_gpo(key=self.WINTRUST_KEY.lower())])

        assert len(found) == 1

    def test_a_bare_key_creation_item_is_still_no_disclosure(self):
        """Fix 3 keeps dropping key creations: they configure nothing."""
        creation = preference_gpo(GUID_CONFLICT, "Create Wintrust Key", (
            f'action="C" hive="HKEY_LOCAL_MACHINE" key="{self.WINTRUST_KEY}"',
            "", ""))

        assert creation.registry_xml_entries == []
        assert find_preference_key_deletes(self.wintrust_control(),
                                          [creation]) == []
        finding = evaluate_control(self.wintrust_control(),
                                   [self.value_gpo(), creation])
        assert not any("DELETE a registry KEY" in note
                       for note in finding["evidence"]["notes"])

    def test_a_value_delete_still_reports_as_a_value_delete(self):
        """The two disclosures are distinct and must not be conflated."""
        value_delete = preference_gpo(GUID_CONFLICT, "Undo The Value", properties(
            self.WINTRUST_KEY, "EnableCertPaddingCheck", "1",
            reg_type="REG_SZ", action="D"))

        notes = evaluate_control(self.wintrust_control(),
                                 [value_delete])["evidence"]["notes"]

        assert any("DELETE this value" in note for note in notes)
        assert not any("DELETE a registry KEY" in note for note in notes)

    def test_a_security_template_control_is_unaffected(self):
        """Preferences are only searched for gpo-registry-pol controls."""
        assert find_preference_key_deletes(control(), [self.key_delete_gpo()]) == []

    def test_a_key_delete_does_not_break_an_absent_control(self):
        finding = evaluate_control(
            self.wintrust_control(operator="absent", final_expected=None,
                                  interim_expected=None),
            [self.key_delete_gpo()])

        assert finding["result"] == RESULT_PASS
        assert any("DELETE a registry KEY" in note
                   for note in finding["evidence"]["notes"])

    def test_the_shipped_catalog_still_evaluates_with_a_key_delete_present(self):
        catalog = load_catalog()

        findings, counts = evaluate_controls(
            catalog.controls, [self.key_delete_gpo()],
            include_not_applicable=True, directory=clean_directory(catalog))

        assert counts["total"] == len(catalog.controls)
        assert counts[RESULT_ERROR] == 0
        assert len(findings) == len(catalog.controls)
