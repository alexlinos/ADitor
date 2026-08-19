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
"""

import pytest

from aditor.gpo.parsers import (
    parse_ini,
    parse_registry_pol,
    parse_security_template_registry_values,
)
from aditor.hardening.catalog import build_catalog, load_catalog
from aditor.hardening.evaluator import (
    EVIDENCE_SOURCE_GPO,
    EVIDENCE_SOURCE_NOT_CONFIGURED,
    EVIDENCE_SOURCE_OS_DEFAULT,
    EVIDENCE_SOURCE_UNKNOWN,
    RESULT_ERROR,
    RESULT_FAIL,
    RESULT_NOT_APPLICABLE,
    RESULT_PASS,
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
        c.id for c in load_catalog().scored_controls])
    def test_every_active_control_can_pass(self, control_id):
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [self.compliant_gpo(control_obj)])

        assert finding["result"] == RESULT_PASS, finding["evidence"]
        assert finding["rollout_state"] in (STATE_ENFORCED, STATE_AUDIT)

    @pytest.mark.parametrize("control_id", [
        c.id for c in load_catalog().scored_controls
        if c.os_default is None])
    def test_every_active_control_reports_something_on_an_empty_domain(
            self, control_id):
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [])

        assert finding["result"] in (RESULT_FAIL, RESULT_NOT_APPLICABLE)
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_NOT_CONFIGURED
        assert finding["evidence"]["notes"]

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
                                             include_not_applicable=True)

        assert counts["total"] == len(catalog.controls)
        assert counts[RESULT_ERROR] == 0
        assert counts["needs_baseline_value"] == len(catalog.unscored_controls)
        assert counts["scored"] == len(catalog.scored_controls)
        assert len(findings) == len(catalog.controls)
