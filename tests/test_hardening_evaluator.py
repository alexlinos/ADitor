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
"""

import pytest

from aditor.gpo.parsers import (
    parse_ini,
    parse_registry_pol,
    parse_security_template_registry_values,
)
from aditor.hardening.catalog import build_catalog, load_catalog
from aditor.hardening.evaluator import (
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
        c.id for c in load_catalog().scored_controls])
    def test_every_active_control_reports_something_on_an_empty_domain(
            self, control_id):
        control_obj = load_catalog().by_id(control_id)

        finding = evaluate_control(control_obj, [])

        assert finding["result"] in (RESULT_FAIL, RESULT_NOT_APPLICABLE)
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert finding["evidence"]["notes"]

    def test_the_whole_catalog_evaluates_against_an_empty_domain(self):
        catalog = load_catalog()

        findings, counts = evaluate_controls(catalog.controls, [],
                                             include_not_applicable=True)

        assert counts["total"] == len(catalog.controls)
        assert counts[RESULT_ERROR] == 0
        assert counts["needs_baseline_value"] == len(catalog.unscored_controls)
        assert counts["scored"] == len(catalog.scored_controls)
        assert len(findings) == len(catalog.controls)
