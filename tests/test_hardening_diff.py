"""Tests for diffing two hardening scans.

**Offline by construction.** The diff is a pure function of two dicts. There is
no LDAP, no SMB, no server, no keychain, no port 8813 and no domain controller
anywhere in this file; ``diff_scan_files`` is exercised against files written
under ``tmp_path``.

**Fixture hygiene.** Every payload is synthesized — ``DC=test,DC=local``,
placeholder GUIDs, invented GPO names. A stored scan embeds the domain's GPO
names, registry values and DNs, so no real scan is committed here or anywhere
else.

The load-bearing tests, in the order the review cares about:

* ``TestAttribution`` — the whole point of the module. Two scans differing only
  in ``catalog_version`` or ``engine_version`` must come back ``ambiguous`` with
  the delta named, because a cross-version difference may be the *tool* rather
  than the domain.
* ``TestTheHistoricalCase`` — the real regression this feature exists to prevent,
  reproduced as a fixture:
  ``DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES`` went ``fail`` → ``pass``
  between two real scans because the scanner learned to read Group Policy
  Preferences (engine 1.1.0 → 1.2.0). The domain never changed. A diff that
  called that domain progress would be exactly the confidently-wrong output this
  project has spent five accuracy passes eliminating.
* ``TestRegressions`` — listed before improvements, and a rollout moving
  ``enforced`` → ``audit`` is a regression even though ``result`` stays ``pass``.
* ``TestCatalogChanges`` — a control new to the catalog is not an improvement.
* ``TestEvidenceChanges`` — same verdict, moved grounds.
* ``TestRefusals`` — different domains, and inputs that are not scans.
"""

import json

import pytest
from aditor.hardening.diff import (
    ATTRIBUTION_AMBIGUOUS,
    ATTRIBUTION_DOMAIN,
    AXIS_EVIDENCE,
    AXIS_RESULT,
    AXIS_ROLLOUT,
    CAUSE_CATALOG_VERSION,
    CAUSE_SCAN_SCOPE,
    DIFF_FORMAT_VERSION,
    DIRECTION_BACKWARDS,
    DIRECTION_FORWARDS,
    DIRECTION_SAME,
    DIRECTION_SIDEWAYS,
    ScanDiffError,
    ScanFileError,
    attribution,
    diff_scan_files,
    diff_scans,
    evidence_changes,
    result_direction,
    rollout_direction,
)
from aditor.hardening.scanfile import write_scan
from aditor.hardening.snapshot import write_snapshot

BASE_DN = "DC=test,DC=local"
OTHER_BASE_DN = "DC=other,DC=local"

GUID_POLICY = "11111111-1111-1111-1111-111111111111"
GUID_PREFERENCE = "22222222-2222-2222-2222-222222222222"

# The control from the real historical case, and the value Devore Part 4 quotes.
KDC_CONTROL = "DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES"
KDC_EXPECTED = 56  # 0x38

SIGNING_CONTROL = "DEVORE-03-LDAP-SERVER-SIGNING"
LLMNR_CONTROL = "DEVORE-06-LLMNR-DISABLE"

# The two engine versions the historical case straddles: 1.2.0 is the release in
# which the scan learned to read Group Policy Preferences.
ENGINE_BEFORE_PREFERENCES = "1.1.0"
ENGINE_WITH_PREFERENCES = "1.2.0"
CATALOG = "2026.08.2"


# --------------------------------------------------------------------------- #
# Synthesized inputs
# --------------------------------------------------------------------------- #

def gpo_dn(guid):
    return f"CN={{{guid}}},CN=Policies,CN=System,{BASE_DN}"


def match(value, guid=GUID_POLICY, display_name="Baseline Policy",
          delivery="registry-pol"):
    """One found value, in the shape the evaluator emits."""
    return {
        "gpo_dn": gpo_dn(guid),
        "gpo_display_name": display_name,
        "gpo_guid": guid,
        "value": value,
        "type_name": "REG_DWORD",
        "delivery": delivery,
        "enforced_link": False,
        "links": [],
    }


def finding(control_id, result="pass", rollout_state="enforced",
            severity="high", source="gpo", found=(), expected=None,
            conflict=None, scored=True, title=None, remediation="Set the value."):
    """One finding, carrying only the fields the diff reads."""
    return {
        "control_id": control_id,
        "title": title or f"Control {control_id}",
        "severity": severity,
        "result": result,
        "rollout_state": rollout_state,
        "scored": scored,
        "remediation": remediation,
        "evidence": {
            "source": source,
            "found": list(found),
            "found_count": len(found),
            "expected": expected or {"operator": "equals", "final": 2},
        },
        "conflict": conflict,
    }


def counts_for(findings, **overrides):
    counts = {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0,
              "error": 0, "conflicts": 0, "total": len(findings), "hidden": 0,
              "rendered": len(findings)}
    for item in findings:
        counts[item["result"]] = counts.get(item["result"], 0) + 1
        if item.get("conflict"):
            counts["conflicts"] += 1
    counts.update(overrides)
    return counts


def scan(findings, catalog_version=CATALOG,
         engine_version=ENGINE_WITH_PREFERENCES, base_dn=BASE_DN,
         scan_id="a" * 32, timestamp="2026-08-01T09:00:00+00:00",
         gpos_scanned=2, gpos_unreadable=0, control_count=None,
         include_not_applicable=True, domain="test.local", counts=None):
    """A whole scan payload around ``findings``.

    ``control_count`` defaults to the number of findings, so a scan is
    "evaluated the whole catalog, hid nothing" unless a test says otherwise —
    which is what makes ``catalog_changes.comparable`` true by default.
    """
    findings = list(findings)
    return {
        "scan": {
            "tool": "scan_hardening",
            "tool_version": engine_version,
            "scan_id": scan_id,
            "timestamp": timestamp,
            "domain": domain,
            "base_dn": base_dn,
            "gpos_scanned": gpos_scanned,
            "gpos_unreadable": gpos_unreadable,
            "include_not_applicable": include_not_applicable,
            "read_only": True,
            "catalog_version": catalog_version,
            "control_count": (len(findings) if control_count is None
                              else control_count),
        },
        "counts": counts if counts is not None else counts_for(findings),
        "findings": findings,
        "unscored_control_ids": [],
        "unknown_control_ids": [],
        "gpo_read_errors": [],
    }


def later(payload, **scan_overrides):
    """A deep copy of ``payload`` as a distinct, later scan."""
    clone = json.loads(json.dumps(payload))
    clone["scan"]["scan_id"] = "b" * 32
    clone["scan"]["timestamp"] = "2026-08-20T09:00:00+00:00"
    clone["scan"].update(scan_overrides)
    return clone


def entry_for(bucket, control_id):
    """The one entry in ``bucket`` for ``control_id``, or None."""
    matches = [e for e in bucket if e["control_id"] == control_id]
    assert len(matches) <= 1, f"{control_id} appears {len(matches)} times"
    return matches[0] if matches else None


# --------------------------------------------------------------------------- #
# Direction of travel
# --------------------------------------------------------------------------- #

class TestDirection:
    """The two rankings the classification rests on."""

    @pytest.mark.parametrize("before,after,expected", [
        ("pass", "pass", DIRECTION_SAME),
        ("pass", "fail", DIRECTION_BACKWARDS),
        ("pass", "unknown", DIRECTION_BACKWARDS),
        # A pass we can no longer confirm is a pass we cannot stand behind.
        ("pass", "error", DIRECTION_BACKWARDS),
        ("fail", "pass", DIRECTION_FORWARDS),
        ("unknown", "pass", DIRECTION_FORWARDS),
        # Deliberately NOT an improvement: the earlier scan could not read it,
        # so "it passes now" is not evidence that anything was fixed.
        ("error", "pass", DIRECTION_SIDEWAYS),
        ("fail", "unknown", DIRECTION_SIDEWAYS),
        ("pass", "not_applicable", DIRECTION_SIDEWAYS),
        ("not_applicable", "pass", DIRECTION_SIDEWAYS),
    ])
    def test_result_direction(self, before, after, expected):
        assert result_direction(before, after) == expected

    @pytest.mark.parametrize("before,after,expected", [
        ("enforced", "enforced", DIRECTION_SAME),
        ("enforced", "audit", DIRECTION_BACKWARDS),
        ("audit", "not_started", DIRECTION_BACKWARDS),
        ("enforced", "not_started", DIRECTION_BACKWARDS),
        ("not_started", "audit", DIRECTION_FORWARDS),
        ("audit", "enforced", DIRECTION_FORWARDS),
        # None is what the evaluator uses for an unknown verdict or an unscored
        # control. It cannot be ranked, so it is never guessed at.
        ("enforced", None, DIRECTION_SIDEWAYS),
        (None, "enforced", DIRECTION_SIDEWAYS),
        (None, None, DIRECTION_SAME),
    ])
    def test_rollout_direction(self, before, after, expected):
        assert rollout_direction(before, after) == expected


# --------------------------------------------------------------------------- #
# Attribution — the whole point
# --------------------------------------------------------------------------- #

class TestAttribution:
    """Acceptance 3: a cross-version diff cannot be read as domain progress."""

    def test_matching_versions_attribute_differences_to_the_domain(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        after = later(before)

        result = diff_scans(before, after)["attribution"]

        assert result["verdict"] == ATTRIBUTION_DOMAIN
        assert result["catalog_version"]["changed"] is False
        assert result["engine_version"]["changed"] is False
        assert "same catalog version" in result["summary"]
        assert "attributed to the domain" in result["summary"]

    def test_a_catalog_version_change_alone_makes_attribution_ambiguous(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      catalog_version="2026.08.2")
        after = later(before, catalog_version="2026.08.3")

        result = diff_scans(before, after)["attribution"]

        assert result["verdict"] == ATTRIBUTION_AMBIGUOUS
        # The delta has to be named, not merely flagged.
        assert result["catalog_version"] == {"before": "2026.08.2",
                                             "after": "2026.08.3",
                                             "changed": True}
        assert "catalog_version 2026.08.2 -> 2026.08.3" in result["reason"]
        assert "engine_version" not in result["reason"]
        assert "potentially attributable to the tool" in result["summary"]
        assert "different expected value" in result["summary"]

    def test_an_engine_version_change_alone_makes_attribution_ambiguous(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      engine_version="1.2.0")
        after = later(before, tool_version="1.3.0")

        result = diff_scans(before, after)["attribution"]

        assert result["verdict"] == ATTRIBUTION_AMBIGUOUS
        assert result["engine_version"] == {"before": "1.2.0",
                                            "after": "1.3.0", "changed": True}
        assert result["catalog_version"]["changed"] is False
        assert "engine_version 1.2.0 -> 1.3.0" in result["reason"]
        assert "catalog_version" not in result["reason"]
        assert "read a source an older one could not" in result["summary"]

    def test_both_versions_changing_names_both_pairs(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      catalog_version="2026.08.2", engine_version="1.1.0")
        after = later(before, catalog_version="2026.08.3",
                      tool_version="1.3.0")

        result = diff_scans(before, after)["attribution"]

        assert result["verdict"] == ATTRIBUTION_AMBIGUOUS
        assert "catalog_version 2026.08.2 -> 2026.08.3" in result["reason"]
        assert "engine_version 1.1.0 -> 1.3.0" in result["reason"]

    def test_attribution_is_the_first_key_in_the_payload(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])

        diff = diff_scans(before, later(before))

        assert list(diff)[0] == "attribution", \
            "attribution must be at the top of the payload, not buried"

    def test_an_engine_version_written_as_engine_version_is_still_read(self):
        """Forward compatibility: the header writes tool_version today."""
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before["scan"].pop("tool_version")
        before["scan"]["engine_version"] = "1.3.0"
        after = later(before)
        after["scan"]["engine_version"] = "1.4.0"

        result = attribution(before, after)

        assert result["engine_version"] == {"before": "1.3.0",
                                            "after": "1.4.0", "changed": True}
        assert result["verdict"] == ATTRIBUTION_AMBIGUOUS

    def test_every_change_entry_carries_the_attribution_verdict(self):
        """A renderer that shows only the entries must still carry the caveat."""
        before = scan([finding(SIGNING_CONTROL, result="fail",
                               rollout_state="not_started", found=[])])
        after = later(before, tool_version="1.4.0")
        after["findings"][0].update(result="pass", rollout_state="enforced",
                                    evidence={"source": "gpo",
                                              "found": [match(2)],
                                              "expected": {"operator": "equals",
                                                           "final": 2}})

        entry = diff_scans(before, after)["improvements"][0]

        assert entry["attribution"] == ATTRIBUTION_AMBIGUOUS
        assert any("may be the scanner or the catalog rather than the domain"
                   in note for note in entry["notes"])
        assert any("do not report it as domain progress" in note
                   for note in entry["notes"])


class TestAttributionCaveats:
    """Things that move a verdict without the domain moving, versions aside."""

    def test_a_different_number_of_gpos_read_is_flagged(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      gpos_scanned=3)
        after = later(before, gpos_scanned=2)

        caveats = diff_scans(before, after)["attribution"]["caveats"]

        assert any("different number of GPOs (3 -> 2)" in c for c in caveats)

    def test_unreadable_gpos_in_either_scan_are_flagged_by_side(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      gpos_unreadable=1)
        after = later(before, gpos_unreadable=0)

        caveats = diff_scans(before, after)["attribution"]["caveats"]

        assert any("could not be read in the before scan" in c for c in caveats)
        assert not any("in the after scan" in c for c in caveats)

    def test_a_different_not_applicable_filter_is_flagged(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      include_not_applicable=True)
        after = later(before, include_not_applicable=False)

        caveats = diff_scans(before, after)["attribution"]["caveats"]

        assert any("include_not_applicable" in c for c in caveats)

    def test_a_narrowed_scan_is_flagged(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      control_count=18)
        after = later(before)

        caveats = diff_scans(before, after)["attribution"]["caveats"]

        assert any("evaluated 1 of the catalog's 18 controls" in c
                   for c in caveats)

    def test_reversed_timestamps_warn_about_the_argument_order(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      timestamp="2026-08-20T09:00:00+00:00")
        after = later(before)
        after["scan"]["timestamp"] = "2026-08-01T09:00:00+00:00"

        caveats = diff_scans(before, after)["attribution"]["caveats"]

        assert any("wrong way round" in c for c in caveats)

    def test_diffing_a_scan_against_itself_says_so(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])

        diff = diff_scans(before, json.loads(json.dumps(before)))

        caveats = diff["attribution"]["caveats"]
        assert any("one scan compared with itself" in c for c in caveats)
        assert diff["totals"]["regressions"] == 0
        assert diff["totals"]["improvements"] == 0
        assert diff["unchanged"] == 1

    def test_a_different_domain_name_under_a_matching_base_dn_is_flagged(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      domain="test.local")
        after = later(before, domain="other.local")

        caveats = diff_scans(before, after)["attribution"]["caveats"]

        assert any("name different domains" in c for c in caveats)

    def test_a_clean_pair_of_scans_has_no_caveats(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])

        assert diff_scans(before, later(before))["attribution"]["caveats"] == []


# --------------------------------------------------------------------------- #
# The real historical case
# --------------------------------------------------------------------------- #

class TestTheHistoricalCase:
    """Acceptance 4, reproduced as a fixture.

    ``DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES`` went ``fail`` → ``pass``
    between two real scans of this project's domain. The value (0x38) had been
    set correctly the whole time by a Group Policy *preference*; what changed was
    the scanner, which learned in engine 1.2.0 to read
    ``Preferences\\Registry\\Registry.xml``. Announcing "you remediated RC4"
    there would have been false.
    """

    def before_scan(self):
        """Engine 1.1.0: the preference is invisible, so the key reads as unset."""
        return scan(
            [finding(KDC_CONTROL, result="fail", rollout_state="not_started",
                     source="not-configured", found=[],
                     expected={"operator": "equals", "interim": None,
                               "final": KDC_EXPECTED},
                     title="Disable RC4 at the domain level on domain "
                           "controllers")],
            catalog_version=CATALOG,
            engine_version=ENGINE_BEFORE_PREFERENCES,
            timestamp="2026-08-10T09:00:00+00:00")

    def after_scan(self):
        """Engine 1.2.0: the same domain, now read correctly."""
        payload = later(self.before_scan(),
                        tool_version=ENGINE_WITH_PREFERENCES)
        payload["findings"][0].update(
            result="pass", rollout_state="enforced",
            evidence={"source": "gpo",
                      "found": [match(KDC_EXPECTED, guid=GUID_PREFERENCE,
                                      display_name="KDC Enc Types Preference",
                                      delivery="registry-preference")],
                      "found_count": 1,
                      "expected": {"operator": "equals", "interim": None,
                                   "final": KDC_EXPECTED}})
        payload["counts"] = counts_for(payload["findings"])
        return payload

    def test_attribution_is_ambiguous_and_names_the_engine_delta(self):
        diff = diff_scans(self.before_scan(), self.after_scan())

        assert diff["attribution"]["verdict"] == ATTRIBUTION_AMBIGUOUS
        assert diff["attribution"]["engine_version"] == {
            "before": ENGINE_BEFORE_PREFERENCES,
            "after": ENGINE_WITH_PREFERENCES, "changed": True}
        # The catalog did not move; the ambiguity is entirely the engine's.
        assert diff["attribution"]["catalog_version"]["changed"] is False
        assert "engine_version 1.1.0 -> 1.2.0" in diff["attribution"]["reason"]

    def test_the_summary_refuses_to_call_it_domain_progress(self):
        summary = diff_scans(self.before_scan(),
                             self.after_scan())["attribution"]["summary"]

        assert "ATTRIBUTION IS AMBIGUOUS" in summary
        assert "none of it can be presented as domain progress" in summary
        # And it cites the actual case, so a reader meets the precedent.
        assert KDC_CONTROL in summary
        assert "Group Policy Preferences" in summary
        assert "nothing in the domain had changed" in summary

    def test_the_control_is_never_presented_as_a_domain_improvement(self):
        diff = diff_scans(self.before_scan(), self.after_scan())

        entry = entry_for(diff["improvements"], KDC_CONTROL)
        assert entry is not None, "the verdict change must still be reported"
        # Reported, but labelled on the entry itself so no renderer can show it
        # without the caveat.
        assert entry["attribution"] == ATTRIBUTION_AMBIGUOUS
        assert entry["result"] == {"before": "fail", "after": "pass",
                                  "direction": DIRECTION_FORWARDS}
        assert any("rather than the domain" in note for note in entry["notes"])
        assert any("do not report it as domain progress" in note
                   for note in entry["notes"])
        # Nothing anywhere in the payload attributes this to the domain.
        assert diff["attribution"]["verdict"] != ATTRIBUTION_DOMAIN
        assert all(e["attribution"] != ATTRIBUTION_DOMAIN
                   for bucket in ("regressions", "improvements",
                                  "other_changes", "evidence_changes")
                   for e in diff[bucket])

    def test_the_evidence_change_shows_the_preference_that_was_always_there(self):
        diff = diff_scans(self.before_scan(), self.after_scan())
        entry = entry_for(diff["improvements"], KDC_CONTROL)

        fields = {change["field"] for change in entry["evidence"]["changes"]}
        assert {"source", "value", "gpo", "delivery"} <= fields
        delivery = next(c for c in entry["evidence"]["changes"]
                        if c["field"] == "delivery")
        assert delivery["after"] == ["registry-preference"]
        assert "TATTOOS" in delivery["detail"]

    def test_the_same_two_findings_on_one_engine_version_read_as_the_domain(self):
        """The control: it is the version delta, not the verdicts, that decides.

        Same before/after findings, same everything, except that both scans ran
        one engine version. Now the improvement *is* the domain's, and the diff
        says so — which is what makes the ambiguous label above meaningful rather
        than a blanket disclaimer.
        """
        before = self.before_scan()
        before["scan"]["tool_version"] = ENGINE_WITH_PREFERENCES
        after = self.after_scan()

        diff = diff_scans(before, after)

        assert diff["attribution"]["verdict"] == ATTRIBUTION_DOMAIN
        entry = entry_for(diff["improvements"], KDC_CONTROL)
        assert entry["attribution"] == ATTRIBUTION_DOMAIN
        assert not any("rather than the domain" in note
                       for note in entry["notes"])


# --------------------------------------------------------------------------- #
# Regressions
# --------------------------------------------------------------------------- #

class TestRegressions:
    """Acceptance 5: regressions first, and a rollout can regress on its own."""

    def test_regressions_are_listed_before_improvements(self):
        keys = list(diff_scans(scan([finding(SIGNING_CONTROL,
                                             found=[match(2)])]),
                               later(scan([finding(SIGNING_CONTROL,
                                                   found=[match(2)])]))))

        assert keys.index("regressions") < keys.index("improvements"), \
            "a regression matters more than an improvement"

    @pytest.mark.parametrize("after_result", ["fail", "unknown"])
    def test_losing_a_pass_is_a_regression(self, after_result):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        after = later(before)
        after["findings"][0].update(result=after_result, rollout_state=None,
                                    evidence={"source": "not-configured",
                                              "found": [], "expected": {}})
        after["counts"] = counts_for(after["findings"])

        diff = diff_scans(before, after)

        entry = entry_for(diff["regressions"], SIGNING_CONTROL)
        assert entry["result"]["after"] == after_result
        assert entry["result"]["direction"] == DIRECTION_BACKWARDS
        assert AXIS_RESULT in entry["changed"]
        assert diff["improvements"] == []

    def test_a_rollout_moving_backwards_is_a_regression_with_result_unchanged(
            self):
        """The headline of acceptance 5: enforced -> audit, result pass both times."""
        before = scan([finding(SIGNING_CONTROL, result="pass",
                               rollout_state="enforced", found=[match(2)])])
        after = later(before)
        after["findings"][0].update(rollout_state="audit")
        after["findings"][0]["evidence"]["found"] = [match(1)]

        diff = diff_scans(before, after)

        entry = entry_for(diff["regressions"], SIGNING_CONTROL)
        assert entry is not None
        assert entry["result"] == {"before": "pass", "after": "pass",
                                  "direction": DIRECTION_SAME}
        assert entry["rollout_state"] == {"before": "enforced",
                                          "after": "audit",
                                          "direction": DIRECTION_BACKWARDS}
        assert entry["changed"] == [AXIS_ROLLOUT, AXIS_EVIDENCE]
        assert any("stepped back from enforcing" in note
                   for note in entry["notes"])
        assert diff["improvements"] == []
        assert diff["evidence_changes"] == [], \
            "a rollout regression must not be filed as an evidence change"

    def test_audit_to_not_started_is_also_a_rollout_regression(self):
        before = scan([finding(LLMNR_CONTROL, result="pass",
                               rollout_state="audit", found=[match(1)])])
        after = later(before)
        after["findings"][0].update(rollout_state="not_started")

        assert entry_for(diff_scans(before, after)["regressions"],
                         LLMNR_CONTROL) is not None

    def test_a_pass_that_became_unreadable_is_a_regression_and_says_why(self):
        """pass -> error: the pass cannot be stood behind, whatever the cause."""
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        after = later(before)
        after["findings"][0].update(result="error", rollout_state=None,
                                   evidence={"source": "unknown", "found": [],
                                             "expected": {}})
        after["counts"] = counts_for(after["findings"])

        entry = entry_for(diff_scans(before, after)["regressions"],
                          SIGNING_CONTROL)

        assert entry is not None
        assert any("has not been shown to have broken" in note
                   for note in entry["notes"])

    def test_regressions_are_ordered_worst_severity_first(self):
        findings = [finding(LLMNR_CONTROL, severity="medium", found=[match(1)]),
                    finding(SIGNING_CONTROL, severity="high", found=[match(2)]),
                    finding("Z-INFO", severity="informational",
                            found=[match(1)])]
        before = scan(findings)
        after = later(before)
        for item in after["findings"]:
            item.update(result="fail", rollout_state="not_started")
            item["evidence"] = {"source": "not-configured", "found": [],
                                "expected": {}}
        after["counts"] = counts_for(after["findings"])

        ids = [e["control_id"]
               for e in diff_scans(before, after)["regressions"]]

        assert ids == [SIGNING_CONTROL, LLMNR_CONTROL, "Z-INFO"]


class TestImprovements:

    @pytest.mark.parametrize("before_result", ["fail", "unknown"])
    def test_reaching_a_pass_is_an_improvement(self, before_result):
        before = scan([finding(SIGNING_CONTROL, result=before_result,
                               rollout_state=None, source="not-configured",
                               found=[])])
        after = later(before)
        after["findings"][0].update(result="pass", rollout_state="enforced",
                                   evidence={"source": "gpo",
                                             "found": [match(2)],
                                             "expected": {}})
        after["counts"] = counts_for(after["findings"])

        diff = diff_scans(before, after)

        assert entry_for(diff["improvements"], SIGNING_CONTROL) is not None
        assert diff["regressions"] == []

    def test_a_rollout_advancing_is_an_improvement(self):
        before = scan([finding(SIGNING_CONTROL, result="pass",
                               rollout_state="audit", found=[match(1)])])
        after = later(before)
        after["findings"][0].update(rollout_state="enforced")
        after["findings"][0]["evidence"]["found"] = [match(2)]

        entry = entry_for(diff_scans(before, after)["improvements"],
                          SIGNING_CONTROL)

        assert entry["rollout_state"]["direction"] == DIRECTION_FORWARDS
        assert entry["result"]["direction"] == DIRECTION_SAME

    def test_a_regression_on_either_axis_outranks_an_advance_on_the_other(self):
        before = scan([finding(SIGNING_CONTROL, result="pass",
                               rollout_state="enforced", found=[match(2)])])
        after = later(before)
        after["findings"][0].update(result="fail", rollout_state="enforced")
        after["counts"] = counts_for(after["findings"])

        diff = diff_scans(before, after)

        assert entry_for(diff["regressions"], SIGNING_CONTROL) is not None
        assert diff["improvements"] == []


class TestOtherChanges:
    """Verdict moves that are neither a clean improvement nor a clean regression.

    They cannot be folded into ``unchanged`` — which is a count of controls that
    did not move — so they get their own list rather than being silently dropped
    or misfiled.
    """

    def test_error_to_pass_is_not_an_improvement(self):
        before = scan([finding(SIGNING_CONTROL, result="error",
                               rollout_state=None, source="unknown", found=[])])
        after = later(before)
        after["findings"][0].update(result="pass", rollout_state="enforced",
                                   evidence={"source": "gpo",
                                             "found": [match(2)],
                                             "expected": {}})
        after["counts"] = counts_for(after["findings"])

        diff = diff_scans(before, after)

        assert diff["improvements"] == []
        entry = entry_for(diff["other_changes"], SIGNING_CONTROL)
        assert entry is not None
        assert any("not evidence that anything was fixed" in note
                   for note in entry["notes"])

    def test_fail_to_unknown_is_neither_direction(self):
        before = scan([finding(SIGNING_CONTROL, result="fail",
                               rollout_state="not_started",
                               source="not-configured", found=[])])
        after = later(before)
        after["findings"][0].update(result="unknown", rollout_state=None,
                                   evidence={"source": "unknown", "found": [],
                                             "expected": {}})
        after["counts"] = counts_for(after["findings"])

        diff = diff_scans(before, after)

        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert entry_for(diff["other_changes"], SIGNING_CONTROL) is not None


# --------------------------------------------------------------------------- #
# Catalog changes
# --------------------------------------------------------------------------- #

class TestCatalogChanges:
    """Acceptance 6: a control new to the catalog is not an improvement."""

    def test_a_newly_added_control_lands_in_catalog_changes_not_improvements(
            self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      catalog_version="2026.08.2")
        after = later(scan([finding(SIGNING_CONTROL, found=[match(2)]),
                            finding(LLMNR_CONTROL, result="pass",
                                    severity="medium", found=[match(1)])],
                           catalog_version="2026.08.3"))

        diff = diff_scans(before, after)

        assert [e["control_id"] for e in diff["catalog_changes"]["added"]] == \
            [LLMNR_CONTROL]
        assert diff["improvements"] == []
        assert diff["regressions"] == []
        assert diff["totals"]["catalog_added"] == 1
        added = diff["catalog_changes"]["added"][0]
        assert added["likely_cause"] == CAUSE_CATALOG_VERSION
        assert added["result"] == "pass"
        assert "not an improvement" in added["note"]

    def test_a_removed_control_is_not_a_regression(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)]),
                       finding(LLMNR_CONTROL, result="fail",
                               rollout_state="not_started", severity="medium",
                               source="not-configured", found=[])],
                      catalog_version="2026.08.2")
        after = later(scan([finding(SIGNING_CONTROL, found=[match(2)])],
                           catalog_version="2026.08.3"))

        diff = diff_scans(before, after)

        assert [e["control_id"] for e in diff["catalog_changes"]["removed"]] == \
            [LLMNR_CONTROL]
        assert diff["regressions"] == []
        assert "not a regression" in diff["catalog_changes"]["removed"][0]["note"]

    def test_the_same_catalog_version_means_a_gap_is_scan_scope_not_the_catalog(
            self):
        """Same catalog version ⇒ same controls, so an absence is scan scope."""
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      control_count=2, counts=counts_for(
                          [finding(SIGNING_CONTROL)], total=1))
        after = later(scan([finding(SIGNING_CONTROL, found=[match(2)]),
                            finding(LLMNR_CONTROL, severity="medium",
                                    found=[match(1)])]))

        changes = diff_scans(before, after)["catalog_changes"]

        assert changes["added"][0]["likely_cause"] == CAUSE_SCAN_SCOPE
        assert "same catalog version" in changes["added"][0]["note"]
        assert changes["comparable"] is False
        assert any("not evaluated by one of the scans" in note
                   for note in changes["notes"])

    def test_a_narrowed_scan_makes_the_comparison_incomparable(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      control_count=18)
        after = later(before)

        changes = diff_scans(before, after)["catalog_changes"]

        assert changes["comparable"] is False
        assert any("narrowed with control_ids" in note
                   for note in changes["notes"])

    def test_hidden_not_applicable_findings_make_it_incomparable(self):
        findings = [finding(SIGNING_CONTROL, found=[match(2)])]
        before = scan(findings, control_count=2,
                      counts=counts_for(findings, total=2, hidden=1))
        after = later(before)

        changes = diff_scans(before, after)["catalog_changes"]

        assert changes["comparable"] is False
        assert any("hid 1 not-applicable finding" in note
                   for note in changes["notes"])

    def test_a_scan_that_does_not_state_its_catalog_size_is_incomparable(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before["scan"].pop("control_count")
        after = later(before)

        changes = diff_scans(before, after)["catalog_changes"]

        assert changes["comparable"] is False
        assert any("does not state how many controls" in note
                   for note in changes["notes"])

    def test_two_full_matching_scans_are_comparable_with_no_notes(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])

        changes = diff_scans(before, later(before))["catalog_changes"]

        assert changes == {"added": [], "removed": [], "comparable": True,
                           "notes": []}


# --------------------------------------------------------------------------- #
# Evidence changes
# --------------------------------------------------------------------------- #

class TestEvidenceChanges:
    """Acceptance 7: the verdict held, the grounds moved."""

    def evidence_diff(self, before_finding, after_finding):
        before = scan([before_finding])
        after = later(scan([after_finding]))
        return diff_scans(before, after)

    def test_a_changed_value_under_an_unchanged_verdict_is_surfaced(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL, found=[match(2)]),
            finding(SIGNING_CONTROL, found=[match(3)]))

        entry = entry_for(diff["evidence_changes"], SIGNING_CONTROL)
        assert entry["changed"] == [AXIS_EVIDENCE]
        assert entry["result"]["direction"] == DIRECTION_SAME
        change = next(c for c in entry["evidence"]["changes"]
                      if c["field"] == "value")
        assert change["before"] == [2]
        assert change["after"] == [3]
        assert diff["unchanged"] == 0

    def test_a_different_gpo_delivering_the_same_value_is_surfaced(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL, found=[match(2, display_name="Old GPO")]),
            finding(SIGNING_CONTROL,
                    found=[match(2, guid=GUID_PREFERENCE,
                                 display_name="New GPO")]))

        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "gpo")
        assert "Old GPO -> New GPO" in change["detail"]

    def test_policy_to_preference_carries_the_tattoo_caveat(self):
        """A pass held by a preference is a weaker statement than by a policy."""
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL,
                    found=[match(2, delivery="registry-pol")]),
            finding(SIGNING_CONTROL,
                    found=[match(2, delivery="registry-preference")]))

        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "delivery")
        assert change["before"] == ["registry-pol"]
        assert change["after"] == ["registry-preference"]
        assert "TATTOOS" in change["detail"]
        assert "weaker statement" in change["detail"]

    def test_preference_to_policy_is_framed_as_a_strengthening(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL,
                    found=[match(2, delivery="registry-preference")]),
            finding(SIGNING_CONTROL,
                    found=[match(2, delivery="registry-pol")]))

        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "delivery")
        assert "strengthening, not a no-op" in change["detail"]

    def test_an_evidence_source_change_is_surfaced(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL, source="gpo", found=[match(2)]),
            finding(SIGNING_CONTROL, source="os-default", found=[]))

        fields = {c["field"] for c in entry_for(diff["evidence_changes"],
                                                SIGNING_CONTROL
                                                )["evidence"]["changes"]}
        assert "source" in fields
        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "source")
        assert change["before"] == "gpo"
        assert change["after"] == "os-default"
        assert "Group Policy is not holding in place" in change["detail"]

    def test_a_conflict_appearing_is_surfaced(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL, found=[match(2)]),
            finding(SIGNING_CONTROL, found=[match(2)],
                    conflict={"detected": True, "kind": "enforced-override",
                              "detail": "..."}))

        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "conflict")
        assert change["before"] is None
        assert change["after"] == "enforced-override"
        assert "A conflict appeared" in change["detail"]
        assert "gpresult" in change["detail"]

    def test_a_conflict_clearing_is_surfaced(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL, found=[match(2)],
                    conflict={"detected": True, "kind": "value-disagreement",
                              "detail": "..."}),
            finding(SIGNING_CONTROL, found=[match(2)]))

        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "conflict")
        assert "conflict cleared" in change["detail"]

    def test_a_changed_expected_value_is_called_a_baseline_change(self):
        diff = self.evidence_diff(
            finding(SIGNING_CONTROL, found=[match(2)],
                    expected={"operator": "equals", "final": 2}),
            finding(SIGNING_CONTROL, found=[match(2)],
                    expected={"operator": "gte", "final": 2}))

        entry = entry_for(diff["evidence_changes"], SIGNING_CONTROL)
        assert any(c["field"] == "expected" for c in entry["evidence"]["changes"])
        assert any("baseline change rather than a domain change" in note
                   for note in entry["notes"])

    def test_a_control_becoming_unscored_is_surfaced_with_the_reason(self):
        before_finding = finding(SIGNING_CONTROL, found=[match(2)], scored=True)
        after_finding = finding(SIGNING_CONTROL, found=[match(2)], scored=False)
        after_finding["unscored_reason"] = "needs_baseline_value"

        diff = self.evidence_diff(before_finding, after_finding)

        entry = entry_for(diff["evidence_changes"], SIGNING_CONTROL)
        change = next(c for c in entry["evidence"]["changes"]
                      if c["field"] == "scored")
        assert change["before"] == {"scored": True, "reason": None}
        assert change["after"] == {"scored": False,
                                   "reason": "needs_baseline_value"}
        assert "change in the tool, not the domain" in change["detail"]
        assert entry["evidence"]["after"]["unscored_reason"] == \
            "needs_baseline_value"

    def test_the_unscored_reason_changing_alone_is_surfaced(self):
        """needs_baseline_value and unsupported_check_type are not the same gap."""
        before_finding = finding(SIGNING_CONTROL, found=[], scored=False)
        before_finding["unscored_reason"] = "needs_baseline_value"
        after_finding = finding(SIGNING_CONTROL, found=[], scored=False)
        after_finding["unscored_reason"] = "unsupported_check_type"

        diff = self.evidence_diff(before_finding, after_finding)

        change = next(c for c in entry_for(diff["evidence_changes"],
                                           SIGNING_CONTROL
                                           )["evidence"]["changes"]
                      if c["field"] == "scored")
        assert change["before"]["reason"] == "needs_baseline_value"
        assert change["after"]["reason"] == "unsupported_check_type"

    def test_identical_findings_produce_no_evidence_changes(self):
        assert evidence_changes(finding(SIGNING_CONTROL, found=[match(2)]),
                                finding(SIGNING_CONTROL,
                                        found=[match(2)])) == []

    def test_two_gpos_setting_the_same_value_is_not_flattened_to_one(self):
        """A multiset, not a set: one GPO and two are different situations."""
        changes = evidence_changes(
            finding(SIGNING_CONTROL, found=[match(2)]),
            finding(SIGNING_CONTROL, found=[match(2),
                                            match(2, guid=GUID_PREFERENCE,
                                                  display_name="Second")]))

        assert {c["field"] for c in changes} >= {"value", "gpo"}

    def test_evidence_changes_ride_along_on_a_verdict_change(self):
        """A regression should still show what moved underneath it."""
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        after = later(before)
        after["findings"][0].update(result="fail", rollout_state="not_started")
        after["findings"][0]["evidence"]["found"] = [match(0)]
        after["counts"] = counts_for(after["findings"])

        entry = entry_for(diff_scans(before, after)["regressions"],
                          SIGNING_CONTROL)

        assert AXIS_EVIDENCE in entry["changed"]
        assert any(c["field"] == "value" for c in entry["evidence"]["changes"])


# --------------------------------------------------------------------------- #
# Counts, totals and the unchanged count
# --------------------------------------------------------------------------- #

class TestCountsAndTotals:

    def test_counts_delta_reports_before_after_and_delta_per_key(self):
        before = scan([finding(SIGNING_CONTROL, result="fail",
                               rollout_state="not_started",
                               source="not-configured", found=[])])
        after = later(before)
        after["findings"][0].update(result="pass", rollout_state="enforced")
        after["findings"][0]["evidence"] = {"source": "gpo",
                                            "found": [match(2)],
                                            "expected": {}}
        after["counts"] = counts_for(after["findings"])

        delta = diff_scans(before, after)["counts_delta"]

        assert delta["pass"] == {"before": 0, "after": 1, "delta": 1}
        assert delta["fail"] == {"before": 1, "after": 0, "delta": -1}
        assert delta["total"] == {"before": 1, "after": 1, "delta": 0}

    def test_a_count_key_present_in_only_one_scan_still_appears(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        after = later(before)
        after["counts"]["brand_new_count"] = 4

        delta = diff_scans(before, after)["counts_delta"]

        assert delta["brand_new_count"] == {"before": 0, "after": 4, "delta": 4}

    def test_non_numeric_counts_do_not_crash_the_delta(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before["counts"]["total"] = "one"
        after = later(before)

        assert diff_scans(before, after)["counts_delta"]["total"]["before"] == 0

    def test_unchanged_is_a_count_not_a_list(self):
        findings = [finding(SIGNING_CONTROL, found=[match(2)]),
                    finding(LLMNR_CONTROL, severity="medium",
                            found=[match(1)])]
        before = scan(findings)

        diff = diff_scans(before, later(before))

        assert diff["unchanged"] == 2
        assert isinstance(diff["unchanged"], int)
        assert diff["totals"]["unchanged"] == 2

    def test_totals_reconcile_with_the_lists(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)]),
                       finding(LLMNR_CONTROL, severity="medium",
                               found=[match(1)])])
        after = later(before)
        after["findings"][0].update(result="fail", rollout_state="not_started")
        after["findings"][1]["evidence"]["found"] = [match(9)]
        after["counts"] = counts_for(after["findings"])

        diff = diff_scans(before, after)

        assert diff["totals"]["regressions"] == len(diff["regressions"]) == 1
        assert diff["totals"]["evidence_changes"] == \
            len(diff["evidence_changes"]) == 1
        assert diff["totals"]["controls_compared"] == 2
        assert (diff["totals"]["regressions"]
                + diff["totals"]["improvements"]
                + diff["totals"]["other_changes"]
                + diff["totals"]["evidence_changes"]
                + diff["unchanged"]) == diff["totals"]["controls_compared"]


# --------------------------------------------------------------------------- #
# Scan metadata
# --------------------------------------------------------------------------- #

class TestScanMetadata:
    """Requirement 3: both scan ids and timestamps, reported."""

    def test_both_scan_ids_and_timestamps_are_reported(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      scan_id="1" * 32, timestamp="2026-08-01T09:00:00+00:00")
        after = later(before)
        after["scan"]["scan_id"] = "2" * 32

        scans = diff_scans(before, after)["scans"]

        assert scans["before"]["scan_id"] == "1" * 32
        assert scans["after"]["scan_id"] == "2" * 32
        assert scans["before"]["timestamp"] == "2026-08-01T09:00:00+00:00"
        assert scans["after"]["timestamp"] == "2026-08-20T09:00:00+00:00"
        assert scans["base_dn"] == BASE_DN
        assert scans["domain"] == "test.local"

    def test_each_side_reports_its_versions_and_read_coverage(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      catalog_version="2026.08.2", engine_version="1.2.0",
                      gpos_scanned=4, gpos_unreadable=1)
        after = later(before)

        side = diff_scans(before, after)["scans"]["before"]

        assert side["catalog_version"] == "2026.08.2"
        assert side["engine_version"] == "1.2.0"
        assert side["gpos_scanned"] == 4
        assert side["gpos_unreadable"] == 1
        assert side["controls_evaluated"] == 1
        assert side["catalog_control_count"] == 1


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #

class TestRefusals:
    """Acceptance 8, plus "that file is not a scan"."""

    def test_two_different_domains_are_refused_with_a_clear_error(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      base_dn=BASE_DN)
        after = later(scan([finding(SIGNING_CONTROL, found=[match(2)])],
                           base_dn=OTHER_BASE_DN))

        with pytest.raises(ScanDiffError, match="different domains") as caught:
            diff_scans(before, after, "before.json", "after.json")

        message = str(caught.value)
        # Both DNs and both file names, so the reader can tell which is which.
        assert BASE_DN in message
        assert OTHER_BASE_DN in message
        assert "before.json" in message
        assert "after.json" in message
        assert "Control ids are shared across domains" in message

    def test_the_base_dn_comparison_is_case_and_space_insensitive(self):
        """DNs are case-insensitive; a casing difference is not a new domain."""
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])],
                      base_dn="DC=test,DC=local")
        after = later(before, base_dn="dc=Test, dc=Local")

        assert diff_scans(before, after)["attribution"]["verdict"] == \
            ATTRIBUTION_DOMAIN

    @pytest.mark.parametrize("side", ["before", "after"])
    def test_a_payload_that_is_not_a_scan_is_refused_by_name(self, side):
        good = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        bad = {"not": "a scan"}
        args = (bad, good) if side == "before" else (good, bad)

        with pytest.raises(ScanFileError, match="not a hardening scan payload") \
                as caught:
            diff_scans(*args, "before.json", "after.json")

        assert f"{side}.json" in str(caught.value)

    def test_a_scan_with_no_base_dn_is_refused_before_the_domain_check(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before["scan"].pop("base_dn")

        with pytest.raises(ScanFileError, match="does not state a 'base_dn'"):
            diff_scans(before, later(scan([])), "before.json", "after.json")

    def test_duplicate_control_ids_are_reported_rather_than_silently_dropped(
            self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)]),
                       finding(SIGNING_CONTROL, found=[match(9)])])
        after = later(before)

        notes = diff_scans(before, after)["notes"]

        assert any(SIGNING_CONTROL in note and "more than once" in note
                   for note in notes)

    def test_findings_that_are_not_objects_are_skipped_not_crashed_on(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before["findings"].append("junk")
        after = later(before)

        assert diff_scans(before, after)["unchanged"] == 1

    def test_a_finding_with_no_control_id_is_skipped(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before["findings"].append({"title": "no id here"})
        after = later(before)

        assert diff_scans(before, after)["totals"]["controls_compared"] == 1


# --------------------------------------------------------------------------- #
# The file wrapper
# --------------------------------------------------------------------------- #

class TestDiffScanFiles:
    """Acceptance 2: written scans read back and diff."""

    def test_two_written_scans_round_trip_into_a_diff(self, tmp_path):
        before = scan([finding(SIGNING_CONTROL, result="fail",
                               rollout_state="not_started",
                               source="not-configured", found=[])])
        after = later(before)
        after["findings"][0].update(result="pass", rollout_state="enforced")
        after["findings"][0]["evidence"] = {"source": "gpo",
                                            "found": [match(2)],
                                            "expected": {}}
        after["counts"] = counts_for(after["findings"])
        before_path = tmp_path / "before.json"
        after_path = tmp_path / "after.json"
        write_scan(before, str(before_path))
        write_scan(after, str(after_path))

        diff = diff_scan_files(str(before_path), str(after_path))

        assert diff["attribution"]["verdict"] == ATTRIBUTION_DOMAIN
        assert entry_for(diff["improvements"], SIGNING_CONTROL) is not None
        assert diff["diff_format_version"] == DIFF_FORMAT_VERSION

    def test_the_diff_names_the_files_it_came_from(self, tmp_path):
        payload = scan([finding(SIGNING_CONTROL, found=[match(2)])])
        before_path = tmp_path / "before.json"
        after_path = tmp_path / "after.json"
        write_scan(payload, str(before_path))
        write_scan(later(payload), str(after_path))

        scans = diff_scan_files(str(before_path), str(after_path))["scans"]

        assert scans["before"]["source"] == str(before_path)
        assert scans["after"]["source"] == str(after_path)

    def test_a_missing_file_is_refused(self, tmp_path):
        payload = tmp_path / "before.json"
        write_scan(scan([finding(SIGNING_CONTROL, found=[match(2)])]),
                   str(payload))

        with pytest.raises(ScanFileError, match="does not exist"):
            diff_scan_files(str(payload), str(tmp_path / "gone.json"))

    def test_diffing_the_same_file_twice_reports_no_change(self, tmp_path):
        path = tmp_path / "scan.json"
        write_scan(scan([finding(SIGNING_CONTROL, found=[match(2)])]),
                   str(path))

        diff = diff_scan_files(str(path), str(path))

        assert diff["totals"]["regressions"] == 0
        assert diff["totals"]["improvements"] == 0
        assert diff["unchanged"] == 1
        assert any("one scan compared with itself" in caveat
                   for caveat in diff["attribution"]["caveats"])


class TestDiffingSnapshotFolders:
    """Acceptance 6: a snapshot folder stands in for the scan.json inside it.

    Once a scan is a folder, ``diff <folder-a> <folder-b>`` is the natural thing
    to type, and a caller should not have to reach inside for the payload.
    """

    def improved_pair(self):
        """A before/after pair where the signing control was remediated."""
        before = scan([finding(SIGNING_CONTROL, result="fail",
                               rollout_state="not_started",
                               source="not-configured", found=[])])
        after = later(before)
        after["findings"][0].update(result="pass", rollout_state="enforced")
        after["findings"][0]["evidence"] = {"source": "gpo",
                                            "found": [match(2)],
                                            "expected": {}}
        after["counts"] = counts_for(after["findings"])
        return before, after

    def test_two_snapshot_folders_diff_without_naming_scan_json(self, tmp_path):
        before, after = self.improved_pair()
        first = write_snapshot(before, str(tmp_path))
        second = write_snapshot(after, str(tmp_path))

        diff = diff_scan_files(str(first.folder), str(second.folder))

        assert diff["attribution"]["verdict"] == ATTRIBUTION_DOMAIN
        assert entry_for(diff["improvements"], SIGNING_CONTROL) is not None

    def test_folders_give_exactly_what_the_two_scan_json_paths_give(self,
                                                                   tmp_path):
        """The headline of acceptance 6: same result, either way in."""
        before, after = self.improved_pair()
        first = write_snapshot(before, str(tmp_path))
        second = write_snapshot(after, str(tmp_path))

        from_folders = diff_scan_files(str(first.folder), str(second.folder))
        from_files = diff_scan_files(str(first.scan_path),
                                     str(second.scan_path))

        assert from_folders == from_files

    def test_the_diff_names_the_scan_file_it_actually_read(self, tmp_path):
        """``source`` has to name the file, not the folder: a reader asking
        "which payload produced this?" needs the payload's path."""
        before, after = self.improved_pair()
        first = write_snapshot(before, str(tmp_path))
        second = write_snapshot(after, str(tmp_path))

        scans = diff_scan_files(str(first.folder), str(second.folder))["scans"]

        assert scans["before"]["source"] == str(first.scan_path)
        assert scans["after"]["source"] == str(second.scan_path)

    def test_a_folder_and_a_file_can_be_mixed(self, tmp_path):
        """The existing tool takes files; adding folders must not force a choice."""
        before, after = self.improved_pair()
        snapshot = write_snapshot(before, str(tmp_path))
        after_path = tmp_path / "after.json"
        write_scan(after, str(after_path))

        diff = diff_scan_files(str(snapshot.folder), str(after_path))

        assert entry_for(diff["improvements"], SIGNING_CONTROL) is not None

    def test_a_directory_with_no_scan_json_is_refused_clearly(self, tmp_path):
        before, _ = self.improved_pair()
        snapshot = write_snapshot(before, str(tmp_path))
        not_a_snapshot = tmp_path / "downloads"
        not_a_snapshot.mkdir()

        with pytest.raises(ScanFileError) as raised:
            diff_scan_files(str(snapshot.folder), str(not_a_snapshot))

        assert str(not_a_snapshot) in str(raised.value)
        assert "holds no scan.json" in str(raised.value)

    def test_a_plain_file_path_is_unaffected_by_the_folder_support(self,
                                                                  tmp_path):
        """The pre-existing error messages must still name what was asked for."""
        with pytest.raises(ScanFileError, match="does not exist"):
            diff_scan_files(str(tmp_path / "a.json"), str(tmp_path / "b.json"))


# --------------------------------------------------------------------------- #
# Payload shape
# --------------------------------------------------------------------------- #

class TestPayloadShape:

    def test_the_payload_is_json_serialisable_and_ordered_for_a_reader(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])

        diff = diff_scans(before, later(before))
        json.dumps(diff)  # must not raise

        assert list(diff) == [
            "attribution", "scans", "regressions", "improvements",
            "other_changes", "unchanged", "catalog_changes",
            "evidence_changes", "counts_delta", "totals", "notes",
            "diff_format_version",
        ]

    def test_the_standing_notes_explain_the_rules_the_diff_applied(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)])])

        notes = " ".join(diff_scans(before, later(before))["notes"])

        assert "matched on control_id" in notes
        assert "rollout state moving backwards" in notes
        assert "pass -> error is a regression" in notes
        assert "Policy precedence (RSoP) is not resolved" in notes

    def test_an_empty_scan_pair_diffs_to_nothing_without_crashing(self):
        before = scan([])

        diff = diff_scans(before, later(before))

        assert diff["unchanged"] == 0
        assert diff["regressions"] == []
        assert diff["improvements"] == []
        assert diff["catalog_changes"]["added"] == []

    def test_every_entry_carries_the_remediation_so_a_reader_can_act(self):
        before = scan([finding(SIGNING_CONTROL, found=[match(2)],
                               remediation="Set LDAPServerIntegrity to 2.")])
        after = later(before)
        after["findings"][0].update(result="fail", rollout_state="not_started")
        after["counts"] = counts_for(after["findings"])

        entry = entry_for(diff_scans(before, after)["regressions"],
                          SIGNING_CONTROL)

        assert entry["remediation"] == "Set LDAPServerIntegrity to 2."
