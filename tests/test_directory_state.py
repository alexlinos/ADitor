"""The directory-state engine: catalog rules, the verdict, the queries, the report.

A directory-state control names a fixed read-only directory query and asserts
that it finds nothing. No network: the LDAP manager is a Mock whose ``search``
answers by filter, and every DN and account name is synthesized.
"""

from unittest.mock import Mock

import pytest
from aditor.hardening.catalog import (
    DIRECTORY_CHECK_NON_EMPTY_GROUPS,
    DIRECTORY_CHECK_SPN_WITHOUT_AES,
    DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION,
    CatalogError,
    build_catalog,
    load_catalog,
)
from aditor.hardening.collect import Scanner
from aditor.hardening.diff import diff_scans
from aditor.hardening.evaluator import (
    EVIDENCE_SOURCE_DIRECTORY,
    RESULT_ERROR,
    RESULT_FAIL,
    RESULT_PASS,
    STATE_ENFORCED,
    STATE_NOT_STARTED,
    evaluate_control,
    evaluate_controls,
)
from aditor.hardening.report import render_report

BASE_DN = "DC=test,DC=local"
SPN_CONTROL = "DEVORE-04-SPN-ACCOUNTS-AES"
GROUPS_CONTROL = "DEVORE-07-EMPTY-PRIVILEGED-GROUPS"
DELEGATION_CONTROL = "DEVORE-07-UNCONSTRAINED-DELEGATION"


def a_directory_control(**overrides):
    control = {
        "id": "TEST-DIR", "title": "Synthetic directory control",
        "source": {"part": 7, "url": "https://example.invalid/doc"},
        "scope": "domain-root", "check_type": "directory-state",
        "severity": "high", "status": "active", "operator": "absent",
        "directory_check": DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION,
        "value_source": "Synthetic.", "remediation": "Fix the listed objects.",
        "caveats": ["Synthetic caveat."],
    }
    control.update(overrides)
    return control


def catalog_of(*controls):
    return build_catalog({"catalog_version": "test", "baseline": {},
                          "controls": list(controls)}, "<test>")


def obj(name, dn=None, kind="user", detail="synthetic"):
    return {"value": name, "dn": dn or f"CN={name},{BASE_DN}",
            "object_class": kind, "detail": detail}


# --------------------------------------------------------------------------- #
# Catalog rules
# --------------------------------------------------------------------------- #

class TestCatalogRules:

    def test_a_well_formed_directory_control_loads(self):
        control = catalog_of(a_directory_control()).by_id("TEST-DIR")
        assert control.directory_check == DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION
        assert control.scored

    @pytest.mark.parametrize("overrides, message", [
        ({"directory_check": None}, "directory_check"),
        ({"directory_check": "(objectClass=*)"}, "directory_check"),
        ({"operator": "equals", "final_expected": 1}, "operator must be 'absent'"),
        ({"registry_key": r"HKLM\Software\X"}, "registry_key"),
        ({"missing_result": "fail"}, "missing_result"),
        ({"directory_check": DIRECTORY_CHECK_NON_EMPTY_GROUPS},
         "directory_targets"),
        ({"directory_check": DIRECTORY_CHECK_NON_EMPTY_GROUPS,
          "directory_targets": []}, "directory_targets"),
        ({"directory_targets": ["Schema Admins"]}, "takes no"),
    ])
    def test_malformed_directory_controls_are_refused(self, overrides, message):
        with pytest.raises(CatalogError, match=message):
            catalog_of(a_directory_control(**overrides))

    def test_a_gpo_control_cannot_name_a_directory_query(self):
        gpo = {
            "id": "TEST-GPO", "title": "t",
            "source": {"part": 1, "url": "https://example.invalid/doc"},
            "scope": "all", "check_type": "gpo-registry-pol",
            "severity": "low", "status": "active", "operator": "equals",
            "registry_key": r"HKLM\Software\Test\Value", "final_expected": 1,
            "missing_result": "fail", "remediation": "Set it.",
            "directory_check": DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION,
        }
        with pytest.raises(CatalogError, match="only apply to directory-state"):
            catalog_of(gpo)

    def test_the_shipped_catalog_carries_all_three_checks(self):
        checks = {c.directory_check for c in load_catalog().controls
                  if c.check_type == "directory-state"}
        assert checks == {DIRECTORY_CHECK_SPN_WITHOUT_AES,
                          DIRECTORY_CHECK_NON_EMPTY_GROUPS,
                          DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION}


# --------------------------------------------------------------------------- #
# The verdict
# --------------------------------------------------------------------------- #

class TestVerdict:

    @pytest.fixture
    def control(self):
        return load_catalog().by_id(DELEGATION_CONTROL)

    def run(self, control, result):
        return evaluate_control(control, [],
                                {control.directory_check: result})

    def test_nothing_found_is_a_pass(self, control):
        finding = self.run(control, {"objects": [], "notes": [], "error": None})
        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_DIRECTORY

    def test_anything_found_is_a_fail_that_lists_it(self, control):
        found = [obj("SRV01$", kind="computer"), obj("svc-app")]
        finding = self.run(control, {"objects": found, "notes": [],
                                     "error": None})
        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert [o["value"] for o in finding["evidence"]["found"]] == [
            "SRV01$", "svc-app"]
        assert finding["evidence"]["found_count"] == 2

    def test_a_failed_query_is_an_error_never_a_pass(self, control):
        finding = self.run(control, {"objects": [], "notes": [],
                                     "error": "LDAP server down"})
        assert finding["result"] == RESULT_ERROR
        assert "LDAP server down" in finding["error"]

    def test_a_query_that_never_ran_is_an_error_never_a_pass(self, control):
        finding = evaluate_control(control, [], directory=None)
        assert finding["result"] == RESULT_ERROR

    def test_the_counts_include_directory_findings(self, control):
        _findings, counts = evaluate_controls(
            [control], [], directory={control.directory_check: {
                "objects": [obj("svc-app")], "notes": [], "error": None}})
        assert counts[RESULT_FAIL] == 1 and counts["total"] == 1


# --------------------------------------------------------------------------- #
# The queries
# --------------------------------------------------------------------------- #

def entry(dn, **attributes):
    return {"dn": dn, "attributes": attributes}


def manager_answering(answers, fail_on=None):
    """A Mock LDAP manager: ``answers`` maps a filter substring to results."""
    manager = Mock()
    manager.ad_config.base_dn = BASE_DN
    seen = []

    def search(search_base=None, search_filter=None, **_kwargs):
        seen.append(search_filter)
        if fail_on and fail_on in search_filter:
            raise RuntimeError("LDAP server down")
        for needle, result in answers.items():
            if needle in search_filter:
                return result
        return []
    manager.search.side_effect = search
    manager.filters = seen
    return manager


def read(manager, *control_ids):
    catalog = load_catalog()
    controls = [catalog.by_id(cid) for cid in control_ids]
    return Scanner(manager)._read_directory_state(controls)


class TestQueries:

    def test_spn_accounts_without_aes_are_listed_and_aes_ones_are_not(self):
        manager = manager_answering({"servicePrincipalName=*": [
            entry(f"CN=svc-blank,{BASE_DN}", sAMAccountName="svc-blank"),
            entry(f"CN=svc-rc4,{BASE_DN}", sAMAccountName="svc-rc4",
                  **{"msDS-SupportedEncryptionTypes": 4}),
            entry(f"CN=svc-aes,{BASE_DN}", sAMAccountName="svc-aes",
                  **{"msDS-SupportedEncryptionTypes": 24}),
        ]})
        result = read(manager, SPN_CONTROL)[DIRECTORY_CHECK_SPN_WITHOUT_AES]
        assert [o["value"] for o in result["objects"]] == ["svc-blank",
                                                           "svc-rc4"]
        assert "not set" in result["objects"][0]["detail"]
        # The query itself skips krbtgt and disabled accounts.
        spn_filter = next(f for f in manager.filters
                          if "servicePrincipalName" in f)
        assert "sAMAccountName=krbtgt" in spn_filter
        assert ":1.2.840.113556.1.4.803:=2" in spn_filter

    def test_only_groups_with_members_are_listed(self):
        manager = manager_answering({
            "sAMAccountName=Schema Admins": [entry(
                f"CN=Schema Admins,{BASE_DN}", sAMAccountName="Schema Admins",
                member=[f"CN=Administrator,CN=Users,{BASE_DN}"])],
            "sAMAccountName=Backup Operators": [entry(
                f"CN=Backup Operators,CN=Builtin,{BASE_DN}",
                sAMAccountName="Backup Operators", member=[])],
        })
        result = read(manager, GROUPS_CONTROL)[DIRECTORY_CHECK_NON_EMPTY_GROUPS]
        assert [o["value"] for o in result["objects"]] == ["Schema Admins"]
        assert "1 member(s): Administrator" in result["objects"][0]["detail"]
        # Groups this domain doesn't have are noted, not reported.
        assert any("does not exist" in note for note in result["notes"])

    def test_group_names_are_escaped_in_the_filter(self):
        manager = manager_answering({})
        catalog = catalog_of(a_directory_control(
            directory_check=DIRECTORY_CHECK_NON_EMPTY_GROUPS,
            directory_targets=["Evil*)(objectClass=*"]))
        Scanner(manager)._read_directory_state(list(catalog.controls))
        assert "Evil\\2a\\29\\28objectClass=\\2a" in manager.filters[0]

    def test_unconstrained_delegation_excludes_domain_controllers(self):
        manager = manager_answering({":1.2.840.113556.1.4.803:=524288": [
            entry(f"CN=SRV01,{BASE_DN}", sAMAccountName="SRV01$",
                  objectClass=["top", "computer"]),
        ]})
        result = read(manager, DELEGATION_CONTROL)[
            DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION]
        assert [(o["value"], o["object_class"]) for o in result["objects"]] == [
            ("SRV01$", "computer")]
        delegation_filter = manager.filters[0]
        assert "(!(primaryGroupID=516))" in delegation_filter
        assert "(!(primaryGroupID=521))" in delegation_filter

    def test_one_failing_query_does_not_sink_the_others(self):
        manager = manager_answering({}, fail_on="servicePrincipalName")
        results = read(manager, SPN_CONTROL, DELEGATION_CONTROL)
        assert "LDAP server down" in results[DIRECTORY_CHECK_SPN_WITHOUT_AES][
            "error"]
        assert results[DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION]["error"] is None

    def test_no_query_runs_when_no_directory_control_is_selected(self):
        manager = manager_answering({})
        catalog = load_catalog()
        gpo_only = [c for c in catalog.controls
                    if c.check_type != "directory-state"]
        assert Scanner(manager)._read_directory_state(gpo_only) == {}
        manager.search.assert_not_called()


# --------------------------------------------------------------------------- #
# The report and the diff
# --------------------------------------------------------------------------- #

def payload_with(delegation_objects, scan_id="a" * 32,
                 timestamp="2026-09-28T09:00:00+00:00"):
    catalog = load_catalog()
    controls = [c for c in catalog.controls if c.check_type == "directory-state"]
    directory = {c.directory_check: {"objects": [], "notes": [], "error": None}
                 for c in controls}
    directory[DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION]["objects"] = \
        delegation_objects
    findings, counts = evaluate_controls(controls, [], True, directory)
    return {
        "scan": {"tool": "scan_hardening", "tool_version": "1.4.0",
                 "scan_id": scan_id, "timestamp": timestamp,
                 "domain": "test.local", "base_dn": BASE_DN,
                 "gpos_scanned": 0, "gpos_unreadable": 0,
                 "include_not_applicable": True, "read_only": True,
                 **catalog.provenance()},
        "counts": counts, "findings": findings,
        "unscored_control_ids": [], "unknown_control_ids": [],
        "gpo_read_errors": [],
    }


class TestReportAndDiff:

    def test_a_failing_card_names_what_it_found(self):
        document = render_report(payload_with([obj("SRV01$", kind="computer")]))
        card = document[document.index(f'id="{DELEGATION_CONTROL.lower()}"'):]
        card = card[:card.index("</article>")]
        assert "1 listed: SRV01$" in card
        assert "<strong>Target:</strong> none" in card
        assert "Why it is listed" in card  # the evidence table
        start = document[document.index('id="start-here"'):]
        assert "Next: fix the 1 listed on the card" in start

    def test_a_passing_control_says_nothing_was_found(self):
        document = render_report(payload_with([]))
        assert DELEGATION_CONTROL in document[document.index('id="passes"'):]

    def test_the_diff_reports_the_list_changing_not_a_gpo_changing(self):
        before = payload_with([obj("SRV01$", kind="computer")])
        after = payload_with([obj("SRV01$", kind="computer"), obj("svc-app")],
                             scan_id="b" * 32,
                             timestamp="2026-09-29T09:00:00+00:00")
        diff = diff_scans(before, after)
        changes = [c for entry in diff["evidence_changes"]
                   if entry["control_id"] == DELEGATION_CONTROL
                   for c in entry["evidence"]["changes"]]
        fields = {c["field"] for c in changes}
        assert "value" in fields
        assert "gpo" not in fields

    def test_the_diff_calls_a_new_offender_a_regression(self):
        before = payload_with([])
        after = payload_with([obj("svc-app")], scan_id="b" * 32,
                             timestamp="2026-09-29T09:00:00+00:00")
        diff = diff_scans(before, after)
        assert [r["control_id"] for r in diff["regressions"]] == [
            DELEGATION_CONTROL]
