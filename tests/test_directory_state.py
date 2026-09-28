"""The directory-state engine: catalog rules, the verdict, the queries, the report.

A directory-state control names a fixed read-only directory query and asserts
that it finds nothing. No network: the LDAP manager is a Mock whose ``search``
answers by filter, and every DN, SID and account name is synthesized.

Several tests here are regressions from an adversarial QA pass. Each one names
the false pass (or false clean) it pins.
"""

import json
from unittest.mock import Mock

import pytest
from aditor.app.render import render_scan_result
from aditor.app.scanning import ScanResult
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
DOMAIN_SID = "S-1-5-21-1111-2222-3333"
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


def obj(name, dn=None, kind="user", detail="synthetic", members=None):
    out = {"value": name, "dn": dn or f"CN={name},{BASE_DN}",
           "object_class": kind, "detail": detail}
    if members is not None:
        out["members"] = members
    return out


def ok(objects=(), notes=()):
    return {"objects": list(objects), "notes": list(notes), "error": None}


# --------------------------------------------------------------------------- #
# A fake directory: answers the scanner's real filter strings
# --------------------------------------------------------------------------- #

def entry(dn, **attributes):
    return {"dn": dn, "attributes": attributes}


class FakeDirectory:
    """Routes each search to a handler by what its filter asks for.

    ``groups`` maps SID -> (sAMAccountName, [member DNs]); a SID absent from
    it is a group the domain doesn't have. ``primary`` maps a RID to the
    accounts using it as their primary group.
    """

    def __init__(self, groups=None, primary=None, spn=(), delegation=(),
                 fail_on=None, forest_root=BASE_DN, member_of=None):
        self.groups = groups if groups is not None else {}
        self.primary = primary or {}
        # group DN -> accounts whose memberOf names it
        self.member_of = member_of or {}
        # the RootDSE's rootDomainNamingContext; None = can't be read
        self.forest_root = forest_root
        self.spn, self.delegation = list(spn), list(delegation)
        self.fail_on = fail_on
        self.filters = []

    def manager(self):
        manager = Mock()
        manager.ad_config.base_dn = BASE_DN
        manager.search.side_effect = self.search
        if self.forest_root is None:
            manager.connect.side_effect = RuntimeError("no RootDSE")
        else:
            manager.connect.return_value.server.info.other = {
                "rootDomainNamingContext": [self.forest_root]}
        return manager

    def search(self, search_base=None, search_filter=None, **_kwargs):
        self.filters.append(search_filter)
        if self.fail_on and self.fail_on in search_filter:
            raise RuntimeError("LDAP server down")
        if search_filter == "(objectClass=*)":
            return [entry(BASE_DN, objectSid=DOMAIN_SID)]
        if "objectSid=" in search_filter:
            sid = search_filter.split("objectSid=", 1)[1].split(")", 1)[0]
            if sid not in self.groups:
                return []
            name, members = self.groups[sid]
            return [entry(f"CN={name},{BASE_DN}", sAMAccountName=name,
                          member=members)]
        if search_filter.startswith("(memberOf="):
            group_dn = search_filter[len("(memberOf="):-1]
            return [entry(dn, sAMAccountName=dn) for dn in
                    self.member_of.get(group_dn, [])]
        if search_filter.startswith("(primaryGroupID="):
            rid = int(search_filter[len("(primaryGroupID="):-1])
            return [entry(dn, sAMAccountName=dn) for dn in
                    self.primary.get(rid, [])]
        if "servicePrincipalName=*" in search_filter:
            return self.spn
        if ":=524288" in search_filter:
            return self.delegation
        return []


def every_group_empty():
    """Every group in the shipped control present, and empty."""
    return {sid: (name, []) for name, sid in (
        ("Account Operators", "S-1-5-32-548"),
        ("Server Operators", "S-1-5-32-549"),
        ("Print Operators", "S-1-5-32-550"),
        ("Backup Operators", "S-1-5-32-551"),
        ("Replicator", "S-1-5-32-552"),
        ("Incoming Forest Trust Builders", "S-1-5-32-557"),
        ("Storage Replica Administrators", "S-1-5-32-582"),
        ("Schema Admins", f"{DOMAIN_SID}-518"),
        ("Group Policy Creator Owners", f"{DOMAIN_SID}-520"),
    )}


def read(directory, *control_ids, catalog=None):
    catalog = catalog or load_catalog()
    controls = [catalog.by_id(cid) for cid in control_ids]
    return Scanner(directory.manager())._read_directory_state(controls)


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
        ({"directory_check": DIRECTORY_CHECK_NON_EMPTY_GROUPS,
          "directory_targets": ["Some Custom Group"]}, "well-known SID"),
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
        return evaluate_control(control, [], {control.id: result})

    def test_nothing_found_is_a_pass(self, control):
        finding = self.run(control, ok())
        assert finding["result"] == RESULT_PASS
        assert finding["rollout_state"] == STATE_ENFORCED
        assert finding["evidence"]["source"] == EVIDENCE_SOURCE_DIRECTORY

    def test_anything_found_is_a_fail_that_lists_it(self, control):
        finding = self.run(control, ok([obj("SRV01$", kind="computer"),
                                        obj("svc-app")]))
        assert finding["result"] == RESULT_FAIL
        assert finding["rollout_state"] == STATE_NOT_STARTED
        assert [o["value"] for o in finding["evidence"]["found"]] == [
            "SRV01$", "svc-app"]

    def test_a_failed_query_is_an_error_never_a_pass(self, control):
        finding = self.run(control, {"objects": [], "notes": [],
                                     "error": "LDAP server down"})
        assert finding["result"] == RESULT_ERROR
        assert "LDAP server down" in finding["error"]

    def test_a_query_that_never_ran_is_an_error_never_a_pass(self, control):
        assert evaluate_control(control, [], directory=None)["result"] == \
            RESULT_ERROR

    def test_the_counts_include_directory_findings(self, control):
        _findings, counts = evaluate_controls(
            [control], [], directory={control.id: ok([obj("svc-app")])})
        assert counts[RESULT_FAIL] == 1 and counts["total"] == 1

    def test_two_controls_sharing_a_query_are_judged_separately(self):
        """QA: results were keyed by query, so the last control's targets
        judged both, and a Schema Admins member passed unseen."""
        groups = every_group_empty()
        groups[f"{DOMAIN_SID}-518"] = ("Schema Admins",
                                       [f"CN=Eve,{BASE_DN}"])
        catalog = catalog_of(
            a_directory_control(id="A",
                                directory_check=DIRECTORY_CHECK_NON_EMPTY_GROUPS,
                                directory_targets=["Schema Admins"]),
            a_directory_control(id="B",
                                directory_check=DIRECTORY_CHECK_NON_EMPTY_GROUPS,
                                directory_targets=["Print Operators"]))
        results = read(FakeDirectory(groups=groups), "A", "B", catalog=catalog)
        findings, _ = evaluate_controls(list(catalog.controls), [],
                                        directory=results)
        verdicts = {f["control_id"]: f["result"] for f in findings}
        assert verdicts == {"A": RESULT_FAIL, "B": RESULT_PASS}


# --------------------------------------------------------------------------- #
# The queries
# --------------------------------------------------------------------------- #

class TestServiceAccountsWithoutAes:

    def result(self, *entries):
        directory = FakeDirectory(spn=list(entries))
        return read(directory, SPN_CONTROL)[SPN_CONTROL], directory

    def test_blank_and_rc4_only_are_listed_and_aes_is_not(self):
        result, directory = self.result(
            entry(f"CN=svc-blank,{BASE_DN}", sAMAccountName="svc-blank"),
            entry(f"CN=svc-rc4,{BASE_DN}", sAMAccountName="svc-rc4",
                  **{"msDS-SupportedEncryptionTypes": 4}),
            entry(f"CN=svc-aes,{BASE_DN}", sAMAccountName="svc-aes",
                  **{"msDS-SupportedEncryptionTypes": 24}),
            entry(f"CN=svc-both,{BASE_DN}", sAMAccountName="svc-both",
                  **{"msDS-SupportedEncryptionTypes": 28}))
        listed = {o["value"]: o["detail"] for o in result["objects"]}
        assert set(listed) == {"svc-blank", "svc-rc4"}
        assert "domain default" in listed["svc-blank"]
        assert "RC4 and no AES" in listed["svc-rc4"]
        spn_filter = directory.filters[0]
        assert "sAMAccountName=krbtgt" in spn_filter
        assert ":1.2.840.113556.1.4.803:=2" in spn_filter

    def test_managed_service_accounts_are_checked_too(self):
        """QA: (objectCategory=person) excluded gMSAs and sMSAs."""
        result, directory = self.result(entry(
            f"CN=gmsa-sql,{BASE_DN}", sAMAccountName="gmsa-sql$",
            objectClass=["top", "user", "computer",
                         "msDS-GroupManagedServiceAccount"],
            **{"msDS-SupportedEncryptionTypes": 4}))
        assert [(o["value"], o["object_class"]) for o in result["objects"]] == [
            ("gmsa-sql$", "managed service account")]
        assert "objectCategory=msDS-GroupManagedServiceAccount" in \
            directory.filters[0]

    def test_an_explicit_zero_is_not_called_not_set(self):
        result, _ = self.result(entry(
            f"CN=svc0,{BASE_DN}", sAMAccountName="svc0",
            **{"msDS-SupportedEncryptionTypes": 0}))
        assert result["objects"][0]["detail"].startswith("set to 0")

    def test_a_malformed_entry_is_listed_not_skipped(self):
        """Skipping it could turn a fail into a pass."""
        result, _ = self.result(
            entry(f"CN=svc-ok,{BASE_DN}", sAMAccountName="svc-ok",
                  **{"msDS-SupportedEncryptionTypes": 24}),
            None)
        assert result["error"] is None
        assert [o["object_class"] for o in result["objects"]] == ["unknown"]
        assert "couldn't be read" in result["objects"][0]["detail"]

    def test_a_bytes_name_still_serialises(self):
        result, _ = self.result(entry(
            f"CN=svc-bytes,{BASE_DN}", sAMAccountName=b"svc-\xff"))
        json.dumps(result)  # would raise on bytes
        assert result["objects"][0]["value"].startswith("svc-")


class TestPrivilegedGroups:

    def result(self, directory):
        return read(directory, GROUPS_CONTROL)[GROUPS_CONTROL]

    def test_an_empty_domain_passes(self):
        result = self.result(FakeDirectory(groups=every_group_empty()))
        assert result["error"] is None and result["objects"] == []

    def test_groups_are_found_by_sid_not_name(self):
        """QA: a localized group was 'not found' by its English name, so a
        member-filled group passed."""
        groups = every_group_empty()
        groups["S-1-5-32-551"] = ("Sicherungs-Operatoren",
                                  [f"CN=Eve,{BASE_DN}"])
        directory = FakeDirectory(groups=groups)
        result = self.result(directory)
        assert [o["value"] for o in result["objects"]] == [
            "Backup Operators (Sicherungs-Operatoren)"]
        assert any("objectSid=S-1-5-32-551" in f for f in directory.filters)
        assert not any("sAMAccountName=Backup Operators" in f
                       for f in directory.filters)

    def test_primary_group_members_are_counted(self):
        """QA: AD leaves an account out of its primary group's ``member``, so
        primaryGroupID=518 hid a Schema Admin."""
        directory = FakeDirectory(groups=every_group_empty(),
                                  primary={518: [f"CN=mallory,{BASE_DN}"]})
        result = self.result(directory)
        assert [o["value"] for o in result["objects"]] == ["Schema Admins"]
        assert "mallory" in result["objects"][0]["detail"]

    def test_a_group_that_must_exist_but_cannot_be_found_is_an_error(self):
        groups = every_group_empty()
        del groups["S-1-5-32-548"]  # Account Operators
        result = self.result(FakeDirectory(groups=groups))
        assert result["error"] and "Account Operators" in result["error"]

    def test_a_forest_root_only_group_missing_in_a_child_domain_is_noted(self):
        groups = every_group_empty()
        del groups[f"{DOMAIN_SID}-518"]  # Schema Admins
        result = self.result(FakeDirectory(groups=groups,
                                           forest_root="DC=local"))
        assert result["error"] is None
        assert any("Schema Admins" in note and "not the forest root" in note
                   for note in result["notes"])

    @pytest.mark.parametrize("forest_root", [BASE_DN, None])
    def test_a_forest_root_only_group_missing_in_the_root_is_an_error(
            self, forest_root):
        """Final QA: in the forest root Schema Admins always exists, so not
        seeing it (hidden by ACL, say) passed quietly. An unreadable RootDSE
        is treated as the root: an error, never a quiet pass."""
        groups = every_group_empty()
        del groups[f"{DOMAIN_SID}-518"]
        result = self.result(FakeDirectory(groups=groups,
                                           forest_root=forest_root))
        assert result["error"] and "Schema Admins" in result["error"]

    def test_a_failed_member_query_is_an_error_not_a_listed_group(self):
        """Final QA: the primaryGroupID search failing listed every domain
        group as an offender ("fix the 2 listed") instead of erroring."""
        directory = FakeDirectory(groups=every_group_empty(),
                                  fail_on="(primaryGroupID=")
        result = self.result(directory)
        assert result["objects"] == [] or result.get("error")
        findings, _ = evaluate_controls(
            [load_catalog().by_id(GROUPS_CONTROL)], [],
            directory=read(directory, GROUPS_CONTROL))
        assert findings[0]["result"] == RESULT_ERROR

    def test_members_are_cross_checked_through_member_of(self):
        """Final QA: AD omits ``member`` when the bind account can't read it,
        which looked like an empty group. The memberOf back-link catches the
        member anyway."""
        groups = every_group_empty()
        groups["S-1-5-32-548"] = ("Account Operators", [])
        directory = FakeDirectory(groups=groups, member_of={
            f"CN=Account Operators,{BASE_DN}": [f"CN=hidden,{BASE_DN}"]})
        result = self.result(directory)
        assert [o["value"] for o in result["objects"]] == ["Account Operators"]
        assert "hidden" in result["objects"][0]["detail"]

    def test_member_names_with_escaped_commas_display_properly(self):
        groups = every_group_empty()
        groups["S-1-5-32-550"] = ("Print Operators",
                                  [f"CN=Doe\\, Jane,OU=People,{BASE_DN}"])
        result = self.result(FakeDirectory(groups=groups))
        assert "Doe, Jane" in result["objects"][0]["detail"]

    def test_the_full_member_list_is_kept_for_the_diff(self):
        groups = every_group_empty()
        members = [f"CN=user{i},{BASE_DN}" for i in range(8)]
        groups["S-1-5-32-550"] = ("Print Operators", members)
        result = self.result(FakeDirectory(groups=groups))
        assert len(result["objects"][0]["members"]) == 8
        assert "and 3 more" in result["objects"][0]["detail"]

    def test_group_names_never_reach_the_filter(self):
        """The catalog names a group; the filter carries only its SID."""
        directory = FakeDirectory(groups=every_group_empty())
        self.result(directory)
        group_filters = [f for f in directory.filters if "objectSid=" in f]
        assert group_filters and not any("Operators" in f
                                         for f in group_filters)


class TestUnconstrainedDelegation:

    def result(self, *entries):
        directory = FakeDirectory(delegation=list(entries))
        return read(directory, DELEGATION_CONTROL)[DELEGATION_CONTROL], directory

    def test_only_writable_dcs_are_excluded_by_account_type(self):
        """QA: the exclusion keyed on primaryGroupID, so a user with
        primaryGroupID=516 (and any RODC) was hidden."""
        _result, directory = self.result()
        delegation_filter = directory.filters[0]
        assert "primaryGroupID" not in delegation_filter
        assert "(!(&(objectCategory=computer)(userAccountControl:" \
            "1.2.840.113556.1.4.803:=8192)))" in delegation_filter

    def test_computers_and_users_are_both_listed(self):
        result, _ = self.result(
            entry(f"CN=SRV01,{BASE_DN}", sAMAccountName="SRV01$",
                  objectClass=["top", "computer"], userAccountControl=0x81000),
            entry(f"CN=backdoor,{BASE_DN}", sAMAccountName="backdoor",
                  objectClass=["top", "user"], userAccountControl=0x80200))
        assert [(o["value"], o["object_class"]) for o in result["objects"]] == [
            ("backdoor", "user"), ("SRV01$", "computer")]

    def test_results_outside_this_domain_are_ignored(self):
        """A referral followed into a child domain must not report that
        domain's accounts as this one's."""
        result, _ = self.result(
            entry(f"CN=local,{BASE_DN}", sAMAccountName="local$",
                  objectClass=["computer"], userAccountControl=0x81000),
            entry("CN=child,DC=child,DC=test,DC=local", sAMAccountName="child$",
                  objectClass=["computer"], userAccountControl=0x81000),
            entry("CN=other,DC=other,DC=local", sAMAccountName="other$",
                  objectClass=["computer"], userAccountControl=0x81000))
        # The child domain's DN ends with this domain's DN too; it is dropped
        # because its DC= components are the child's, not this domain's.
        assert [o["value"] for o in result["objects"]] == ["local$"]

    def test_disabled_accounts_are_listed_and_marked(self):
        result, directory = self.result(entry(
            f"CN=old,{BASE_DN}", sAMAccountName="old$",
            objectClass=["computer"], userAccountControl=0x80002))
        assert "disabled" in result["objects"][0]["detail"]
        assert ":=2)" not in directory.filters[0]

    def test_one_failing_query_does_not_sink_the_others(self):
        directory = FakeDirectory(groups=every_group_empty(),
                                  fail_on="servicePrincipalName")
        results = read(directory, SPN_CONTROL, DELEGATION_CONTROL)
        assert "LDAP server down" in results[SPN_CONTROL]["error"]
        assert results[DELEGATION_CONTROL]["error"] is None

    def test_no_query_runs_when_no_directory_control_is_selected(self):
        directory = FakeDirectory()
        gpo_only = [c for c in load_catalog().controls
                    if c.check_type != "directory-state"]
        assert Scanner(directory.manager())._read_directory_state(gpo_only) == {}
        assert directory.filters == []


# --------------------------------------------------------------------------- #
# The report, the app and the diff
# --------------------------------------------------------------------------- #

def payload_with(delegation=None, groups=None, errors=None, scan_id="a" * 32,
                 timestamp="2026-09-28T09:00:00+00:00"):
    catalog = load_catalog()
    controls = [c for c in catalog.controls if c.check_type == "directory-state"]
    directory = {c.id: ok() for c in controls}
    if delegation is not None:
        directory[DELEGATION_CONTROL] = ok(delegation)
    if groups is not None:
        directory[GROUPS_CONTROL] = ok(groups)
    for control_id in errors or ():
        directory[control_id] = {"objects": [], "notes": [],
                                 "error": "LDAP server down"}
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


def later(**kwargs):
    return payload_with(scan_id="b" * 32,
                        timestamp="2026-09-29T09:00:00+00:00", **kwargs)


def card_for(document, control_id):
    start = document.index(f'id="{control_id.lower()}"')
    return document[start:document.index("</article>", start)]


def evidence_changes_for(diff, control_id):
    return [c for e in diff["evidence_changes"] if e["control_id"] == control_id
            for c in e["evidence"]["changes"]]


class TestReportAppAndDiff:

    def test_a_failing_card_names_what_it_found(self):
        document = render_report(payload_with(
            delegation=[obj("SRV01$", kind="computer")]))
        card = card_for(document, DELEGATION_CONTROL)
        assert "1 listed: SRV01$" in card
        assert "<strong>Target:</strong> none" in card
        assert "Why it is listed" in card
        start = document[document.index('id="start-here"'):]
        assert "Next: fix the 1 listed on the card" in start

    def test_a_failed_query_is_never_described_as_finding_nothing(self):
        """QA: the evidence said 'returned no matching objects' under an
        error."""
        document = render_report(payload_with(errors=[SPN_CONTROL]))
        card = card_for(document, SPN_CONTROL)
        assert "returned no matching objects" not in card
        assert "Not read" in card
        start = document[document.index('id="start-here"'):]
        assert "the directory query failed" in start

    def test_a_passing_control_reads_found_none(self):
        document = render_report(payload_with())
        passes = document[document.index('id="passes"'):]
        row = passes[passes.index(DELEGATION_CONTROL):]
        assert "found none" in row[:row.index("</summary>")]

    def test_the_app_warns_when_directory_queries_failed(self):
        result = ScanResult(ok=True, payload={
            "success": True, "snapshot_name": "s", "snapshot_dir": "/tmp/s",
            "scans_run": 1, "counts": {}, "headline": {},
            "scan": {"gpos_scanned": 0, "gpos_unreadable": 0},
            "directory_errors": [SPN_CONTROL]})
        html = render_scan_result(result)
        assert "1 directory check(s) could not run" in html
        assert SPN_CONTROL in html

    def test_the_diff_sees_a_new_member_in_an_already_populated_group(self):
        """QA: only the group name was compared, so a new Schema Admin made no
        diff entry at all."""
        one = [f"CN=Administrator,{BASE_DN}"]
        two = one + [f"CN=attacker,{BASE_DN}"]
        diff = diff_scans(
            payload_with(groups=[obj("Schema Admins", kind="group",
                                     detail="1 member(s): Administrator",
                                     members=one)]),
            later(groups=[obj("Schema Admins", kind="group",
                              detail="2 member(s): Administrator, attacker",
                              members=two)]))
        assert "value" in {c["field"] for c in
                           evidence_changes_for(diff, GROUPS_CONTROL)}

    def test_the_diff_sees_a_member_swapped_for_another(self):
        """Same count, same shown names (only 5 are shown): the member digest
        is what catches it."""
        base = [f"CN=user{i},{BASE_DN}" for i in range(6)]
        detail = "6 member(s): user0, user1, user2, user3, user4 and 1 more"
        swapped = base[:5] + [f"CN=intruder,{BASE_DN}"]
        diff = diff_scans(
            payload_with(groups=[obj("Print Operators", kind="group",
                                     detail=detail, members=base)]),
            later(groups=[obj("Print Operators", kind="group", detail=detail,
                              members=swapped)]))
        assert evidence_changes_for(diff, GROUPS_CONTROL)

    def test_the_diff_ignores_a_reordered_but_identical_list(self):
        a, b = obj("svc-a"), obj("svc-b")
        diff = diff_scans(payload_with(delegation=[a, b]),
                          later(delegation=[b, a]))
        assert evidence_changes_for(diff, DELEGATION_CONTROL) == []

    def test_the_diff_reports_a_list_change_not_a_gpo_change(self):
        diff = diff_scans(payload_with(delegation=[obj("SRV01$")]),
                          later(delegation=[obj("SRV01$"), obj("svc-app")]))
        fields = {c["field"] for c in evidence_changes_for(diff,
                                                           DELEGATION_CONTROL)}
        assert "value" in fields and "gpo" not in fields

    def test_the_diff_calls_a_new_offender_a_regression(self):
        diff = diff_scans(payload_with(), later(delegation=[obj("svc-app")]))
        assert [r["control_id"] for r in diff["regressions"]] == [
            DELEGATION_CONTROL]
