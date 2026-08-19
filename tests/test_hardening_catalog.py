"""Tests for the hardening control catalog and its validating loader.

Two jobs here:

1. The *loader* rejects malformed catalogs with a clear, id-bearing error —
   unknown check_type/operator/status, duplicate ids, missing fields, unknown
   fields, an assertion with no expected value, and (the important one) a
   ``needs_baseline_value`` control that carries a guessed value anyway.
2. The *shipped* catalog holds to its own invariants: every control cites a
   source, every active control is deterministically evaluatable, and every
   control the source leaves undefined is present, flagged, and unscored.

Everything is offline: JSON dicts and the packaged data file, no LDAP, no SMB.
"""

import json

import pytest

from aditor.hardening.catalog import (
    CHECK_TYPES,
    DEFAULT_CATALOG_PATH,
    EVALUABLE_CHECK_TYPES,
    MISSING_RESULTS,
    OPERATORS,
    PRESENCE_OPERATORS,
    SEVERITIES,
    STATUS_ACTIVE,
    STATUS_NEEDS_BASELINE_VALUE,
    VALUE_OPERATORS,
    Catalog,
    CatalogError,
    build_catalog,
    load_catalog,
)


def a_control(**overrides):
    """A minimal valid active control; override one field per test."""
    control = {
        "id": "TEST-01",
        "title": "A test control",
        "source": {"part": 1, "url": "https://example.invalid/part-1"},
        "scope": "all",
        "check_type": "gpo-security-template",
        "severity": "high",
        "status": STATUS_ACTIVE,
        "operator": "equals",
        "registry_key": "HKLM\\Software\\Test\\Flag",
        "registry_type": "REG_DWORD",
        "final_expected": 1,
        "missing_result": "fail",
        "remediation": "Set the thing.",
    }
    control.update(overrides)
    return {k: v for k, v in control.items() if v is not _OMIT}


_OMIT = object()


def a_catalog(*controls, **overrides):
    """A minimal valid catalog document around the given controls."""
    document = {
        "catalog_version": "test-1",
        "baseline": {"primary_source": "test"},
        "controls": list(controls) or [a_control()],
    }
    document.update(overrides)
    return {k: v for k, v in document.items() if v is not _OMIT}


class TestLoaderAcceptsValidCatalogs:

    def test_minimal_catalog_builds(self):
        catalog = build_catalog(a_catalog())

        assert catalog.version == "test-1"
        assert [c.id for c in catalog.controls] == ["TEST-01"]
        assert catalog.controls[0].scored is True

    def test_registry_key_splits_into_key_path_and_value_name(self):
        control = build_catalog(a_catalog(a_control(
            registry_key="HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS"
                         "\\Parameters\\LDAPServerIntegrity"))).controls[0]

        assert control.registry_value_name == "LDAPServerIntegrity"
        assert control.registry_key_path.endswith("NTDS\\Parameters")

    def test_by_id_is_case_insensitive_and_returns_none_for_unknown(self):
        catalog = build_catalog(a_catalog())

        assert catalog.by_id("test-01").id == "TEST-01"
        assert catalog.by_id("NOPE-99") is None

    def test_select_returns_matched_controls_and_unknown_ids(self):
        catalog = build_catalog(a_catalog(a_control(id="TEST-01"),
                                         a_control(id="TEST-02")))

        selected, unknown = catalog.select(["TEST-02", "MISSING-1"])

        assert [c.id for c in selected] == ["TEST-02"]
        assert unknown == ("MISSING-1",)

    def test_select_none_returns_every_control(self):
        catalog = build_catalog(a_catalog(a_control(id="TEST-01"),
                                         a_control(id="TEST-02")))

        selected, unknown = catalog.select(None)

        assert len(selected) == 2 and unknown == ()

    def test_select_keeps_catalog_order_and_deduplicates(self):
        catalog = build_catalog(a_catalog(a_control(id="TEST-01"),
                                         a_control(id="TEST-02")))

        selected, _ = catalog.select(["TEST-02", "TEST-01", "TEST-02"])

        assert [c.id for c in selected] == ["TEST-01", "TEST-02"]

    def test_select_accepts_a_bare_string(self):
        catalog = build_catalog(a_catalog())

        selected, unknown = catalog.select("TEST-01")

        assert [c.id for c in selected] == ["TEST-01"] and unknown == ()

    def test_provenance_reports_version_and_unscored_ids(self):
        catalog = build_catalog(a_catalog(
            a_control(id="TEST-01"),
            a_control(id="TEST-02", status=STATUS_NEEDS_BASELINE_VALUE,
                      operator="present", registry_key=None,
                      final_expected=_OMIT, missing_result=_OMIT,
                      baseline_gap="value not stated by the source"),
        ))

        provenance = catalog.provenance()

        assert provenance["catalog_version"] == "test-1"
        assert provenance["control_count"] == 2
        assert provenance["scored_control_count"] == 1
        assert provenance["unscored_control_ids"] == ["TEST-02"]


class TestLoaderRejectsMalformedCatalogs:

    def test_not_an_object(self):
        with pytest.raises(CatalogError, match="must be a JSON object"):
            build_catalog(["nope"])

    def test_missing_catalog_version(self):
        with pytest.raises(CatalogError, match="catalog_version"):
            build_catalog(a_catalog(catalog_version=_OMIT))

    def test_blank_catalog_version(self):
        with pytest.raises(CatalogError, match="catalog_version"):
            build_catalog(a_catalog(catalog_version="   "))

    def test_missing_controls_list(self):
        with pytest.raises(CatalogError, match="'controls' must be a non-empty list"):
            build_catalog(a_catalog(controls=_OMIT))

    def test_empty_controls_list(self):
        with pytest.raises(CatalogError, match="non-empty list"):
            build_catalog(a_catalog(controls=[]))

    def test_duplicate_ids_name_both_positions(self):
        with pytest.raises(CatalogError, match="duplicate control id 'TEST-01'"):
            build_catalog(a_catalog(a_control(), a_control()))

    def test_duplicate_ids_are_caught_across_case(self):
        with pytest.raises(CatalogError, match="duplicate control id"):
            build_catalog(a_catalog(a_control(id="TEST-01"),
                                    a_control(id="test-01")))

    def test_control_without_an_id(self):
        with pytest.raises(CatalogError, match="no usable 'id'"):
            build_catalog(a_catalog(a_control(id=_OMIT)))

    def test_unknown_check_type_names_the_control_and_the_options(self):
        with pytest.raises(CatalogError) as excinfo:
            build_catalog(a_catalog(a_control(check_type="gpo-magic")))

        message = str(excinfo.value)
        assert "TEST-01" in message and "gpo-magic" in message
        assert "gpo-security-template" in message

    def test_unknown_operator(self):
        with pytest.raises(CatalogError, match="unknown operator 'roughly'"):
            build_catalog(a_catalog(a_control(operator="roughly")))

    def test_unknown_status(self):
        with pytest.raises(CatalogError, match="unknown status"):
            build_catalog(a_catalog(a_control(status="probably-fine")))

    def test_unknown_severity(self):
        with pytest.raises(CatalogError, match="unknown severity"):
            build_catalog(a_catalog(a_control(severity="apocalyptic")))

    def test_unknown_scope(self):
        with pytest.raises(CatalogError, match="unknown scope"):
            build_catalog(a_catalog(a_control(scope="everywhere-ish")))

    @pytest.mark.parametrize("missing_field", [
        "title", "source", "scope", "check_type", "severity", "status",
        "operator", "remediation",
    ])
    def test_missing_required_field(self, missing_field):
        with pytest.raises(CatalogError, match="missing required field"):
            build_catalog(a_catalog(a_control(**{missing_field: _OMIT})))

    def test_unknown_field_is_rejected_so_typos_cannot_disable_an_assertion(self):
        with pytest.raises(CatalogError, match="unknown field\\(s\\): finel_expected"):
            build_catalog(a_catalog(a_control(finel_expected=2)))

    def test_source_without_a_url(self):
        with pytest.raises(CatalogError, match="must cite where it came from"):
            build_catalog(a_catalog(a_control(source={"part": 1})))

    def test_active_control_without_a_registry_key(self):
        with pytest.raises(CatalogError, match="no 'registry_key' to assert against"):
            build_catalog(a_catalog(a_control(registry_key=None)))

    def test_active_control_without_missing_result(self):
        with pytest.raises(CatalogError, match="missing_result"):
            build_catalog(a_catalog(a_control(missing_result=_OMIT)))

    def test_active_control_with_unknown_missing_result(self):
        with pytest.raises(CatalogError, match="missing_result"):
            build_catalog(a_catalog(a_control(missing_result="shrug")))

    def test_value_operator_without_an_expected_value(self):
        with pytest.raises(CatalogError, match="needs a 'final_expected' value"):
            build_catalog(a_catalog(a_control(final_expected=_OMIT)))

    def test_in_operator_needs_a_list(self):
        with pytest.raises(CatalogError, match="needs 'final_expected' to be a list"):
            build_catalog(a_catalog(a_control(operator="in", final_expected=2)))

    def test_presence_operator_must_not_carry_expected_values(self):
        with pytest.raises(CatalogError, match="asserts only presence"):
            build_catalog(a_catalog(a_control(operator="present",
                                              final_expected=1)))

    def test_presence_rollout_state_on_a_value_operator(self):
        with pytest.raises(CatalogError, match="only applies to the"):
            build_catalog(a_catalog(a_control(presence_rollout_state="audit")))

    def test_unknown_presence_rollout_state(self):
        with pytest.raises(CatalogError, match="unknown presence_rollout_state"):
            build_catalog(a_catalog(a_control(
                operator="present", final_expected=_OMIT,
                presence_rollout_state="halfway")))

    def test_active_control_carrying_a_baseline_gap_must_be_flagged(self):
        with pytest.raises(CatalogError, match="must be flagged needs_baseline_value"):
            build_catalog(a_catalog(a_control(
                baseline_gap="the post never says which value")))

    def test_caveats_must_be_a_list(self):
        with pytest.raises(CatalogError, match="'caveats' must be a list"):
            build_catalog(a_catalog(a_control(caveats="just the one")))

    def test_notes_must_be_a_list(self):
        with pytest.raises(CatalogError, match="'notes' must be a list"):
            build_catalog(a_catalog(notes="a note"))

    def test_baseline_must_be_an_object(self):
        with pytest.raises(CatalogError, match="'baseline' must be an object"):
            build_catalog(a_catalog(baseline=["a source"]))

    def test_control_that_is_not_an_object(self):
        with pytest.raises(CatalogError, match="must be an object"):
            build_catalog(a_catalog("DEVORE-01"))

    def test_registry_key_of_the_wrong_type(self):
        with pytest.raises(CatalogError, match="'registry_key' must be a string"):
            build_catalog(a_catalog(a_control(registry_key=42)))


class TestNeedsBaselineValueGuard:
    """The catalog must not be able to smuggle in a guessed value."""

    def unscored(self, **overrides):
        base = dict(
            id="TEST-GAP",
            status=STATUS_NEEDS_BASELINE_VALUE,
            operator="present",
            registry_key=None,
            final_expected=_OMIT,
            missing_result=_OMIT,
            baseline_gap="the post names the policy but prints no value",
        )
        base.update(overrides)
        return a_control(**base)

    def test_a_valid_unscored_control_loads_and_is_excluded_from_scoring(self):
        catalog = build_catalog(a_catalog(self.unscored()))

        control = catalog.controls[0]
        assert control.scored is False
        assert control.baseline_gap
        assert catalog.scored_controls == ()
        assert [c.id for c in catalog.unscored_controls] == ["TEST-GAP"]

    def test_final_expected_on_an_unscored_control_is_a_load_error(self):
        with pytest.raises(CatalogError, match="never guessed"):
            build_catalog(a_catalog(self.unscored(final_expected=1)))

    def test_interim_expected_on_an_unscored_control_is_a_load_error(self):
        with pytest.raises(CatalogError, match="never guessed"):
            build_catalog(a_catalog(self.unscored(interim_expected=1)))

    def test_unscored_control_must_explain_the_gap(self):
        with pytest.raises(CatalogError, match="no 'baseline_gap'"):
            build_catalog(a_catalog(self.unscored(baseline_gap=_OMIT)))

    def test_unscored_control_must_not_declare_a_missing_result(self):
        with pytest.raises(CatalogError, match="'missing_result' must be null"):
            build_catalog(a_catalog(self.unscored(missing_result="fail")))

    def test_an_unscored_control_may_still_carry_a_known_registry_key(self):
        """Path known, value not: still unscored, because the value is the gap."""
        catalog = build_catalog(a_catalog(self.unscored(
            registry_key="HKLM\\Software\\Test\\Flag")))

        assert catalog.controls[0].registry_key
        assert catalog.controls[0].scored is False

    def test_an_os_default_on_an_unscored_control_is_a_load_error(self):
        """A flagged control carries no values at all, defaults included."""
        with pytest.raises(CatalogError, match="never guessed"):
            build_catalog(a_catalog(self.unscored(os_default=1)))


class TestOsDefaultField:
    """``os_default`` lets an unset key be judged — only when it is sourced."""

    def defaulted(self, **overrides):
        base = dict(operator="gte", final_expected=2, os_default=1,
                    value_source="Microsoft doc: effective default is 1.")
        base.update(overrides)
        return a_control(**base)

    def test_a_sourced_os_default_loads_and_is_exposed_on_the_control(self):
        catalog = build_catalog(a_catalog(self.defaulted()))

        control = catalog.controls[0]
        assert control.os_default == 1
        assert control.final_expected == 2
        assert control.scored is True

    def test_absent_os_default_stays_none_so_behaviour_is_unchanged(self):
        catalog = build_catalog(a_catalog(a_control()))

        assert catalog.controls[0].os_default is None

    def test_an_os_default_without_a_value_source_is_a_load_error(self):
        """An uncitable default would let an unset key report as compliant."""
        with pytest.raises(CatalogError, match="os_default' needs a 'value_source"):
            build_catalog(a_catalog(self.defaulted(value_source=_OMIT)))

    def test_an_os_default_on_a_presence_operator_is_a_load_error(self):
        with pytest.raises(CatalogError, match="needs a value operator"):
            build_catalog(a_catalog(self.defaulted(
                operator="present", final_expected=_OMIT,
                presence_rollout_state="audit")))

    def test_an_os_default_of_zero_is_kept_rather_than_treated_as_absent(self):
        """``0`` is a real documented default, not a missing field."""
        catalog = build_catalog(a_catalog(self.defaulted(os_default=0)))

        assert catalog.controls[0].os_default == 0


class TestLoadCatalogFromDisk:

    def test_the_packaged_catalog_loads(self):
        catalog = load_catalog()

        assert isinstance(catalog, Catalog)
        assert catalog.version
        assert catalog.controls

    def test_the_default_catalog_is_cached(self):
        assert load_catalog() is load_catalog()

    def test_missing_file_is_a_clear_error(self, tmp_path):
        with pytest.raises(CatalogError, match="cannot read control catalog"):
            load_catalog(tmp_path / "nope.json")

    def test_invalid_json_is_a_clear_error(self, tmp_path):
        path = tmp_path / "controls.json"
        path.write_text("{not json", encoding="utf-8")

        with pytest.raises(CatalogError, match="invalid JSON"):
            load_catalog(path)

    def test_a_valid_file_on_disk_loads(self, tmp_path):
        path = tmp_path / "controls.json"
        path.write_text(json.dumps(a_catalog()), encoding="utf-8")

        catalog = load_catalog(path)

        assert catalog.source == str(path)
        assert [c.id for c in catalog.controls] == ["TEST-01"]

    def test_a_malformed_file_names_its_path_in_the_error(self, tmp_path):
        path = tmp_path / "controls.json"
        path.write_text(json.dumps(a_catalog(a_control(operator="vibes"))),
                        encoding="utf-8")

        with pytest.raises(CatalogError, match=str(path)):
            load_catalog(path)


class TestShippedCatalogInvariants:
    """The real controls.json, checked against its own promises."""

    @pytest.fixture
    def catalog(self):
        return load_catalog()

    def test_catalog_file_ships_inside_the_package(self):
        assert DEFAULT_CATALOG_PATH.name == "controls.json"
        assert DEFAULT_CATALOG_PATH.exists()

    def test_the_live_verified_ldap_controls_are_present_and_scored(self, catalog):
        """The two controls one real GPO satisfies (the WP's verified premise)."""
        for control_id, expected in (("DEVORE-03-LDAP-SERVER-SIGNING", 2),
                                     ("DEVORE-05-LDAP-CHANNEL-BINDING", 2)):
            control = catalog.by_id(control_id)
            assert control is not None, control_id
            assert control.scored
            assert control.final_expected == expected
            assert control.registry_value_name in ("LDAPServerIntegrity",
                                                   "LdapEnforceChannelBinding")

    @pytest.mark.parametrize("control_id", [
        "DEVORE-01-NTLM-LMCOMPATIBILITYLEVEL",
        "DEVORE-03-LDAP-SERVER-SIGNING",
        "DEVORE-03-LDAP-CLIENT-SIGNING",
        "DEVORE-03-LDAP-DIAG-LOGGING",
        "DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES",
        "DEVORE-05-LDAP-CHANNEL-BINDING",
        "DEVORE-06-LLMNR-DISABLE",
        "DEVORE-06-NBTNS-NODETYPE",
        "DEVORE-08-PRINT-RPCNAMEDPIPE",
        "DEVORE-08-NTLM-AUDIT-INCOMING",
        "DEVORE-08-NTLM-AUDIT-OUTGOING",
        "DEVORE-08-NTLM-AUDIT-INDOMAIN",
    ])
    def test_the_deterministic_controls_are_active(self, catalog, control_id):
        control = catalog.by_id(control_id)

        assert control is not None, f"{control_id} missing from the catalog"
        assert control.status == STATUS_ACTIVE
        assert control.registry_key

    @pytest.mark.parametrize("control_id", [
        "DEVORE-04-KERB-CONFIGURE-ENCTYPES",
        "DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS",
        "DEVORE-06-SMB-SERVER-SIGNING-ALWAYS",
        "DEVORE-08-NTLM-BLOCK-INCOMING",
        "DEVORE-08-NTLM-BLOCK-OUTGOING",
        "DEVORE-08-NTLM-BLOCK-INDOMAIN",
    ])
    def test_the_not_stated_controls_are_present_flagged_and_unscored(
            self, catalog, control_id):
        """Present so they cannot be forgotten; unscored so they cannot lie."""
        control = catalog.by_id(control_id)

        assert control is not None, f"{control_id} missing from the catalog"
        assert control.status == STATUS_NEEDS_BASELINE_VALUE
        assert control.scored is False
        assert control.interim_expected is None
        assert control.final_expected is None
        assert control.baseline_gap

    def test_the_smb_signing_gap_records_the_hint_without_asserting_it(self, catalog):
        """The commonly cited path stays prose, never an assertion."""
        control = catalog.by_id("DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS")

        assert control.registry_key is None
        assert "RequireSecuritySignature" in control.baseline_gap
        assert "UNVERIFIED" in control.baseline_gap

    def test_every_control_cites_a_devore_part_and_url(self, catalog):
        for control in catalog.controls:
            assert control.source.get("url", "").startswith("https://"), control.id
            assert control.source.get("part") in range(1, 9), control.id

    def test_every_control_has_remediation_text(self, catalog):
        for control in catalog.controls:
            assert control.remediation and len(control.remediation) > 20, control.id

    def test_every_active_control_states_where_its_value_came_from(self, catalog):
        for control in catalog.scored_controls:
            assert control.value_source, control.id

    def test_every_active_control_says_what_an_unset_key_means(self, catalog):
        for control in catalog.scored_controls:
            assert control.missing_result in MISSING_RESULTS, control.id
            assert control.missing_note, control.id

    def test_both_missing_result_semantics_are_exercised(self, catalog):
        """A hardening gap fails; a conditional setting is not_applicable."""
        semantics = {c.missing_result for c in catalog.scored_controls}

        assert semantics == MISSING_RESULTS
        assert catalog.by_id("DEVORE-08-PRINT-RPCNAMEDPIPE").missing_result \
            == "not_applicable"

    def test_presence_only_controls_declare_their_rollout_state_and_warn(self, catalog):
        for control in catalog.scored_controls:
            if control.operator in PRESENCE_OPERATORS:
                assert control.presence_rollout_state == "audit", control.id
                assert any("PRESENCE ONLY" in c for c in control.caveats), control.id

    def test_every_control_is_a_check_type_the_evaluator_can_run(self, catalog):
        for control in catalog.scored_controls:
            assert control.check_type in EVALUABLE_CHECK_TYPES, control.id

    def test_no_directory_state_controls_ship_before_their_engine_exists(self, catalog):
        """They are deliberately absent, not present-and-unevaluatable."""
        assert "directory-state" in CHECK_TYPES
        assert [c.id for c in catalog.controls
                if c.check_type == "directory-state"] == []
        assert any("directory-state" in note for note in catalog.notes)

    def test_operators_and_severities_stay_inside_the_supported_sets(self, catalog):
        for control in catalog.controls:
            assert control.operator in OPERATORS, control.id
            assert control.severity in SEVERITIES, control.id

    def test_phased_controls_carry_an_interim_below_their_final(self, catalog):
        phased = [c for c in catalog.scored_controls if c.interim_expected is not None]

        assert phased, "the catalog should model at least one phased rollout"
        for control in phased:
            assert control.operator in VALUE_OPERATORS, control.id
            assert control.interim_expected < control.final_expected, control.id

    def test_registry_keys_are_machine_hive_paths(self, catalog):
        for control in catalog.controls:
            if control.registry_key:
                assert control.registry_key.upper().startswith("HKLM\\"), control.id

    def test_catalog_version_is_reportable(self, catalog):
        assert catalog.version and catalog.version[0].isdigit()
        assert catalog.baseline.get("primary_source")
        assert catalog.baseline.get("value_policy")
