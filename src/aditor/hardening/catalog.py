"""The hardening control catalog: data file, model, and validating loader.

The catalog is the product spec in machine-readable form — one declarative,
source-cited assertion per control (see ``docs/HARDENING_CATALOG.md``). The
evaluator reads controls; it never hard-codes a registry key or an expected
value.

**Format: JSON, not YAML.** ``json`` is in the standard library, so the catalog
costs no runtime dependency; Phase 1 spent a work package removing needless
ones and adding PyYAML back for a single data file would undo that. The tradeoff
is real — JSON has no comments and needs ``\\\\`` for every registry
separator — so the fields that would have been YAML comments (``value_source``,
``baseline_gap``, ``caveats``, ``missing_note``) are first-class data instead,
which is strictly better for a report that has to cite its sources anyway.

**Unset is not the same as insecure.** Some settings have a documented Windows
default that is already partly compliant — ``LdapClientIntegrity`` defaults to
``1`` (Negotiate signing) whether or not a GPO says so. Those controls carry an
optional ``os_default``, and the evaluator compares it against the assertion when
no GPO sets the key, instead of reporting a bare ``fail``. ``os_default`` is
populated **only where a Microsoft document states the default**, which the loader
enforces by requiring a dedicated ``os_default_source`` alongside it; a control
without one keeps the original behaviour (unset -> ``missing_result``). The
citation is a *separate field on purpose*: every control already carries a
``value_source`` for its baseline value, so requiring that one would have been a
guard that no catalog edit could ever fail. ``os_default_source`` has to name the
document that states **the default**, and a dangling ``os_default_source`` with no
``os_default`` is rejected too.

A default is an *assumption*, never enforcement, so the evaluator marks such
evidence ``source: "os-default"`` — and caps its ``rollout_state`` at ``audit``,
because "enforced" means Group Policy holds the value and nothing enforces a
default. That cap lives in the evaluator, not here: it is a property of what an OS
default is, so no catalog value can opt out of it.

**Absence from every GPO is not always evidence.** For most controls a GPO *is*
the delivery mechanism, so a key that appears in no GPO is strong evidence that
nothing sets it — that is what licenses ``missing_result: "fail"``. A few
controls are different: the source's own remediation writes the registry
directly on the domain controllers (``reg add``), which leaves no trace in
SYSVOL at all, so "not in any GPO" says nothing about the value on the DCs.
Those controls carry ``gpo_deliverable: false``, and the evaluator reports
``unknown`` instead of ``fail`` when their key is found in no GPO, with the
exact ``reg query`` command that closes the gap.

The field is deliberately **narrow**, and the loader only accepts it on an
active control with a full ``registry_key`` (the check command is derived from
the key, so a control without one could not produce it). Setting it broadly
would turn every unset key into ``unknown`` and gut the tool. It changes only
the *absent* case: a ``gpo_deliverable: false`` control that **is** found in a
GPO is judged on the value exactly like any other.

**Only known values are asserted.** A control whose exact expected value the
source does not state is carried with ``status: "needs_baseline_value"``, no
expected values at all, and a ``baseline_gap`` explaining what is missing and
where to source it. The loader *enforces* that: a ``needs_baseline_value``
control that carries an expected value is a load-time error, so a guess cannot
enter the catalog quietly. Those controls are excluded from scoring — a
plausible wrong verdict is the worst outcome for an audit tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# The catalog file shipped inside the package.
DEFAULT_CATALOG_PATH = Path(__file__).with_name("controls.json")

# Check types the catalog may declare.
CHECK_TYPES = frozenset({
    "gpo-security-template",
    "gpo-registry-pol",
    "directory-state",
})

# Check types the evaluator in this release can actually run.
EVALUABLE_CHECK_TYPES = frozenset({
    "gpo-security-template",
    "gpo-registry-pol",
    "directory-state",
})

# The directory queries a ``directory-state`` control can name in
# ``directory_check``. Each is a fixed, read-only LDAP query in
# :mod:`aditor.hardening.collect` that returns the objects breaking the rule;
# the control passes when it returns none. Named rather than written as LDAP
# filters in the catalog, so a catalog edit can never become an arbitrary
# directory query.
DIRECTORY_CHECK_SPN_WITHOUT_AES = "spn-accounts-without-aes"
DIRECTORY_CHECK_NON_EMPTY_GROUPS = "non-empty-groups"
DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION = "unconstrained-delegation"
DIRECTORY_CHECKS = frozenset({
    DIRECTORY_CHECK_SPN_WITHOUT_AES,
    DIRECTORY_CHECK_NON_EMPTY_GROUPS,
    DIRECTORY_CHECK_UNCONSTRAINED_DELEGATION,
})
# Checks that need ``directory_targets`` (the group names to inspect).
DIRECTORY_CHECKS_WITH_TARGETS = frozenset({DIRECTORY_CHECK_NON_EMPTY_GROUPS})

# The groups ``non-empty-groups`` can inspect, by the English name the catalog
# uses. They are looked up by well-known SID, never by name: built-in group
# names are localized when a domain is created and can be renamed, and a
# name lookup that finds nothing would read as an empty group.
#
# name: (scope, id, exists). ``builtin`` ids are full SIDs; ``domain`` ids are
# RIDs relative to the domain SID. ``exists`` is True for groups every domain
# has, "forest-root" for groups only the forest root domain has, and False for
# groups a newer schema or role adds. A missing group that should exist is an
# error.
WELL_KNOWN_GROUPS: Dict[str, Tuple[str, Any, Any]] = {
    "Account Operators": ("builtin", "S-1-5-32-548", True),
    "Server Operators": ("builtin", "S-1-5-32-549", True),
    "Print Operators": ("builtin", "S-1-5-32-550", True),
    "Backup Operators": ("builtin", "S-1-5-32-551", True),
    "Replicator": ("builtin", "S-1-5-32-552", True),
    "Incoming Forest Trust Builders": ("builtin", "S-1-5-32-557",
                                       "forest-root"),
    "Storage Replica Administrators": ("builtin", "S-1-5-32-582", False),
    "Schema Admins": ("domain", 518, "forest-root"),
    "Group Policy Creator Owners": ("domain", 520, True),
}

OPERATORS = frozenset({"equals", "gte", "in", "aes_only", "present", "absent"})
PRESENCE_OPERATORS = frozenset({"present", "absent"})
VALUE_OPERATORS = frozenset({"equals", "gte", "in", "aes_only"})

SCOPES = frozenset({"all", "domain-controllers", "domain-root"})

# Severities, worst first. The rank lives here rather than in a consumer because
# it is intrinsic to the vocabulary: the report and the scan diff both order
# their output by it and must agree on what "worst first" means.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                 "informational": 4}
SEVERITIES = frozenset(SEVERITY_RANK)

STATUS_ACTIVE = "active"
STATUS_NEEDS_BASELINE_VALUE = "needs_baseline_value"
STATUSES = frozenset({STATUS_ACTIVE, STATUS_NEEDS_BASELINE_VALUE})

# What a control means by "nothing sets this key anywhere".
MISSING_RESULTS = frozenset({"fail", "not_applicable"})

ROLLOUT_STATES = frozenset({"not_started", "audit", "enforced"})

# Every field a control may carry. Unknown fields are rejected so that a typo
# (``finel_expected``) fails the load instead of silently disabling an
# assertion.
_CONTROL_FIELDS = frozenset({
    "id", "title", "source", "scope", "check_type", "severity", "status",
    "friendly_policy", "registry_key", "registry_type", "operator",
    "interim_expected", "interim_effect", "final_expected", "os_default",
    "os_default_source", "presence_rollout_state", "missing_result", "missing_note", "value_source",
    "baseline_gap", "remediation", "caveats", "audit_before_enforce",
    "gpo_deliverable", "directory_check", "directory_targets",
    "why_it_matters", "change_risk", "microsoft_deadline",
})

#: How much a change to reach the target can break, safest first. The report
#: orders "what to do this month" by this, before severity.
CHANGE_RISKS = ("logging-only", "low", "pilot", "can-lock-out")

_REQUIRED_CONTROL_FIELDS = ("id", "title", "source", "scope", "check_type",
                            "severity", "status", "operator", "remediation")


class CatalogError(ValueError):
    """A catalog file (or catalog dict) is malformed.

    Raised at load time, with the offending control id in the message, so a bad
    catalog fails loudly on startup instead of producing quiet mis-verdicts.
    """


@dataclass(frozen=True)
class Control:
    """One declarative, source-cited hardening assertion."""

    id: str
    title: str
    source: Dict[str, Any]
    scope: str
    check_type: str
    severity: str
    status: str
    operator: str
    remediation: str
    registry_key: Optional[str] = None
    registry_type: Optional[str] = None
    friendly_policy: Optional[str] = None
    interim_expected: Any = None
    #: What setting ``interim_expected`` actually does. An interim step is not
    #: always an audit: some already change behaviour, so each one says so.
    interim_effect: Optional[str] = None
    final_expected: Any = None
    os_default: Any = None
    os_default_source: Optional[str] = None
    presence_rollout_state: Optional[str] = None
    missing_result: Optional[str] = None
    missing_note: Optional[str] = None
    value_source: Optional[str] = None
    baseline_gap: Optional[str] = None
    caveats: Tuple[str, ...] = ()
    audit_before_enforce: Optional[str] = None
    gpo_deliverable: bool = True
    directory_check: Optional[str] = None
    directory_targets: Tuple[str, ...] = ()
    #: One plain sentence: what an attacker gets while this is unfixed.
    why_it_matters: Optional[str] = None
    #: One of ``CHANGE_RISKS``.
    change_risk: Optional[str] = None
    #: ``{"date": "YYYY-MM[-DD]", "summary": str, "url": str}``: when Microsoft
    #: changes the default for this setting, cited.
    microsoft_deadline: Optional[Dict[str, Any]] = None

    @property
    def absence_check_command(self) -> Optional[str]:
        """The command that reads this key's live value on a domain controller.

        Derived from ``registry_key`` rather than stored as a second catalog
        field, so it cannot drift away from the key the control asserts. Used by
        the evaluator when a ``gpo_deliverable: false`` control's key is in no
        GPO: the finding is ``unknown``, and this is the one command that turns
        it into a fact.
        """
        if not self.registry_key_path or not self.registry_value_name:
            return None
        return (f'reg query "{self.registry_key_path}" '
                f'/v "{self.registry_value_name}"')

    @property
    def scored(self) -> bool:
        """Whether this control counts towards pass/fail totals."""
        return self.status == STATUS_ACTIVE

    @property
    def registry_value_name(self) -> Optional[str]:
        """The value name — the last component of ``registry_key``."""
        if not self.registry_key:
            return None
        return self.registry_key.rsplit("\\", 1)[-1]

    @property
    def registry_key_path(self) -> Optional[str]:
        """``registry_key`` without its value name (the Registry.pol key)."""
        if not self.registry_key or "\\" not in self.registry_key:
            return None
        return self.registry_key.rsplit("\\", 1)[0]

    def summary(self) -> Dict[str, Any]:
        """The control's identity fields, for a finding's header."""
        return {
            "control_id": self.id,
            "title": self.title,
            "severity": self.severity,
            "scope": self.scope,
            "check_type": self.check_type,
            "status": self.status,
            "source": dict(self.source),
            "friendly_policy": self.friendly_policy,
            "remediation": self.remediation,
            "why_it_matters": self.why_it_matters,
            "change_risk": self.change_risk,
            "microsoft_deadline": (dict(self.microsoft_deadline)
                                   if self.microsoft_deadline else None),
        }


@dataclass(frozen=True)
class Catalog:
    """A loaded, validated set of controls plus its provenance."""

    version: str
    baseline: Dict[str, Any]
    controls: Tuple[Control, ...]
    source: str = ""
    notes: Tuple[str, ...] = field(default=())

    def by_id(self, control_id: str) -> Optional[Control]:
        """Look a control up by id (case-insensitively), or ``None``."""
        wanted = (control_id or "").strip().upper()
        for control in self.controls:
            if control.id.upper() == wanted:
                return control
        return None

    def select(self, control_ids: Optional[Iterable[str]] = None
               ) -> Tuple[Tuple[Control, ...], Tuple[str, ...]]:
        """Pick a subset of controls by id.

        Returns:
            ``(controls, unknown_ids)`` — the controls matched, in catalog
            order, and the ids that matched nothing. Unknown ids are returned
            rather than ignored so the caller can report them; silently
            scanning fewer controls than asked for is how an audit tool starts
            lying.
        """
        if control_ids is None:
            return self.controls, ()
        if isinstance(control_ids, str):
            control_ids = [control_ids]

        wanted = [str(cid).strip() for cid in control_ids if str(cid).strip()]
        matched: List[Control] = []
        unknown: List[str] = []
        for cid in wanted:
            control = self.by_id(cid)
            if control is None:
                unknown.append(cid)
            elif control not in matched:
                matched.append(control)
        ordered = tuple(c for c in self.controls if c in matched)
        return ordered, tuple(unknown)

    @property
    def scored_controls(self) -> Tuple[Control, ...]:
        return tuple(c for c in self.controls if c.scored)

    @property
    def unscored_controls(self) -> Tuple[Control, ...]:
        return tuple(c for c in self.controls if not c.scored)

    def provenance(self) -> Dict[str, Any]:
        """The catalog half of a scan's provenance header.

        ``catalog_source`` is trimmed to its last two path components: a scan
        report is a shareable artifact and does not need the operator's absolute
        install path in it. Full paths stay in load-time error messages, where
        they are useful.
        """
        parts = Path(self.source).parts if self.source else ()
        return {
            "catalog_version": self.version,
            "catalog_source": "/".join(parts[-2:]) if parts else "",
            "control_count": len(self.controls),
            "scored_control_count": len(self.scored_controls),
            "unscored_control_ids": [c.id for c in self.unscored_controls],
            "baseline": dict(self.baseline),
        }


def build_catalog(data: Any, source: str = "<dict>") -> Catalog:
    """Validate an already-parsed catalog document and build a :class:`Catalog`.

    Pure: no file I/O. ``load_catalog`` is the thin file wrapper around this.

    Raises:
        CatalogError: on anything wrong — missing ``controls``, a duplicate id,
            an unknown ``check_type``/``operator``/``status``/``severity``, a
            missing required field, an unknown field, an assertion without an
            expected value, or a ``needs_baseline_value`` control that carries
            an expected value anyway.
    """
    if not isinstance(data, dict):
        raise CatalogError(f"{source}: catalog must be a JSON object, "
                           f"got {type(data).__name__}")

    version = data.get("catalog_version")
    if not isinstance(version, str) or not version.strip():
        raise CatalogError(f"{source}: 'catalog_version' is required and must be "
                           f"a non-empty string (a scan report must be able to "
                           f"state which baseline it ran against)")

    raw_controls = data.get("controls")
    if not isinstance(raw_controls, list) or not raw_controls:
        raise CatalogError(f"{source}: 'controls' must be a non-empty list")

    controls: List[Control] = []
    seen: Dict[str, int] = {}
    for index, raw in enumerate(raw_controls):
        control = _build_control(raw, index, source)
        key = control.id.upper()
        if key in seen:
            raise CatalogError(
                f"{source}: duplicate control id {control.id!r} at positions "
                f"{seen[key]} and {index}")
        seen[key] = index
        controls.append(control)

    baseline = data.get("baseline") or {}
    if not isinstance(baseline, dict):
        raise CatalogError(f"{source}: 'baseline' must be an object")

    notes = data.get("notes") or []
    if not isinstance(notes, list):
        raise CatalogError(f"{source}: 'notes' must be a list")

    return Catalog(
        version=version.strip(),
        baseline=baseline,
        controls=tuple(controls),
        source=source,
        notes=tuple(str(note) for note in notes),
    )


def load_catalog(path: Optional[Any] = None) -> Catalog:
    """Load and validate the control catalog from disk.

    Args:
        path: Catalog file; defaults to the packaged ``controls.json``. The
            default is cached, so repeated scans do not re-read the file.

    Raises:
        CatalogError: the file is missing, is not valid JSON, or fails
            validation.
    """
    if path is None:
        return _load_default_catalog()
    return _load_catalog_file(Path(path))


@lru_cache(maxsize=1)
def _load_default_catalog() -> Catalog:
    return _load_catalog_file(DEFAULT_CATALOG_PATH)


def _load_catalog_file(path: Path) -> Catalog:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"cannot read control catalog {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"{path}: invalid JSON: {exc}") from exc
    return build_catalog(data, source=str(path))


# --------------------------------------------------------------------------- #
# Per-control validation
# --------------------------------------------------------------------------- #

def _build_control(raw: Any, index: int, source: str) -> Control:
    where = f"{source}: control #{index}"
    if not isinstance(raw, dict):
        raise CatalogError(f"{where} must be an object, got {type(raw).__name__}")

    control_id = raw.get("id")
    if not isinstance(control_id, str) or not control_id.strip():
        raise CatalogError(f"{where} has no usable 'id'")
    where = f"{source}: control {control_id!r}"

    unknown_fields = set(raw) - _CONTROL_FIELDS
    if unknown_fields:
        raise CatalogError(f"{where} has unknown field(s): "
                           f"{', '.join(sorted(unknown_fields))}")

    missing = [name for name in _REQUIRED_CONTROL_FIELDS
               if raw.get(name) in (None, "")]
    if missing:
        raise CatalogError(f"{where} is missing required field(s): "
                           f"{', '.join(missing)}")

    _require_enum(raw, "check_type", CHECK_TYPES, where)
    _require_enum(raw, "operator", OPERATORS, where)
    _require_enum(raw, "status", STATUSES, where)
    _require_enum(raw, "severity", SEVERITIES, where)
    _require_enum(raw, "scope", SCOPES, where)

    source_info = raw.get("source")
    if not isinstance(source_info, dict) or not source_info.get("url"):
        raise CatalogError(f"{where} needs a 'source' object with a 'url' "
                           f"(every control must cite where it came from)")

    caveats = raw.get("caveats") or []
    if not isinstance(caveats, list):
        raise CatalogError(f"{where}: 'caveats' must be a list")

    status = raw["status"]
    operator = raw["operator"]
    registry_key = raw.get("registry_key")
    interim = raw.get("interim_expected")
    final = raw.get("final_expected")
    os_default = raw.get("os_default")
    presence_state = raw.get("presence_rollout_state")
    missing_result = raw.get("missing_result")
    gpo_deliverable = raw.get("gpo_deliverable")

    if gpo_deliverable is not None and not isinstance(gpo_deliverable, bool):
        raise CatalogError(
            f"{where}: 'gpo_deliverable' must be true or false — it declares "
            f"whether absence from every GPO is evidence that this key is unset "
            f"— got {type(gpo_deliverable).__name__}")

    if registry_key is not None and not isinstance(registry_key, str):
        raise CatalogError(f"{where}: 'registry_key' must be a string or null")

    if presence_state is not None:
        if presence_state not in ROLLOUT_STATES:
            raise CatalogError(
                f"{where}: unknown presence_rollout_state {presence_state!r} "
                f"(expected one of: {', '.join(sorted(ROLLOUT_STATES))})")
        if operator not in PRESENCE_OPERATORS:
            raise CatalogError(
                f"{where}: 'presence_rollout_state' only applies to the "
                f"{'/'.join(sorted(PRESENCE_OPERATORS))} operators, not "
                f"{operator!r}")

    directory_check = raw.get("directory_check")
    directory_targets = raw.get("directory_targets")
    if raw["check_type"] == "directory-state":
        _validate_directory_control(raw, where)
    elif directory_check is not None or directory_targets is not None:
        raise CatalogError(
            f"{where}: 'directory_check' and 'directory_targets' only apply to "
            f"directory-state controls")

    if raw["check_type"] == "directory-state" and status != \
            STATUS_NEEDS_BASELINE_VALUE:
        pass  # validated above; the registry rules below do not apply
    elif status == STATUS_NEEDS_BASELINE_VALUE:
        if interim is not None or final is not None or os_default is not None:
            raise CatalogError(
                f"{where} is flagged {STATUS_NEEDS_BASELINE_VALUE} but carries "
                f"an expected value — expected values must be null for a "
                f"control whose baseline value is unknown, never guessed")
        if raw.get("os_default_source"):
            raise CatalogError(
                f"{where} is flagged {STATUS_NEEDS_BASELINE_VALUE} but carries an "
                f"'os_default_source'; with no 'os_default' to cite it can only "
                f"mislead")
        if not raw.get("baseline_gap"):
            raise CatalogError(
                f"{where} is flagged {STATUS_NEEDS_BASELINE_VALUE} but has no "
                f"'baseline_gap' explaining what is missing and where to source it")
        if missing_result is not None:
            raise CatalogError(
                f"{where} is flagged {STATUS_NEEDS_BASELINE_VALUE}, which is "
                f"never evaluated, so 'missing_result' must be null")
        if gpo_deliverable is False:
            raise CatalogError(
                f"{where} is flagged {STATUS_NEEDS_BASELINE_VALUE}, which is "
                f"never evaluated, so 'gpo_deliverable: false' cannot change any "
                f"verdict and can only mislead the next editor")
    else:
        if not registry_key or not registry_key.strip():
            raise CatalogError(f"{where} is active but has no 'registry_key' to "
                               f"assert against")
        if missing_result not in MISSING_RESULTS:
            raise CatalogError(
                f"{where}: active controls need 'missing_result' to be one of "
                f"{', '.join(sorted(MISSING_RESULTS))} — what an unset key means "
                f"is a per-control judgement, not a default")
        if operator in VALUE_OPERATORS and final is None:
            raise CatalogError(
                f"{where}: operator {operator!r} needs a 'final_expected' value")
        if operator in PRESENCE_OPERATORS and (interim is not None
                                               or final is not None):
            raise CatalogError(
                f"{where}: operator {operator!r} asserts only presence, so "
                f"expected values must be null")
        if operator == "in" and not isinstance(final, list):
            raise CatalogError(
                f"{where}: operator 'in' needs 'final_expected' to be a list")
        if gpo_deliverable is False and "\\" not in registry_key:
            raise CatalogError(
                f"{where}: 'gpo_deliverable: false' makes the finding 'unknown' "
                f"when no GPO sets the key, and that finding has to carry the "
                f"'reg query' command that checks the live value on a domain "
                f"controller. That command is derived from 'registry_key', so the "
                f"key must be a full path including its value name")
        if raw.get("baseline_gap"):
            raise CatalogError(
                f"{where} is active but carries a 'baseline_gap'; a control with "
                f"an unresolved baseline gap must be flagged "
                f"{STATUS_NEEDS_BASELINE_VALUE}")
        if os_default is not None:
            if operator not in VALUE_OPERATORS:
                raise CatalogError(
                    f"{where}: 'os_default' is a value to compare, so it needs a "
                    f"value operator ({', '.join(sorted(VALUE_OPERATORS))}), not "
                    f"{operator!r}")
            if not raw.get("os_default_source"):
                raise CatalogError(
                    f"{where}: 'os_default' needs its own 'os_default_source' "
                    f"citing the Microsoft document that states the default — an "
                    f"OS default that cannot be cited is a guess, and a guessed "
                    f"default would let an unset key report as compliant. "
                    f"'value_source' does not satisfy this: every control already "
                    f"has one for its *baseline* value, so requiring it proves "
                    f"nothing about the default")
        elif raw.get("os_default_source"):
            raise CatalogError(
                f"{where} has an 'os_default_source' but no 'os_default' — a "
                f"citation with nothing to cite is a leftover, and the next "
                f"editor would reasonably read it as a default that is being "
                f"applied")

    change_risk = raw.get("change_risk")
    if change_risk is not None and change_risk not in CHANGE_RISKS:
        raise CatalogError(f"{where}: 'change_risk' must be one of "
                           f"{', '.join(CHANGE_RISKS)}, not {change_risk!r}")
    deadline = raw.get("microsoft_deadline")
    if deadline is not None and not (
            isinstance(deadline, dict)
            and all(str(deadline.get(k) or "").strip()
                    for k in ("date", "summary", "url"))):
        raise CatalogError(f"{where}: 'microsoft_deadline' needs a 'date', a "
                           f"'summary' and a source 'url'")

    return Control(
        id=control_id.strip(),
        title=raw["title"],
        source=source_info,
        scope=raw["scope"],
        check_type=raw["check_type"],
        severity=raw["severity"],
        status=status,
        operator=operator,
        remediation=raw["remediation"],
        registry_key=registry_key,
        registry_type=raw.get("registry_type"),
        friendly_policy=raw.get("friendly_policy"),
        interim_expected=interim,
        interim_effect=raw.get("interim_effect"),
        final_expected=final,
        os_default=os_default,
        os_default_source=raw.get("os_default_source"),
        presence_rollout_state=presence_state,
        missing_result=missing_result,
        missing_note=raw.get("missing_note"),
        value_source=raw.get("value_source"),
        baseline_gap=raw.get("baseline_gap"),
        caveats=tuple(str(c) for c in caveats),
        audit_before_enforce=raw.get("audit_before_enforce"),
        gpo_deliverable=True if gpo_deliverable is None else gpo_deliverable,
        directory_check=directory_check,
        directory_targets=tuple(directory_targets or ()),
        why_it_matters=raw.get("why_it_matters"),
        change_risk=change_risk,
        microsoft_deadline=dict(deadline) if deadline else None,
    )


def _validate_directory_control(raw: Dict[str, Any], where: str) -> None:
    """The rules for a ``directory-state`` control.

    It asserts that a named directory query returns nothing, so it carries no
    registry key, no expected values and no OS default, and its operator is
    ``absent``. An unscored one (``needs_baseline_value``) needs no query.
    """
    check = raw.get("directory_check")
    targets = raw.get("directory_targets")
    if raw.get("status") == STATUS_NEEDS_BASELINE_VALUE and check is None:
        return
    if check not in DIRECTORY_CHECKS:
        raise CatalogError(
            f"{where}: directory-state controls need 'directory_check' to be "
            f"one of: {', '.join(sorted(DIRECTORY_CHECKS))} (got {check!r})")
    if raw.get("operator") != "absent":
        raise CatalogError(
            f"{where}: a directory-state control asserts that its query finds "
            f"nothing, so its operator must be 'absent'")
    for name in ("registry_key", "registry_type", "interim_expected",
                 "final_expected", "os_default", "os_default_source",
                 "missing_result", "presence_rollout_state"):
        if raw.get(name) is not None:
            raise CatalogError(
                f"{where}: '{name}' has no meaning for a directory-state "
                f"control and must be null")
    if raw.get("gpo_deliverable") is False:
        raise CatalogError(
            f"{where}: 'gpo_deliverable' has no meaning for a directory-state "
            f"control")
    if check in DIRECTORY_CHECKS_WITH_TARGETS:
        if (not isinstance(targets, list) or not targets
                or not all(isinstance(t, str) and t.strip() for t in targets)):
            raise CatalogError(
                f"{where}: directory_check {check!r} needs 'directory_targets', "
                f"a non-empty list of names")
        unknown = [t for t in targets if t not in WELL_KNOWN_GROUPS]
        if unknown:
            raise CatalogError(
                f"{where}: unknown group(s) {', '.join(map(repr, unknown))}. "
                f"Groups are looked up by well-known SID, so each name must be "
                f"one of: {', '.join(sorted(WELL_KNOWN_GROUPS))}")
    elif targets is not None:
        raise CatalogError(
            f"{where}: directory_check {check!r} takes no 'directory_targets'")


def _require_enum(raw: Dict[str, Any], field_name: str,
                  allowed: Sequence[str], where: str) -> None:
    value = raw.get(field_name)
    if value not in allowed:
        raise CatalogError(
            f"{where}: unknown {field_name} {value!r} "
            f"(expected one of: {', '.join(sorted(allowed))})")
