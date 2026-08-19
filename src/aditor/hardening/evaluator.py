"""Pure evaluation of hardening controls against parsed GPO content.

Everything here is a pure function of its arguments — a list of
:class:`GpoSnapshot` (already-parsed GPO content plus link metadata) and a
:class:`~aditor.hardening.catalog.Control`. No LDAP, no SMB, no clock, no
config. The tool layer (:mod:`aditor.tools.hardening`) does the I/O and hands
the results in, which is what lets the whole verdict engine be tested offline
against synthesized fixtures.

**v1 deliberately does not resolve RSoP.** Working out which GPO actually wins
means modelling link order, enforcement, block-inheritance, security filtering,
WMI filters and loopback — and a half-modelled precedence engine produces
confident wrong answers. So this evaluator reports **every** GPO that sets the
control's key, with its DN and link/enforced status, and flags **conflicts**:

* ``value-disagreement`` — two GPOs set the same key to different values.
* ``enforced-override`` — the disagreeing set includes an enforced link, which
  is the case where a compliant-looking setting is most likely being overridden
  elsewhere.

When settings disagree, the verdict follows the **least compliant** of them.
A "pass" that some other GPO silently overrides is a lie, and refusing to issue
one is what makes the no-RSoP approach defensible rather than merely simpler.

**An unset key is not automatically a failure.** Where Microsoft documents an OS
default for a setting, the control carries ``os_default`` and a domain that sets
nothing is judged against that default rather than reported as ``fail`` /
``not_started`` — ``LdapClientIntegrity`` is Negotiate (1) on an untouched
machine, so "no GPO sets it" is a documentation gap, not an unsigned-LDAP
finding. Such a verdict is always labelled: ``evidence.source`` is
``"os-default"``, ``evidence.os_default`` records the assumed value and where it
is documented, and a note states that no GPO enforces it. Controls without an
``os_default`` keep the ``missing_result`` behaviour unchanged.

**Rollout state is not pass/fail.** Most network controls are audit-first, then
enforce (NTLM 3 -> 5, LDAP signing 1 -> 2, channel binding 1 -> 2), so each
finding carries ``rollout_state``: ``not_started`` when nothing sets the key or
the value is below the interim step, ``audit`` when it meets the interim step,
``enforced`` when it meets the final one. A domain correctly mid-rollout reads
as ``pass`` / ``audit``, not as a failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..gpo.parsers import normalize_registry_key
from .catalog import (
    EVALUABLE_CHECK_TYPES,
    STATUS_NEEDS_BASELINE_VALUE,
    Control,
)

# Results a finding can carry.
RESULT_PASS = "pass"
RESULT_FAIL = "fail"
RESULT_NOT_APPLICABLE = "not_applicable"
RESULT_ERROR = "error"

# Rollout states, ordered least to most compliant.
STATE_NOT_STARTED = "not_started"
STATE_AUDIT = "audit"
STATE_ENFORCED = "enforced"
_STATE_RANK = {STATE_NOT_STARTED: 0, STATE_AUDIT: 1, STATE_ENFORCED: 2}

# PReg keys carry no hive: the machine Registry.pol is implicitly HKLM. Only
# machine-side policy is scanned in this release — every catalog control is a
# machine setting.
MACHINE_POL_HIVE = "HKLM"

# Why a finding is not scored.
UNSCORED_NEEDS_BASELINE_VALUE = STATUS_NEEDS_BASELINE_VALUE
UNSCORED_UNSUPPORTED_CHECK_TYPE = "unsupported_check_type"

# Where the value a verdict rests on came from. ``os-default`` is the honest
# label for "no GPO sets this, but Microsoft documents the OS default" — a
# reader (and the report layer) must be able to tell an assumed value from a
# configured one without parsing prose.
EVIDENCE_SOURCE_GPO = "gpo"
EVIDENCE_SOURCE_OS_DEFAULT = "os-default"
EVIDENCE_SOURCE_NOT_CONFIGURED = "not-configured"

_PRESENCE_ONLY_NOTE = (
    "Operator 'present': the source states this setting's registry path but not "
    "its compliant numeric value, so the control asserts only that the policy is "
    "configured. Read the found value below — the verdict does not judge it."
)
_NO_RSOP_NOTE = (
    "Precedence is not resolved (v1): every GPO that sets this key is listed. "
    "Check the conflict field before treating a single GPO's value as effective."
)
_OS_DEFAULT_NOTE = (
    "No GPO sets this key, so this verdict rests on the documented Windows "
    "default ({value!r}) — an assumed value, not a configured one. Nothing in "
    "Group Policy enforces it and this finding is not evidence that anything "
    "would stop a GPO from lowering it: configure the policy explicitly to make "
    "the value enforced and auditable."
)


@dataclass(frozen=True)
class GpoLink:
    """Where a GPO is linked, and how."""

    target_dn: str
    enforced: bool = False
    link_enabled: bool = True
    block_inheritance: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target_dn": self.target_dn,
            "enforced": self.enforced,
            "link_enabled": self.link_enabled,
            "block_inheritance": self.block_inheritance,
        }


@dataclass(frozen=True)
class GpoSnapshot:
    """One GPO's parsed policy content, as the evaluator needs it.

    Args:
        dn: The GPO's distinguished name (the evidence an auditor cites).
        display_name: Its friendly name.
        guid: Its GUID, without braces.
        security_template_entries: ``{key, type, type_name, value}`` dicts from
            ``parse_security_template_registry_values`` over a ``GptTmpl.inf``
            ``[Registry Values]`` section.
        registry_pol_entries: ``{key, value, type, data}`` dicts from
            ``parse_registry_pol`` over the machine ``Registry.pol``.
        links: Where the GPO is linked, with enforcement flags.
        read_error: Set when the GPO's content could not be read, so findings
            can say "unknown" rather than "not configured".
    """

    dn: str
    display_name: str = ""
    guid: str = ""
    security_template_entries: Sequence[Dict[str, Any]] = field(default_factory=tuple)
    registry_pol_entries: Sequence[Dict[str, Any]] = field(default_factory=tuple)
    links: Sequence[GpoLink] = field(default_factory=tuple)
    read_error: Optional[str] = None

    @property
    def enforced(self) -> bool:
        """Whether any enabled link of this GPO is enforced."""
        return any(link.enforced and link.link_enabled for link in self.links)

    def link_dicts(self) -> List[Dict[str, Any]]:
        return [link.as_dict() for link in self.links]


# --------------------------------------------------------------------------- #
# Matching: find every GPO that sets the control's key
# --------------------------------------------------------------------------- #

def find_matches(control: Control,
                 gpos: Iterable[GpoSnapshot]) -> List[Dict[str, Any]]:
    """Collect every setting of ``control``'s registry key across ``gpos``.

    Keys are compared through :func:`normalize_registry_key`, because a security
    template writes ``MACHINE\\System\\...`` where the catalog writes
    ``HKLM\\SYSTEM\\...``. For ``gpo-registry-pol`` the entry's key and value
    name are rejoined (``Registry.pol`` keeps them in separate fields) and the
    implicit ``HKLM`` hive of the machine file is supplied, since PReg keys carry
    no hive at all.

    Returns:
        One dict per setting found: the GPO's identity and links, the key and
        value as they appear in the GPO, and the type.
    """
    wanted = normalize_registry_key(control.registry_key)
    matches: List[Dict[str, Any]] = []
    if not wanted:
        return matches

    for gpo in gpos:
        if control.check_type == "gpo-security-template":
            for entry in gpo.security_template_entries or ():
                if normalize_registry_key(entry.get("key")) != wanted:
                    continue
                matches.append(_match(gpo, entry.get("key"), entry.get("value"),
                                     entry.get("type_name"),
                                     "GptTmpl.inf [Registry Values]"))
        elif control.check_type == "gpo-registry-pol":
            for entry in gpo.registry_pol_entries or ():
                full_key = f"{entry.get('key', '')}\\{entry.get('value', '')}"
                if normalize_registry_key(full_key, MACHINE_POL_HIVE) != wanted:
                    continue
                matches.append(_match(gpo, full_key, entry.get("data"),
                                     entry.get("type"), "Registry.pol"))
    return matches


def _match(gpo: GpoSnapshot, key: Any, value: Any, type_name: Any,
           source_file: str) -> Dict[str, Any]:
    return {
        "gpo_dn": gpo.dn,
        "gpo_display_name": gpo.display_name,
        "gpo_guid": gpo.guid,
        "registry_key": key,
        "type_name": type_name,
        "value": value,
        "source_file": source_file,
        "enforced_link": gpo.enforced,
        "links": gpo.link_dicts(),
    }


# --------------------------------------------------------------------------- #
# Operators
# --------------------------------------------------------------------------- #

class OperatorError(ValueError):
    """A value could not be compared with the control's operator.

    Surfaced as a finding with ``result: "error"`` — an uncomparable value is an
    honest "I do not know", not a pass and not a fail.
    """


def satisfies(operator: str, found: Any, expected: Any) -> bool:
    """Apply one catalog operator to a found value.

    Supported: ``equals``, ``gte``, ``in``, ``present``, ``absent``. ``present``
    and ``absent`` are decided by whether a setting was found at all and are
    handled by the caller, so they are trivially true here.

    Raises:
        OperatorError: the operator is unknown, or the comparison is impossible
            (``gte`` against a non-numeric value).
    """
    if operator in ("present", "absent"):
        return True
    if expected is None:
        raise OperatorError("no expected value to compare against")
    if operator == "equals":
        return _as_comparable(found) == _as_comparable(expected)
    if operator == "gte":
        return _as_number(found, "found") >= _as_number(expected, "expected")
    if operator == "in":
        options = expected if isinstance(expected, (list, tuple)) else [expected]
        return any(_as_comparable(found) == _as_comparable(option)
                   for option in options)
    raise OperatorError(f"unsupported operator {operator!r}")


def _as_comparable(value: Any) -> Any:
    """Normalise for equality: ints compare as ints, strings case-insensitively."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return text.lower()
    if isinstance(value, list):
        return tuple(_as_comparable(item) for item in value)
    return value


def _as_number(value: Any, role: str) -> int:
    number = _as_comparable(value)
    if isinstance(number, int):
        return number
    raise OperatorError(f"{role} value {value!r} is not numeric, so it cannot be "
                        f"compared with 'gte'")


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

def evaluate_control(control: Control,
                     gpos: Iterable[GpoSnapshot]) -> Dict[str, Any]:
    """Evaluate one control against every GPO, returning one finding.

    The finding carries ``result`` (``pass``/``fail``/``not_applicable``/
    ``error``), ``rollout_state``, ``evidence`` (expected versus found, with the
    source GPO DN and link path) and ``conflict``.

    Controls flagged ``needs_baseline_value`` are not evaluated at all: they come
    back ``not_applicable`` with ``scored: False`` and the catalog's
    ``baseline_gap`` as the reason. Guessing their value is the one thing an
    audit tool must never do.
    """
    gpos = list(gpos)

    if control.status == STATUS_NEEDS_BASELINE_VALUE:
        return _unscored_finding(control, UNSCORED_NEEDS_BASELINE_VALUE,
                                 control.baseline_gap or
                                 "the source does not state this control's "
                                 "expected value")
    if control.check_type not in EVALUABLE_CHECK_TYPES:
        return _unscored_finding(
            control, UNSCORED_UNSUPPORTED_CHECK_TYPE,
            f"check type {control.check_type!r} has no evaluator in this release")

    try:
        matches = find_matches(control, gpos)
    except Exception as exc:  # pragma: no cover - defensive
        return _error_finding(control, f"could not scan GPO content: {exc}", [])

    if control.operator == "absent":
        return _absent_finding(control, matches, gpos)
    if not matches:
        return _missing_finding(control, gpos)

    try:
        assessed = [dict(match, rollout_state=_state_for(control, match["value"]))
                    for match in matches]
    except OperatorError as exc:
        return _error_finding(control, str(exc), matches)

    states = {match["rollout_state"] for match in assessed}
    worst = min(states, key=lambda state: _STATE_RANK[state])
    conflict = _detect_conflict(assessed)

    if control.operator == "present":
        result = RESULT_PASS
        rollout_state = control.presence_rollout_state or STATE_AUDIT
    else:
        result = RESULT_FAIL if worst == STATE_NOT_STARTED else RESULT_PASS
        rollout_state = worst

    finding = _finding(control, result, rollout_state, assessed, gpos)
    finding["conflict"] = conflict
    if conflict:
        finding["evidence"]["notes"].append(conflict["detail"])
    return finding


def evaluate_controls(controls: Iterable[Control],
                      gpos: Iterable[GpoSnapshot],
                      include_not_applicable: bool = False
                      ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Evaluate many controls and count the outcomes.

    Args:
        controls: The controls to evaluate, in report order.
        gpos: The GPO snapshots to evaluate them against.
        include_not_applicable: Include findings that came back
            ``not_applicable`` because the control did not apply (an unset
            conditional setting). ``needs_baseline_value`` findings are **always**
            included regardless: a control the scanner cannot evaluate has to say
            so loudly, or it is indistinguishable from one that passed.

    Returns:
        ``(findings, counts)``. ``counts`` reports every result, plus
        ``needs_baseline_value``, ``conflicts``, ``os_default``, ``scored`` and
        ``total``, so a report never has to infer a total from a filtered list.
        ``os_default`` counts the findings whose verdict rests on a documented
        Windows default rather than on any GPO — a summary that lumps those in
        with configured passes overstates what the domain enforces.
    """
    gpos = list(gpos)
    counts = {RESULT_PASS: 0, RESULT_FAIL: 0, RESULT_NOT_APPLICABLE: 0,
              RESULT_ERROR: 0, "needs_baseline_value": 0, "conflicts": 0,
              "os_default": 0, "scored": 0, "total": 0}
    findings: List[Dict[str, Any]] = []

    for control in controls:
        finding = evaluate_control(control, gpos)
        counts["total"] += 1
        counts[finding["result"]] += 1
        if finding["scored"]:
            counts["scored"] += 1
        if finding.get("unscored_reason") == UNSCORED_NEEDS_BASELINE_VALUE:
            counts["needs_baseline_value"] += 1
        if finding.get("conflict"):
            counts["conflicts"] += 1
        if finding["evidence"].get("source") == EVIDENCE_SOURCE_OS_DEFAULT:
            counts["os_default"] += 1

        hide = (finding["result"] == RESULT_NOT_APPLICABLE
                and not include_not_applicable
                and finding.get("unscored_reason") is None)
        if not hide:
            findings.append(finding)

    return findings, counts


# --------------------------------------------------------------------------- #
# Finding construction
# --------------------------------------------------------------------------- #

def _state_for(control: Control, found: Any) -> str:
    """Which rollout step a found value has reached."""
    if control.final_expected is not None and satisfies(
            control.operator, found, control.final_expected):
        return STATE_ENFORCED
    if control.interim_expected is not None and satisfies(
            control.operator, found, control.interim_expected):
        return STATE_AUDIT
    if control.operator in ("present", "absent"):
        return control.presence_rollout_state or STATE_AUDIT
    return STATE_NOT_STARTED


def _detect_conflict(assessed: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Flag disagreement between GPOs setting the same key.

    Two shapes matter. Plain ``value-disagreement`` means two GPOs set different
    values and, without RSoP, which one wins is unproven. ``enforced-override``
    means one of the disagreeing GPOs is linked with enforcement, so it very
    likely overrides the others regardless of where they sit — the case where a
    "pass" read off the compliant GPO would be actively misleading.
    """
    if len(assessed) < 2:
        return None
    distinct = {_as_comparable(match["value"]) for match in assessed}
    if len(distinct) < 2:
        return None

    settings = [{"gpo_dn": m["gpo_dn"], "gpo_display_name": m["gpo_display_name"],
                 "value": m["value"], "enforced_link": m["enforced_link"],
                 "rollout_state": m["rollout_state"]} for m in assessed]
    enforcing = [m for m in assessed if m["enforced_link"]]

    if enforcing:
        names = ", ".join(f"{m['gpo_display_name'] or m['gpo_dn']} = {m['value']!r}"
                          for m in enforcing)
        return {
            "detected": True,
            "kind": "enforced-override",
            "detail": (f"{len(assessed)} GPOs set this key to different values and "
                       f"at least one is linked with enforcement ({names}), so the "
                       f"other settings are likely overridden. Precedence is not "
                       f"resolved here — verify with RSoP / gpresult before "
                       f"trusting any single value."),
            "settings": settings,
        }
    return {
        "detected": True,
        "kind": "value-disagreement",
        "detail": (f"{len(assessed)} GPOs set this key to different values "
                   f"({', '.join(repr(v) for v in sorted(map(str, distinct)))}). "
                   f"Which one applies depends on link precedence, which this scan "
                   f"does not resolve; the verdict follows the least compliant "
                   f"value."),
        "settings": settings,
    }


def _finding(control: Control, result: str, rollout_state: Optional[str],
             matches: List[Dict[str, Any]], gpos: Sequence[GpoSnapshot],
             notes: Optional[List[str]] = None,
             evidence_source: Optional[str] = None,
             os_default_evidence: Optional[Dict[str, Any]] = None
             ) -> Dict[str, Any]:
    notes = list(notes or [])
    if control.operator == "present" and matches:
        notes.append(_PRESENCE_ONLY_NOTE)
    if len(matches) > 1:
        notes.append(_NO_RSOP_NOTE)
    unreadable = [gpo.dn for gpo in gpos if gpo.read_error]
    if unreadable:
        notes.append(f"{len(unreadable)} GPO(s) could not be read and were not "
                     f"searched for this key: {', '.join(unreadable)}")

    finding = control.summary()
    finding.update({
        "result": result,
        "rollout_state": rollout_state,
        "scored": control.scored,
        "unscored_reason": None,
        "evidence": {
            "registry_key": control.registry_key,
            "registry_type": control.registry_type,
            "expected": {
                "operator": control.operator,
                "interim": control.interim_expected,
                "final": control.final_expected,
                "os_default": control.os_default,
                "value_source": control.value_source,
            },
            "source": evidence_source or (EVIDENCE_SOURCE_GPO if matches
                                          else EVIDENCE_SOURCE_NOT_CONFIGURED),
            "os_default": os_default_evidence,
            "found": matches,
            "found_count": len(matches),
            "gpos_searched": len(gpos),
            "notes": notes,
        },
        "conflict": None,
        "caveats": list(control.caveats),
        "audit_before_enforce": control.audit_before_enforce,
    })
    return finding


def _missing_finding(control: Control,
                     gpos: Sequence[GpoSnapshot]) -> Dict[str, Any]:
    """No GPO sets the key: the control's own semantics decide what that means.

    A control that documents an ``os_default`` is evaluated against that default
    instead (see :func:`_os_default_finding`) — for those settings, "no GPO sets
    it" does not mean "off".
    """
    note = control.missing_note or "No GPO in the domain sets this key."
    if control.os_default is not None:
        return _os_default_finding(control, gpos, note)
    return _finding(control, control.missing_result or RESULT_FAIL,
                    STATE_NOT_STARTED, [], gpos, notes=[note])


def _os_default_finding(control: Control, gpos: Sequence[GpoSnapshot],
                        missing_note: str) -> Dict[str, Any]:
    """Judge the assertion against the documented Windows default.

    Unset is not automatically insecure: ``LdapClientIntegrity`` is ``1``
    (Negotiate signing) on a machine no GPO has ever touched, so reporting
    ``fail`` / ``not_started`` there states more than the evidence supports.
    The value is still only *assumed*, so the finding says so three ways —
    ``evidence.source`` is ``os-default``, ``evidence.os_default`` carries the
    value with the source that documents it, and a note spells out that no GPO
    enforces it. ``found`` stays empty and ``found_count`` zero, because no GPO
    was found; the default is not fabricated into a match.

    A default that does *not* meet the assertion falls back to the control's own
    ``missing_result``. Knowing the default cannot make a control apply that its
    author said does not apply when nothing sets the key, so a conditional
    control keeps reporting ``not_applicable`` rather than being upgraded to a
    failure by an unset key it already excused.
    """
    try:
        rollout_state = _state_for(control, control.os_default)
    except OperatorError as exc:  # pragma: no cover - defensive
        return _error_finding(control, f"os_default {control.os_default!r} "
                                       f"could not be compared: {exc}", [])

    result = (control.missing_result or RESULT_FAIL
              if rollout_state == STATE_NOT_STARTED else RESULT_PASS)
    return _finding(
        control, result, rollout_state, [], gpos,
        notes=[missing_note, _OS_DEFAULT_NOTE.format(value=control.os_default)],
        evidence_source=EVIDENCE_SOURCE_OS_DEFAULT,
        os_default_evidence={
            "value": control.os_default,
            "source": EVIDENCE_SOURCE_OS_DEFAULT,
            "enforced_by_gpo": False,
            "value_source": control.value_source,
        })


def _absent_finding(control: Control, matches: List[Dict[str, Any]],
                    gpos: Sequence[GpoSnapshot]) -> Dict[str, Any]:
    """``absent`` inverts the usual sense: finding the key is the failure."""
    if matches:
        assessed = [dict(match, rollout_state=STATE_NOT_STARTED)
                    for match in matches]
        finding = _finding(control, RESULT_FAIL, STATE_NOT_STARTED, assessed, gpos,
                           notes=["This key must not be set; the GPO(s) below set it."])
        finding["conflict"] = _detect_conflict(assessed)
        return finding
    return _finding(control, RESULT_PASS,
                    control.presence_rollout_state or STATE_ENFORCED, [], gpos,
                    notes=["No GPO sets this key, which is what the control requires."])


def _unscored_finding(control: Control, reason: str,
                      detail: str) -> Dict[str, Any]:
    """A control the engine deliberately refuses to judge."""
    finding = control.summary()
    finding.update({
        "result": RESULT_NOT_APPLICABLE,
        "rollout_state": None,
        "scored": False,
        "unscored_reason": reason,
        "evidence": {
            "registry_key": control.registry_key,
            "registry_type": control.registry_type,
            "expected": None,
            "source": None,
            "os_default": None,
            "found": [],
            "found_count": 0,
            "notes": [
                detail,
                "Excluded from scoring: no verdict is issued rather than a guessed "
                "one. Source the exact value from a Microsoft Security Baseline or "
                "CIS Benchmark to activate this control.",
            ],
        },
        "conflict": None,
        "caveats": list(control.caveats),
        "audit_before_enforce": control.audit_before_enforce,
    })
    return finding


def _error_finding(control: Control, message: str,
                   matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    finding = control.summary()
    finding.update({
        "result": RESULT_ERROR,
        "rollout_state": None,
        "scored": control.scored,
        "unscored_reason": None,
        "error": message,
        "evidence": {
            "registry_key": control.registry_key,
            "registry_type": control.registry_type,
            "expected": {
                "operator": control.operator,
                "interim": control.interim_expected,
                "final": control.final_expected,
                "os_default": control.os_default,
                "value_source": control.value_source,
            },
            "source": (EVIDENCE_SOURCE_GPO if matches
                       else EVIDENCE_SOURCE_NOT_CONFIGURED),
            "os_default": None,
            "found": matches,
            "found_count": len(matches),
            "notes": [f"Could not evaluate: {message}. Reported as an error rather "
                      f"than a pass or a fail."],
        },
        "conflict": None,
        "caveats": list(control.caveats),
        "audit_before_enforce": control.audit_before_enforce,
    })
    return finding
