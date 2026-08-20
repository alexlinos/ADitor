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
* ``policy-preference-disagreement`` — a policy setting and a Group Policy
  preference item set the same key to different values, which link precedence
  cannot settle at all (see below).

When settings disagree, the verdict follows the **least compliant** of them.
A "pass" that some other GPO silently overrides is a lie, and refusing to issue
one is what makes the no-RSoP approach defensible rather than merely simpler.

**An unset key is not always readable evidence.** A control flagged
``gpo_deliverable: false`` documents a remediation that writes the registry
directly on the domain controllers, so its key is not expected to appear in a GPO
even where the setting *is* applied. For those controls an empty match list
proves nothing, and the finding is ``result: "unknown"`` with ``rollout_state``
``None``, ``evidence.source: "unknown"``, and a note giving the ``reg query``
that reads the live value. ``DEVORE-03-LDAP-DIAG-LOGGING`` reported a confident
``fail`` on a domain where the value was correctly set to 3 on the DC; that is
the false negative this closes. It changes only the absent case — such a control
found in a GPO is judged on its value like any other.

**An unset key is not automatically a failure.** Where Microsoft documents an OS
default for a setting, the control carries ``os_default`` and a domain that sets
nothing is judged against that default rather than reported as ``fail`` /
``not_started`` — ``LdapClientIntegrity`` is Negotiate (1) on an untouched
machine, so "no GPO sets it" is a documentation gap, not an unsigned-LDAP
finding. Such a verdict is always labelled: ``evidence.source`` is
``"os-default"``, ``evidence.os_default`` records the assumed value and where it
is documented, and a note states that no GPO enforces it. Controls without an
``os_default`` keep the ``missing_result`` behaviour unchanged.

**"We could not look" is not "nothing sets it".** An empty match list only means
no GPO *that was read* sets the key, so if any GPO carries a ``read_error`` the
os-default branch is refused outright and the finding is an ``error``: concluding
that the Windows default is effective would rest on GPOs nobody read, and an
unreadable GPO could set the value below the default. This holds whether all or
only some of the GPOs failed to read — the branch needs "no GPO sets this key",
and a partial read cannot establish it.

**Rollout state is not pass/fail.** Most network controls are audit-first, then
enforce (NTLM 3 -> 5, LDAP signing 1 -> 2, channel binding 1 -> 2), so each
finding carries ``rollout_state``: ``not_started`` when nothing sets the key or
the value is below the interim step, ``audit`` when it meets the interim step,
``enforced`` when it meets the final one. A domain correctly mid-rollout reads
as ``pass`` / ``audit``, not as a failure.

**How a value was delivered is evidence, not a different kind of check.** A GPO
can put a registry value in place three ways: a security template's
``[Registry Values]`` line, an admin-template ``Registry.pol`` entry, or a Group
Policy Preferences ``Registry.xml`` item. A control asserts the *key*, so all
three satisfy the same control and there is deliberately no separate
``check_type`` for preferences. But which mechanism delivered it is real audit
information and every found value records it in ``delivery``:

* a **preference tattoos** — the value is written into the registry and stays
  there if the GPO is unlinked or deleted, where a policy value reverts. So
  "configured by preference" is a weaker guarantee about ongoing state, and also
  a stickier one: it can persist on machines the GPO no longer reaches.
* a preference's **action** decides whether drift is corrected. ``U``/``R``
  rewrite the value every refresh; ``C`` writes it only when absent, so a value
  someone lowers by hand stays lowered. ``D`` *removes* the value and is never
  counted as configuring it.
* item-level targeting (``<Filters>``) can narrow a preference to a subset of
  the machines its GPO reaches. Resolving filters is out of scope, so a filtered
  item says so in the evidence rather than implying domain-wide coverage.
* a policy and a preference setting the same key to different values is a
  conflict like any other, reported as ``policy-preference-disagreement``.
* a preference item can delete a whole **key**, not just a value. That removes
  the key and everything in it, so a key-delete covering a control's key is
  disclosed in the finding's notes — if the control passes, another GPO is
  removing the key under the value that passed it, and which lands depends on
  client-side extension ordering, which this scan does not resolve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..gpo.parsers import (
    REGISTRY_XML_ACTIONS,
    REGISTRY_XML_DRIFT_CORRECTING_ACTIONS,
    REGISTRY_XML_WRITE_ACTIONS,
    normalize_registry_key,
)
from .catalog import (
    EVALUABLE_CHECK_TYPES,
    STATUS_NEEDS_BASELINE_VALUE,
    Control,
)

# Results a finding can carry. ``unknown`` is the verdict-less verdict: the scan
# established neither compliance nor non-compliance, and says so instead of
# guessing. It is distinct from ``error`` — nothing went wrong, the evidence a
# GPO scan can reach simply does not settle the question (see
# :func:`_no_gpo_trace_finding`).
RESULT_PASS = "pass"
RESULT_FAIL = "fail"
RESULT_UNKNOWN = "unknown"
RESULT_NOT_APPLICABLE = "not_applicable"
RESULT_ERROR = "error"

# Every value ``result`` can take. Advertised by the tool layer, so it lives
# next to the constants rather than being retyped there.
RESULTS = (RESULT_PASS, RESULT_FAIL, RESULT_UNKNOWN, RESULT_NOT_APPLICABLE,
           RESULT_ERROR)

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
# configured one without parsing prose. ``unknown`` is the label for "the scan
# does not know", which covers both a control the engine refuses to judge and a
# scan whose GPO reads failed: neither may be rendered as "not configured",
# because "we could not look" is not the same claim as "nothing sets it".
EVIDENCE_SOURCE_GPO = "gpo"
EVIDENCE_SOURCE_OS_DEFAULT = "os-default"
EVIDENCE_SOURCE_NOT_CONFIGURED = "not-configured"
EVIDENCE_SOURCE_UNKNOWN = "unknown"

# Every value ``evidence.source`` can take. The tool layer advertises this list,
# so it lives next to the constants rather than being retyped there.
EVIDENCE_SOURCES = (EVIDENCE_SOURCE_GPO, EVIDENCE_SOURCE_OS_DEFAULT,
                    EVIDENCE_SOURCE_NOT_CONFIGURED, EVIDENCE_SOURCE_UNKNOWN)

# How a GPO put the value in place. Recorded per found value in
# ``evidence.found[].delivery`` — see the module docstring for why this is
# evidence rather than a separate ``check_type``.
DELIVERY_SECURITY_TEMPLATE = "security-template"
DELIVERY_REGISTRY_POL = "registry-pol"
DELIVERY_REGISTRY_PREFERENCE = "registry-preference"
DELIVERIES = (DELIVERY_SECURITY_TEMPLATE, DELIVERY_REGISTRY_POL,
              DELIVERY_REGISTRY_PREFERENCE)

# The two mechanisms that are *policy*: the value reverts when the GPO stops
# applying. Everything not in here is a preference, which tattoos.
POLICY_DELIVERIES = frozenset({DELIVERY_SECURITY_TEMPLATE,
                               DELIVERY_REGISTRY_POL})

# Where each delivery mechanism was read from, for the evidence's source_file.
SOURCE_FILE_SECURITY_TEMPLATE = "GptTmpl.inf [Registry Values]"
SOURCE_FILE_REGISTRY_POL = "Registry.pol"
SOURCE_FILE_REGISTRY_XML = "Preferences\\Registry\\Registry.xml"

# Why a preference item that names the control's key is not counted as setting
# it. Recorded per excluded item so the note can say which case it was.
NON_WRITE_DISABLED = "disabled"
NON_WRITE_DELETE = "delete"
NON_WRITE_UNRECOGNISED_ACTION = "unrecognised-action"

# A preference item that deletes the whole KEY the control's value lives in.
# Reported by :func:`find_preference_key_deletes` rather than by
# :func:`find_preference_non_writes`: it names no value at all, so it is not a
# "this item does not write the value" case but a "something is removing the
# ground the value stands on" case.
NON_WRITE_KEY_DELETE = "key-delete"

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
_OS_DEFAULT_CAP_NOTE = (
    "Rollout state is capped at 'audit': the documented default ({value!r}) "
    "meets this control's final target, but nothing enforces a default, so "
    "reporting 'enforced' would credit Group Policy with a value it does not "
    "set. Configure the policy explicitly to reach 'enforced'."
)
_PREFERENCE_TATTOO_NOTE = (
    "At least one value below is delivered by a Group Policy Preferences "
    "registry item, not by a policy setting. A preference TATTOOS: it writes the "
    "value into the registry and the value stays there if the GPO is unlinked, "
    "deleted or scoped away, where a policy value reverts. So a pass here is a "
    "weaker statement about ongoing state than a policy would be - and also a "
    "stickier one, because the value can persist on machines the GPO no longer "
    "reaches. This scan reads Group Policy, not the machines."
)
_PREFERENCE_CREATE_NOTE = (
    "At least one preference item below uses action 'C' (Create), which writes "
    "the value ONLY when it does not already exist. It therefore does not "
    "correct drift: if the value is changed on a machine afterwards, Group "
    "Policy will leave the changed value in place. Use Update or Replace where "
    "the intent is to hold the value at this setting."
)
_PREFERENCE_FILTER_NOTE = (
    "At least one preference item below carries item-level targeting "
    "(<Filters>), so it may apply to only some of the machines its GPO reaches. "
    "This scan does not evaluate targeting, so read this verdict as 'configured "
    "where the filter matches', not as domain-wide coverage - check the filter "
    "in GPMC before relying on it."
)
_MIXED_DELIVERY_DETAIL = (
    "One of these values comes from a policy setting and one from a Group Policy "
    "preference item ({summary}), so which value a machine ends up with depends "
    "on the order the Group Policy client-side extensions run - not on link "
    "precedence - and this scan resolves neither. The two can also diverge over "
    "time: the preference value tattoos and survives its GPO being unlinked, "
    "while the policy value reverts. Confirm the effective value on a "
    "representative machine before trusting either."
)
_NO_GPO_TRACE_NOTE = (
    "Reported as 'unknown', not as a failure. This control's documented "
    "remediation is a direct registry write on the domain controllers, which "
    "leaves no trace in Group Policy at all, so the key appearing in no GPO is "
    "NOT evidence that the value is unset. This scan reads Group Policy and not "
    "the machines, so it cannot see the live value either way and issues no "
    "verdict. Check it on each domain controller with: {command}"
)
_NO_GPO_TRACE_NOTE_NO_COMMAND = (
    "Reported as 'unknown', not as a failure. This control's documented "
    "remediation is a direct registry write on the domain controllers, which "
    "leaves no trace in Group Policy at all, so the key appearing in no GPO is "
    "NOT evidence that the value is unset. This scan reads Group Policy and not "
    "the machines, so it cannot see the live value either way and issues no "
    "verdict. Read the value directly on each domain controller to settle it."
)
_UNREADABLE_OS_DEFAULT_NOTE = (
    "No GPO that could be read sets this key, but {unreadable} of {total} GPO(s) "
    "could not be read at all, so 'nothing sets this key' is unproven. The "
    "documented Windows default ({value!r}) is therefore NOT applied: an "
    "unreadable GPO could set this value to anything, including a value below "
    "the default. Reported as an error rather than a pass — fix the read failures "
    "below and re-scan."
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
        registry_xml_entries: ``{hive, key, value_name, type, type_name, value,
            action, order, has_filters, disabled, deletes_key}`` dicts from
            ``parse_registry_xml`` over the machine
            ``Preferences\\Registry\\Registry.xml``. Defaults to empty, so a
            caller that does not read preferences behaves exactly as before.
        links: Where the GPO is linked, with enforcement flags.
        read_error: Set when the GPO's content could not be read, so findings
            can say "unknown" rather than "not configured".
    """

    dn: str
    display_name: str = ""
    guid: str = ""
    security_template_entries: Sequence[Dict[str, Any]] = field(default_factory=tuple)
    registry_pol_entries: Sequence[Dict[str, Any]] = field(default_factory=tuple)
    registry_xml_entries: Sequence[Dict[str, Any]] = field(default_factory=tuple)
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

    ``gpo-registry-pol`` searches **two** sources: the admin-template
    ``Registry.pol`` and Group Policy Preferences ``Registry.xml``. A registry
    value with no ADMX policy behind it can only be delivered by a preference
    item, so searching ``Registry.pol`` alone systematically under-reports
    hardening the operator has really done. Preference items name their hive in
    full (``HKEY_LOCAL_MACHINE``), which ``normalize_registry_key`` already
    folds.

    A preference item that does not *write* the value is not a match: an
    ``action="D"`` item removes it, and a disabled item writes nothing. Counting
    either as configuring the value would report hardening that Group Policy is
    actively undoing. Those items are not discarded silently — see
    :func:`find_preference_non_writes`.

    Returns:
        One dict per setting found: the GPO's identity and links, the key and
        value as they appear in the GPO, the type, and ``delivery`` (plus a
        ``preference`` sub-dict for preference items, ``None`` otherwise).
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
                                     SOURCE_FILE_SECURITY_TEMPLATE,
                                     DELIVERY_SECURITY_TEMPLATE))
        elif control.check_type == "gpo-registry-pol":
            for entry in gpo.registry_pol_entries or ():
                full_key = f"{entry.get('key', '')}\\{entry.get('value', '')}"
                if normalize_registry_key(full_key, MACHINE_POL_HIVE) != wanted:
                    continue
                matches.append(_match(gpo, full_key, entry.get("data"),
                                     entry.get("type"), SOURCE_FILE_REGISTRY_POL,
                                     DELIVERY_REGISTRY_POL))
            for entry in gpo.registry_xml_entries or ():
                full_key = _preference_key(entry)
                if normalize_registry_key(full_key, MACHINE_POL_HIVE) != wanted:
                    continue
                if _non_write_reason(entry) is not None:
                    continue
                matches.append(_match(gpo, full_key, entry.get("value"),
                                     entry.get("type_name"),
                                     SOURCE_FILE_REGISTRY_XML,
                                     DELIVERY_REGISTRY_PREFERENCE,
                                     preference=_preference_evidence(entry)))
    return matches


def find_preference_non_writes(control: Control,
                               gpos: Iterable[GpoSnapshot]
                               ) -> List[Dict[str, Any]]:
    """Preference items that name the control's key but do not set a value.

    Three cases, and none of them is a match:

    * ``action="D"`` — the item **deletes** the value. Reporting a Delete as
      "configured" would be the most damaging possible misread: it would show
      hardening on a key the GPO is actively clearing.
    * the item is disabled in GPMC, so it writes nothing.
    * the action is not one of ``C``/``R``/``U``/``D``, so whether it writes the
      value is unknown — and unknown is not a pass.

    They are reported rather than dropped, because "a GPO deletes this value" is
    very often the explanation for the failure the reader is looking at.
    """
    wanted = normalize_registry_key(control.registry_key)
    excluded: List[Dict[str, Any]] = []
    if not wanted or control.check_type != "gpo-registry-pol":
        return excluded

    for gpo in gpos:
        for entry in gpo.registry_xml_entries or ():
            full_key = _preference_key(entry)
            if normalize_registry_key(full_key, MACHINE_POL_HIVE) != wanted:
                continue
            reason = _non_write_reason(entry)
            if reason is None:
                continue
            excluded.append({
                "gpo_dn": gpo.dn,
                "gpo_display_name": gpo.display_name,
                "gpo_guid": gpo.guid,
                "registry_key": full_key,
                "delivery": DELIVERY_REGISTRY_PREFERENCE,
                "source_file": SOURCE_FILE_REGISTRY_XML,
                "reason": reason,
                "preference": _preference_evidence(entry),
            })
    return excluded


def find_preference_key_deletes(control: Control,
                                gpos: Iterable[GpoSnapshot]
                                ) -> List[Dict[str, Any]]:
    """Preference items that delete a whole **key** covering the control's key.

    A GPP registry item can be scoped to a key rather than a value:
    ``<Properties action="D" hive="HKEY_LOCAL_MACHINE" key="...\\Wintrust\\Config"/>``
    removes that key and everything in it. Such an item names no value, so it can
    never appear in :func:`find_matches` or :func:`find_preference_non_writes`,
    both of which compare a full value path — which is exactly how it went
    unnoticed: a GPO clearing the key underneath a hardened value was invisible,
    and the value read as configured.

    "Covers" means the deleted key **is** the control's key path, or is a parent
    of it: deleting ``...\\Wintrust`` takes ``...\\Wintrust\\Config`` with it.
    Matching is on path components, so ``...\\Config`` never matches
    ``...\\ConfigExtra``.

    A **disabled** item is not reported: it writes nothing and deletes nothing,
    so disclosing it as removing the key would be its own false statement.

    Like :func:`find_preference_non_writes`, this is restricted to
    ``gpo-registry-pol`` controls, matching where :func:`find_matches` looks at
    preferences at all. Widening it would change verdict evidence for
    security-template controls, which is not what this fix is for.

    Returns:
        One dict per covering key-delete: the GPO's identity, the key it deletes
        (as written), and the preference evidence. These are *disclosures*, never
        matches — the evaluator has no precedence model and does not pretend to
        know whether the delete or the write wins.
    """
    deletes: List[Dict[str, Any]] = []
    wanted_path = normalize_registry_key(control.registry_key_path,
                                         MACHINE_POL_HIVE)
    if not wanted_path or control.check_type != "gpo-registry-pol":
        return deletes

    for gpo in gpos:
        for entry in gpo.registry_xml_entries or ():
            if not entry.get("deletes_key") or entry.get("disabled"):
                continue
            deleted = normalize_registry_key(
                "\\".join(part for part in (entry.get("hive"), entry.get("key"))
                          if part),
                MACHINE_POL_HIVE)
            if not deleted or not _key_covers(deleted, wanted_path):
                continue
            deletes.append({
                "gpo_dn": gpo.dn,
                "gpo_display_name": gpo.display_name,
                "gpo_guid": gpo.guid,
                "deleted_key": "\\".join(
                    part for part in (entry.get("hive"), entry.get("key"))
                    if part),
                "delivery": DELIVERY_REGISTRY_PREFERENCE,
                "source_file": SOURCE_FILE_REGISTRY_XML,
                "reason": NON_WRITE_KEY_DELETE,
                "preference": _preference_evidence(entry),
            })
    return deletes


def _key_covers(deleted: str, wanted_path: str) -> bool:
    """Whether a deleted key is, or contains, ``wanted_path``.

    Both arguments must already be normalised. The separator check is what stops
    ``...\\CONFIG`` from being read as covering ``...\\CONFIGEXTRA``.
    """
    return wanted_path == deleted or wanted_path.startswith(deleted + "\\")


def _preference_key(entry: Dict[str, Any]) -> str:
    """Rejoin a preference item's hive, key and value name into one path."""
    parts = [entry.get("hive"), entry.get("key"), entry.get("value_name")]
    return "\\".join(part for part in parts if part)


def _non_write_reason(entry: Dict[str, Any]) -> Optional[str]:
    """Why this preference item does not set the value, or ``None`` if it does.

    Order matters: a disabled item writes nothing whatever its action says, so
    ``disabled`` is checked first and every item lands in exactly one bucket.
    """
    if entry.get("disabled"):
        return NON_WRITE_DISABLED
    action = entry.get("action")
    if action in REGISTRY_XML_WRITE_ACTIONS:
        return None
    if action == "D":
        return NON_WRITE_DELETE
    return NON_WRITE_UNRECOGNISED_ACTION


def _preference_evidence(entry: Dict[str, Any]) -> Dict[str, Any]:
    """The preference-specific facts an auditor needs about a found value."""
    action = entry.get("action")
    return {
        "action": action,
        "action_name": REGISTRY_XML_ACTIONS.get(action) if isinstance(action, str)
                       else None,
        "corrects_drift": action in REGISTRY_XML_DRIFT_CORRECTING_ACTIONS,
        # Every preference item tattoos; it is stated per value rather than
        # left to prose so the report layer never has to infer it.
        "tattoos": True,
        "has_filters": bool(entry.get("has_filters")),
        "disabled": bool(entry.get("disabled")),
        "item_order": entry.get("order"),
    }


def _match(gpo: GpoSnapshot, key: Any, value: Any, type_name: Any,
           source_file: str, delivery: str,
           preference: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "gpo_dn": gpo.dn,
        "gpo_display_name": gpo.display_name,
        "gpo_guid": gpo.guid,
        "registry_key": key,
        "type_name": type_name,
        "value": value,
        "source_file": source_file,
        "delivery": delivery,
        "preference": preference,
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

    The finding carries ``result`` (``pass``/``fail``/``unknown``/
    ``not_applicable``/``error``), ``rollout_state``, ``evidence`` (expected
    versus found, with the source GPO DN and link path) and ``conflict``.

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
                                 "expected value", gpos)
    if control.check_type not in EVALUABLE_CHECK_TYPES:
        return _unscored_finding(
            control, UNSCORED_UNSUPPORTED_CHECK_TYPE,
            f"check type {control.check_type!r} has no evaluator in this release",
            gpos)

    try:
        matches = find_matches(control, gpos)
        non_writes = find_preference_non_writes(control, gpos)
        key_deletes = find_preference_key_deletes(control, gpos)
    except Exception as exc:  # pragma: no cover - defensive
        return _error_finding(control, f"could not scan GPO content: {exc}",
                              [], gpos)

    # Preference items that name the key but delete it, are disabled, or carry
    # an action we do not recognise. They set nothing, so they are not matches —
    # but they are usually the explanation for whatever verdict follows. A
    # key-scoped delete is the same story one level up: it removes the key the
    # value lives in, which no value-path comparison can see.
    extra_notes = _non_write_notes(non_writes) + _key_delete_notes(key_deletes)

    if control.operator == "absent":
        return _absent_finding(control, matches, gpos, extra_notes)
    if not matches:
        return _missing_finding(control, gpos, extra_notes)

    try:
        assessed = [dict(match, rollout_state=_state_for(control, match["value"]))
                    for match in matches]
    except OperatorError as exc:
        return _error_finding(control, str(exc), matches, gpos,
                              notes=extra_notes)

    states = {match["rollout_state"] for match in assessed}
    worst = min(states, key=lambda state: _STATE_RANK[state])
    conflict = _detect_conflict(assessed)

    if control.operator == "present":
        result = RESULT_PASS
        rollout_state = control.presence_rollout_state or STATE_AUDIT
    else:
        result = RESULT_FAIL if worst == STATE_NOT_STARTED else RESULT_PASS
        rollout_state = worst

    finding = _finding(control, result, rollout_state, assessed, gpos,
                       notes=extra_notes)
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
        ``needs_baseline_value``, ``conflicts``, ``os_default``,
        ``os_default_pass``, ``hidden``, ``rendered``, ``scored`` and ``total``,
        so a report never has to infer a total from a filtered list.

        **Every count describes what was evaluated, not what was rendered.**
        ``total`` and the per-result counts have always been pre-filter, and
        ``os_default`` is deliberately the same — a control that was judged
        against a documented default was judged whether or not the visibility
        filter shows it. ``rendered`` and ``hidden`` say how many findings the
        filter kept and dropped, so a caller comparing ``len(findings)`` with the
        counts has the reconciliation instead of having to guess at a discrepancy.

        ``os_default`` counts findings whose verdict rests on a documented Windows
        default rather than on any GPO. It is **not** a number to subtract from
        ``pass``: an os-default finding can now be ``fail`` (a default below the
        floor) or ``not_applicable`` (a conditional control), so subtracting the
        total would understate configured passes. ``os_default_pass`` is the
        subset that actually returned ``pass``, and is the number to subtract from
        ``pass`` to get "passes a GPO configures".
    """
    gpos = list(gpos)
    counts = {RESULT_PASS: 0, RESULT_FAIL: 0, RESULT_UNKNOWN: 0,
              RESULT_NOT_APPLICABLE: 0,
              RESULT_ERROR: 0, "needs_baseline_value": 0, "conflicts": 0,
              "os_default": 0, "os_default_pass": 0, "scored": 0,
              "rendered": 0, "hidden": 0, "total": 0}
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
            if finding["result"] == RESULT_PASS:
                counts["os_default_pass"] += 1

        hide = (finding["result"] == RESULT_NOT_APPLICABLE
                and not include_not_applicable
                and finding.get("unscored_reason") is None)
        if hide:
            counts["hidden"] += 1
        else:
            counts["rendered"] += 1
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


def _delivery_notes(matches: Sequence[Dict[str, Any]]) -> List[str]:
    """The caveats that follow from *how* the found values were delivered.

    Only preferences carry any, and only when they apply: a finding whose values
    all come from ``Registry.pol`` or a security template gains nothing here, so
    existing verdicts are untouched.
    """
    preferences = [match for match in matches
                   if match.get("delivery") == DELIVERY_REGISTRY_PREFERENCE]
    if not preferences:
        return []

    notes = [_PREFERENCE_TATTOO_NOTE]
    if any((match.get("preference") or {}).get("action") == "C"
           for match in preferences):
        notes.append(_PREFERENCE_CREATE_NOTE)
    if any((match.get("preference") or {}).get("has_filters")
           for match in preferences):
        notes.append(_PREFERENCE_FILTER_NOTE)
    return notes


def _non_write_notes(non_writes: Sequence[Dict[str, Any]]) -> List[str]:
    """State the preference items that name the key but do not set it.

    One note per reason, naming the GPOs, because "a preference deletes this
    value" is usually the answer to the question the reader is holding.
    """
    if not non_writes:
        return []

    def names(items: Sequence[Dict[str, Any]]) -> str:
        return ", ".join(item.get("gpo_display_name") or item.get("gpo_dn") or "?"
                         for item in items)

    notes: List[str] = []
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in non_writes:
        grouped.setdefault(item["reason"], []).append(item)

    deletes = grouped.get(NON_WRITE_DELETE) or []
    if deletes:
        notes.append(
            f"{len(deletes)} Group Policy preference item(s) DELETE this value "
            f"rather than set it ({names(deletes)}). A Delete action removes the "
            f"value, so it is never counted as configuring it. If this control "
            f"fails, that is very likely why; if it passes, something else is "
            f"setting the value and the two are working against each other.")

    disabled = grouped.get(NON_WRITE_DISABLED) or []
    if disabled:
        notes.append(
            f"{len(disabled)} Group Policy preference item(s) naming this value "
            f"are disabled and write nothing ({names(disabled)}). They are not "
            f"counted as configuring it - re-enable the item in GPMC if the "
            f"value was meant to be applied.")

    unrecognised = grouped.get(NON_WRITE_UNRECOGNISED_ACTION) or []
    if unrecognised:
        actions = ", ".join(sorted({
            repr((item.get("preference") or {}).get("action"))
            for item in unrecognised}))
        notes.append(
            f"{len(unrecognised)} Group Policy preference item(s) naming this "
            f"value carry an action this scan does not recognise ({actions}) "
            f"({names(unrecognised)}). They are not counted as configuring it, "
            f"because whether they write the value is unknown - and unknown is "
            f"not a pass.")
    return notes


def _key_delete_notes(key_deletes: Sequence[Dict[str, Any]]) -> List[str]:
    """Disclose preference items that delete the key this value lives in.

    The shape mirrors the value-level Delete disclosure, one level up. It is a
    *disclosure*, not a verdict: this scan has no precedence model, so it says
    what both GPOs do, names them, and points at the mechanism that decides —
    client-side extension ordering, which link precedence cannot settle.
    """
    if not key_deletes:
        return []

    names = ", ".join(item.get("gpo_display_name") or item.get("gpo_dn") or "?"
                      for item in key_deletes)
    keys = ", ".join(sorted({str(item.get("deleted_key") or "?")
                             for item in key_deletes}))
    return [
        f"{len(key_deletes)} Group Policy preference item(s) DELETE a registry "
        f"KEY that contains this control's value, rather than deleting the value "
        f"itself ({names}; key(s): {keys}). A key delete removes the key and "
        f"everything in it, so it is never counted as configuring anything. If "
        f"this control passes, another GPO is removing the key underneath the "
        f"value that passed it, and which one takes effect depends on the order "
        f"the Group Policy client-side extensions run - not on link precedence, "
        f"and this scan resolves neither. Confirm the effective state on a "
        f"representative machine before trusting this verdict."
    ]


def _detect_conflict(assessed: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Flag disagreement between GPOs setting the same key.

    Three shapes matter. Plain ``value-disagreement`` means two GPOs set
    different values and, without RSoP, which one wins is unproven.
    ``enforced-override`` means one of the disagreeing GPOs is linked with
    enforcement, so it very likely overrides the others regardless of where they
    sit — the case where a "pass" read off the compliant GPO would be actively
    misleading. ``policy-preference-disagreement`` means the disagreement is
    between a *policy* value and a Group Policy *preference* item, which is a
    different failure mode: which one lands depends on the order the client-side
    extensions run rather than on link precedence, and because a preference
    tattoos while a policy reverts, the two can also drift apart over time.

    The delivery distinction never suppresses ``enforced-override`` — an enforced
    link is the more urgent fact — but it is added to that conflict's detail when
    a preference is involved, so the reader is not told to settle it with link
    precedence alone.
    """
    if len(assessed) < 2:
        return None
    distinct = {_as_comparable(match["value"]) for match in assessed}
    if len(distinct) < 2:
        return None

    settings = [{"gpo_dn": m["gpo_dn"], "gpo_display_name": m["gpo_display_name"],
                 "value": m["value"], "enforced_link": m["enforced_link"],
                 "rollout_state": m["rollout_state"],
                 "delivery": m.get("delivery"),
                 "preference_action": (m.get("preference") or {}).get("action")}
                for m in assessed]
    enforcing = [m for m in assessed if m["enforced_link"]]
    deliveries = {m.get("delivery") for m in assessed}
    mixed_delivery = (DELIVERY_REGISTRY_PREFERENCE in deliveries
                      and bool(deliveries & POLICY_DELIVERIES))

    if enforcing:
        names = ", ".join(f"{m['gpo_display_name'] or m['gpo_dn']} = {m['value']!r}"
                          for m in enforcing)
        detail = (f"{len(assessed)} GPOs set this key to different values and "
                  f"at least one is linked with enforcement ({names}), so the "
                  f"other settings are likely overridden. Precedence is not "
                  f"resolved here — verify with RSoP / gpresult before "
                  f"trusting any single value.")
        if mixed_delivery:
            detail += " " + _MIXED_DELIVERY_DETAIL.format(
                summary=_delivery_summary(assessed))
        return {
            "detected": True,
            "kind": "enforced-override",
            "detail": detail,
            "settings": settings,
        }
    if mixed_delivery:
        return {
            "detected": True,
            "kind": "policy-preference-disagreement",
            "detail": (f"{len(assessed)} GPOs set this key to different values, "
                       f"and the disagreement is between a policy setting and a "
                       f"Group Policy preference item. "
                       + _MIXED_DELIVERY_DETAIL.format(
                           summary=_delivery_summary(assessed))),
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


def _delivery_summary(assessed: Sequence[Dict[str, Any]]) -> str:
    """``'Policy A' = 2 (registry-pol), 'Pref B' = 0 (registry-preference)``."""
    return ", ".join(
        f"{match['gpo_display_name'] or match['gpo_dn']} = {match['value']!r} "
        f"({match.get('delivery')})" for match in assessed)


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
    notes.extend(_delivery_notes(matches))
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


def _unreadable_gpos(gpos: Sequence[GpoSnapshot]) -> List[GpoSnapshot]:
    """The GPOs whose content could not be read at all."""
    return [gpo for gpo in gpos if gpo.read_error]


def _missing_finding(control: Control, gpos: Sequence[GpoSnapshot],
                     extra_notes: Sequence[str] = ()) -> Dict[str, Any]:
    """No GPO sets the key: the control's own semantics decide what that means.

    A control that documents an ``os_default`` is evaluated against that default
    instead (see :func:`_os_default_finding`) — for those settings, "no GPO sets
    it" does not mean "off".

    **Unless the scan could not read every GPO.** ``find_matches`` can only
    report keys it managed to read, so an empty match list means "no GPO *that
    we read* sets this key", which is not the same claim as "no GPO sets this
    key". The os-default branch depends on the stronger claim — it concludes that
    the Windows default is what is actually in effect — so a single unreadable
    GPO invalidates it, and the finding becomes an ``error`` rather than an
    assumed pass (see :func:`_incomplete_scan_finding`).

    The no-``os_default`` branch is left alone deliberately: it already returns
    the control's ``missing_result`` (``fail`` or ``not_applicable``), never a
    pass, and :func:`_finding` already notes which GPOs went unread. Turning
    those into errors as well would change every verdict on any domain with one
    unreadable GPO, which is a far larger change than the unsound-pass this fix
    exists to close.

    **And unless a GPO was never the delivery mechanism.** A control flagged
    ``gpo_deliverable: false`` documents a remediation that writes the registry
    directly on the domain controllers, so its key is not expected to appear in a
    GPO even on a domain that has applied it. For those controls an empty match
    list is not evidence of anything, and the finding is ``unknown`` (see
    :func:`_no_gpo_trace_finding`).

    That branch is checked **first**, before the os-default branch, for the same
    reason the unreadable-GPO branch exists: the os-default branch concludes that
    the Windows default is the effective value, which needs "nothing sets this
    key" to be established, and a documented direct-write remediation is exactly
    the case where absence from GPO does not establish it.
    """
    note = control.missing_note or "No GPO in the domain sets this key."
    if not control.gpo_deliverable:
        return _no_gpo_trace_finding(control, gpos, note, extra_notes)
    if control.os_default is not None:
        unreadable = _unreadable_gpos(gpos)
        if unreadable:
            return _incomplete_scan_finding(control, gpos, unreadable,
                                            extra_notes)
        return _os_default_finding(control, gpos, note, extra_notes)
    return _finding(control, control.missing_result or RESULT_FAIL,
                    STATE_NOT_STARTED, [], gpos,
                    notes=[note] + list(extra_notes))


def _no_gpo_trace_finding(control: Control, gpos: Sequence[GpoSnapshot],
                          missing_note: str,
                          extra_notes: Sequence[str] = ()) -> Dict[str, Any]:
    """The key is in no GPO, and for this control that proves nothing.

    ``DEVORE-03-LDAP-DIAG-LOGGING`` was the case that exposed this: Devore's own
    instruction for it is ``reg add`` on the domain controllers, not a GPO, so a
    domain with the value correctly set to 3 *directly on the DC* reported
    ``fail`` / ``not-configured``. That is a false negative asserted with full
    confidence — the scanner claiming a fact ("this is not configured") that the
    evidence it holds cannot support — and it cost real remediation time.

    So the verdict is ``unknown`` with ``rollout_state`` ``None``: no rollout step
    was reached because no value was read, and inventing ``not_started`` would
    imply a value below the interim step. ``evidence.source`` is ``unknown``,
    never ``not-configured``: "we cannot see it" is a different claim from
    "nothing sets it", which is the whole point of the fix.

    This is **more** actionable than a bare ``fail``, not less. The notes say
    exactly what the scan can and cannot see, and hand the reader the one
    ``reg query`` that closes the gap — derived from the control's own
    ``registry_key``, so it always names the key actually asserted.

    ``result`` is not ``error``: nothing went wrong, and an error means the scan
    broke. It is not ``not_applicable`` either — the control applies perfectly
    well, and ``not_applicable`` findings are hidden by default, which would bury
    precisely the thing the reader needs. ``unknown`` is never hidden.

    The field only affects the *absent* case. A ``gpo_deliverable: false`` control
    whose key **is** found in a GPO never reaches here: it is judged on the value
    exactly like any other control.
    """
    command = control.absence_check_command
    reason = (_NO_GPO_TRACE_NOTE.format(command=command) if command
              else _NO_GPO_TRACE_NOTE_NO_COMMAND)
    return _finding(control, RESULT_UNKNOWN, None, [], gpos,
                    notes=[missing_note, reason] + list(extra_notes),
                    evidence_source=EVIDENCE_SOURCE_UNKNOWN)


def _incomplete_scan_finding(control: Control, gpos: Sequence[GpoSnapshot],
                             unreadable: Sequence[GpoSnapshot],
                             extra_notes: Sequence[str] = ()) -> Dict[str, Any]:
    """The key is unset in everything we read, but we could not read everything.

    This is the honest verdict for "the scan found nothing and also could not
    look everywhere". It must not be a ``pass``: taking the os-default branch
    here would assert that the Windows default is the effective value on the
    strength of GPOs nobody read, which is exactly the "more confidence than the
    evidence supports" failure this catalog exists to avoid.

    ``error`` rather than ``not_applicable``, for two reasons. ``not_applicable``
    is a claim about *scope* — "this control does not apply to this domain" —
    which is not what happened; and ``not_applicable`` findings are hidden by
    default (``include_not_applicable=False``), so the one thing a reader most
    needs to see would be filtered out of the report. ``error`` is never hidden,
    is counted separately, and says what is true: the scan could not decide.

    The documented default is still reported in ``evidence.os_default`` — a
    reader wants to know what the default *would* have been — but carries
    ``applied: False`` and the reason, so nothing downstream can mistake it for
    the value the verdict rests on.
    """
    detail = (f"{len(unreadable)} of {len(gpos)} GPO(s) could not be read, so it "
              f"is unproven that no GPO sets this key; the documented Windows "
              f"default was not applied")
    return _error_finding(
        control, detail, [], gpos,
        evidence_source=EVIDENCE_SOURCE_UNKNOWN,
        os_default_evidence={
            "value": control.os_default,
            "source": EVIDENCE_SOURCE_OS_DEFAULT,
            "applied": False,
            "enforced_by_gpo": False,
            "not_applied_reason": (
                "one or more GPOs could not be read, so 'no GPO sets this key' "
                "is unproven and the default cannot be assumed effective"),
            "value_source": control.value_source,
        },
        notes=[_UNREADABLE_OS_DEFAULT_NOTE.format(
            unreadable=len(unreadable), total=len(gpos),
            value=control.os_default)] + list(extra_notes))


def _os_default_finding(control: Control, gpos: Sequence[GpoSnapshot],
                        missing_note: str,
                        extra_notes: Sequence[str] = ()) -> Dict[str, Any]:
    """Judge the assertion against the documented Windows default.

    Unset is not automatically insecure: ``LdapClientIntegrity`` is ``1``
    (Negotiate signing) on a machine no GPO has ever touched, so reporting
    ``fail`` / ``not_started`` there states more than the evidence supports.
    The value is still only *assumed*, so the finding says so three ways —
    ``evidence.source`` is ``os-default``, ``evidence.os_default`` carries the
    value with the source that documents it, and a note spells out that no GPO
    enforces it. ``found`` stays empty and ``found_count`` zero, because no GPO
    was found; the default is not fabricated into a match.

    **``missing_result`` wins in both directions.** A control whose
    ``missing_result`` is ``not_applicable`` has declared that an unset key means
    "this does not apply here" — a statement about *scope*, which knowing the OS
    default cannot change. So such a control reports ``not_applicable`` whether the
    default falls below the floor or meets it. Honouring ``missing_result`` only on
    the way down (the original behaviour) contradicted the rule it was written to
    express: a default that met the floor returned a scored ``pass``, quietly making
    a control apply that its author said does not.

    Controls whose ``missing_result`` is ``fail`` are unaffected: the default is
    judged, and it passes or fails on its merits.

    **``rollout_state`` is capped at ``audit``.** ``_state_for`` will happily
    return ``enforced`` for a default that meets ``final_expected``, but nothing
    enforces a default — the phrase means "Group Policy holds this value here",
    and on a domain that configures nothing that is simply false. The cap lives
    here rather than in the catalog because it is a property of what an OS default
    *is*, not of any particular control's numbers: the single shipped default
    happens to sit below its final step today, and a future control whose
    documented default meets its target must not quietly start reporting
    ``enforced``.
    """
    try:
        rollout_state = _state_for(control, control.os_default)
    except OperatorError as exc:  # pragma: no cover - defensive
        return _error_finding(control, f"os_default {control.os_default!r} "
                                       f"could not be compared: {exc}", [], gpos)

    notes = [missing_note, _OS_DEFAULT_NOTE.format(value=control.os_default)]
    notes.extend(extra_notes)
    capped = rollout_state == STATE_ENFORCED
    if capped:
        rollout_state = STATE_AUDIT
        notes.append(_OS_DEFAULT_CAP_NOTE.format(value=control.os_default))

    if control.missing_result == RESULT_NOT_APPLICABLE:
        # The control declared that an unset key puts it out of scope. A default
        # cannot bring it back into scope, however compliant that default is.
        result = RESULT_NOT_APPLICABLE
        notes.append(
            "This control reports 'not applicable' when no GPO sets the key, so "
            "the documented default is reported for information only and does not "
            "produce a pass: knowing the default cannot make a control apply that "
            "its author said does not apply here.")
    elif rollout_state == STATE_NOT_STARTED:
        result = RESULT_FAIL
    else:
        result = RESULT_PASS

    return _finding(
        control, result, rollout_state, [], gpos,
        notes=notes,
        evidence_source=EVIDENCE_SOURCE_OS_DEFAULT,
        os_default_evidence={
            "value": control.os_default,
            "source": EVIDENCE_SOURCE_OS_DEFAULT,
            "applied": True,
            "enforced_by_gpo": False,
            "meets_final_expected": capped,
            "rollout_state_capped": capped,
            "value_source": control.os_default_source,
        })


def _absent_finding(control: Control, matches: List[Dict[str, Any]],
                    gpos: Sequence[GpoSnapshot],
                    extra_notes: Sequence[str] = ()) -> Dict[str, Any]:
    """``absent`` inverts the usual sense: finding the key is the failure."""
    if matches:
        assessed = [dict(match, rollout_state=STATE_NOT_STARTED)
                    for match in matches]
        finding = _finding(
            control, RESULT_FAIL, STATE_NOT_STARTED, assessed, gpos,
            notes=["This key must not be set; the GPO(s) below set it."]
                  + list(extra_notes))
        finding["conflict"] = _detect_conflict(assessed)
        return finding
    return _finding(
        control, RESULT_PASS,
        control.presence_rollout_state or STATE_ENFORCED, [], gpos,
        notes=["No GPO sets this key, which is what the control requires."]
              + list(extra_notes))


def _unscored_finding(control: Control, reason: str, detail: str,
                      gpos: Sequence[GpoSnapshot] = ()) -> Dict[str, Any]:
    """A control the engine deliberately refuses to judge.

    ``evidence.source`` is ``unknown`` rather than ``None``: the state of this
    setting genuinely was not established, and every finding advertising a
    ``source`` from the same small vocabulary is what lets the report layer
    render it without special-casing a null.
    """
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
            "source": EVIDENCE_SOURCE_UNKNOWN,
            "os_default": None,
            "found": [],
            "found_count": 0,
            "gpos_searched": len(gpos),
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
                   matches: List[Dict[str, Any]],
                   gpos: Sequence[GpoSnapshot] = (),
                   evidence_source: Optional[str] = None,
                   os_default_evidence: Optional[Dict[str, Any]] = None,
                   notes: Optional[List[str]] = None) -> Dict[str, Any]:
    """A control the engine could not decide.

    ``evidence_source`` defaults to ``gpo`` when settings were found and
    ``unknown`` when they were not: an error means the scan does not know what is
    configured, and labelling that ``not-configured`` would state a fact the scan
    did not establish. Callers whose error is *about* the OS default pass
    ``os_default_evidence`` so the finding can report the default it declined to
    apply, rather than a bare ``None`` that hides what was at stake.
    """
    notes = list(notes or [])
    notes.append(f"Could not evaluate: {message}. Reported as an error rather "
                 f"than a pass or a fail.")
    unreadable = _unreadable_gpos(gpos)
    if unreadable:
        notes.append(f"{len(unreadable)} GPO(s) could not be read and were not "
                     f"searched for this key: "
                     f"{', '.join(gpo.dn for gpo in unreadable)}")
        notes.extend(f"{gpo.dn}: {gpo.read_error}" for gpo in unreadable)

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
            "source": evidence_source or (EVIDENCE_SOURCE_GPO if matches
                                          else EVIDENCE_SOURCE_UNKNOWN),
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
