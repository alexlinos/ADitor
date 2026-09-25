"""Compare two stored hardening scans: "did my fix land, and did anything regress?"

Pure functions over two scan payloads. No LDAP, no SMB, no clock, no catalog
lookup — :func:`diff_scans` takes two dicts and returns one dict, and
:func:`diff_scan_files` is the thin file wrapper around it. Two files in, one
diff out; there is deliberately no scan store, no history directory and no
trend analysis across N scans.

Either input may also be a snapshot folder from ``aditor scan``, in
which case the ``scan.json`` inside it is read. That is a path-resolution
convenience and nothing more: it happens before any comparison, so diffing two
folders is the same call as diffing the two payloads they hold.

The whole correctness of this module
------------------------------------

**A diff must distinguish "the domain changed" from "the tool changed."**

The case that makes this non-negotiable is from this project's own history.
``DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES`` went ``fail`` → ``pass``
between two real scans. The domain had *not* changed: the value had been
correctly set the whole time. What changed was the scanner, which learned to read
Group Policy Preferences (``SCAN_ENGINE_VERSION`` 1.1.0 → 1.2.0). A naive diff
would have announced "you remediated RC4" — false, and precisely the
confidently-wrong output that several accuracy passes existed to eliminate.

So :func:`attribution` is computed **first** and reported **first**. Whenever
``catalog_version`` or ``engine_version`` differ between the two scans, every
difference is potentially attributable to the tool, the verdict is
``ambiguous``, both version pairs are named, and the payload says in plain
language that nothing below can be read as domain progress. Only matching
versions earn ``domain``.

Three further traps this module refuses to fall into:

* **A control new to the catalog is not an improvement.** It appears under
  ``catalog_changes``, never under ``improvements`` — there is no "before" verdict
  to have improved on. Same for a removed control.
* **Absence from a scan's findings is not absence from the catalog.** A scan
  narrowed with ``control_ids``, or one that filtered its not-applicable
  findings, simply did not evaluate everything. ``catalog_changes.comparable``
  says when that is the case, and each entry carries a ``likely_cause`` — if both
  scans ran the *same* catalog version then the control exists in both catalogs
  by definition, so the difference is scan scope, not the catalog.
* **A rollout can move backwards while the verdict stays ``pass``.** A domain that
  was ``enforced`` and is now ``audit`` has regressed even though ``result`` is
  unchanged both times, so the two axes are ranked independently and either one
  moving backwards puts the control in ``regressions``.

Asymmetry, on purpose
---------------------

Losing assurance is reported generously; gaining it is reported strictly. A
``pass`` that is now ``error`` lands in ``regressions`` — the pass can no longer
be stood behind, whatever the cause. But an ``error`` that is now ``pass`` lands
in ``other_changes``, not ``improvements``: the previous scan could not read what
it needed, so "it passes now" is not evidence that anything was fixed. An
over-eager regression costs a reader a second look; an over-eager improvement
tells them a job is done when it is not.

Keying
------

Controls are matched on ``control_id``, which is stable by design — P2-WP3a made
report anchors control-id-only for exactly this reason.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .catalog import SEVERITY_RANK
from .scanfile import ScanFileError, read_scan, validate_scan_payload
from .snapshot import resolve_scan_path

# Version of the *diff payload's* shape, so a stored or quoted diff can say
# which comparator produced it.
DIFF_FORMAT_VERSION = "1.0.0"

# --- attribution ----------------------------------------------------------- #

#: Both scans ran the same catalog and the same engine, so a difference is the
#: domain's.
ATTRIBUTION_DOMAIN = "domain"

#: The scans ran different versions of the catalog and/or the engine, so a
#: difference may be the tool's rather than the domain's.
ATTRIBUTION_AMBIGUOUS = "ambiguous"

# --- the axes a control can move along ------------------------------------- #

AXIS_RESULT = "result"
AXIS_ROLLOUT = "rollout_state"
AXIS_EVIDENCE = "evidence"

# Which way a change went. "sideways" is a real answer, not a failure to decide:
# fail -> unknown is neither better nor worse, it is a different kind of
# not-passing.
DIRECTION_SAME = "same"
DIRECTION_FORWARDS = "forwards"
DIRECTION_BACKWARDS = "backwards"
DIRECTION_SIDEWAYS = "sideways"

# Rollout states, ranked. Mirrors the evaluator's own ranking; a lower rank after
# a higher one is a rollout regression whatever the verdict says.
_ROLLOUT_RANK = {"not_started": 0, "audit": 1, "enforced": 2}

_RESULT_PASS = "pass"
_RESULT_FAIL = "fail"
_RESULT_UNKNOWN = "unknown"
_RESULT_ERROR = "error"

# Losing a pass to any of these is a regression: whether the setting broke or the
# scan merely stopped being able to confirm it, the pass no longer stands.
_LOST_PASS = frozenset({_RESULT_FAIL, _RESULT_UNKNOWN, _RESULT_ERROR})

# Reaching a pass from either of these is an improvement. 'error' is deliberately
# absent — see the asymmetry note in the module docstring.
_EARNED_PASS = frozenset({_RESULT_FAIL, _RESULT_UNKNOWN})

# --- catalog_changes causes ------------------------------------------------- #

CAUSE_CATALOG_VERSION = "catalog-version-differs"
CAUSE_SCAN_SCOPE = "scan-scope-differs"

_PREFERENCE_DELIVERY = "registry-preference"

# Standing notes on the diff itself, restated in every payload because a diff
# gets quoted in a ticket without the tool that produced it.
_STANDING_NOTES = (
    "Controls are matched on control_id. A control in one scan and not the "
    "other is reported under catalog_changes and is never counted as an "
    "improvement or a regression: there is no before-and-after verdict to "
    "compare.",
    "A rollout state moving backwards (enforced -> audit -> not_started) is a "
    "regression even when result stays 'pass', because the domain has stepped "
    "back from enforcing a control it was enforcing.",
    "Losing a pass is reported generously and gaining one strictly. pass -> "
    "error is a regression, because the pass can no longer be stood behind "
    "whatever the cause; error -> pass is not an improvement, because the "
    "earlier scan could not read what it needed and 'it passes now' is not "
    "evidence that anything was fixed. Those land in other_changes.",
    "evidence_changes are controls whose verdict did not move but whose "
    "grounds did — a different value, a different GPO delivering it, a "
    "different delivery mechanism, a different evidence source, or a conflict "
    "appearing or clearing. A pass now held by a Group Policy preference where "
    "a policy held it before is a materially weaker statement and is reported "
    "here even though the verdict is identical.",
    "Policy precedence (RSoP) is not resolved by the scan, so it is not "
    "resolved by this diff either. Where a finding carries a conflict, the "
    "effective value is unproven in both scans and the change between them is "
    "unproven with it.",
)


class ScanDiffError(ValueError):
    """The two payloads cannot be compared.

    Distinct from :class:`~aditor.hardening.scanfile.ScanFileError`, which means
    one input is not a scan at all. This means both are scans but comparing them
    would be meaningless — most importantly, that they describe different
    domains.
    """


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _scan_block(payload: Dict[str, Any]) -> Dict[str, Any]:
    block = payload.get("scan")
    return block if isinstance(block, dict) else {}


def _counts_block(payload: Dict[str, Any]) -> Dict[str, Any]:
    block = payload.get("counts")
    return block if isinstance(block, dict) else {}


def _findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []
    return [f for f in findings if isinstance(f, dict)]


def _engine_version(scan: Dict[str, Any]) -> Any:
    """The scan engine version, whatever the provenance header calls it.

    The header writes it as ``tool_version``; ``engine_version`` is accepted too
    so a future header that renames the field still diffs. The diff reports it as
    ``engine_version``, which is the vocabulary the rest of the payload uses.
    """
    for key in ("tool_version", "engine_version"):
        value = scan.get(key)
        if value not in (None, ""):
            return value
    return None


def _normalise_dn(value: Any) -> str:
    """A DN flattened for comparison: DNs are case-insensitive and space-tolerant."""
    if not isinstance(value, str):
        return ""
    return ",".join(part.strip() for part in value.strip().split(",")).lower()


def _by_control_id(findings: Sequence[Dict[str, Any]]
                   ) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Index findings by ``control_id``, reporting any duplicates.

    A duplicate id would make "the" before-state ambiguous. The catalog loader
    already rejects duplicate ids, so this is defensive — but it reports rather
    than silently keeping the last one, because a diff that quietly dropped half
    a control's history would be worse than one that says it cannot.
    """
    indexed: Dict[str, Dict[str, Any]] = {}
    duplicates: List[str] = []
    for finding in findings:
        control_id = finding.get("control_id")
        if not isinstance(control_id, str) or not control_id.strip():
            continue
        key = control_id.strip()
        if key in indexed:
            duplicates.append(key)
            continue
        indexed[key] = finding
    return indexed, duplicates


def _sort_key(entry: Dict[str, Any]) -> Tuple[int, str]:
    """Worst severity first, then control id — the report's own ordering."""
    return (SEVERITY_RANK.get(str(entry.get("severity")), 99),
            str(entry.get("control_id") or ""))


# --------------------------------------------------------------------------- #
# Direction of travel
# --------------------------------------------------------------------------- #

def result_direction(before: Any, after: Any) -> str:
    """Which way a ``result`` moved.

    ``pass`` → any of fail/unknown/error is backwards. fail/unknown → ``pass`` is
    forwards. Everything else that changed is sideways, including ``error`` →
    ``pass`` (the earlier scan could not tell, so this is not evidence of a fix)
    and anything involving ``not_applicable`` (the control stopped, or started,
    applying — which is a change in what is being asked, not in compliance).
    """
    if before == after:
        return DIRECTION_SAME
    if before == _RESULT_PASS and after in _LOST_PASS:
        return DIRECTION_BACKWARDS
    if before in _EARNED_PASS and after == _RESULT_PASS:
        return DIRECTION_FORWARDS
    return DIRECTION_SIDEWAYS


def rollout_direction(before: Any, after: Any) -> str:
    """Which way a ``rollout_state`` moved, ranked not_started < audit < enforced.

    A state the ranking does not know — ``None``, which the evaluator uses for an
    ``unknown`` verdict or an unscored control — cannot be ranked against one it
    does, so such a move is sideways rather than guessed at in either direction.
    """
    if before == after:
        return DIRECTION_SAME
    before_rank = _ROLLOUT_RANK.get(before) if isinstance(before, str) else None
    after_rank = _ROLLOUT_RANK.get(after) if isinstance(after, str) else None
    if before_rank is None or after_rank is None:
        return DIRECTION_SIDEWAYS
    return (DIRECTION_BACKWARDS if after_rank < before_rank
            else DIRECTION_FORWARDS)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #

def _evidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    evidence = finding.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _found(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    found = _evidence(finding).get("found")
    if not isinstance(found, list):
        return []
    return [match for match in found if isinstance(match, dict)]


def _values(finding: Dict[str, Any]) -> List[Any]:
    """Every value found, ordered so two scans' lists compare directly.

    A list rather than a set: two GPOs setting the same key to the same value is
    a different situation from one GPO doing so, and a diff should not flatten
    the difference away.
    """
    return sorted((match.get("value") for match in _found(finding)),
                  key=lambda value: (str(type(value)), str(value)))


def _gpos(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Which GPOs deliver the setting, ordered by DN."""
    seen = []
    for match in _found(finding):
        seen.append({"dn": match.get("gpo_dn"),
                     "display_name": match.get("gpo_display_name")})
    return sorted(seen, key=lambda gpo: _normalise_dn(gpo.get("dn")))


def _deliveries(finding: Dict[str, Any]) -> List[str]:
    """The distinct delivery mechanisms behind the found values, sorted."""
    return sorted({str(match.get("delivery")) for match in _found(finding)
                   if match.get("delivery") is not None})


def _conflict_kind(finding: Dict[str, Any]) -> Optional[str]:
    conflict = finding.get("conflict")
    if not isinstance(conflict, dict):
        return None
    kind = conflict.get("kind")
    return str(kind) if kind else None


def evidence_side(finding: Dict[str, Any]) -> Dict[str, Any]:
    """One side of an evidence comparison: what the verdict rested on.

    Deliberately not the whole finding. A diff entry has to be readable next to
    its twin, and the fields below are the ones that can move without the verdict
    moving.
    """
    evidence = _evidence(finding)
    return {
        "source": evidence.get("source"),
        "found_count": len(_found(finding)),
        "values": _values(finding),
        "gpos": _gpos(finding),
        "deliveries": _deliveries(finding),
        "conflict": _conflict_kind(finding),
        "expected": evidence.get("expected"),
        "scored": finding.get("scored"),
        # The evaluator's own reason, not re-derived from ``scored``: it
        # distinguishes 'needs_baseline_value' (the source states no expected
        # value) from 'unsupported_check_type' (this release has no engine for
        # the control), and a reader of a change entry wants to know which.
        "unscored_reason": finding.get("unscored_reason"),
    }


def _dn_list(gpos: Sequence[Dict[str, Any]]) -> List[str]:
    return [_normalise_dn(gpo.get("dn")) for gpo in gpos]


def _gpo_label(gpo: Dict[str, Any]) -> str:
    return str(gpo.get("display_name") or gpo.get("dn") or "unnamed GPO")


def evidence_changes(before: Dict[str, Any],
                     after: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every way the grounds for a verdict differ, verdict aside.

    Each entry is ``{field, before, after, detail}``. ``detail`` is prose because
    the interesting cases are not self-explanatory from two values: a pass moving
    from a policy to a preference, or a conflict quietly clearing, both need a
    sentence to be read correctly.
    """
    left, right = evidence_side(before), evidence_side(after)
    changes: List[Dict[str, Any]] = []

    def add(field: str, old: Any, new: Any, detail: str) -> None:
        # ``field`` names the change, not a key of the side dict: "value" is
        # plural in the side dict and singular here, and a reader of one entry
        # should not have to know that. So the values are passed in explicitly.
        changes.append({"field": field, "before": old, "after": new,
                        "detail": detail})

    if left["expected"] != right["expected"]:
        add("expected", left["expected"], right["expected"],
            "The baseline this control is scored against changed between the "
            "two scans, so any verdict change here is at least partly a change "
            "in what is being asked — not in the domain.")

    if left["scored"] != right["scored"] or \
            left["unscored_reason"] != right["unscored_reason"]:
        add("scored",
            {"scored": left["scored"], "reason": left["unscored_reason"]},
            {"scored": right["scored"], "reason": right["unscored_reason"]},
            "Whether this control is scored at all changed between the two "
            "scans. That is a change in the tool, not the domain: an unscored "
            "control has no sourced expected value (or no engine for its check "
            "type) and is never judged, so it can neither pass nor fail.")

    if left["source"] != right["source"]:
        add("source", left["source"], right["source"],
            f"The verdict's basis changed from {left['source']!r} to "
            f"{right['source']!r}. 'gpo' means a GPO sets the key; 'os-default' "
            f"means nothing does and the verdict rests on a documented Windows "
            f"default, which Group Policy is not holding in place; "
            f"'not-configured' means the key was found nowhere; 'unknown' means "
            f"the scan did not establish the state at all.")

    if [str(value) for value in left["values"]] != \
            [str(value) for value in right["values"]]:
        add("value", left["values"], right["values"],
            f"The value(s) found changed from "
            f"{_render_values(left['values'])} to "
            f"{_render_values(right['values'])}.")

    if _dn_list(left["gpos"]) != _dn_list(right["gpos"]):
        add("gpo", left["gpos"], right["gpos"],
            f"A different set of GPOs delivers this setting: "
            f"{_render_gpos(left['gpos'])} -> {_render_gpos(right['gpos'])}. "
            f"The same value from a different GPO can reach a different set of "
            f"machines, and precedence is not resolved by this scan.")

    if left["deliveries"] != right["deliveries"]:
        detail = (f"How the value is delivered changed from "
                  f"{_render_list(left['deliveries'])} to "
                  f"{_render_list(right['deliveries'])}.")
        if (_PREFERENCE_DELIVERY in right["deliveries"]
                and _PREFERENCE_DELIVERY not in left["deliveries"]):
            detail += (" A Group Policy preference TATTOOS: the value stays in "
                       "the registry if its GPO is unlinked, where a policy "
                       "value reverts. A pass now held by a preference is a "
                       "weaker statement about ongoing state than the same pass "
                       "held by a policy, even though the verdict is identical.")
        elif (_PREFERENCE_DELIVERY in left["deliveries"]
                and _PREFERENCE_DELIVERY not in right["deliveries"]):
            detail += (" The value is no longer delivered by a Group Policy "
                       "preference. If a preference had tattooed the value, the "
                       "registry may still hold it on machines that already "
                       "applied it, so a policy now covering it is a "
                       "strengthening, not a no-op.")
        add("delivery", left["deliveries"], right["deliveries"], detail)

    if left["conflict"] != right["conflict"]:
        if left["conflict"] is None:
            detail = (f"A conflict appeared ({right['conflict']}): GPOs now "
                      f"disagree about this key, so the effective value is "
                      f"unproven. Confirm it with gpresult / RSoP before "
                      f"trusting the verdict.")
        elif right["conflict"] is None:
            detail = (f"The {left['conflict']} conflict cleared: GPOs no longer "
                      f"disagree about this key.")
        else:
            detail = (f"The conflict changed kind, from {left['conflict']} to "
                      f"{right['conflict']}.")
        add("conflict", left["conflict"], right["conflict"], detail)

    return changes


def _render_values(values: Sequence[Any]) -> str:
    return ", ".join(repr(value) for value in values) if values else "nothing"


def _render_list(items: Sequence[Any]) -> str:
    return ", ".join(str(item) for item in items) if items else "nothing"


def _render_gpos(gpos: Sequence[Dict[str, Any]]) -> str:
    return ", ".join(_gpo_label(gpo) for gpo in gpos) if gpos else "no GPO"


# --------------------------------------------------------------------------- #
# Attribution — computed first, reported first
# --------------------------------------------------------------------------- #

def attribution(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Whether differences between these two scans can be laid at the domain's door.

    ``verdict`` is decided by the versions alone — ``domain`` when both the
    catalog and the engine match, ``ambiguous`` otherwise — because that is the
    only part of the question the payloads answer definitively. Everything else
    that could make a difference not-the-domain's (a GPO that became unreadable,
    a narrower scan, a different filter) lands in ``caveats``, which qualify how
    a *domain* verdict should be read without pretending to be a version change.

    Args:
        before: The earlier scan's payload.
        after: The later scan's payload.

    Returns:
        The ``attribution`` block: ``verdict``, ``reason``, both version pairs,
        a plain-language ``summary``, and ``caveats``.
    """
    before_scan, after_scan = _scan_block(before), _scan_block(after)
    catalog = _version_pair(before_scan.get("catalog_version"),
                            after_scan.get("catalog_version"))
    engine = _version_pair(_engine_version(before_scan),
                           _engine_version(after_scan))

    ambiguous = catalog["changed"] or engine["changed"]
    verdict = ATTRIBUTION_AMBIGUOUS if ambiguous else ATTRIBUTION_DOMAIN

    return {
        "verdict": verdict,
        "reason": _attribution_reason(catalog, engine),
        "catalog_version": catalog,
        "engine_version": engine,
        "summary": _attribution_summary(catalog, engine),
        "caveats": _attribution_caveats(before, after),
    }


def _version_pair(before: Any, after: Any) -> Dict[str, Any]:
    return {"before": before, "after": after, "changed": before != after}


def _shown(value: Any) -> str:
    return "unstated" if value in (None, "") else str(value)


def _attribution_reason(catalog: Dict[str, Any],
                        engine: Dict[str, Any]) -> str:
    """One line naming the version delta, for a caller that reads only this."""
    moves = []
    if catalog["changed"]:
        moves.append(f"catalog_version {_shown(catalog['before'])} -> "
                     f"{_shown(catalog['after'])}")
    if engine["changed"]:
        moves.append(f"engine_version {_shown(engine['before'])} -> "
                     f"{_shown(engine['after'])}")
    if not moves:
        return (f"catalog_version and engine_version match "
                f"({_shown(catalog['before'])} / {_shown(engine['before'])})")
    return " and ".join(moves)


def _attribution_summary(catalog: Dict[str, Any],
                         engine: Dict[str, Any]) -> str:
    """The paragraph a reader must not be able to miss."""
    if not (catalog["changed"] or engine["changed"]):
        return (
            f"Both scans were produced by the same catalog version "
            f"({_shown(catalog['before'])}) and the same scan engine version "
            f"({_shown(engine['before'])}), so the tool asked the same "
            f"questions of the domain both times and the differences below can "
            f"be attributed to the domain. This is the only case in which \"the "
            f"fix landed\" or \"something regressed\" can be read off a diff "
            f"directly. Read the caveats anyway: a GPO that became unreadable, "
            f"or a scan narrowed to a subset of controls, can still move a "
            f"verdict without the domain moving.")

    lead = (f"ATTRIBUTION IS AMBIGUOUS. These two scans were not produced by "
            f"the same version of the tool: "
            f"{_attribution_reason(catalog, engine)}. Every difference below is "
            f"therefore potentially attributable to the tool rather than to the "
            f"domain, and none of it can be presented as domain progress on "
            f"this evidence.")

    if engine["changed"]:
        lead += (
            " A newer scan engine can read a source an older one could not, so "
            "a control can change verdict with the domain untouched. This has "
            "actually happened here: DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES "
            "went fail -> pass between two real scans purely because the "
            "scanner learned to read Group Policy Preferences. The value had "
            "been set correctly the whole time; nothing in the domain had "
            "changed.")
    if catalog["changed"]:
        lead += (
            " A newer catalog can score against a different expected value, add "
            "or remove controls, or change what a missing key means, so a "
            "verdict can move with the domain untouched here too.")

    lead += (" To attribute a change to the domain, re-scan the current state "
             "with the same catalog and engine version that produced the older "
             "scan, or keep the newer version and treat this diff as a new "
             "baseline rather than as progress.")
    return lead


def _attribution_caveats(before: Dict[str, Any],
                         after: Dict[str, Any]) -> List[str]:
    """Everything else that can move a verdict without the domain moving."""
    before_scan, after_scan = _scan_block(before), _scan_block(after)
    before_counts, after_counts = _counts_block(before), _counts_block(after)
    caveats: List[str] = []

    before_gpos = _as_int(before_scan.get("gpos_scanned"))
    after_gpos = _as_int(after_scan.get("gpos_scanned"))
    if before_gpos != after_gpos:
        caveats.append(
            f"The two scans read a different number of GPOs ({before_gpos} -> "
            f"{after_gpos}). A verdict can move because a GPO was created, "
            f"deleted, or became unreadable rather than because a setting "
            f"changed.")

    for label, scan in (("before", before_scan), ("after", after_scan)):
        unreadable = _as_int(scan.get("gpos_unreadable"))
        if unreadable:
            caveats.append(
                f"{unreadable} GPO(s) could not be read in the {label} scan. "
                f"Any of them could set any of these keys to anything, so "
                f"verdicts in that scan are unknown rather than clean, and a "
                f"difference against it is unknown with them.")

    if before_scan.get("include_not_applicable") != \
            after_scan.get("include_not_applicable"):
        caveats.append(
            "The two scans filtered not-applicable findings differently "
            "(include_not_applicable "
            f"{before_scan.get('include_not_applicable')!r} -> "
            f"{after_scan.get('include_not_applicable')!r}), so a control's "
            "presence in one findings list and absence from the other may be "
            "the filter rather than the catalog. See catalog_changes.")

    for label, scan, counts in (("before", before_scan, before_counts),
                                ("after", after_scan, after_counts)):
        catalog_size = scan.get("control_count")
        evaluated = counts.get("total")
        if isinstance(catalog_size, int) and isinstance(evaluated, int) \
                and evaluated != catalog_size:
            caveats.append(
                f"The {label} scan evaluated {evaluated} of the catalog's "
                f"{catalog_size} controls, so it was narrowed with control_ids. "
                f"Controls it did not evaluate cannot be compared.")

    before_domain = before_scan.get("domain")
    after_domain = after_scan.get("domain")
    if before_domain != after_domain:
        caveats.append(
            f"The scans name different domains ({before_domain!r} -> "
            f"{after_domain!r}) even though their base DNs match. Confirm both "
            f"came from the directory you think they did.")

    order = _timestamp_order(before_scan.get("timestamp"),
                             after_scan.get("timestamp"))
    if order == "reversed":
        caveats.append(
            f"The 'after' scan is older than the 'before' scan "
            f"({before_scan.get('timestamp')!r} -> "
            f"{after_scan.get('timestamp')!r}). The arguments are probably the "
            f"wrong way round, which would invert every regression and "
            f"improvement below.")
    elif order == "identical":
        caveats.append(
            "Both scans carry the same timestamp. If they are the same scan "
            "file, every difference below is spurious; check the scan_ids.")

    if before_scan.get("scan_id") and \
            before_scan.get("scan_id") == after_scan.get("scan_id"):
        caveats.append(
            "Both inputs carry the same scan_id, so this is one scan compared "
            "with itself. Any difference reported below would be a bug.")

    return caveats


def _timestamp_order(before: Any, after: Any) -> Optional[str]:
    """``'reversed'``, ``'identical'``, ``'ok'`` or ``None`` if not comparable.

    Compares the ISO-8601 strings the provenance header writes lexicographically
    — which is chronological for that format — rather than parsing them, so a
    header from a future version with a shape this release does not know simply
    returns ``None`` instead of raising inside a diff.
    """
    if not isinstance(before, str) or not isinstance(after, str):
        return None
    if not before or not after:
        return None
    if before == after:
        return "identical"
    return "reversed" if after < before else "ok"


# --------------------------------------------------------------------------- #
# The diff
# --------------------------------------------------------------------------- #

def diff_scans(before: Dict[str, Any], after: Dict[str, Any],
               before_source: str = "<before>",
               after_source: str = "<after>") -> Dict[str, Any]:
    """Compare two scan payloads.

    Args:
        before: The earlier scan's payload (as returned by ``scan_hardening`` or
            read back from a file by
            :func:`aditor.hardening.scanfile.read_scan`).
        after: The later scan's payload.
        before_source: What to call ``before`` in error messages — a file path,
            normally.
        after_source: Likewise for ``after``.

    Returns:
        The diff payload. ``attribution`` first, then the scan metadata, then
        ``regressions`` ahead of ``improvements`` because a regression matters
        more than an improvement.

    Raises:
        ScanFileError: either payload is not a hardening scan.
        ScanDiffError: both are scans but of different domains, so comparing them
            control by control would be meaningless.
    """
    validate_scan_payload(before, before_source)
    validate_scan_payload(after, after_source)

    before_scan, after_scan = _scan_block(before), _scan_block(after)
    before_dn = before_scan.get("base_dn")
    after_dn = after_scan.get("base_dn")
    if _normalise_dn(before_dn) != _normalise_dn(after_dn):
        raise ScanDiffError(
            f"these two scans describe different domains and cannot be "
            f"compared: {before_source} has base_dn {before_dn!r} and "
            f"{after_source} has base_dn {after_dn!r}. Control ids are shared "
            f"across domains, so a control-by-control diff would silently "
            f"compare one domain's settings with another's. Diff two scans of "
            f"the same domain.")

    verdict = attribution(before, after)
    attribution_verdict = verdict["verdict"]

    before_by_id, before_dupes = _by_control_id(_findings(before))
    after_by_id, after_dupes = _by_control_id(_findings(after))

    regressions: List[Dict[str, Any]] = []
    improvements: List[Dict[str, Any]] = []
    other_changes: List[Dict[str, Any]] = []
    changed_evidence: List[Dict[str, Any]] = []
    unchanged = 0

    for control_id in sorted(set(before_by_id) & set(after_by_id)):
        old, new = before_by_id[control_id], after_by_id[control_id]
        result_dir = result_direction(old.get("result"), new.get("result"))
        rollout_dir = rollout_direction(old.get("rollout_state"),
                                        new.get("rollout_state"))
        changes = evidence_changes(old, new)
        directions = (result_dir, rollout_dir)

        axes = [axis for axis, direction in ((AXIS_RESULT, result_dir),
                                             (AXIS_ROLLOUT, rollout_dir))
                if direction != DIRECTION_SAME]
        if changes:
            axes.append(AXIS_EVIDENCE)

        if DIRECTION_BACKWARDS in directions:
            regressions.append(_entry(control_id, old, new, axes, result_dir,
                                      rollout_dir, changes,
                                      attribution_verdict))
        elif DIRECTION_FORWARDS in directions:
            improvements.append(_entry(control_id, old, new, axes, result_dir,
                                       rollout_dir, changes,
                                       attribution_verdict))
        elif DIRECTION_SIDEWAYS in directions:
            other_changes.append(_entry(control_id, old, new, axes, result_dir,
                                        rollout_dir, changes,
                                        attribution_verdict))
        elif changes:
            changed_evidence.append(_entry(control_id, old, new, axes,
                                           result_dir, rollout_dir, changes,
                                           attribution_verdict))
        else:
            unchanged += 1

    for bucket in (regressions, improvements, other_changes, changed_evidence):
        bucket.sort(key=_sort_key)

    catalog_changes = _catalog_changes(before, after, before_by_id, after_by_id,
                                       verdict["catalog_version"]["changed"])

    payload: Dict[str, Any] = {
        # First, always. Whether these differences are the domain's is the
        # question every number below depends on.
        "attribution": verdict,
        "scans": _scan_metadata(before, after),
        # Regressions before improvements: a regression matters more.
        "regressions": regressions,
        "improvements": improvements,
        "other_changes": other_changes,
        "unchanged": unchanged,
        "catalog_changes": catalog_changes,
        "evidence_changes": changed_evidence,
        "counts_delta": _counts_delta(before, after),
        "totals": {
            "controls_compared": len(set(before_by_id) & set(after_by_id)),
            "regressions": len(regressions),
            "improvements": len(improvements),
            "other_changes": len(other_changes),
            "unchanged": unchanged,
            "evidence_changes": len(changed_evidence),
            "catalog_added": len(catalog_changes["added"]),
            "catalog_removed": len(catalog_changes["removed"]),
        },
        "notes": list(_STANDING_NOTES),
        "diff_format_version": DIFF_FORMAT_VERSION,
    }

    duplicates = sorted(set(before_dupes) | set(after_dupes))
    if duplicates:
        payload["notes"].append(
            f"These control ids appeared more than once in a scan's findings "
            f"and only the first occurrence of each was compared: "
            f"{', '.join(duplicates)}. That should be impossible — the catalog "
            f"loader rejects duplicate ids — so treat the diff as unreliable "
            f"and re-run both scans.")
    return payload


def _entry(control_id: str, before: Dict[str, Any], after: Dict[str, Any],
           axes: Sequence[str], result_dir: str, rollout_dir: str,
           changes: Sequence[Dict[str, Any]],
           attribution_verdict: str) -> Dict[str, Any]:
    """One control's change, in the shape every bucket uses.

    The same shape everywhere on purpose: a reader (or a future renderer) that
    can display a regression can display an improvement or an evidence-only
    change without a second code path, and ``changed`` says which axes moved.
    """
    notes: List[str] = []
    if attribution_verdict == ATTRIBUTION_AMBIGUOUS:
        notes.append(
            "The two scans ran different tool versions, so this difference may "
            "be the scanner or the catalog rather than the domain. See "
            "attribution at the top of this diff; do not report it as domain "
            "progress or as a domain regression without re-scanning both states "
            "on one version.")
    if result_dir == DIRECTION_BACKWARDS and after.get("result") == _RESULT_ERROR:
        notes.append(
            "The after scan could not evaluate this control (result 'error'), "
            "so the pass has not been shown to have broken — it has stopped "
            "being demonstrable. Fix the read failure, then re-scan.")
    if result_dir == DIRECTION_SIDEWAYS and before.get("result") == _RESULT_ERROR \
            and after.get("result") == _RESULT_PASS:
        notes.append(
            "The before scan could not evaluate this control (result 'error'), "
            "so this is not evidence that anything was fixed — only that the "
            "later scan could read it and it passes. It is reported here rather "
            "than as an improvement for that reason.")
    if rollout_dir == DIRECTION_BACKWARDS and result_dir == DIRECTION_SAME:
        notes.append(
            f"The verdict is unchanged ({after.get('result')!r}) but the "
            f"rollout moved backwards, from {before.get('rollout_state')!r} to "
            f"{after.get('rollout_state')!r}: the domain has stepped back from "
            f"enforcing a control it was enforcing. This is a regression even "
            f"though result did not move.")
    if any(change["field"] == "expected" for change in changes):
        notes.append(
            "The catalog's expected value for this control changed between the "
            "scans, so this is at least partly a baseline change rather than a "
            "domain change.")

    return {
        "control_id": control_id,
        "title": after.get("title") or before.get("title"),
        "severity": after.get("severity") or before.get("severity"),
        "changed": list(axes),
        "result": {"before": before.get("result"), "after": after.get("result"),
                   "direction": result_dir},
        "rollout_state": {"before": before.get("rollout_state"),
                          "after": after.get("rollout_state"),
                          "direction": rollout_dir},
        "attribution": attribution_verdict,
        "notes": notes,
        "evidence": {
            "changes": list(changes),
            "before": evidence_side(before),
            "after": evidence_side(after),
        },
        "remediation": after.get("remediation") or before.get("remediation"),
    }


def _catalog_changes(before: Dict[str, Any], after: Dict[str, Any],
                     before_by_id: Dict[str, Dict[str, Any]],
                     after_by_id: Dict[str, Dict[str, Any]],
                     catalog_version_changed: bool) -> Dict[str, Any]:
    """Controls in one scan and not the other — never an improvement or regression.

    There is no before-and-after verdict to compare for these, so calling a newly
    catalogued control an "improvement" would be inventing progress out of the
    catalog growing.

    ``comparable`` is the honest part. A control's absence from a findings list is
    only evidence of absence from the *catalog* when the scan evaluated the whole
    catalog and hid nothing; a scan narrowed with ``control_ids``, or one that
    filtered its not-applicable findings, simply did not report on everything. And
    when both scans ran the same catalog version, the catalogs are identical by
    definition — so any difference is scan scope, which is what ``likely_cause``
    records.
    """
    comparable, reasons = _scope_comparable(before, after)
    cause = (CAUSE_CATALOG_VERSION if catalog_version_changed
             else CAUSE_SCAN_SCOPE)

    added = [_catalog_entry(after_by_id[control_id], "added", cause)
             for control_id in sorted(set(after_by_id) - set(before_by_id))]
    removed = [_catalog_entry(before_by_id[control_id], "removed", cause)
               for control_id in sorted(set(before_by_id) - set(after_by_id))]

    notes: List[str] = []
    if added or removed:
        notes.append(
            "These controls appear in only one of the two scans, so there is no "
            "before-and-after verdict for them. They are reported here and are "
            "never counted as improvements or regressions.")
    notes.extend(reasons)
    if (added or removed) and not catalog_version_changed:
        notes.append(
            "Both scans ran the same catalog version, so both had the same "
            "controls available. Anything listed here was therefore not "
            "evaluated by one of the scans rather than added to or removed from "
            "the catalog.")

    return {
        "added": sorted(added, key=_sort_key),
        "removed": sorted(removed, key=_sort_key),
        "comparable": comparable,
        "notes": notes,
    }


def _scope_comparable(before: Dict[str, Any],
                      after: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Whether "missing from findings" can be read as "missing from the catalog"."""
    reasons: List[str] = []
    comparable = True
    for label, payload in (("before", before), ("after", after)):
        scan, counts = _scan_block(payload), _counts_block(payload)
        catalog_size = scan.get("control_count")
        evaluated = counts.get("total")
        hidden = _as_int(counts.get("hidden"))
        if not isinstance(catalog_size, int) or not isinstance(evaluated, int):
            comparable = False
            reasons.append(
                f"The {label} scan does not state how many controls its catalog "
                f"holds, so whether it evaluated all of them is unknown and a "
                f"control missing from it may simply not have been evaluated.")
            continue
        if evaluated != catalog_size:
            comparable = False
            reasons.append(
                f"The {label} scan evaluated {evaluated} of its catalog's "
                f"{catalog_size} controls, so it was narrowed with control_ids "
                f"and a control missing from it may simply not have been "
                f"evaluated.")
        if hidden:
            comparable = False
            reasons.append(
                f"The {label} scan hid {hidden} not-applicable finding(s) "
                f"(include_not_applicable was false), so a control missing from "
                f"its findings may have been evaluated and filtered out.")
    return comparable, reasons


def _catalog_entry(finding: Dict[str, Any], change: str,
                   likely_cause: str) -> Dict[str, Any]:
    if change == "added":
        if likely_cause == CAUSE_CATALOG_VERSION:
            note = ("Present in the after scan only, and the catalog version "
                    "changed between the scans: this is a catalog addition. Its "
                    "verdict here is a first observation, not an improvement — "
                    "there is nothing it improved on.")
        else:
            note = ("Present in the after scan only, but both scans ran the "
                    "same catalog version, so the before scan did not evaluate "
                    "it (narrowed with control_ids, or its not-applicable "
                    "finding was filtered out). A scan-scope difference, not a "
                    "change in the catalog or the domain.")
    else:
        if likely_cause == CAUSE_CATALOG_VERSION:
            note = ("Present in the before scan only, and the catalog version "
                    "changed between the scans: this control was removed from "
                    "the catalog. Its old verdict is not a regression — the "
                    "control is simply no longer asked.")
        else:
            note = ("Present in the before scan only, but both scans ran the "
                    "same catalog version, so the after scan did not evaluate "
                    "it (narrowed with control_ids, or its not-applicable "
                    "finding was filtered out). A scan-scope difference, not a "
                    "change in the catalog or the domain.")
    return {
        "control_id": finding.get("control_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "change": change,
        "likely_cause": likely_cause,
        "result": finding.get("result"),
        "rollout_state": finding.get("rollout_state"),
        "scored": finding.get("scored"),
        "note": note,
    }


def _counts_delta(before: Dict[str, Any],
                  after: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    """Before, after and delta for every count key, in the scan's own key order."""
    before_counts, after_counts = _counts_block(before), _counts_block(after)
    keys = list(before_counts)
    keys.extend(key for key in after_counts if key not in before_counts)
    delta: Dict[str, Dict[str, int]] = {}
    for key in keys:
        old, new = _as_int(before_counts.get(key)), _as_int(after_counts.get(key))
        delta[key] = {"before": old, "after": new, "delta": new - old}
    return delta


def _scan_metadata(before: Dict[str, Any],
                   after: Dict[str, Any]) -> Dict[str, Any]:
    """Which two scans this is, so a diff quoted in a ticket identifies itself.

    ``base_dn`` and ``domain`` come from the *before* scan alone because
    :func:`diff_scans` has already established the base DNs match; where the
    ``domain`` strings differ under one base DN, each side's own value is in its
    own block and ``attribution.caveats`` says so.
    """
    before_scan = _scan_block(before)
    return {
        "base_dn": before_scan.get("base_dn"),
        "domain": before_scan.get("domain"),
        "before": _scan_side(before),
        "after": _scan_side(after),
    }


def _scan_side(payload: Dict[str, Any]) -> Dict[str, Any]:
    scan, counts = _scan_block(payload), _counts_block(payload)
    return {
        "scan_id": scan.get("scan_id"),
        "timestamp": scan.get("timestamp"),
        "catalog_version": scan.get("catalog_version"),
        "engine_version": _engine_version(scan),
        "domain": scan.get("domain"),
        "base_dn": scan.get("base_dn"),
        "gpos_scanned": _as_int(scan.get("gpos_scanned")),
        "gpos_unreadable": _as_int(scan.get("gpos_unreadable")),
        "include_not_applicable": scan.get("include_not_applicable"),
        "catalog_control_count": scan.get("control_count"),
        "controls_evaluated": counts.get("total"),
        "source": payload.get("source_path"),
    }


def diff_scan_files(before_path: Any, after_path: Any) -> Dict[str, Any]:
    """Read two stored scans and diff them.

    The only file I/O in this module, and the only thing separating it from
    :func:`diff_scans`.

    Either side may be a ``.json`` scan file **or** a snapshot folder written by
    ``aditor scan``, in which case its ``scan.json`` is read — see
    :func:`aditor.hardening.snapshot.resolve_scan_path`. Resolution happens
    before anything else, so ``scans.<side>.source`` always names the file that
    was actually read and diffing two folders gives exactly the result diffing
    the two ``scan.json`` paths gives.

    Raises:
        ScanFileError: a path is unusable, a directory holds no ``scan.json``,
            or a file is not a scan payload.
        ScanDiffError: the two scans describe different domains.
    """
    before_file = resolve_scan_path(before_path)
    after_file = resolve_scan_path(after_path)
    before = read_scan(before_file)
    after = read_scan(after_file)
    before = dict(before, source_path=str(before_file))
    after = dict(after, source_path=str(after_file))
    return diff_scans(before, after, str(before_file), str(after_file))


__all__ = [
    "ATTRIBUTION_AMBIGUOUS",
    "ATTRIBUTION_DOMAIN",
    "AXIS_EVIDENCE",
    "AXIS_RESULT",
    "AXIS_ROLLOUT",
    "DIFF_FORMAT_VERSION",
    "DIRECTION_BACKWARDS",
    "DIRECTION_FORWARDS",
    "DIRECTION_SAME",
    "DIRECTION_SIDEWAYS",
    "ScanDiffError",
    "ScanFileError",
    "attribution",
    "diff_scan_files",
    "diff_scans",
    "evidence_changes",
    "evidence_side",
    "result_direction",
    "rollout_direction",
]
