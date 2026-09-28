"""The ``aditor`` command: a read-only hardening scan, and a diff of two scans.

::

    aditor scan [--config PATH] [--out DIR]
    aditor diff OLD NEW

``scan`` writes one dated snapshot folder (``scan.json`` + ``report.html``)
under ``--out``. ``diff`` compares two scans, given as ``scan.json`` files or
snapshot folders.

Exit codes, so the command can run unattended (cron, an RMM agent):

* ``0`` — nothing needs attention.
* ``1`` — the scan has a ``fail`` or ``error`` finding, or the diff has a
  regression.
* ``2`` — the command could not do its job: bad config, the directory could not
  be read, or an input file was refused. Nothing is written.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import List, Optional

EXIT_OK = 0
EXIT_ATTENTION = 1
EXIT_ERROR = 2


def _password_missing(password: str) -> bool:
    """True when the config gave no usable password.

    ``os.path.expandvars`` leaves an unset ``${AD_MCP_PASSWORD}`` in place
    rather than emptying it, so a leftover ``$`` reference counts as missing.
    """
    return not password or password.startswith("$")


def cmd_scan(args: argparse.Namespace) -> int:
    from .config.loader import load_config
    from .core.ldap_manager import LDAPManager
    from .hardening.collect import GpoReadFailure, Scanner
    from .hardening.report import ReportPathError
    from .hardening.scanfile import ScanFileError
    from .hardening.snapshot import SnapshotError, write_snapshot

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"error: could not load config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    ad = config.active_directory
    if _password_missing(ad.password):
        if not sys.stdin.isatty():
            print("error: no bind password. Set AD_MCP_PASSWORD, or run "
                  "interactively to be prompted.", file=sys.stderr)
            return EXIT_ERROR
        ad.password = getpass.getpass(f"Password for {ad.bind_dn}: ")

    print(f"Scanning {ad.domain} via {ad.server} (read-only)...", file=sys.stderr)
    try:
        manager = LDAPManager(ad, config.security, config.performance)
        payload = Scanner(manager).scan(operation="aditor scan")
    except GpoReadFailure as failure:
        # The actual LDAP/SMB error: its wording is what tells the operator
        # which of credentials, certificate trust or reachability to fix.
        print(f"error: could not read the directory: {failure.cause}",
              file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if payload.get("success") is False:
        print(f"error: {payload['error']}", file=sys.stderr)
        return EXIT_ERROR

    try:
        snapshot = write_snapshot(payload, args.out)
    except (SnapshotError, ScanFileError, ReportPathError) as exc:
        print(f"error: the scan ran but could not be written: {exc}",
              file=sys.stderr)
        return EXIT_ERROR

    counts = payload["counts"]
    scan = payload["scan"]
    print(f"{counts['total']} controls, {scan['gpos_scanned']} GPOs "
          f"({scan['gpos_unreadable']} unreadable): "
          f"{counts['fail']} fail, {counts['error']} error, "
          f"{counts['unknown']} unknown, {counts['conflicts']} conflicts, "
          f"{counts['pass']} pass")
    print(f"Report: {snapshot.report_path}")
    print(f"Scan:   {snapshot.scan_path}")
    print("Both files contain directory content (GPO names, DNs, registry "
          "values, account and group member names). Share them accordingly.",
          file=sys.stderr)
    return EXIT_ATTENTION if counts["fail"] or counts["error"] else EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    from .hardening.diff import ATTRIBUTION_AMBIGUOUS, ScanDiffError, diff_scan_files
    from .hardening.scanfile import ScanFileError

    try:
        diff = diff_scan_files(args.old, args.new)
    except (ScanFileError, ScanDiffError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    attribution = diff["attribution"]
    # Attribution first: every number below depends on it.
    if attribution["verdict"] == ATTRIBUTION_AMBIGUOUS:
        print("Different ADitor versions: a difference below may come from the "
              "tool rather than the domain. Treat this as a new starting "
              "point, not as progress.")
        print(f"What changed: {attribution.get('reason')}")
    else:
        print("Same ADitor version: the differences below are changes in the "
              "domain.")

    totals = diff["totals"]
    print(f"\n{totals['controls_compared']} controls compared: "
          f"{totals['regressions']} regressions, "
          f"{totals['improvements']} improvements, "
          f"{totals['other_changes']} other changes, "
          f"{totals['evidence_changes']} evidence changes, "
          f"{totals['unchanged']} unchanged")
    if totals["catalog_added"] or totals["catalog_removed"]:
        print(f"Catalog: {totals['catalog_added']} added, "
              f"{totals['catalog_removed']} removed")
    added = diff["catalog_changes"]["added"]
    if added:
        print("\nNew checks (first result, not a regression):")
        order = {"fail": 0, "error": 1, "unknown": 2, "pass": 3}
        for entry in sorted(added, key=lambda e: (order.get(e.get("result"), 9),
                                                  str(e.get("control_id")))):
            print(f"  {entry.get('result')}: {entry.get('control_id')} "
                  f"({entry.get('severity')})")

    for label in ("regressions", "improvements", "other_changes"):
        if diff[label]:
            print(f"\n{label.replace('_', ' ').capitalize()}:")
            for change in diff[label]:
                result = change["result"]
                print(f"  {change['control_id']}: "
                      f"{result['before']} -> {result['after']}")

    return EXIT_ATTENTION if totals["regressions"] else EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aditor",
        description="Read-only Active Directory / GPO hardening audit.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan the domain and write a report")
    scan.add_argument("--config", help="config JSON (default: $AD_MCP_CONFIG)")
    scan.add_argument("--out", default="scans",
                      help="directory to create the snapshot folder in "
                           "(default: ./scans)")
    scan.set_defaults(func=cmd_scan)

    diff = sub.add_parser("diff", help="compare two scans")
    diff.add_argument("old", help="earlier scan.json or snapshot folder")
    diff.add_argument("new", help="later scan.json or snapshot folder")
    diff.set_defaults(func=cmd_diff)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
