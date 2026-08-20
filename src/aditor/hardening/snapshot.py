"""One scan, one dated folder, both artifacts.

``write_hardening_scan`` and ``write_hardening_report`` each run their **own**
scan. Calling both and dropping the results side by side would produce a folder
whose ``report.html`` and ``scan.json`` came from two different scans — different
``scan_id``, different timestamps, and on a domain that moved between them,
different findings. The JSON is the evidence of record; a report that disagrees
with it defeats the point of keeping either.

So this module takes a scan payload that has **already been produced once** and
feeds it to both writers::

    <output_dir>/2026-08-20T162647Z-b288e925/
        scan.json      <- the payload (source of truth)
        report.html    <- the rendered document

It never scans. It has no clock, no LDAP, no SMB and no catalog lookup: the one
run of the scan happens in :mod:`aditor.tools.hardening`, and everything here is
derived from the payload it hands over. That is what makes "exactly one scan"
structural rather than a thing a caller has to remember.

**The folder name comes from the scan's own timestamp**, never from a freshly
computed ``now()``. A directory listing sorted by name and the provenance inside
the files have to tell the same story, and re-deriving the time would let them
drift by however long the scan took.

**No colons.** ISO-8601's ``16:26:47`` is illegal in a Windows filename and the
packaging target is a Windows ``.exe`` (see ``docs/REPLATFORM_BRIEF.md``), so the
time is rendered ``162647Z``. The short ``scan_id`` prefix that follows is what
keeps two scans in the same second in separate folders — the timestamp alone has
one-second resolution and is not an identity.

**A snapshot folder holds directory content**: both files embed this domain's GPO
display names, registry values and DNs, exactly as the standalone report and scan
files do.

The path guards are the ones already written: :func:`aditor.hardening.write_scan`
vets the ``.json`` and :func:`aditor.hardening.report.write_report` the ``.html``,
including creating the folder's contents and refusing to clobber a file of
another kind. This module adds exactly one guard of its own — the snapshot folder
must not already exist — because that is the only question the two file writers
cannot answer.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, NamedTuple

from .report import ReportPathError, write_report
from .scanfile import ScanFileError, write_scan

# The two files a snapshot folder holds, and nothing else. Fixed names: a
# snapshot is identified by its folder, so the caller has one thing to keep and a
# reader has nowhere to look for the payload but ``scan.json``.
SNAPSHOT_SCAN_FILENAME = "scan.json"
SNAPSHOT_REPORT_FILENAME = "report.html"

# Version of the *folder layout* — the two file names and the folder-name
# format. The files inside carry their own format versions.
SNAPSHOT_FORMAT_VERSION = "1.0.0"

# ``2026-08-20T162647Z``. The date keeps its hyphens (they are legal everywhere
# and the string stays readable); the time loses its colons, which are not.
# ``%H%M%SZ`` rather than ``%H:%M:%SZ`` is the whole Windows story.
_FOLDER_TIME_FORMAT = "%Y-%m-%dT%H%M%SZ"

# How much of a scan_id goes in the folder name. Eight hex characters is enough
# to separate scans taken in the same second while leaving the name readable;
# the full id is in both files.
_SCAN_ID_PREFIX_LENGTH = 8

# What a folder name may contain, checked after it is built. Belt and braces
# over the format above: the scan_id half comes from a payload, and a payload
# read back from a hand-edited file could carry anything. Colons, path
# separators, spaces and Windows' other reserved characters are all excluded by
# construction here.
_SAFE_FOLDER_NAME = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._-]*\Z")


class SnapshotError(ValueError):
    """A snapshot folder could not be created, or the payload cannot name one.

    Raised *before* anything is written whenever the problem is the output path
    or the payload's provenance. The two file writers raise their own
    :class:`~aditor.hardening.scanfile.ScanFileError` and
    :class:`~aditor.hardening.report.ReportPathError`; this is only for what
    those two cannot see — the folder.
    """


class Snapshot(NamedTuple):
    """What :func:`write_snapshot` wrote, so the caller need not re-stat it."""

    folder: Path
    scan_path: Path
    scan_bytes: int
    report_path: Path
    report_bytes: int


def _provenance(scan_result: Any) -> Dict[str, Any]:
    """The scan's provenance block, or say why the payload cannot name a folder."""
    if not isinstance(scan_result, dict):
        raise SnapshotError(
            f"a scan payload must be a JSON object, got "
            f"{type(scan_result).__name__}")
    scan = scan_result.get("scan")
    if not isinstance(scan, dict):
        raise SnapshotError(
            "the scan payload has no 'scan' provenance block, so the snapshot "
            "folder cannot be named after the scan that produced it")
    return scan


def _folder_timestamp(scan: Dict[str, Any]) -> str:
    """Render the scan's own ``timestamp`` as a filesystem-safe UTC stamp.

    Deliberately no fallback to the current time. A snapshot folder whose name
    disagreed with the provenance inside it would be worse than a refusal: the
    refusal is visible, the disagreement is not.
    """
    raw = scan.get("timestamp")
    if not isinstance(raw, str) or not raw.strip():
        raise SnapshotError(
            "the scan states no 'timestamp', so the snapshot folder cannot be "
            "named after it. The folder name is derived from the scan's own "
            "timestamp and is never taken from the current clock, so that the "
            "directory listing and the files agree.")
    try:
        moment = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotError(
            f"the scan's timestamp {raw!r} is not an ISO-8601 datetime "
            f"({exc}), so the snapshot folder cannot be named after it") from exc
    if moment.tzinfo is None:
        # A scan written without an offset is UTC by construction (the scanner
        # uses ``datetime.now(timezone.utc)``); say so rather than letting the
        # local zone silently relabel the folder.
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(_FOLDER_TIME_FORMAT)


def _folder_scan_id(scan: Dict[str, Any]) -> str:
    """The short ``scan_id`` prefix that makes the folder name unique."""
    scan_id = scan.get("scan_id")
    if not isinstance(scan_id, str) or not scan_id.strip():
        raise SnapshotError(
            "the scan states no 'scan_id'. The id is what keeps two scans "
            "taken in the same second in separate folders, so a snapshot "
            "cannot be named without it.")
    return scan_id.strip()[:_SCAN_ID_PREFIX_LENGTH]


def snapshot_folder_name(scan_result: Dict[str, Any]) -> str:
    """The folder name for ``scan_result``: its own timestamp, then its own id.

    ``2026-08-20T162647Z-b288e925``. Both halves come out of the payload, so the
    name and the provenance inside the files cannot disagree, and the name is
    legal on Windows as well as POSIX — no colon, no separator, no space.

    Raises:
        SnapshotError: the payload has no provenance block, no timestamp, no
            ``scan_id``, or the derived name is not a safe file name.
    """
    scan = _provenance(scan_result)
    name = f"{_folder_timestamp(scan)}-{_folder_scan_id(scan)}"
    if not _SAFE_FOLDER_NAME.match(name):
        raise SnapshotError(
            f"the snapshot folder name derived from this scan, {name!r}, is not "
            f"a safe directory name; the scan's timestamp and scan_id must be a "
            f"plain ISO-8601 datetime and a plain identifier")
    return name


def _validate_output_dir(output_dir: Any) -> Path:
    """Resolve and vet the *parent* directory the snapshot folder goes in.

    Deliberately does not require it to exist — the parents are created — but
    does refuse a path that exists and is not a directory, which is the one way
    a caller can hand over somewhere no folder can be made.
    """
    if not isinstance(output_dir, str) or not output_dir.strip():
        raise SnapshotError(
            "output_dir must be a non-empty directory path: the folder to "
            "create the snapshot inside. There is deliberately no default — a "
            "snapshot holds real directory content, so where it lands is the "
            "operator's choice, not a fallback's.")

    path = Path(os.path.expanduser(output_dir.strip()))
    if not path.is_absolute():
        path = Path.cwd() / path

    if path.exists() and not path.is_dir():
        raise SnapshotError(
            f"output_dir {str(path)!r} exists and is not a directory; the "
            f"snapshot needs a directory to create its own folder inside")
    return path


def _discard(folder: Path) -> None:
    """Remove a snapshot folder this call created and then failed to fill.

    Best effort, and conservative: only the two file names this module writes
    are removed, and the folder only if it is then empty. A half-written
    snapshot left on disk would be read later as a whole one.
    """
    for name in (SNAPSHOT_SCAN_FILENAME, SNAPSHOT_REPORT_FILENAME):
        try:
            (folder / name).unlink()
        except OSError:
            pass
    try:
        folder.rmdir()
    except OSError:
        pass


def write_snapshot(scan_result: Dict[str, Any], output_dir: Any) -> Snapshot:
    """Write one scan payload into one new folder as both artifacts.

    ``scan_result`` is scanned **by the caller, once**. Both files here render
    that same payload, which is what stops the folder holding two scans.

    Args:
        scan_result: The scan payload, as ``scan_hardening`` returns it.
        output_dir: The directory to create the snapshot folder inside. Missing
            parents are created.

    Returns:
        A :class:`Snapshot` naming the folder, both files and both byte counts.

    Raises:
        SnapshotError: the payload cannot name a folder, ``output_dir`` is
            unusable, or the snapshot folder already exists.
        ScanFileError: ``scan.json`` could not be written.
        ReportPathError: ``report.html`` could not be written.
    """
    parent = _validate_output_dir(output_dir)
    folder = parent / snapshot_folder_name(scan_result)

    try:
        # No ``exist_ok``: an existing folder is a refusal, not something to
        # merge into, and letting mkdir decide keeps the check and the create
        # from being two racing steps.
        folder.mkdir(parents=True)
    except FileExistsError as exc:
        raise SnapshotError(
            f"the snapshot folder {str(folder)!r} already exists; refusing to "
            f"overwrite or merge into it. A snapshot is one scan's evidence, so "
            f"mixing two into a folder would leave no way to tell which file "
            f"came from which run. Move or delete that folder if you meant to "
            f"replace it.") from exc
    except OSError as exc:
        raise SnapshotError(
            f"could not create the snapshot folder {str(folder)!r}: "
            f"{exc}") from exc

    try:
        scan_path, scan_bytes = write_scan(
            scan_result, str(folder / SNAPSHOT_SCAN_FILENAME))
        report_path, report_bytes = write_report(
            scan_result, str(folder / SNAPSHOT_REPORT_FILENAME))
    except (ScanFileError, ReportPathError):
        # The folder is one this call just created, so nothing of anyone else's
        # is in it. Leaving a folder with one of the two files in it would read
        # later as a complete snapshot.
        _discard(folder)
        raise

    return Snapshot(folder=folder, scan_path=scan_path, scan_bytes=scan_bytes,
                    report_path=report_path, report_bytes=report_bytes)


def resolve_scan_path(path: Any) -> str:
    """Accept either a scan file or a snapshot folder, and return the file.

    This is what lets ``diff_hardening_scans`` be handed two snapshot folders:
    ``diff <folder-a> <folder-b>`` is the natural thing to type once a scan is a
    folder, and the caller should not have to reach inside for ``scan.json``.

    A path that is not an existing directory is returned unchanged, so every
    existing caller — and every error message about a missing or malformed file
    — behaves exactly as before.

    Raises:
        ScanFileError: ``path`` is a directory that holds no ``scan.json``. It
            is the read side's error type because that is what the caller is
            doing: reading a scan that is not there.
    """
    if not isinstance(path, str) or not path.strip():
        return path

    candidate = Path(os.path.expanduser(path.strip()))
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if not candidate.is_dir():
        return path

    inner = candidate / SNAPSHOT_SCAN_FILENAME
    if not inner.is_file():
        raise ScanFileError(
            f"{str(candidate)} is a directory, but it holds no "
            f"{SNAPSHOT_SCAN_FILENAME}, so it is not a snapshot folder. Give a "
            f"snapshot folder written by write_hardening_snapshot, or the path "
            f"of a .json scan written by write_hardening_scan.")
    return str(inner)


__all__ = [
    "SNAPSHOT_FORMAT_VERSION",
    "SNAPSHOT_REPORT_FILENAME",
    "SNAPSHOT_SCAN_FILENAME",
    "Snapshot",
    "SnapshotError",
    "resolve_scan_path",
    "snapshot_folder_name",
    "write_snapshot",
]
