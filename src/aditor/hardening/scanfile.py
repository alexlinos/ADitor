"""Store a hardening scan on disk as JSON, and read one back.

The scan payload is already the source of truth —
:meth:`aditor.hardening.collect.Scanner.scan` returns it and the report renders
it.
This module gives it somewhere to *live*, so two runs can be compared later by
:mod:`aditor.hardening.diff`. It adds no analysis: a stored scan is the same
payload plus two identifying fields.

**A stored scan is directory content.** It embeds the domain's GPO display names,
registry values and DNs — exactly what a rendered report embeds, and the same
caveat applies when the file is shared, attached to a ticket or committed.

Pure but for the file I/O: no LDAP, no SMB, no clock, no catalog lookup.

The path guards mirror :func:`aditor.hardening.report.write_report`, deliberately:

* the path must end in ``.json``, which is what stops a scan being written over a
  ``.html`` report or a ``.py`` source file by a typo;
* an existing file is overwritten **only** if it carries :data:`SCAN_FILE_MARKER`
  in its opening bytes, i.e. only if it is a previous ADitor scan;
* missing parent directories are created, and anything that cannot be created or
  written fails with a :class:`ScanFileError` naming the path rather than a bare
  ``OSError`` from the middle of a write.

:data:`SCAN_FILE_MARKER` is the document's **first** key so that the
overwrite check only has to read the head of a candidate file, however large it
is.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

# Identifies a file as one of our stored scans. It is the first key in the
# document.
SCAN_FILE_MARKER = "aditor-hardening-scan"

# Version of the *stored file's* envelope: the two fields this module adds, not
# the scan inside it (that carries its own engine and catalog versions).
SCAN_FILE_FORMAT_VERSION = "1.0.0"

# The keys a payload must carry to be a scan at all. ``scan`` holds the
# provenance a diff needs to attribute a change; ``findings`` and ``counts`` hold
# what is being compared. A payload missing any of them is not a scan, and
# saying so beats producing a diff of nothing.
_REQUIRED_KEYS = ("scan", "counts", "findings")


class ScanFileError(ValueError):
    """A scan file could not be written, read, or recognised as a scan.

    Raised *before* anything is written when the problem is the output path:
    writing the file is this module's only side effect, so refusing a doubtful
    path loudly beats overwriting something a reader cared about. On the read
    side it means the file is missing, is not JSON, or is JSON that is not a
    scan payload — each with a message saying which.
    """


def scan_document(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """The on-disk document for ``scan_result``: the payload plus its envelope.

    The marker and the envelope version go first and the scan payload follows
    unchanged, key order intact. Nothing is removed and nothing is derived, so a
    stored scan and the scan payload it came from say the same
    thing.
    """
    if not isinstance(scan_result, dict):
        raise ScanFileError(
            f"a scan payload must be a JSON object, got "
            f"{type(scan_result).__name__}")
    document: Dict[str, Any] = {
        "format": SCAN_FILE_MARKER,
        "scan_format_version": SCAN_FILE_FORMAT_VERSION,
    }
    document.update(scan_result)
    return document


def validate_scan_payload(payload: Any, source: str) -> Dict[str, Any]:
    """Check that ``payload`` really is a scan, or say what it is instead.

    ``source`` names the file (or ``'<payload>'``) in the error message, because
    the caller is holding two of these and needs to know which one is wrong.

    Returns:
        The payload itself, for use inline.

    Raises:
        ScanFileError: it is not an object, it is an error response rather than a
            scan, it is missing a required key, or it has no ``base_dn`` to
            identify the domain it describes.
    """
    if not isinstance(payload, dict):
        raise ScanFileError(
            f"{source}: expected a hardening scan payload (a JSON object), got "
            f"{type(payload).__name__}")

    if payload.get("success") is False:
        error = payload.get("error") or "no error message"
        raise ScanFileError(
            f"{source}: this is a failed-scan error response, not a scan "
            f"({error}). Re-run `aditor scan` and diff the "
            f"scan.json it writes.")

    missing = [key for key in _REQUIRED_KEYS if key not in payload]
    if missing:
        raise ScanFileError(
            f"{source}: not a hardening scan payload — missing "
            f"{', '.join(repr(key) for key in missing)}. A scan carries "
            f"{', '.join(repr(key) for key in _REQUIRED_KEYS)}; write one with "
            f"`aditor scan`. (An HTML report is not a scan payload and "
            f"cannot be diffed.)")

    scan = payload.get("scan")
    if not isinstance(scan, dict):
        raise ScanFileError(
            f"{source}: the 'scan' provenance block must be an object, got "
            f"{type(scan).__name__}")
    if not isinstance(payload.get("counts"), dict):
        raise ScanFileError(
            f"{source}: the 'counts' block must be an object, got "
            f"{type(payload.get('counts')).__name__}")
    if not isinstance(payload.get("findings"), list):
        raise ScanFileError(
            f"{source}: 'findings' must be a list, got "
            f"{type(payload.get('findings')).__name__}")

    base_dn = scan.get("base_dn")
    if not isinstance(base_dn, str) or not base_dn.strip():
        raise ScanFileError(
            f"{source}: the scan does not state a 'base_dn', so there is no way "
            f"to tell which domain it describes. Two scans can only be compared "
            f"when both name their domain.")
    return payload


def read_scan(path: Any) -> Dict[str, Any]:
    """Read a stored scan from ``path`` and validate that it is one.

    The envelope fields :func:`scan_document` added are left in place: a caller
    that wants to know whether a payload came from a file can look for
    ``format``, and everything else reads the same as a live scan response.

    Raises:
        ScanFileError: the path is unusable, the file is missing or unreadable,
            it is not JSON, or it is JSON that is not a scan payload.
    """
    if not isinstance(path, str) or not path.strip():
        raise ScanFileError(
            "a scan path must be a non-empty file path ending in .json")

    resolved = Path(os.path.expanduser(path.strip()))
    if not resolved.is_absolute():
        resolved = Path.cwd() / resolved
    shown = str(resolved)

    if resolved.is_dir():
        raise ScanFileError(
            f"{shown} is a directory, not a scan file; give the full file name")
    if not resolved.exists():
        raise ScanFileError(
            f"{shown} does not exist. Write a scan first with "
            f"`aditor scan`.")

    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanFileError(f"{shown} could not be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ScanFileError(
            f"{shown} is not UTF-8 text, so it is not a scan file written by "
            f"`aditor scan`: {exc}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        hint = ""
        if text.lstrip()[:9].lower().startswith("<!doctype") or \
                text.lstrip()[:5].lower().startswith("<html"):
            hint = (" This looks like an HTML file — probably report.html. "
                    "Reports are rendered documents; diffing needs the "
                    "scan.json next to it.")
        raise ScanFileError(
            f"{shown} is not valid JSON ({exc}).{hint}") from exc

    return validate_scan_payload(payload, shown)


def write_scan(scan_result: Dict[str, Any], output_path: Any) -> Tuple[Path, int]:
    """Write ``scan_result`` to ``output_path`` as a stored scan.

    The only caller is :func:`aditor.hardening.snapshot.write_snapshot`, which
    writes into a folder it has just created, so there is nothing to clobber.

    Returns:
        ``(path, bytes_written)``.

    Raises:
        ScanFileError: the payload is not JSON-serialisable, or the write failed.
    """
    path = Path(output_path)
    try:
        # indent=2 costs a few bytes and buys a file a human can read, and that
        # plain `diff` and git can handle line by line.
        text = json.dumps(scan_document(scan_result), indent=2,
                          ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ScanFileError(
            f"the scan payload could not be serialised to JSON: {exc}") from exc
    payload = text.encode("utf-8")
    try:
        path.write_bytes(payload)
    except OSError as exc:
        raise ScanFileError(
            f"could not write the scan to '{path}': {exc}") from exc
    return path, len(payload)
