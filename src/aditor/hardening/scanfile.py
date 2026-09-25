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
# document, so ``_marker_present`` never has to parse a whole file — and a
# mistyped output path cannot silently destroy someone else's JSON.
SCAN_FILE_MARKER = "aditor-hardening-scan"

# Version of the *stored file's* envelope: the two fields this module adds, not
# the scan inside it (that carries its own engine and catalog versions).
SCAN_FILE_FORMAT_VERSION = "1.0.0"

# How much of an existing file to search for the marker before refusing it.
_MARKER_SCAN_BYTES = 8192

# Suffixes :func:`write_scan` accepts.
JSON_SUFFIXES = (".json",)

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


def _validate_output_path(output_path: Any) -> Path:
    """Resolve and vet an output path without reading more than it has to.

    Guards, in order: a usable string; a ``.json`` suffix; the path is not an
    existing directory; and, if the file already exists, that it carries
    :data:`SCAN_FILE_MARKER` — so re-running the tool over its own output is
    fine while clobbering an unrelated document is refused.
    """
    if not isinstance(output_path, str) or not output_path.strip():
        raise ScanFileError(
            "output_path must be a non-empty file path ending in .json")

    path = Path(os.path.expanduser(output_path.strip()))
    if not path.is_absolute():
        path = Path.cwd() / path

    if path.suffix.lower() not in JSON_SUFFIXES:
        raise ScanFileError(
            f"output_path must end in {JSON_SUFFIXES[0]} (got "
            f"{path.suffix or 'no suffix'!r}); a stored scan is the JSON "
            f"payload, and requiring the suffix is what stops it being written "
            f"over a file of another kind — an HTML report, say")

    if path.is_dir():
        raise ScanFileError(
            f"output_path {str(path)!r} is a directory; give the full file name "
            f"to write, e.g. {str(path / 'hardening-scan.json')!r}")

    if path.exists():
        if not path.is_file():
            raise ScanFileError(
                f"output_path {str(path)!r} exists and is not a regular file; "
                f"refusing to write to it")
        try:
            with path.open("rb") as handle:
                head = handle.read(_MARKER_SCAN_BYTES)
        except OSError as exc:
            raise ScanFileError(
                f"output_path {str(path)!r} exists but could not be read to "
                f"check whether it is a previous scan: {exc}") from exc
        if SCAN_FILE_MARKER.encode("ascii") not in head:
            raise ScanFileError(
                f"output_path {str(path)!r} already exists and is not an ADitor "
                f"hardening scan (it does not carry the "
                f"{SCAN_FILE_MARKER!r} marker); refusing to overwrite it. "
                f"Choose a new file name, or delete that file first if you "
                f"meant to replace it")
    return path


def write_scan(scan_result: Dict[str, Any], output_path: Any) -> Tuple[Path, int]:
    """Write ``scan_result`` to ``output_path`` as a stored scan.

    Returns:
        ``(path, bytes_written)``.

    Raises:
        ScanFileError: the path is unusable, would clobber a non-scan file, the
            payload is not JSON-serialisable, or the write failed.
    """
    path = _validate_output_path(output_path)
    document = scan_document(scan_result)

    try:
        # indent=2 costs a few bytes and buys a file a human can read, and that
        # plain `diff` and git can handle line by line.
        text = json.dumps(document, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ScanFileError(
            f"the scan payload could not be serialised to JSON: {exc}") from exc
    payload = text.encode("utf-8")

    parent = path.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ScanFileError(
                f"could not create the directory {str(parent)!r} for the "
                f"scan: {exc}") from exc
    elif not parent.is_dir():
        raise ScanFileError(
            f"the parent path {str(parent)!r} is not a directory, so "
            f"{str(path)!r} cannot be written")

    try:
        path.write_bytes(payload)
    except OSError as exc:
        raise ScanFileError(
            f"could not write the scan to {str(path)!r}: {exc}") from exc
    return path, len(payload)
