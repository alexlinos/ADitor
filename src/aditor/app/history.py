"""The snapshot archive: list it, open a report, diff two.

A snapshot is a folder (:mod:`aditor.hardening.snapshot`) holding ``scan.json``
and ``report.html``. This module reads that folder structure and nothing else —
no LDAP, no SMB, no clock, no directory access of any kind. History works with
the domain controller switched off, which is the point of storing scans.

Two design notes worth stating.

**The diff goes through the real tool.** ``diff_hardening_scans`` is the one
hardening tool that touches no directory: it reads two files and returns a diff.
So it is called on a :class:`~aditor.tools.hardening.HardeningTools` built with
**no LDAP manager at all** — that is exactly as much connection as the diff
needs, and it means History does not demand credentials to compare two files
that are already on disk. Using the tool rather than reaching past it to
:func:`aditor.hardening.diff.diff_scan_files` keeps the tool's own ``headline``,
which is where the ambiguous-attribution wording already lives. A test pins the
no-LDAP property, because it is the sort of thing a later edit breaks silently.

**Opening a report is confined to the archive.** :func:`report_uri` refuses any
path that is not inside the snapshot directory it was given. The app hands the
path to the operating system's default browser, so an unchecked path is a
"open arbitrary file" primitive driven by whatever string arrives from the page.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..hardening.snapshot import (
    SNAPSHOT_REPORT_FILENAME,
    SNAPSHOT_SCAN_FILENAME,
)
from .credentials import redact


@dataclass(frozen=True)
class SnapshotEntry:
    """One row of the History list, read out of one snapshot folder.

    ``readable`` is false for a folder that looks like a snapshot but whose
    ``scan.json`` will not parse. Such a folder is listed rather than hidden: a
    scan that is on disk and unreadable is something the operator needs to see,
    and silently dropping it makes the archive look smaller than it is.
    """

    name: str
    folder: str
    scan_path: str
    report_path: str
    has_report: bool
    readable: bool
    timestamp: str = ""
    scan_id: str = ""
    domain: str = ""
    base_dn: str = ""
    catalog_version: str = ""
    engine_version: str = ""
    gpos_scanned: int = 0
    gpos_unreadable: int = 0
    counts: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def sort_key(self) -> Tuple[str, str]:
        """Newest first is by timestamp; the folder name is the tie-break.

        The folder name begins with the same timestamp, so an entry whose
        ``scan.json`` is unreadable still sorts into roughly the right place
        instead of falling to the bottom.
        """
        return (self.timestamp or self.name, self.name)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def read_entry(folder: Path) -> Optional[SnapshotEntry]:
    """Read one snapshot folder, or ``None`` if it is not a snapshot at all.

    "Not a snapshot at all" means no ``scan.json``: an unrelated directory the
    operator happens to keep alongside their scans, which should not appear in
    the list. A ``scan.json`` that exists but does not parse *is* a snapshot,
    and comes back with ``readable=False``.
    """
    scan_path = folder / SNAPSHOT_SCAN_FILENAME
    if not scan_path.is_file():
        return None

    report_path = folder / SNAPSHOT_REPORT_FILENAME
    base = {
        "name": folder.name,
        "folder": str(folder),
        "scan_path": str(scan_path),
        "report_path": str(report_path),
        "has_report": report_path.is_file(),
    }

    try:
        payload = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return SnapshotEntry(readable=False,
                             error=redact(f"{type(exc).__name__}: {exc}"),
                             **base)
    if not isinstance(payload, dict):
        return SnapshotEntry(
            readable=False,
            error="scan.json does not contain a JSON object.", **base)

    scan = payload.get("scan")
    scan = scan if isinstance(scan, dict) else {}
    counts = payload.get("counts")
    counts = counts if isinstance(counts, dict) else {}

    return SnapshotEntry(
        readable=True,
        timestamp=str(scan.get("timestamp") or ""),
        scan_id=str(scan.get("scan_id") or ""),
        domain=str(scan.get("domain") or ""),
        base_dn=str(scan.get("base_dn") or ""),
        catalog_version=str(scan.get("catalog_version") or ""),
        engine_version=str(scan.get("tool_version") or ""),
        gpos_scanned=_as_int(scan.get("gpos_scanned")),
        gpos_unreadable=_as_int(scan.get("gpos_unreadable")),
        counts=counts,
        **base)


def list_snapshots(directory: Any, limit: int = 200) -> List[SnapshotEntry]:
    """Every snapshot in ``directory``, newest first.

    Only immediate children are examined. A snapshot folder is created directly
    inside the output directory by ``write_hardening_snapshot``, and recursing
    would eventually walk into whatever else the operator keeps under there.
    """
    try:
        root = Path(directory).expanduser()
    except (TypeError, ValueError):
        return []
    if not root.is_dir():
        return []

    entries: List[SnapshotEntry] = []
    try:
        children = sorted(root.iterdir())
    except OSError:
        return []
    for child in children:
        if not child.is_dir():
            continue
        entry = read_entry(child)
        if entry is not None:
            entries.append(entry)
    entries.sort(key=lambda item: item.sort_key, reverse=True)
    return entries[:limit]


class HistoryError(RuntimeError):
    """A history action was refused, with the reason."""


def _within(root: Path, candidate: Path) -> bool:
    """Whether ``candidate`` is inside ``root``, after resolving both.

    ``resolve`` on both sides so a path containing ``..`` or a symlink cannot
    step out of the archive and still compare equal by string prefix.
    """
    try:
        candidate.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def report_uri(directory: Any, folder_name: str) -> str:
    """A ``file://`` URI for a snapshot's report, or refuse.

    ``folder_name`` is a *name*, not a path: it comes from the page, and the
    page is the least trustworthy input in the app. Rejecting anything with a
    separator in it, and then re-checking containment after resolution, means an
    arbitrary path arriving here cannot become an arbitrary file opened in the
    operator's browser.
    """
    name = str(folder_name or "").strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise HistoryError(
            f"{name!r} is not a snapshot folder name.")
    root = Path(directory).expanduser()
    folder = root / name
    if not _within(root, folder) or not folder.is_dir():
        raise HistoryError(
            f"there is no snapshot folder called {name!r} in {root}.")
    report = folder / SNAPSHOT_REPORT_FILENAME
    if not report.is_file():
        raise HistoryError(
            f"the snapshot {name!r} has no {SNAPSHOT_REPORT_FILENAME}. Its "
            f"scan.json may still be diffable.")
    return report.resolve().as_uri()


def scan_path(directory: Any, folder_name: str) -> Path:
    """The ``scan.json`` inside a named snapshot folder, with the same guards."""
    name = str(folder_name or "").strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise HistoryError(f"{name!r} is not a snapshot folder name.")
    root = Path(directory).expanduser()
    folder = root / name
    if not _within(root, folder) or not folder.is_dir():
        raise HistoryError(
            f"there is no snapshot folder called {name!r} in {root}.")
    path = folder / SNAPSHOT_SCAN_FILENAME
    if not path.is_file():
        raise HistoryError(
            f"the snapshot {name!r} has no {SNAPSHOT_SCAN_FILENAME}, so it "
            f"cannot be diffed.")
    return path


def diff_snapshots(directory: Any, before_name: str, after_name: str,
                   tools: Any = None) -> Dict[str, Any]:
    """Diff two snapshot folders through the ``diff_hardening_scans`` tool.

    ``tools`` is injectable for tests; production builds a
    :class:`~aditor.tools.hardening.HardeningTools` with **no LDAP manager**,
    because the diff reads two files and touches no directory. If a future edit
    makes ``diff_hardening_scans`` reach for ``self.ldap``, the test that pins
    this will fail — which is the intent.

    Returns:
        The tool's own diff payload. ``attribution`` is its first key and stays
        first; the renderer leads with it.
    """
    before = scan_path(directory, before_name)
    after = scan_path(directory, after_name)
    if before.resolve() == after.resolve():
        raise HistoryError(
            "those are the same snapshot. Pick two different scans — a diff of "
            "a scan against itself says nothing.")

    if tools is None:
        from ..tools.hardening import HardeningTools

        tools = HardeningTools(None)

    response = tools.diff_hardening_scans(str(before), str(after))
    payload = _unwrap(response)
    if payload is None:
        raise HistoryError(
            "the diff tool returned something this app could not read.")
    if not payload.get("success"):
        raise HistoryError(redact(str(payload.get("error")
                                      or "the two scans could not be "
                                         "compared.")))
    return payload


def _unwrap(response: Any) -> Optional[Dict[str, Any]]:
    if isinstance(response, dict):
        return response
    if not isinstance(response, (list, tuple)) or not response:
        return None
    text = getattr(response[0], "text", None)
    if text is None and isinstance(response[0], dict):
        text = response[0].get("text")
    if not isinstance(text, str):
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


__all__ = [
    "HistoryError",
    "SnapshotEntry",
    "diff_snapshots",
    "list_snapshots",
    "read_entry",
    "report_uri",
    "scan_path",
]
