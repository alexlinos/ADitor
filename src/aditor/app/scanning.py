"""One scan, in-process, with progress the operator can watch.

**One scan.** The Scan screen runs
:meth:`aditor.hardening.collect.Scanner.scan` exactly once and hands that single
payload to :func:`aditor.hardening.snapshot.write_snapshot`, which writes both
files from it. The counts the screen then shows come out of *that* payload and
are never recomputed here and never obtained by scanning again, so the screen,
the report and ``scan.json`` cannot disagree.

**In-process.** The scanner runs over an
:class:`~aditor.core.ldap_manager.LDAPManager` in this process; the ``aditor
scan`` command does the same.

**Progress.** A domain with dozens of GPOs spends seconds in SYSVOL reads over SMB, and
a window that shows nothing for eight seconds reads as a hang — the operator
kills it and files a bug. There is no callback in the scan path, so
:func:`run_scan` installs two *observers* around the seams it does have:

* the LDAP search that enumerates ``groupPolicyContainer`` objects, which is
  where the **total** number of GPOs first becomes known;
* :meth:`Scanner._read_gpo_sysvol`, which is called once per GPO and is the
  slow part.

Both wrappers call straight through, return the result unchanged, swallow
nothing and alter nothing. They are attached to the *instances* this module
built and to nothing global, so no other caller of these classes is affected.
The alternative — threading a progress callback down through the scanner —
would change a tested signature to serve the GUI alone.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ..hardening.collect import GpoReadFailure, Scanner
from ..hardening.report import ReportPathError, headline_counts
from ..hardening.scanfile import ScanFileError
from ..hardening.snapshot import SnapshotError, write_snapshot
from .connection import ManagerFactory, build_manager
from .credentials import redact
from .settings import ConnectionSettings

# The stages, in order, with the share of the bar each one owns. The weights are
# honest about where the time goes: the SYSVOL read is the long pole and gets
# most of the bar, so the bar does not sit at 90% for eight seconds.
STAGE_CONNECT = "connect"
STAGE_ENUMERATE = "enumerate"
STAGE_READ = "read"
STAGE_EVALUATE = "evaluate"
STAGE_WRITE = "write"
STAGE_DONE = "done"
STAGE_FAILED = "failed"

_STAGE_LABELS = {
    STAGE_CONNECT: "Connecting to the domain controller",
    STAGE_ENUMERATE: "Listing Group Policy objects",
    STAGE_READ: "Reading Group Policy content from SYSVOL",
    STAGE_EVALUATE: "Evaluating the hardening catalog",
    STAGE_WRITE: "Writing the snapshot",
    STAGE_DONE: "Done",
    STAGE_FAILED: "Failed",
}

# Where each stage starts on a 0-100 bar. The read stage owns 20..88 -- most of
# the bar -- because that is genuinely most of the wall clock on a real domain,
# and a bar that sat at 90% for eight seconds would be a lie about which part is
# slow.
_STAGE_FLOOR = {
    STAGE_CONNECT: 2,
    STAGE_ENUMERATE: 10,
    STAGE_READ: 20,
    STAGE_EVALUATE: 88,
    STAGE_WRITE: 95,
    STAGE_DONE: 100,
    STAGE_FAILED: 100,
}
_READ_SPAN = 68


@dataclass
class ScanProgress:
    """A snapshot of where the scan is, safe to read from the UI thread.

    Every field is written under the lock and read as a plain dict, because the
    caller is a JS poll arriving on a different thread from the scan.
    """

    stage: str = STAGE_CONNECT
    gpos_total: int = 0
    gpos_read: int = 0
    message: str = ""
    started_at: float = field(default_factory=time.monotonic)
    finished: bool = False
    ok: Optional[bool] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_stage(self, stage: str, message: str = "") -> None:
        with self._lock:
            self.stage = stage
            self.message = message or _STAGE_LABELS.get(stage, stage)
            if stage in (STAGE_DONE, STAGE_FAILED):
                self.finished = True
                self.ok = stage == STAGE_DONE

    def set_total(self, total: int) -> None:
        with self._lock:
            self.gpos_total = max(0, int(total))

    def count_read(self) -> None:
        with self._lock:
            self.gpos_read += 1
            total = self.gpos_total
            position = (f"{self.gpos_read} of {total}" if total
                        else str(self.gpos_read))
            # The GPO's display name is deliberately NOT put in the message.
            # It is directory content, it would land in the UI, and a progress
            # line is not worth an escaping question — the count answers the
            # only thing the operator is asking, which is "is it moving".
            self.message = (f"Reading Group Policy content from SYSVOL — "
                            f"GPO {position}")

    def percent(self) -> int:
        """A 0-100 figure, monotonic and never a fake 99%."""
        with self._lock:
            floor = _STAGE_FLOOR.get(self.stage, 0)
            if self.stage != STAGE_READ:
                return floor
            if not self.gpos_total:
                # Unknown total: creep, but never past the stage's ceiling, so
                # the bar does not claim progress it cannot know it has made.
                return min(floor + min(self.gpos_read, 30), floor + 30)
            done = min(self.gpos_read, self.gpos_total)
            return floor + int(_READ_SPAN * done / self.gpos_total)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = int(time.monotonic() - self.started_at)
            stage, message = self.stage, self.message
            total, read = self.gpos_total, self.gpos_read
            finished, ok = self.finished, self.ok
        return {
            "stage": stage,
            "stage_label": _STAGE_LABELS.get(stage, stage),
            "message": message or _STAGE_LABELS.get(stage, stage),
            "percent": self.percent(),
            "gpos_total": total,
            "gpos_read": read,
            "elapsed_seconds": elapsed,
            "finished": finished,
            "ok": ok,
        }


class ScanError(RuntimeError):
    """The scan could not run, or ran and refused to write."""


@dataclass
class ScanResult:
    """The scan's outcome, plus where the snapshot went.

    ``counts`` and ``headline`` are lifted straight out of the one scan's
    payload — not recomputed. ``payload`` keeps the provenance header so the
    renderer can show scan id, timestamp and catalog version without a second
    read of ``scan.json``.
    """

    ok: bool
    payload: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def counts(self) -> Dict[str, Any]:
        counts = self.payload.get("counts")
        return counts if isinstance(counts, dict) else {}

    @property
    def headline(self) -> Dict[str, Any]:
        headline = self.payload.get("headline")
        return headline if isinstance(headline, dict) else {}

    @property
    def snapshot_dir(self) -> str:
        return str(self.payload.get("snapshot_dir") or "")

    @property
    def report_path(self) -> str:
        files = self.payload.get("files")
        if isinstance(files, dict):
            report = files.get("report")
            if isinstance(report, dict):
                return str(report.get("path") or "")
        return ""


def _observe_gpo_reads(scanner: Scanner, progress: ScanProgress) -> None:
    """Wrap the two slow seams so progress can be reported per GPO.

    Pure observation: both wrappers call the original, return its result
    unchanged, and let every exception propagate. They are bound to the objects
    this module just constructed, so nothing outside this scan sees them.
    """
    manager = scanner.ldap
    original_search = manager.search
    original_read = scanner._read_gpo_sysvol

    def search(*args: Any, **kwargs: Any) -> Any:
        result = original_search(*args, **kwargs)
        base = str(kwargs.get("search_base") or
                   (args[0] if args else "") or "")
        # The GPO enumeration is the search rooted at CN=Policies,CN=System —
        # that is where the total first exists. The gPLink search runs first and
        # is rooted at the base DN, so it cannot be confused for this one.
        if base.upper().startswith("CN=POLICIES,CN=SYSTEM,"):
            try:
                progress.set_total(len(result or []))
            except TypeError:  # pragma: no cover - defensive
                pass
            progress.set_stage(STAGE_READ)
        return result

    def read_sysvol(*args: Any, **kwargs: Any) -> Any:
        progress.count_read()
        return original_read(*args, **kwargs)

    manager.search = search  # type: ignore[method-assign]
    scanner._read_gpo_sysvol = read_sysvol  # type: ignore[method-assign]


def run_scan(settings: ConnectionSettings, password: str,
             output_dir: Optional[Path] = None,
             progress: Optional[ScanProgress] = None,
             factory: Optional[ManagerFactory] = None,
             ) -> ScanResult:
    """Run the read-only hardening scan and write one snapshot folder.

    Args:
        settings: The saved (or on-screen) connection.
        password: The bind password, held for this call only.
        output_dir: Where the snapshot folder is created. Defaults to the
            connection's resolved snapshot directory.
        progress: Updated as the scan moves. The UI polls
            :meth:`ScanProgress.snapshot`.
        factory: Injected ``LDAPManager`` builder, for tests.

    Returns:
        A :class:`ScanResult` whose counts came from this one scan.
    """
    tracker = progress or ScanProgress()
    target = Path(output_dir) if output_dir else settings.resolved_snapshot_dir()

    missing = settings.missing_fields()
    if missing:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, error=(
            f"this connection is not filled in yet: {', '.join(missing)}. "
            f"Complete the Connection screen and test it first."))
    if not password:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, error=(
            "no password is available for this connection, so the scan cannot "
            "bind. Enter it on the Connection screen."))

    tracker.set_stage(STAGE_CONNECT)
    try:
        manager = build_manager(settings, password, factory)
    except Exception as exc:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, error=(
            f"these connection settings are not usable: {redact(str(exc))}"))

    scanner = Scanner(manager)
    _observe_gpo_reads(scanner, tracker)
    tracker.set_stage(STAGE_ENUMERATE)

    try:
        payload = scanner.scan(operation="aditor app scan")
    except GpoReadFailure as failure:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, error=(
            f"the scan could not read the directory: "
            f"{redact(str(failure.cause))}"))
    except Exception as exc:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, error=(
            f"the scan failed: {redact(str(exc))}"))
    finally:
        try:
            manager.disconnect()
        except Exception:
            pass

    tracker.set_stage(STAGE_EVALUATE)
    if payload.get("success") is False:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, payload=payload,
                          error=redact(str(payload.get("error")
                                           or "the scan did not succeed")))

    tracker.set_stage(STAGE_WRITE)
    try:
        snapshot = write_snapshot(payload, str(target))
    except (SnapshotError, ScanFileError, ReportPathError) as exc:
        tracker.set_stage(STAGE_FAILED)
        return ScanResult(ok=False, error=(
            f"the scan completed but could not be written, and no snapshot "
            f"folder was left behind: {redact(str(exc))}"))

    tracker.set_stage(STAGE_DONE)
    return ScanResult(ok=True, payload={
        "success": True,
        "snapshot_dir": str(snapshot.folder),
        "snapshot_name": snapshot.folder.name,
        "scan_id": payload["scan"]["scan_id"],
        "scans_run": 1,
        "files": {
            "scan": {"path": str(snapshot.scan_path),
                     "bytes_written": snapshot.scan_bytes},
            "report": {"path": str(snapshot.report_path),
                       "bytes_written": snapshot.report_bytes},
        },
        "counts": payload["counts"],
        "headline": headline_counts(payload),
        "scan": payload["scan"],
    })


class ScanJob:
    """One background scan, pollable from the UI thread.

    pywebview dispatches JS calls on its own thread and the scan blocks for
    seconds, so the scan runs in a worker and the page polls
    :meth:`progress`. Polling rather than pushing on purpose: an
    ``evaluate_js`` from a worker thread is the sort of thing that works on one
    of the three pywebview backends.
    """

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._progress = ScanProgress()
        self._result: Optional[ScanResult] = None
        self._lock = threading.Lock()

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, settings: ConnectionSettings, password: str,
              output_dir: Optional[Path] = None, **kwargs: Any) -> None:
        with self._lock:
            if self.running():
                raise ScanError("a scan is already running.")
            self._progress = ScanProgress()
            self._result = None

            def work() -> None:
                result = run_scan(settings, password, output_dir,
                                  self._progress, **kwargs)
                with self._lock:
                    self._result = result

            self._thread = threading.Thread(target=work, name="aditor-scan",
                                            daemon=True)
            self._thread.start()

    def progress(self) -> Dict[str, Any]:
        state = self._progress.snapshot()
        state["running"] = self.running()
        return state

    def result(self) -> Optional[ScanResult]:
        with self._lock:
            return self._result

    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for the worker. For tests and for shutdown, not for the UI."""
        if self._thread is not None:
            self._thread.join(timeout)


__all__ = [
    "STAGE_CONNECT",
    "STAGE_DONE",
    "STAGE_ENUMERATE",
    "STAGE_EVALUATE",
    "STAGE_FAILED",
    "STAGE_READ",
    "STAGE_WRITE",
    "ScanError",
    "ScanJob",
    "ScanProgress",
    "ScanResult",
    "run_scan",
]
