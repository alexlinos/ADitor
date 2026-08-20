"""The object the page calls: one method per thing a button can do.

pywebview exposes an instance's public methods to JavaScript as
``window.pywebview.api.<name>``. This is that instance, and it is deliberately
thin: it holds the app's state, calls into the modules that do the work, and
returns dicts of **already-escaped HTML fragments** plus a few scalars. No
domain logic lives here.

**What this class does not expose is the point.** The MCP server offers 52 tools,
22 of which write to Active Directory. The app's surface is the methods below:
test a connection, save it, run one read-only scan, list and diff snapshots,
start and stop the server, generate a config snippet. There is no method here
that modifies the directory, and none that takes a tool name — so the page
cannot reach a write tool by asking for one.

**The password.** It lives in ``self._password`` and in the OS credential store,
and nowhere else. It is:

* never returned to the page — :meth:`state` reports ``password_present`` as a
  boolean and the page's field is a write-only input;
* never written to the app's config file (:mod:`aditor.app.settings` writes the
  ``${AD_MCP_PASSWORD}`` placeholder);
* never logged — and registered with the redaction filter so a future edit that
  logs it emits ``***REDACTED***`` instead;
* passed to the server child process only through its environment, never in
  ``argv``.

``tests/test_app_password_never_leaks.py`` drives this class end to end with a
distinctive password and asserts it appears in none of those places.
"""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

from . import render
from .connection import run_connection_test
from .credentials import (
    CredentialStoreError,
    forget_secret,
    get_store,
    install_redaction,
    redact,
    register_secret,
)
from .endpoint import (
    Endpoint,
    ServerControlError,
    ServerProcess,
    assess_exposure,
    default_endpoint,
    snippets,
)
from .history import HistoryError, diff_snapshots, list_snapshots, report_uri
from .scanning import ScanError, ScanJob
from .settings import (
    AppSettings,
    ConnectionSettings,
    PersistRefused,
    config_path,
    load_password,
    load_settings,
    persist_connection,
    settings_dir,
)


def _ok(**extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"ok": True}
    payload.update(extra)
    return payload


def _fail(message: Any, **extra: Any) -> Dict[str, Any]:
    """A refusal, pre-rendered. Every message passes through redaction first.

    Redaction here rather than at each call site: this is the single funnel
    every error takes on its way to the page, so it is the one place that has to
    be right.
    """
    payload: Dict[str, Any] = {"ok": False,
                               "message": redact(str(message)),
                               "html": render.render_error(redact(str(message)))}
    payload.update(extra)
    return payload


class AditorApi:
    """The bridge between ``web/app.js`` and the rest of this package."""

    def __init__(self, directory: Optional[Path] = None,
                 endpoint: Optional[Endpoint] = None,
                 store: Any = None) -> None:
        install_redaction()
        self._dir = Path(directory) if directory else settings_dir()
        self._store = store or get_store()
        self._settings: AppSettings = load_settings(self._dir)
        self._endpoint = endpoint or default_endpoint()
        self._server = ServerProcess(endpoint=self._endpoint,
                                     config_path=config_path(self._dir))
        self._scan = ScanJob()
        self._password: str = ""
        self._load_saved_password()

    # -- helpers ----------------------------------------------------------- #
    #
    # Everything below is underscore-prefixed, and that is load-bearing rather
    # than stylistic: pywebview builds the JavaScript API by *walking every
    # public attribute* of this object and recursing into the ones that are not
    # callable. A public property here would put whatever it returns -- and
    # whatever that object's own properties do -- inside the bridge. This was
    # found by launching the app: a public ``connection`` property let the
    # generator reach ``ConnectionSettings.credential_ref`` and the JS API
    # failed to build on a fresh install with an empty form.

    @property
    def _connection(self) -> ConnectionSettings:
        return self._settings.connection

    def _load_saved_password(self) -> None:
        """Pick the password up from the credential store, if it is there.

        A read failure is *not* treated as "no password": a locked keychain
        would otherwise look identical to a first run, and the operator would be
        told to re-enter a password that is sitting there fine.
        """
        self._store_error = ""
        try:
            found = load_password(self._connection, self._store)
        except CredentialStoreError as exc:
            self._store_error = redact(str(exc))
            return
        if found:
            self._set_password(found)

    def _set_password(self, password: str) -> None:
        previous = self._password
        self._password = password or ""
        if previous and previous != self._password:
            forget_secret(previous)
        if self._password:
            register_secret(self._password)

    # -- 0. state ---------------------------------------------------------- #

    def state(self) -> Dict[str, Any]:
        """Everything the page needs to draw itself. No password, ever."""
        connection = self._connection
        available = self._store.available()
        return _ok(
            connection={
                "server": connection.server,
                "domain": connection.domain,
                "base_dn": connection.base_dn,
                "bind_dn": connection.bind_dn,
                "validate_certificate": connection.validate_certificate,
                "snapshot_dir": str(connection.resolved_snapshot_dir()),
            },
            # A boolean. The value is never sent to the page.
            password_present=bool(self._password),
            credential_store={
                "name": self._store.name,
                "available": available,
                "html": render.render_credential_store(
                    self._store.name, available, self._store.where,
                    self._store_error or self._store.unavailable_reason()),
            },
            settings_path=str(config_path(self._dir)),
            scan_running=self._scan.running(),
            server=self.server_status(),
        )

    # -- 1. connection ----------------------------------------------------- #

    def _settings_from_form(self, form: Dict[str, Any]) -> ConnectionSettings:
        form = form if isinstance(form, dict) else {}
        return self._connection.with_values(
            server=str(form.get("server") or "").strip(),
            domain=str(form.get("domain") or "").strip(),
            base_dn=str(form.get("base_dn") or "").strip(),
            bind_dn=str(form.get("bind_dn") or "").strip(),
            validate_certificate=bool(form.get("validate_certificate", True)),
            snapshot_dir=str(form.get("snapshot_dir") or "").strip(),
        )

    def test_connection(self, form: Dict[str, Any]) -> Dict[str, Any]:
        """Bind read-only with what is on screen and report the real result."""
        candidate = self._settings_from_form(form)
        password = str((form or {}).get("password") or "") or self._password
        if password:
            register_secret(password)
        result = run_connection_test(candidate, password)
        return _ok(passed=result.ok, kind=result.kind,
                   html=render.render_connection_result(result))

    def save_connection(self, form: Dict[str, Any]) -> Dict[str, Any]:
        """Store the password in the OS store and the rest in config.json.

        Both or neither: :func:`aditor.app.settings.persist_connection` puts the
        secret away first and writes no file at all if that fails.
        """
        candidate = self._settings_from_form(form)
        password = str((form or {}).get("password") or "") or self._password
        try:
            result = persist_connection(candidate, password, self._dir,
                                        self._store)
        except PersistRefused as exc:
            return _fail(exc)

        self._settings = AppSettings(connection=candidate)
        self._set_password(password)
        self._server.config_path = result.config_path
        return _ok(html=render.render_notice(
            f"Saved. The password is in {result.store_name}.",
            f"Connection settings: {result.config_path}. The password is not "
            f"in that file — it holds the ${{AD_MCP_PASSWORD}} placeholder.",
            kind="ok"), state=self.state())

    def forget_password(self) -> Dict[str, Any]:
        """Drop the password from memory and from the OS credential store."""
        removed = False
        ref = self._connection.credential_ref
        try:
            if ref is not None and self._store.available():
                removed = self._store.delete_password(ref)
        except CredentialStoreError as exc:
            return _fail(exc)
        if self._password:
            forget_secret(self._password)
        self._password = ""
        return _ok(html=render.render_notice(
            "Password removed." if removed else
            "Password cleared from this session.",
            "Enter it again to test the connection or run a scan.",
            kind="info"), state=self.state())

    # -- 2. scan ----------------------------------------------------------- #

    def start_scan(self) -> Dict[str, Any]:
        """Kick the one read-only scan off in the background.

        Background because it blocks for seconds on a real domain and pywebview
        would otherwise freeze the window; the page polls :meth:`scan_progress`.
        """
        try:
            self._scan.start(self._connection, self._password,
                             self._connection.resolved_snapshot_dir())
        except ScanError as exc:
            return _fail(exc)
        return _ok(html=render.render_notice(
            "Scan started.",
            "This reads Group Policy content from SYSVOL and writes nothing to "
            "the directory.", kind="info"))

    def scan_progress(self) -> Dict[str, Any]:
        """Where the scan is. Polled; returns the finished result once done."""
        progress = self._scan.progress()
        result = self._scan.result()
        payload = _ok(progress=progress, finished=result is not None)
        if result is not None:
            payload["passed"] = result.ok
            payload["html"] = render.render_scan_result(result)
            payload["report_path"] = result.report_path
            payload["snapshot_dir"] = result.snapshot_dir
        return payload

    def open_path(self, path: str) -> Dict[str, Any]:
        """Open a report in the operator's browser.

        Confined to the snapshot archive by :func:`aditor.app.history.report_uri`
        — the page is the least trustworthy input in the app, so a path arriving
        from it is checked against the archive before the OS is asked to open
        anything.
        """
        archive = self._connection.resolved_snapshot_dir()
        candidate = Path(str(path or ""))
        name = candidate.parent.name if candidate.name.endswith(".html") \
            else candidate.name
        try:
            uri = report_uri(archive, name)
        except HistoryError as exc:
            return _fail(exc)
        webbrowser.open(uri)
        return _ok(opened=uri)

    # -- 3. history -------------------------------------------------------- #

    def history(self) -> Dict[str, Any]:
        archive = self._connection.resolved_snapshot_dir()
        entries = list_snapshots(archive)
        return _ok(count=len(entries),
                   directory=str(archive),
                   html=render.render_history(entries, archive))

    def open_report(self, folder_name: str) -> Dict[str, Any]:
        archive = self._connection.resolved_snapshot_dir()
        try:
            uri = report_uri(archive, str(folder_name or ""))
        except HistoryError as exc:
            return _fail(exc)
        webbrowser.open(uri)
        return _ok(opened=uri)

    def diff(self, before: str, after: str) -> Dict[str, Any]:
        """Diff two snapshots. Needs no credentials and touches no directory."""
        archive = self._connection.resolved_snapshot_dir()
        if not before or not after:
            return _fail("Pick an earlier scan and a later scan, then diff.")
        try:
            payload = diff_snapshots(archive, str(before), str(after))
        except HistoryError as exc:
            return _fail(exc)
        return _ok(html=render.render_diff(payload),
                   attribution=str((payload.get("attribution") or {})
                                   .get("verdict") or ""))

    # -- 4. connect Claude Code / Codex ------------------------------------ #

    def server_status(self) -> Dict[str, Any]:
        status = self._server.status()
        exposure = assess_exposure(self._endpoint)
        return {
            "running": status["running"],
            "url": status["url"],
            "loopback": exposure.loopback,
            "status_html": render.render_server_status(status),
            "exposure_html": render.render_exposure(exposure),
        }

    def connect_screen(self) -> Dict[str, Any]:
        """Status, exposure and both generated snippets, in one call.

        The snippets are generated from :class:`aditor.app.endpoint.Endpoint` on
        every call, so they always describe the endpoint this app would actually
        serve — including the trailing slash.
        """
        data = snippets(self._endpoint)
        return _ok(server=self.server_status(),
                   url=data["url"],
                   snippets={"claude_code": data["claude_code"]["snippet"],
                             "codex": data["codex"]["snippet"]},
                   html=render.render_snippets(data))

    def start_server(self) -> Dict[str, Any]:
        try:
            self._server.start(self._password)
        except ServerControlError as exc:
            return _fail(exc, server=self.server_status())
        return _ok(server=self.server_status())

    def stop_server(self) -> Dict[str, Any]:
        try:
            self._server.stop()
        except ServerControlError as exc:
            return _fail(exc, server=self.server_status())
        return _ok(server=self.server_status())

    # -- shutdown ---------------------------------------------------------- #

    def shutdown(self) -> None:
        """Stop the child server when the window closes.

        A GUI that leaves an unauthenticated AD API listening after its window
        is gone is a worse thing than a GUI that takes an extra second to quit.
        """
        try:
            self._server.stop(timeout=3.0)
        except Exception:
            pass
        if self._password:
            forget_secret(self._password)
            self._password = ""


__all__ = ["AditorApi"]
