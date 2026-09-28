"""The object the page calls: one method per thing a button can do.

pywebview exposes an instance's public methods to JavaScript as
``window.pywebview.api.<name>``. This is that instance, and it is deliberately
thin: it holds the app's state, calls into the modules that do the work, and
returns dicts of **already-escaped HTML fragments** plus a few scalars. No
domain logic lives here.

**What this class does not expose is the point.** The app's surface is the
methods below: test a connection, save it, run one read-only scan, list and
diff snapshots, and help establish LDAPS trust. There is no method here that
modifies the directory.

**The password.** It lives in ``self._password`` and in the OS credential store,
and nowhere else. It is:

* never returned to the page — :meth:`state` reports ``password_present`` as a
  boolean and the page's field is a write-only input;
* never written to the app's config file (:mod:`aditor.app.settings` writes the
  ``${AD_MCP_PASSWORD}`` placeholder);
* never logged — and registered with the redaction filter so a future edit that
  logs it emits ``***REDACTED***`` instead.

``tests/test_app_password_never_leaks.py`` drives this class end to end with a
distinctive password and asserts it appears in none of those places.
"""

from __future__ import annotations

import webbrowser
from dataclasses import replace
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
from .history import HistoryError, diff_snapshots, list_snapshots, report_uri

# Aliased on import: the method below is called ``export_ca_certificate`` too,
# and the page calls the method.
from .issuer import fetch_issuing_ca
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
from .trust import (
    EXPORT_DIRNAME,
    TrustExportError,
    build_trust_report,
    install_commands,
)
from .trust import export_ca_certificate as write_ca_certificate


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
                 store: Any = None,
                 chain_fetch: Any = None,
                 ldap_factory: Any = None) -> None:
        install_redaction()
        self._dir = Path(directory) if directory else settings_dir()
        self._store = store or get_store()
        self._settings: AppSettings = load_settings(self._dir)
        self._scan = ScanJob()
        self._password: str = ""
        # Injected for the certificate tests, which run with no domain
        # controller and no network. Production passes neither.
        self._chain_fetch = chain_fetch
        self._ldap_factory = ldap_factory
        self._trust_report: Any = None
        self._export_path: str = ""
        # The result of the last issuer fetch, so the panel can show it.
        self._issuer_fetch: Any = None
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

    # -- 1b. the certificate chain ----------------------------------------- #
    #
    # Two methods, and the names matter as much as the bodies: there is no
    # ``trust_certificate``, no ``install_certificate`` and no
    # ``add_to_trust_store`` on this class, and ``tests/test_app_surface.py``
    # asserts the whole method list. The page cannot ask for an installation
    # because there is nothing to ask.

    def certificate_screen(self, form: Dict[str, Any]) -> Dict[str, Any]:
        """Inspect the controller's chain, compare it with the directory, and
        say what to do on this machine.

        Reads only. It writes no file, changes no trust store, and **does not
        touch** ``validate_certificate``: the settings object built from the
        form is a local that is never assigned to ``self._settings``, so the
        operator's saved choice is the same before and after — asserted by
        ``tests/test_app_certificate_panel.py``. The on-screen value *is* used
        for the directory read, because using anything else would mean the app
        had quietly overridden the operator's choice in either direction.
        """
        candidate = self._settings_from_form(form)
        password = str((form or {}).get("password") or "") or self._password
        if password:
            register_secret(password)
        report = build_trust_report(candidate, password,
                                    factory=self._ldap_factory,
                                    fetch=self._chain_fetch,
                                    export_path=self._export_path)
        self._trust_report = report
        return _ok(
            corroboration=report.corroboration.outcome,
            chain_read=report.chain.ok,
            # A scalar for the toast. The panel says it properly.
            expiry_warning=report.chain.needs_expiry_attention()
            or any(item.needs_expiry_attention()
                   for item in report.directory.certificates),
            html=render.render_certificate_panel(report))

    def export_ca_certificate(self, fingerprint: str) -> Dict[str, Any]:
        """Write one of the certificates on screen to a ``.crt`` file.

        Writing a file is the entire extent of it. The install command is
        rendered for the operator to run; ADitor does not run it, and adding
        one that did would be the trust-on-first-use button this work package
        exists to not build.

        Keyed by fingerprint, and only against the chain currently on screen:
        the page is the least trustworthy input in the app, and this way it can
        only ask for a certificate the operator is looking at.
        """
        report = self._trust_report
        if report is None:
            return _fail("Inspect the certificate chain first — there is "
                         "nothing on screen to export.")
        wanted = str(fingerprint or "").strip().lower().replace(":", "")
        available = {item.fingerprint_hex: item
                     for item in tuple(report.exportable)
                     + tuple(report.directory.certificates)}
        facts = available.get(wanted)
        if facts is None:
            return _fail("That is not one of the certificates on screen. "
                         "Inspect the chain again and use the button next to "
                         "the certificate you want.")
        try:
            path = write_ca_certificate(facts, self._dir / EXPORT_DIRNAME)
        except TrustExportError as exc:
            return _fail(exc)

        self._export_path = str(path)
        # Re-render from the chain already in hand rather than inspecting
        # again: a second handshake could return a different certificate, and
        # the fingerprints on screen would then no longer be the ones the
        # operator was told to verify.
        report = replace(report, export_path=self._export_path,
                         steps=install_commands(report.machine, path))
        self._trust_report = report
        return _ok(path=self._export_path,
                   html=render.render_certificate_panel(report))

    def download_issuing_ca(self) -> Dict[str, Any]:
        """Fetch the CA certificate that issued the controller's, and save it.

        The step every platform's instructions used to begin by assuming. It
        does two things and no more: finds a certificate and writes it to a
        file. It does not install it, does not ask the OS to trust it, and does
        not run the command that would — the command is rendered with the saved
        path filled in, for the operator to run.

        **It sends no credential.** It looks in this computer's certificate
        stores and at the certificate's own http(s) AIA address, never in the
        directory: reading the directory would mean binding with the password
        over a connection whose certificate can't be validated yet. A
        certificate is only offered if **its key signed the certificate the
        controller presented** (a signature check, not a name comparison; see
        :mod:`aditor.app.issuer`), and the panel still asks for the fingerprint
        to be confirmed out of band before anything is installed.
        """
        report = self._trust_report
        if report is None or not report.chain.certificates:
            return _fail("Inspect the certificate chain first — there is no "
                         "presented certificate to find the issuer of.")
        # The leaf as it is on screen, not a fresh handshake: this proves an
        # issuer for the certificate the operator is looking at, and a second
        # handshake could return a different one.
        leaf = report.chain.certificates[0]
        try:
            fetch = fetch_issuing_ca(leaf)
        except Exception as exc:  # pragma: no cover - defensive
            return _fail(exc)

        if not fetch.ok or fetch.match is None:
            self._issuer_fetch = fetch
            return _fail(
                f"{fetch.headline} {fetch.detail}",
                outcome=fetch.outcome,
                html=render.render_certificate_panel(report, fetch=fetch))

        try:
            path = write_ca_certificate(fetch.match,
                                        self._dir / EXPORT_DIRNAME)
        except TrustExportError as exc:
            return _fail(exc)

        self._export_path = str(path)
        self._issuer_fetch = fetch
        report = replace(report, export_path=self._export_path,
                         steps=install_commands(report.machine, path))
        self._trust_report = report
        return _ok(path=self._export_path,
                   outcome=fetch.outcome,
                   fingerprint=fetch.match.fingerprint,
                   html=render.render_certificate_panel(report, fetch=fetch))

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

    # -- shutdown ---------------------------------------------------------- #

    def shutdown(self) -> None:
        """Forget the password when the window closes."""
        if self._password:
            forget_secret(self._password)
            self._password = ""


__all__ = ["AditorApi"]
