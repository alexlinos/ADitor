"""The app's own persisted settings — everything except the password.

Two files, one directory, outside the repository and outside the user's
Documents::

    %APPDATA%\\ADitor\\                        (Windows)
    ~/Library/Application Support/ADitor/     (macOS)
    $XDG_CONFIG_HOME/aditor/                  (anything else)

        config.json      an ADitor server config, password = ${AD_MCP_PASSWORD}
        snapshots/       where scans land unless the operator moves them

``config.json`` is deliberately **the same shape the headless server already
reads** (:func:`aditor.config.loader.load_config`), rather than an app-specific
format. Two reasons. The onboarding story the app exists for is "enter
credentials here, then start the server and paste the config" — if the app kept
its own format, starting the server would mean translating between two files
that could disagree about which domain is being scanned. And the loader already
expands ``${AD_MCP_PASSWORD}``, which is the whole mechanism keeping the secret
off disk.

**The password is never in this file.** Its ``password`` field holds the literal
string ``${AD_MCP_PASSWORD}`` and nothing else, ever.
:func:`persist_connection` is the only writer, it takes the password only to
hand it to the OS credential store, and if the store refuses it **writes
nothing at all** — see the docstring there for why a partial save is worse than
no save.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .credentials import (
    CONFIG_PASSWORD_PLACEHOLDER,
    DEFAULT_SERVICE,
    CredentialRef,
    CredentialStore,
    CredentialStoreError,
    CredentialStoreUnavailable,
    get_store,
)

APP_DIR_NAME = "ADitor"
CONFIG_FILENAME = "config.json"
SNAPSHOTS_DIRNAME = "snapshots"

# Owner-only. The file holds no secret, but it does hold the bind account DN and
# the domain's base DN, and there is no reason for another local user to read
# them.
_CONFIG_MODE = 0o600
_DIR_MODE = 0o700


def settings_dir(platform: Optional[str] = None,
                 environ: Optional[Dict[str, str]] = None) -> Path:
    """Where the app keeps its config and (by default) its snapshots.

    ``platform`` and ``environ`` are injectable so the Windows layout is
    covered by a test on any machine — the path convention is the sort of thing
    that is only ever wrong on the platform you are not developing on.
    """
    name = platform or sys.platform
    env = os.environ if environ is None else environ

    if name.startswith("win"):
        base = env.get("APPDATA") or env.get("LOCALAPPDATA")
        if base:
            return Path(base) / APP_DIR_NAME
        return Path(env.get("USERPROFILE", "~")).expanduser() / APP_DIR_NAME
    if name == "darwin":
        return (Path(env.get("HOME", "~")).expanduser()
                / "Library" / "Application Support" / APP_DIR_NAME)
    base = env.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "aditor"
    return Path(env.get("HOME", "~")).expanduser() / ".config" / "aditor"


@dataclass(frozen=True)
class ConnectionSettings:
    """Everything about the connection that is *not* the password.

    Frozen because a screen that mutates the settings object it was handed is
    how a "Test connection" ends up testing something other than what is in the
    form. Every change goes through :meth:`with_values`, which returns a new
    one.
    """

    server: str = ""
    domain: str = ""
    base_dn: str = ""
    bind_dn: str = ""
    validate_certificate: bool = True
    snapshot_dir: str = ""
    #: The credential-store service name. Exposed so an operator with more than
    #: one forest can keep the two secrets apart, but defaulted to the value
    #: ``start_server_keychain.sh`` already uses.
    credential_service: str = DEFAULT_SERVICE

    def with_values(self, **changes: Any) -> "ConnectionSettings":
        return replace(self, **changes)

    @property
    def credential_ref(self) -> Optional[CredentialRef]:
        """Which credential-store item holds this password, if there is one.

        ``None`` rather than a raise when the bind account is still blank. A
        fresh install has an empty form, and a *property* that raises in that
        state is a trap: anything that walks this object's attributes — a
        debugger, a serialiser, or pywebview's JS-API generator, which is how
        this was actually found — blows up on an ordinary empty connection.
        """
        if not str(self.bind_dn or "").strip():
            return None
        return CredentialRef(account=self.bind_dn,
                             service=self.credential_service)

    def missing_fields(self) -> Tuple[str, ...]:
        """Which required fields are still blank, in form order.

        Returned rather than raised: the Connection screen wants to say "these
        three fields", not to blow up on the first one.
        """
        required = (("server", "LDAPS server"), ("domain", "Domain"),
                    ("base_dn", "Base DN"), ("bind_dn", "Bind account"))
        return tuple(label for name, label in required
                     if not str(getattr(self, name) or "").strip())

    def resolved_snapshot_dir(self) -> Path:
        """The snapshot directory, defaulted under the app's own directory.

        Defaulted rather than required — unlike the ``write_hardening_snapshot``
        tool, which deliberately has no default because an agent choosing where
        directory content lands is a different risk. Here a human is looking at
        the path on screen and can change it, and an app whose one button fails
        with "output_dir is required" is not an app for someone who does not
        want a terminal.
        """
        raw = str(self.snapshot_dir or "").strip()
        if raw:
            path = Path(os.path.expanduser(raw))
            return path if path.is_absolute() else Path.cwd() / path
        return settings_dir() / SNAPSHOTS_DIRNAME


@dataclass
class AppSettings:
    """The persisted state as a whole. One connection, for now.

    Multi-forest switching is explicitly out of scope for this work package, so
    there is one connection rather than a list — but it is a field on a
    container rather than the top level, so growing to a list later does not
    change the file's shape for everything else.
    """

    connection: ConnectionSettings = field(default_factory=ConnectionSettings)


# --------------------------------------------------------------------------- #
# Reading and writing the server-shaped config file
# --------------------------------------------------------------------------- #

def config_path(directory: Optional[Path] = None) -> Path:
    return (directory or settings_dir()) / CONFIG_FILENAME


def build_config_document(settings: ConnectionSettings) -> Dict[str, Any]:
    """The ``config.json`` contents for these settings.

    A pure function, so the one property that matters most — that the
    ``password`` field is the placeholder and never a secret — is asserted by a
    test without touching a filesystem.

    The OU block is required by :class:`aditor.config.models.Config` and is
    derived from the base DN rather than asked for on the Connection screen:
    the app runs no tool that resolves a default OU (it exposes none of the 22
    write tools), so making an operator type four DNs to run a read-only scan
    would be asking for input that nothing reads.
    """
    base_dn = str(settings.base_dn or "").strip()
    return {
        "_comment": (
            "Written by the ADitor desktop app. The password is NOT stored "
            "here: the field below is a placeholder that the config loader "
            "expands from the AD_MCP_PASSWORD environment variable, and the "
            "secret itself lives in the OS credential store."),
        "active_directory": {
            "server": str(settings.server or "").strip(),
            "use_ssl": True,
            "ssl_port": 636,
            "domain": str(settings.domain or "").strip(),
            "base_dn": base_dn,
            "bind_dn": str(settings.bind_dn or "").strip(),
            # The one line this whole module exists to guarantee.
            "password": CONFIG_PASSWORD_PLACEHOLDER,
            "timeout": 30,
            "auto_bind": True,
            "receive_timeout": 10,
        },
        "organizational_units": {
            "users_ou": f"CN=Users,{base_dn}" if base_dn else "",
            "groups_ou": f"CN=Users,{base_dn}" if base_dn else "",
            "computers_ou": f"CN=Computers,{base_dn}" if base_dn else "",
            "service_accounts_ou": f"CN=Users,{base_dn}" if base_dn else "",
        },
        "security": {
            "enable_tls": True,
            "validate_certificate": bool(settings.validate_certificate),
            "ca_cert_file": None,
            "require_secure_connection": True,
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            # No log file by default. A log file is one more artifact that has
            # to be proven free of the password, and the app has nowhere to
            # show it; the server writes to stderr, which the app captures.
            "file": None,
        },
        "performance": {
            "connection_pool_size": 10,
            # One attempt, not three. The server's own default retries a
            # failed bind three times; against a real domain that turns one
            # wrong password into three failed logons and walks the bind
            # account toward the lockout threshold. An interactive app gets its
            # answer faster from one attempt anyway.
            "max_retries": 1,
            "retry_delay": 1.0,
            "page_size": 1000,
        },
        "aditor_app": {
            "snapshot_dir": str(settings.snapshot_dir or "").strip(),
            "credential_service": settings.credential_service,
            "credential_account": str(settings.bind_dn or "").strip(),
        },
    }


def load_settings(directory: Optional[Path] = None) -> AppSettings:
    """Read the persisted settings, or return the defaults.

    A missing, unreadable or malformed file yields defaults rather than an
    error: the app's first run has no file, and a corrupted one should land the
    operator on an empty Connection screen, not on a stack trace.
    """
    path = config_path(directory)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return AppSettings()
    if not isinstance(document, dict):
        return AppSettings()

    active = document.get("active_directory")
    active = active if isinstance(active, dict) else {}
    security = document.get("security")
    security = security if isinstance(security, dict) else {}
    app_block = document.get("aditor_app")
    app_block = app_block if isinstance(app_block, dict) else {}

    return AppSettings(connection=ConnectionSettings(
        server=str(active.get("server") or ""),
        domain=str(active.get("domain") or ""),
        base_dn=str(active.get("base_dn") or ""),
        bind_dn=str(active.get("bind_dn") or ""),
        validate_certificate=bool(security.get("validate_certificate", True)),
        snapshot_dir=str(app_block.get("snapshot_dir") or ""),
        credential_service=str(app_block.get("credential_service")
                               or DEFAULT_SERVICE),
    ))


class PersistRefused(RuntimeError):
    """Nothing was written, and the message says why.

    Its own type because the Connection screen has to tell these apart from a
    failed *connection*: an operator whose Keychain is unavailable has a
    different problem from one whose password is wrong, and both arrive at the
    same button.
    """


@dataclass(frozen=True)
class PersistResult:
    """What :func:`persist_connection` did, for the screen to report."""

    config_path: Path
    store_name: str
    store_location: str


def persist_connection(settings: ConnectionSettings, password: str,
                       directory: Optional[Path] = None,
                       store: Optional[CredentialStore] = None
                       ) -> PersistResult:
    """Save the connection: the secret to the OS store, the rest to config.json.

    **The credential store goes first, and a refusal there aborts the whole
    save.** Not because the config file would leak anything — it holds the
    placeholder either way — but because the alternative is a config file
    pointing at a credential that does not exist. The app would then start a
    server whose ``${AD_MCP_PASSWORD}`` expands to nothing, and the operator
    would debug an authentication failure instead of reading "there is nowhere
    to keep your password". A save is both halves or neither.

    Raises:
        PersistRefused: required fields are missing, or the OS credential store
            is unavailable or refused. In every case **nothing has been
            written** — not the config file, not a temp file, not a fallback.
    """
    missing = settings.missing_fields()
    if missing:
        raise PersistRefused(
            f"cannot save this connection: {', '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} still empty.")
    if not isinstance(password, str) or not password:
        raise PersistRefused(
            "cannot save this connection without a password. The password is "
            "not kept in the config file, so there is nothing to save without "
            "it — enter it and save again.")

    credential_store = store or get_store()
    ref = settings.credential_ref
    if ref is None:  # pragma: no cover - missing_fields() already caught this
        raise PersistRefused(
            "cannot save this connection without a bind account.")
    try:
        credential_store.require().set_password(ref, password)
    except CredentialStoreUnavailable as exc:
        raise PersistRefused(
            f"{exc} Nothing has been saved.") from exc
    except CredentialStoreError as exc:
        raise PersistRefused(
            f"the password could not be stored in {credential_store.name}: "
            f"{exc} Nothing has been saved — ADitor does not write the "
            f"password to a file as a fallback.") from exc

    target_dir = directory or settings_dir()
    path = config_path(target_dir)
    document = build_config_document(settings)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(target_dir, _DIR_MODE)
        except OSError:
            # A filesystem that does not do POSIX modes (a Windows one) is
            # fine; the directory is already under the user's profile.
            pass
        path.write_text(json.dumps(document, indent=2) + "\n",
                        encoding="utf-8")
        try:
            os.chmod(path, _CONFIG_MODE)
        except OSError:
            pass
    except OSError as exc:
        raise PersistRefused(
            f"the password was stored in {credential_store.name}, but the "
            f"settings file {path} could not be written: {exc}") from exc

    return PersistResult(config_path=path,
                         store_name=credential_store.name,
                         store_location=credential_store.where)


def load_password(settings: ConnectionSettings,
                  store: Optional[CredentialStore] = None) -> Optional[str]:
    """The stored password for this connection, or ``None`` if there is none.

    Raises :class:`aditor.app.credentials.CredentialStoreError` if the store is
    there but unreadable, which the caller must not treat as "no password
    saved" — see :meth:`CredentialStore.get_password`.
    """
    ref = settings.credential_ref
    if ref is None:
        return None
    credential_store = store or get_store()
    if not credential_store.available():
        return None
    return credential_store.get_password(ref)


__all__ = [
    "APP_DIR_NAME",
    "CONFIG_FILENAME",
    "SNAPSHOTS_DIRNAME",
    "AppSettings",
    "ConnectionSettings",
    "PersistRefused",
    "PersistResult",
    "build_config_document",
    "config_path",
    "load_password",
    "load_settings",
    "persist_connection",
    "settings_dir",
]
