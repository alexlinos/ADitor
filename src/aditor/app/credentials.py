"""The OS credential store, behind one small platform abstraction.

**The password is never written to disk by ADitor.** Not to the app's own
config, not to a temp file, not to a log. It lives in the operating system's
credential store — Windows Credential Manager (DPAPI-backed) on Windows, the
login Keychain on macOS — and is read back into memory at the moment it is
needed.

This is not a new scheme. ``scan_keychain.sh`` already established the
pattern this module generalises:

* the config file's ``password`` field holds the literal
  ``${AD_MCP_PASSWORD}`` placeholder (:data:`CONFIG_PASSWORD_PLACEHOLDER`),
  which :func:`aditor.config.loader.load_config` expands from the environment;
* the secret is fetched from the OS store at runtime and put in
  ``AD_MCP_PASSWORD`` (:data:`PASSWORD_ENV_VAR`) only for the process that needs
  it;
* the default service name is ``admcp-ldap``, the same one the script uses, so
  an operator who set the Keychain item up by hand does not have a second,
  competing item.

**If the store is unavailable, this module raises.** It never falls back to a
file. A silent fallback is the failure mode that matters here: the operator
would believe the secret is in the OS store, and it would be sitting in
plaintext in a JSON file. :class:`CredentialStoreUnavailable` is raised instead,
and :mod:`aditor.app.settings` turns that into a visible refusal to persist
*anything* — see :func:`aditor.app.settings.persist_connection`.

The Windows implementation calls ``CredWriteW``/``CredReadW``/``CredDeleteW``
through :mod:`ctypes`, so the GUI extra stays a single dependency
(``pywebview``) and no credential library is pulled in. The macOS
implementation shells out to ``security``, and **passes the secret on stdin,
never in ``argv``** — anything in ``argv`` is world-readable through ``ps``.

Log redaction
-------------

No call site in this package passes a password to the logging module, and a
test asserts that. :class:`SecretRedactingFilter` is the belt to that braces:
:func:`register_secret` hands a live secret to a filter that
:func:`install_redaction` wires into the log-record factory, so even a future
edit that logs the wrong variable emits ``***REDACTED***`` — on any logger, at
any depth. This mirrors the discipline in :mod:`aditor.hardening.report`, where
every value goes through one escaper so no later edit can open a hole.

Only the desktop app installs it. ``aditor scan`` does not import this module,
so its logging behaviour is unchanged.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

# The environment variable the config loader expands, and the placeholder that
# stands in for the password inside a config file. Both are fixed by
# ``scan_keychain.sh`` and the patched loader; this module does not get
# to pick new ones.
PASSWORD_ENV_VAR = "AD_MCP_PASSWORD"
CONFIG_PASSWORD_PLACEHOLDER = "${" + PASSWORD_ENV_VAR + "}"

# The credential-store service name. Same default as
# ``ADMCP_KEYCHAIN_SERVICE`` in ``scan_keychain.sh``, so the app and the
# script read the same item rather than each keeping their own copy.
DEFAULT_SERVICE = "admcp-ldap"

# What a redacted secret looks like in a log line. Deliberately loud: a reader
# should be able to tell that something was removed, not wonder whether the
# field was empty.
REDACTED = "***REDACTED***"


class CredentialStoreError(RuntimeError):
    """The credential store exists but the operation failed.

    A wrong Keychain ACL, a locked keychain, a Credential Manager error. The
    store is there; this particular call did not work. The message carries the
    platform tool's own words, because "could not save the password" tells an
    operator nothing about which of those it was.
    """


class CredentialStoreUnavailable(CredentialStoreError):
    """There is no OS credential store to use on this platform.

    Raised rather than falling back to a file. The caller's job is to say so and
    refuse to persist — see :func:`aditor.app.settings.persist_connection`.
    """


@dataclass(frozen=True)
class CredentialRef:
    """Which secret: a service name and an account, as both stores model it.

    The pair, not just a service name, because one machine can legitimately hold
    a credential for more than one bind account — a per-forest read-only
    account, say — and a service-only key would let the second overwrite the
    first.
    """

    account: str
    service: str = DEFAULT_SERVICE

    def __post_init__(self) -> None:
        if not isinstance(self.account, str) or not self.account.strip():
            raise ValueError(
                "a credential reference needs an account name: the bind "
                "account the password belongs to. Without it the two stores "
                "have nothing to key the item on.")
        if not isinstance(self.service, str) or not self.service.strip():
            raise ValueError("a credential reference needs a service name")

    @property
    def target(self) -> str:
        """``service:account`` — the Windows Credential Manager target name.

        A pure function of the ref so it can be asserted in a test on any
        platform, which is the only way the Windows naming gets covered from a
        Mac.
        """
        return f"{self.service.strip()}:{self.account.strip()}"


# --------------------------------------------------------------------------- #
# The abstraction
# --------------------------------------------------------------------------- #

class CredentialStore(ABC):
    """One platform's credential store.

    Four operations and a name. Deliberately no "store this somewhere" method:
    every implementation is a real OS store or it is
    :class:`NoCredentialStore`, which refuses.
    """

    #: Short name for the UI — "Windows Credential Manager", "macOS Keychain".
    name: str = "credential store"

    #: One line telling the operator where the secret actually goes.
    where: str = ""

    @abstractmethod
    def available(self) -> bool:
        """Whether this store can be used on this machine right now."""

    @abstractmethod
    def set_password(self, ref: CredentialRef, password: str) -> None:
        """Store (or replace) the secret. Raises rather than half-succeeding."""

    @abstractmethod
    def get_password(self, ref: CredentialRef) -> Optional[str]:
        """The stored secret, or ``None`` if there is no such item.

        ``None`` means "no item"; a :class:`CredentialStoreError` means "there
        is a store, an item may well exist, and reading it failed". A caller
        that conflated the two would tell the operator to re-enter a password
        that is sitting there fine behind a locked keychain.
        """

    @abstractmethod
    def delete_password(self, ref: CredentialRef) -> bool:
        """Remove the item. ``False`` if there was nothing to remove."""

    def require(self) -> "CredentialStore":
        """Return self, or raise :class:`CredentialStoreUnavailable`."""
        if not self.available():
            raise CredentialStoreUnavailable(self.unavailable_reason())
        return self

    def unavailable_reason(self) -> str:
        """Why this store cannot be used, in words for the operator.

        Public because the Connection screen shows it *before* anything is
        attempted: an operator on an unsupported platform should learn that
        saving is impossible from the screen, not from a failed save.
        """
        return (f"{self.name} is not available on this machine, so there is "
                f"nowhere to keep the password that is not a plaintext file. "
                f"ADitor will not write the password to disk, so it cannot "
                f"save this connection.")


# --------------------------------------------------------------------------- #
# Windows — Credential Manager (DPAPI) through ctypes
# --------------------------------------------------------------------------- #

# Generic credential, persisted for this user on this machine. Not
# CRED_PERSIST_ENTERPRISE: an AD bind password should not roam to every machine
# the operator logs into.
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168


def encode_windows_blob(password: str) -> bytes:
    """The credential blob Credential Manager stores, as bytes.

    UTF-16LE with no BOM and no terminator — what every Windows tool expects to
    find in ``CredentialBlob``, and what :func:`decode_windows_blob` reverses.
    Split out as a pure function so the encoding is covered by a test on any
    platform: the ctypes calls around it cannot run off Windows, but getting
    the encoding wrong is the mistake that would actually happen.
    """
    if not isinstance(password, str):
        raise TypeError("a password must be a string")
    return password.encode("utf-16-le")


def decode_windows_blob(blob: bytes) -> str:
    """Reverse :func:`encode_windows_blob`, tolerating an odd trailing byte.

    A blob written by another tool can carry a UTF-16 NUL terminator; an odd
    length would make ``decode`` raise, so the byte count is truncated to an
    even one and any trailing NULs are stripped. Returning a mangled password is
    not a risk worth guarding against here — the bind simply fails and the
    operator re-enters it — whereas raising on a credential another tool wrote
    would look like "no password stored".
    """
    usable = bytes(blob)[: len(blob) - (len(blob) % 2)]
    return usable.decode("utf-16-le", errors="replace").rstrip("\x00")


class WindowsCredentialManagerStore(CredentialStore):
    """Windows Credential Manager, via ``advapi32`` ``Cred*W``.

    Credential Manager encrypts a generic credential's blob with DPAPI under the
    calling user's profile, which is exactly the property wanted: another user
    on the same machine cannot read it, and it never exists as plaintext on
    disk.

    ``ctypes`` rather than a credential package on purpose. The GUI extra is one
    dependency (``pywebview``); adding a second to write four fields into a
    documented Win32 struct would be a poor trade, and Phase 1 spent a work
    package removing dependencies that earned less than this.
    """

    name = "Windows Credential Manager"
    where = (r"Control Panel > Credential Manager > Windows Credentials, "
             r"as a generic credential. The secret is encrypted with DPAPI "
             r"under your Windows profile.")

    def available(self) -> bool:
        if not sys.platform.startswith("win"):
            return False
        return self._advapi32() is not None

    @staticmethod
    def _advapi32():  # type: ignore[no-untyped-def]
        """The ``advapi32`` handle, or ``None`` off Windows.

        Imported inside the method so this module imports cleanly on macOS and
        Linux — ``ctypes.windll`` does not exist there, and a module that cannot
        be imported cannot be unit-tested.
        """
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:  # pragma: no cover - exercised only off Windows
            return None
        try:
            return windll.advapi32
        except OSError:  # pragma: no cover - defensive
            return None

    @staticmethod
    def _structures():  # type: ignore[no-untyped-def]
        """Build the ``CREDENTIALW`` structures. Windows only."""
        import ctypes
        from ctypes import wintypes

        class CredentialAttribute(ctypes.Structure):
            _fields_ = [
                ("Keyword", wintypes.LPWSTR),
                ("Flags", wintypes.DWORD),
                ("ValueSize", wintypes.DWORD),
                ("Value", ctypes.POINTER(ctypes.c_char)),
            ]

        class Credential(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.POINTER(CredentialAttribute)),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        return ctypes, Credential

    def set_password(self, ref: CredentialRef, password: str) -> None:
        self.require()
        ctypes_mod, credential_type = self._structures()
        blob = encode_windows_blob(password)
        buffer = ctypes_mod.create_string_buffer(blob, len(blob))

        credential = credential_type()
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = ref.target
        credential.UserName = ref.account
        credential.Comment = "ADitor LDAP bind password"
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes_mod.cast(
            buffer, ctypes_mod.POINTER(ctypes_mod.c_char))
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE

        if not self._advapi32().CredWriteW(ctypes_mod.byref(credential), 0):
            raise CredentialStoreError(
                f"Windows Credential Manager refused to store the password "
                f"for {ref.target!r}: {self._last_error()}. Nothing was "
                f"written to disk.")

    def get_password(self, ref: CredentialRef) -> Optional[str]:
        self.require()
        import ctypes

        ctypes_mod, credential_type = self._structures()
        pointer = ctypes_mod.POINTER(credential_type)()
        advapi32 = self._advapi32()
        if not advapi32.CredReadW(ref.target, _CRED_TYPE_GENERIC, 0,
                                  ctypes_mod.byref(pointer)):
            code = ctypes.get_last_error() if hasattr(
                ctypes, "get_last_error") else 0
            if code == _ERROR_NOT_FOUND:
                return None
            # An unreadable-but-present credential is not "no password": say so
            # rather than sending the operator to re-enter one that is there.
            raise CredentialStoreError(
                f"Windows Credential Manager could not read the password for "
                f"{ref.target!r}: {self._last_error()}")
        try:
            credential = pointer.contents
            size = int(credential.CredentialBlobSize)
            if size <= 0:
                return None
            raw = ctypes_mod.string_at(credential.CredentialBlob, size)
            return decode_windows_blob(raw)
        finally:
            advapi32.CredFree(pointer)

    def delete_password(self, ref: CredentialRef) -> bool:
        self.require()
        if not self._advapi32().CredDeleteW(ref.target, _CRED_TYPE_GENERIC, 0):
            return False
        return True

    @staticmethod
    def _last_error() -> str:
        import ctypes

        try:
            return ctypes.FormatError(ctypes.get_last_error())  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover - defensive
            return "unknown Windows error"


# --------------------------------------------------------------------------- #
# macOS — the login Keychain through /usr/bin/security
# --------------------------------------------------------------------------- #

_SECURITY = "/usr/bin/security"


class MacOSKeychainStore(CredentialStore):
    """The macOS login Keychain, via ``/usr/bin/security``.

    The same service name and the same tool ``scan_keychain.sh`` uses,
    so an operator who already ran::

        security add-generic-password -s admcp-ldap -a 'DOMAIN\\binduser' -w

    is not asked to set the password up a second time.

    **The secret goes in on stdin, never in ``argv``.** ``security
    add-generic-password -w`` with no value reads the password from standard
    input (twice, to confirm), which keeps it out of ``ps`` output and out of
    the process table. Passing ``-w <password>`` would be shorter and would
    publish the domain bind password to every user on the machine.
    """

    name = "macOS Keychain"
    where = ("your login keychain, under the generic-password service "
             f"{DEFAULT_SERVICE!r}. Keychain Access shows it; the secret is "
             "encrypted by macOS and ADitor never copies it to disk.")

    def available(self) -> bool:
        if sys.platform != "darwin":
            return False
        return bool(shutil.which(_SECURITY) or shutil.which("security"))

    @staticmethod
    def _security() -> str:
        return shutil.which(_SECURITY) or shutil.which("security") or _SECURITY

    def set_password(self, ref: CredentialRef, password: str) -> None:
        self.require()
        # ``-U`` updates an existing item rather than failing on a duplicate,
        # which is what a password rotation needs. ``-w`` last with no value is
        # what makes ``security`` read the secret from stdin.
        completed = self._run(
            [self._security(), "add-generic-password", "-U",
             "-s", ref.service, "-a", ref.account,
             "-D", "ADitor LDAP bind password", "-w"],
            stdin=f"{password}\n{password}\n")
        if completed.returncode != 0:
            detail = (_first_line(completed.stderr)
                      or f"security exited {completed.returncode}")
            raise CredentialStoreError(
                f"the macOS Keychain refused to store the password: {detail}. "
                f"Nothing was written to disk.")

    def get_password(self, ref: CredentialRef) -> Optional[str]:
        self.require()
        completed = self._run(
            [self._security(), "find-generic-password",
             "-s", ref.service, "-a", ref.account, "-w"])
        if completed.returncode == 0:
            # ``-w`` prints the password and a newline, and nothing else.
            return completed.stdout.rstrip("\n")
        stderr = completed.stderr or ""
        if "could not be found" in stderr or "SecKeychainSearchCopyNext" in stderr:
            return None
        detail = (_first_line(stderr)
                  or f"security exited {completed.returncode}")
        raise CredentialStoreError(
            f"the macOS Keychain could not be read: {detail}")

    def delete_password(self, ref: CredentialRef) -> bool:
        self.require()
        completed = self._run(
            [self._security(), "delete-generic-password",
             "-s", ref.service, "-a", ref.account])
        return completed.returncode == 0

    @staticmethod
    def _run(argv: list, stdin: Optional[str] = None
             ) -> "subprocess.CompletedProcess":
        """Run ``security``, capturing both streams.

        ``check=False``: the exit code is part of the answer here (an absent
        item is a non-zero exit, not an exception), and a raising call would
        also put the stderr — which can echo the item's attributes — into a
        traceback.
        """
        try:
            return subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv, input=stdin, capture_output=True, text=True, check=False)
        except OSError as exc:
            raise CredentialStoreError(
                f"could not run the macOS 'security' tool: {exc}") from exc


# --------------------------------------------------------------------------- #
# Everywhere else — a store that refuses, loudly
# --------------------------------------------------------------------------- #

class NoCredentialStore(CredentialStore):
    """No OS credential store on this platform: every write refuses.

    This is the class that makes "say so and refuse to persist" structural
    rather than a thing every caller has to remember. There is no file-backed
    implementation in this module to fall back to, by design.
    """

    name = "no OS credential store"

    def __init__(self, platform: Optional[str] = None) -> None:
        self._platform = platform or sys.platform
        self.where = ""

    def available(self) -> bool:
        return False

    def set_password(self, ref: CredentialRef, password: str) -> None:
        raise CredentialStoreUnavailable(self.unavailable_reason())

    def get_password(self, ref: CredentialRef) -> Optional[str]:
        raise CredentialStoreUnavailable(self.unavailable_reason())

    def delete_password(self, ref: CredentialRef) -> bool:
        raise CredentialStoreUnavailable(self.unavailable_reason())

    def unavailable_reason(self) -> str:
        return (
            f"ADitor has no OS credential store on {self._platform!r}: it "
            f"supports Windows Credential Manager and the macOS Keychain. It "
            f"will not write the LDAP bind password to a file instead, so this "
            f"connection cannot be saved. You can still test the connection "
            f"and run a scan by entering the password each time, or run "
            f"`aditor scan` with the password supplied in {PASSWORD_ENV_VAR}.")


def get_store(platform: Optional[str] = None) -> CredentialStore:
    """The credential store for this platform.

    ``platform`` is injectable so the Windows and the unsupported-platform
    branches are both reachable from a test on a Mac. It selects the *class*;
    each class still checks that it can actually run here, so asking for the
    Windows store on Linux gets an object whose ``available()`` is ``False``
    rather than one that pretends.
    """
    name = platform or sys.platform
    if name.startswith("win"):
        return WindowsCredentialManagerStore()
    if name == "darwin":
        return MacOSKeychainStore()
    return NoCredentialStore(name)


class SecretRedactingFilter(logging.Filter):
    """Replace any registered secret with :data:`REDACTED` in every record.

    A backstop, not the mechanism: nothing in this package passes a password to
    a logging call, and ``tests/test_app_password_never_leaks.py`` asserts it.
    This filter is what keeps that true after a future edit — the same reasoning
    as the single escaper in :mod:`aditor.hardening.report`.

    Both ``msg`` and ``args`` are scrubbed, because ``logger.info("bind %s",
    password)`` puts the secret in ``args`` and formatting happens later, inside
    the handler.
    """

    def __init__(self) -> None:
        super().__init__()
        self._secrets: set = set()

    def add(self, secret: str) -> None:
        if isinstance(secret, str) and secret:
            self._secrets.add(secret)

    def discard(self, secret: str) -> None:
        self._secrets.discard(secret)

    def clear(self) -> None:
        self._secrets.clear()

    def scrub(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._secrets:
            return True
        if isinstance(record.msg, str):
            record.msg = self.scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {key: self._scrub_any(value)
                               for key, value in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._scrub_any(value)
                                    for value in record.args)
        return True

    def _scrub_any(self, value):  # type: ignore[no-untyped-def]
        return self.scrub(value) if isinstance(value, str) else value


#: The one filter instance, so ``register_secret`` and the handler agree.
_FILTER = SecretRedactingFilter()

#: Logger names the filter is attached to directly. ``aditor`` covers every
#: module in this package; ``ldap3`` is here because it is the library actually
#: handed the password, and its debug logging is the one place outside our code
#: that could emit it.
_REDACTED_LOGGERS = ("aditor", "ldap3", "smbprotocol")

#: The log-record factory in place before :func:`install_redaction` wrapped it.
_ORIGINAL_RECORD_FACTORY: Any = None


def install_redaction() -> SecretRedactingFilter:
    """Scrub registered secrets out of every log record, wherever it is made.

    Redaction is installed at **record creation** rather than only as a filter
    on a few named loggers, because a ``logging.Filter`` on a logger is *not*
    applied to records that propagate up from its children — only handler-level
    filters are. So attaching the filter to ``aditor`` would miss
    ``aditor.anything.new``, which is exactly the future edit this backstop is
    for. Wrapping ``logging.getLogRecordFactory`` catches every record in the
    process regardless of logger and handler topology.

    The filters on the named loggers are kept as a second layer for anything
    that constructs a :class:`logging.LogRecord` directly rather than through
    the factory.

    This mutates process-global logging state, so it is called **only from the
    desktop app** (:class:`aditor.app.api.AditorApi` and
    :func:`register_secret`). ``aditor scan`` never reaches this module and
    its logging is untouched. With no secret registered the scrub is a
    single empty-set check per record.

    Idempotent — calling it twice does not double-wrap or double-filter.
    """
    global _ORIGINAL_RECORD_FACTORY

    for name in _REDACTED_LOGGERS:
        logger = logging.getLogger(name)
        if _FILTER not in logger.filters:
            logger.addFilter(_FILTER)
        for handler in logger.handlers:
            if _FILTER not in handler.filters:
                handler.addFilter(_FILTER)

    if _ORIGINAL_RECORD_FACTORY is None:
        _ORIGINAL_RECORD_FACTORY = logging.getLogRecordFactory()

        def redacting_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = _ORIGINAL_RECORD_FACTORY(*args, **kwargs)
            _FILTER.filter(record)
            return record

        logging.setLogRecordFactory(redacting_factory)

    return _FILTER


def register_secret(secret: str) -> None:
    """Register a live secret with the redaction filter."""
    install_redaction()
    _FILTER.add(secret)


def forget_secret(secret: str) -> None:
    """Stop redacting a secret that is no longer live."""
    _FILTER.discard(secret)


def redact(text: str) -> str:
    """Scrub every registered secret out of ``text``.

    Used on anything that came from outside and is about to be shown to the
    operator — an LDAP error string, a subprocess's stderr. ldap3 does not put
    the bind password in its error text, but "does not today" is not a property
    to render a page on.
    """
    if not isinstance(text, str):
        return text
    return _FILTER.scrub(text)


def _first_line(text: Optional[str]) -> str:
    """The first non-empty line of a tool's stderr, redacted."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return redact(stripped)
    return ""


__all__ = [
    "CONFIG_PASSWORD_PLACEHOLDER",
    "DEFAULT_SERVICE",
    "PASSWORD_ENV_VAR",
    "REDACTED",
    "CredentialRef",
    "CredentialStore",
    "CredentialStoreError",
    "CredentialStoreUnavailable",
    "MacOSKeychainStore",
    "NoCredentialStore",
    "SecretRedactingFilter",
    "WindowsCredentialManagerStore",
    "decode_windows_blob",
    "encode_windows_blob",
    "forget_secret",
    "get_store",
    "install_redaction",
    "redact",
    "register_secret",
]
