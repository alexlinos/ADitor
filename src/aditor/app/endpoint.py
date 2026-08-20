"""The MCP endpoint, the config snippets generated from it, and its exposure.

Three things live here, and they are one thing really: **the app knows its own
endpoint, so nothing about the endpoint is ever written out as prose.**

1. :class:`Endpoint` — host, port and path, with :meth:`Endpoint.url` producing
   the client URL. It appends **exactly one trailing slash**, because the
   server mounts the MCP app with Starlette's ``Mount`` and a request to the
   bare path 307-redirects. A hand-copied URL gets this wrong routinely, and
   the failure mode is a client that connects and then behaves oddly rather
   than one that says "you missed a slash". ``REPLATFORM_BRIEF.md`` §8 calls it
   out for the same reason.
2. :func:`claude_code_snippet` / :func:`codex_snippet` — the client config,
   built from an :class:`Endpoint` with :func:`json.dumps` and a TOML f-string.
   Never a hard-coded string with the port in it: a snippet that can drift from
   the server it describes is a snippet that will.
3. :func:`assess_exposure` — whether this endpoint is reachable only from this
   machine, and what it costs to make it reachable from another one.

On (3): the MCP endpoint today has **no authentication and no TLS**, and the
bind account is a privileged directory credential. Anything that can reach the
port can drive the whole tool set — including the 22 write tools the *app* does
not expose but the *server* does. ``docs/REPLATFORM_BRIEF.md`` §8 records
endpoint auth + TLS (WP6) as a hard gate before any non-localhost deployment,
and this module's job is to make the UI say the same thing rather than present
"open the port" as routine setup. Hence :data:`DEFAULT_HOST` is loopback: the
safe posture is what happens when nobody changes anything, and exposing the
endpoint is a deliberate act with the warning attached.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..server import DEFAULT_PATH, DEFAULT_PORT
from .credentials import (
    CONFIG_PASSWORD_PLACEHOLDER,
    PASSWORD_ENV_VAR,
    password_environment,
    redact,
)

#: Loopback, not the server's own ``0.0.0.0`` default. The app is for a person
#: at a keyboard whose MCP client is almost always on the same machine; binding
#: everywhere by default would put an unauthenticated privileged AD API on the
#: network as the *out-of-the-box* behaviour of a GUI. See the module docstring.
DEFAULT_HOST = "127.0.0.1"

#: The name a client should dial. ``0.0.0.0`` is a bind address, not a
#: destination, so a snippet must never contain it.
_WILDCARD_HOSTS = {"0.0.0.0", "::", "[::]", "*", ""}

#: The MCP server name the snippets use. One name, both clients, so an operator
#: reading two config files sees the same server twice.
SERVER_KEY = "aditor"


@dataclass(frozen=True)
class Endpoint:
    """Where the MCP server listens, and where a client should dial.

    Bind address and client address are separate questions and this class keeps
    them separate: :attr:`host` is what the server binds, :meth:`client_host` is
    what goes in a snippet.
    """

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    path: str = DEFAULT_PATH

    def normalised_path(self) -> str:
        """The mount path with one leading slash and no trailing slash."""
        raw = str(self.path or DEFAULT_PATH).strip()
        raw = raw.strip("/")
        return "/" + raw if raw else ""

    def client_host(self) -> str:
        """The host a client should connect to.

        A wildcard bind becomes ``localhost``: it means "every interface", and
        the interface a same-machine client uses is the loopback one. Bare IPv6
        gets bracketed, because ``http://::1:8813/`` is not a URL.
        """
        raw = str(self.host or "").strip()
        if raw.lower() in _WILDCARD_HOSTS:
            return "localhost"
        if raw.startswith("[") and raw.endswith("]"):
            return raw
        try:
            if isinstance(ipaddress.ip_address(raw), ipaddress.IPv6Address):
                return f"[{raw}]"
        except ValueError:
            pass
        return raw

    def url(self) -> str:
        """The client URL, **with the required trailing slash**.

        The one function every snippet goes through. Built rather than written
        down: the trailing slash is not decoration, it is what stops the client
        taking a 307 on every request.
        """
        return f"http://{self.client_host()}:{int(self.port)}" \
               f"{self.normalised_path()}/"

    def bind_description(self) -> str:
        return f"{self.host}:{int(self.port)}"

    def is_loopback(self) -> bool:
        """Whether this bind accepts connections only from this machine.

        ``localhost`` and any address in ``127.0.0.0/8`` or ``::1`` are
        loopback. A wildcard bind is **not** — it accepts from everywhere, which
        is the case the warning exists for.
        """
        raw = str(self.host or "").strip().lower()
        if raw in _WILDCARD_HOSTS:
            return False
        if raw in {"localhost", "localhost."}:
            return True
        try:
            return ipaddress.ip_address(raw.strip("[]")).is_loopback
        except ValueError:
            # A host name that is not an IP literal and not "localhost". It may
            # resolve to a loopback address, but the app cannot know that
            # without resolving it, and guessing "safe" would be the wrong way
            # to be wrong. Treat it as exposed.
            return False


# --------------------------------------------------------------------------- #
# Exposure — same box, or on the network?
# --------------------------------------------------------------------------- #

#: The standing warning. Attached to *every* description of remote access, and
#: worded to agree with ``REPLATFORM_BRIEF.md`` §8 rather than to soften it.
EXPOSURE_WARNING = (
    "The MCP endpoint has no authentication and no TLS, and the account it "
    "binds with can read the whole directory. Anything that can reach this "
    "port can drive every tool the server exposes — including the 22 tools "
    "that write to Active Directory, which this app does not show but the "
    "server still serves. Exposing the port puts an unauthenticated, "
    "privileged Active Directory API on the network. Endpoint authentication "
    "and TLS are planned work and are not in this build, so treat a network "
    "binding as a temporary, deliberately-scoped exception rather than as "
    "normal setup.")

#: What to do instead. Named as the recommendation, not as an alternative.
EXPOSURE_RECOMMENDATION = (
    "Recommended: leave the server bound to loopback and run your MCP client "
    "on this same machine. If the client is on another machine, forward the "
    "port over SSH or an existing VPN and still bind loopback here — the "
    "traffic is then authenticated and encrypted by the tunnel, and nothing "
    "new is listening on the network.")

_SAME_BOX_NOTE = (
    "This server is bound to loopback, so it accepts connections only from "
    "this machine. Your MCP client must run here too. No firewall change is "
    "needed, and nothing is listening on the network.")

_REMOTE_NOTE = (
    "This server is bound to an address other than loopback, so a client on "
    "another machine can reach it once the port is open. That is the case the "
    "warning below is about.")


def firewall_command(endpoint: Endpoint,
                     client_addresses: str = "10.0.0.25") -> str:
    """The PowerShell rule to allow the client in — **scoped to a source**.

    ``-RemoteAddress`` is the point of this function. ``New-NetFirewallRule``
    without it defaults to ``Any``, which opens a privileged unauthenticated AD
    API to the entire network the host sits on. The generated command therefore
    always carries a ``-RemoteAddress``, with a placeholder address the operator
    replaces — a command they have to edit before it works is better than one
    that works and is wrong.
    """
    return (
        "New-NetFirewallRule -DisplayName \"ADitor MCP (scoped)\" "
        "-Direction Inbound -Action Allow -Protocol TCP "
        f"-LocalPort {int(endpoint.port)} "
        f"-RemoteAddress {client_addresses} -Profile Domain")


@dataclass(frozen=True)
class ExposureAssessment:
    """Whether this endpoint is same-machine-only, and what remote costs.

    ``warning`` is populated **whenever the bind is not loopback**, and a test
    pins that. This is exactly the copy that gets tidied away in a later
    refactor for being wordy.
    """

    loopback: bool
    headline: str
    detail: str
    warning: str = ""
    recommendation: str = ""
    firewall_command: str = ""
    firewall_note: str = ""


def assess_exposure(endpoint: Endpoint) -> ExposureAssessment:
    """State which case applies — same box, or reachable from the network.

    Both branches carry the recommendation; only the exposed branch carries the
    warning and the firewall command, because a loopback bind needs no firewall
    change and telling someone to open a port they do not need to open is how
    ports get opened.
    """
    if endpoint.is_loopback():
        return ExposureAssessment(
            loopback=True,
            headline="Same machine only — no firewall change needed.",
            detail=_SAME_BOX_NOTE,
            recommendation=EXPOSURE_RECOMMENDATION)

    return ExposureAssessment(
        loopback=False,
        headline=f"Reachable from other machines — {endpoint.bind_description()} "
                 f"is not loopback.",
        detail=_REMOTE_NOTE,
        warning=EXPOSURE_WARNING,
        recommendation=EXPOSURE_RECOMMENDATION,
        firewall_command=firewall_command(endpoint),
        firewall_note=(
            "If it must be remote, allow only the machine that runs your MCP "
            "client. Replace the address after -RemoteAddress with that "
            "machine's address (a single address, or a narrow range) and run "
            "the command in an elevated PowerShell prompt on this host. Do not "
            "leave -RemoteAddress as Any, and do not omit it — the default is "
            "Any, which admits the whole network."))


# --------------------------------------------------------------------------- #
# The generated client snippets
# --------------------------------------------------------------------------- #

#: Where each client keeps its config on Windows, and the numbered steps. Both
#: are data rather than prose in a template so the renderer cannot get one
#: client's file path onto the other client's card.
CLAUDE_CODE_CONFIG_LOCATIONS = (
    r"Per project: .mcp.json in the folder you open Claude Code in "
    r"(check this one in to share it with the team).",
    r"For your user, all projects: %USERPROFILE%\.claude.json",
)

CODEX_CONFIG_LOCATIONS = (
    r"%USERPROFILE%\.codex\config.toml  (create the .codex folder if it is "
    r"not there)",
)


def claude_code_snippet(endpoint: Endpoint,
                        server_key: str = SERVER_KEY) -> str:
    """The Claude Code MCP entry, as JSON, built from the live endpoint."""
    document = {
        "mcpServers": {
            server_key: {
                "type": "http",
                "url": endpoint.url(),
            }
        }
    }
    return json.dumps(document, indent=2)


def claude_code_command(endpoint: Endpoint,
                        server_key: str = SERVER_KEY) -> str:
    """The one-line equivalent, for an operator who would rather not edit JSON."""
    return (f"claude mcp add --transport http {server_key} "
            f"{endpoint.url()}")


def codex_snippet(endpoint: Endpoint, server_key: str = SERVER_KEY) -> str:
    """The Codex CLI MCP entry, as TOML, built from the live endpoint.

    Codex reads ``~/.codex/config.toml`` and takes a streamable-HTTP server as a
    ``url`` under ``[mcp_servers.<name>]``. The URL is the same
    :meth:`Endpoint.url` the Claude Code snippet uses — same trailing slash,
    same source — so the two snippets cannot disagree about where the server is.
    """
    return (f"[mcp_servers.{server_key}]\n"
            f'url = "{endpoint.url()}"\n')


def snippets(endpoint: Endpoint, server_key: str = SERVER_KEY
             ) -> Dict[str, Any]:
    """Everything the Connect screen needs, keyed by client.

    Returned as data rather than rendered here so :mod:`aditor.app.render` owns
    every bit of escaping, and so a test can assert on the URL without going
    through HTML.
    """
    url = endpoint.url()
    return {
        "url": url,
        "trailing_slash": url.endswith("/"),
        "claude_code": {
            "label": "Claude Code",
            "format": "json",
            "snippet": claude_code_snippet(endpoint, server_key),
            "command": claude_code_command(endpoint, server_key),
            "locations": list(CLAUDE_CODE_CONFIG_LOCATIONS),
            "steps": [
                "Make sure the server above says Running. The snippet points "
                "at it, so a stopped server means Claude Code will fail to "
                "connect.",
                "Open (or create) one of the config files listed below.",
                "Paste the JSON. If the file already has an \"mcpServers\" "
                "block, add the \"" + server_key + "\" entry inside it rather "
                "than adding a second block.",
                "Save the file and restart Claude Code.",
                "Run /mcp in Claude Code. \"" + server_key + "\" should be "
                "listed as connected.",
            ],
        },
        "codex": {
            "label": "Codex",
            "format": "toml",
            "snippet": codex_snippet(endpoint, server_key),
            "command": "",
            "locations": list(CODEX_CONFIG_LOCATIONS),
            "steps": [
                "Make sure the server above says Running.",
                r"Open (or create) %USERPROFILE%\.codex\config.toml.",
                "Paste the TOML at the end of the file. TOML section headers "
                "are unique, so if a [mcp_servers." + server_key + "] section "
                "already exists, replace it rather than adding a second.",
                "Save the file and restart Codex.",
            ],
        },
        "trailing_slash_note": (
            "The URL ends in a slash and it has to. The server mounts the MCP "
            "endpoint as a sub-application, so a request to the address "
            "without the trailing slash is answered with a 307 redirect "
            "instead of the endpoint. This snippet was generated from the "
            "running server's own host, port and path, so it cannot drift and "
            "the slash cannot go missing — use Copy rather than retyping it."),
    }


# --------------------------------------------------------------------------- #
# Starting and stopping the server
# --------------------------------------------------------------------------- #

def port_is_in_use(host: str, port: int, timeout: float = 0.4) -> bool:
    """Whether something is already listening there.

    Checked before every start, and the reason is not politeness: an operator
    may already be running ``aditor.server`` from a shell on this port — the
    documented way to run it before this app existed. Binding over it is
    impossible, and *stopping* it is not the app's business. So the app refuses
    to start and says what it found, rather than producing uvicorn's
    "address already in use" traceback in a window with no console.
    """
    target = "127.0.0.1" if str(host).strip() in _WILDCARD_HOSTS else str(host)
    target = target.strip("[]")
    for family, socktype, proto, _canon, address in _addresses(target, port):
        try:
            with socket.socket(family, socktype, proto) as probe:
                probe.settimeout(timeout)
                if probe.connect_ex(address) == 0:
                    return True
        except OSError:
            continue
    return False


def _addresses(host: str, port: int) -> List[Any]:
    try:
        return socket.getaddrinfo(host, int(port), 0, socket.SOCK_STREAM)
    except OSError:
        return []


class ServerControlError(RuntimeError):
    """The server could not be started or stopped, with the reason."""


@dataclass
class ServerProcess:
    """The headless MCP server, as a child process.

    A **subprocess**, not a thread. ``aditor.server`` serves HTTP through
    ``uvicorn.run``, which installs its own signal handlers and blocks; there is
    no clean way to stop that from inside the GUI process, and a Stop button
    that does not stop things is worse than no Stop button. A child process can
    be terminated, its exit observed, and its stderr captured for the status
    panel.

    The password reaches the child **only** through its environment
    (:data:`aditor.app.credentials.PASSWORD_ENV_VAR`), which is what the config
    file's ``${AD_MCP_PASSWORD}`` placeholder expands from. It is never put in
    ``argv`` (visible to every user via ``ps`` / Task Manager) and never in the
    parent's own ``os.environ``, which would be inherited by every later child —
    including whatever ``webbrowser.open`` hands a report to.
    """

    endpoint: Endpoint = field(default_factory=Endpoint)
    config_path: Optional[Path] = None
    _process: Optional[subprocess.Popen] = field(default=None, repr=False)
    _started_at: float = 0.0
    _stderr: List[str] = field(default_factory=list, repr=False)
    _reader: Optional[threading.Thread] = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # -- state ------------------------------------------------------------- #

    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def status(self) -> Dict[str, Any]:
        """Everything the Connect screen shows about the server."""
        running = self.running()
        exit_code = (None if self._process is None or running
                     else self._process.poll())
        return {
            "running": running,
            "pid": self._process.pid if self._process is not None else None,
            "exit_code": exit_code,
            "uptime_seconds": (int(time.monotonic() - self._started_at)
                               if running and self._started_at else 0),
            "bind": self.endpoint.bind_description(),
            "url": self.endpoint.url(),
            "config_path": str(self.config_path) if self.config_path else "",
            # Last few lines only: the panel is a status area, not a log
            # viewer, and uvicorn's startup banner is the useful part.
            "recent_output": list(self._stderr[-12:]),
        }

    # -- lifecycle --------------------------------------------------------- #

    def start(self, password: str,
              popen: Any = None) -> Dict[str, Any]:
        """Launch the server. Refuses rather than fighting for the port.

        Args:
            password: Placed in the child's environment as
                ``AD_MCP_PASSWORD`` and nowhere else.
            popen: Injected process launcher, for tests. Production passes
                nothing and gets :class:`subprocess.Popen`.

        Raises:
            ServerControlError: already running, no saved config, or something
                else is already listening on the port.
        """
        with self._lock:
            if self.running():
                raise ServerControlError(
                    f"the server is already running (pid "
                    f"{self._process.pid}) on {self.endpoint.url()}.")
            if not self.config_path or not Path(self.config_path).is_file():
                raise ServerControlError(
                    "there is no saved connection to start the server with. "
                    "Fill in the Connection screen and save it first — the "
                    "server reads the same config file the app writes.")
            if not password:
                raise ServerControlError(
                    "the bind password is not available, so the server would "
                    "start and fail to authenticate. Enter it on the "
                    "Connection screen (it is read from the OS credential "
                    "store, never from a file).")
            if port_is_in_use(self.endpoint.host, self.endpoint.port):
                raise ServerControlError(
                    f"something is already listening on port "
                    f"{self.endpoint.port}. That may be an ADitor server you "
                    f"started outside this app; the app will not stop it. "
                    f"Either use that one — the snippets below already point "
                    f"at this address — or stop it yourself and try again.")

            argv = [
                sys.executable, "-m", "aditor.server",
                "--transport", "http",
                "--host", self.endpoint.host,
                "--port", str(int(self.endpoint.port)),
                "--path", self.endpoint.normalised_path(),
                "--config", str(self.config_path),
            ]
            launcher = popen or subprocess.Popen
            try:
                self._process = launcher(
                    argv,
                    env=password_environment(password),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=str(Path(__file__).resolve().parents[3]),
                )
            except OSError as exc:
                self._process = None
                raise ServerControlError(
                    f"the server process could not be started: "
                    f"{redact(str(exc))}") from exc

            self._started_at = time.monotonic()
            self._stderr = []
            self._reader = threading.Thread(
                target=self._drain, name="aditor-server-stderr", daemon=True)
            self._reader.start()
            return self.status()

    def stop(self, timeout: float = 6.0) -> Dict[str, Any]:
        """Terminate the child, escalating to a kill if it will not go."""
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                self._process = None
                return self.status()
            try:
                process.terminate()
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    pass
            except OSError as exc:  # pragma: no cover - defensive
                raise ServerControlError(
                    f"the server process could not be stopped: {exc}") from exc
            self._started_at = 0.0
            return self.status()

    def _drain(self) -> None:
        """Collect the child's stderr so the status panel can show it.

        Redacted line by line. The server does not log the password, but this
        text goes straight into the UI and the cost of being sure is one call.
        """
        stream = self._process.stderr if self._process else None
        if stream is None:  # pragma: no cover - only when PIPE was refused
            return
        try:
            for line in stream:
                text = redact(line.rstrip("\n"))
                if text:
                    self._stderr.append(text)
                # Bounded: a server left running for a week must not grow the
                # GUI's memory without limit.
                if len(self._stderr) > 400:
                    del self._stderr[:200]
        except (OSError, ValueError):  # pragma: no cover - stream closed
            pass


def config_uses_placeholder(path: Path) -> bool:
    """Whether a config file's password field is the placeholder, not a secret.

    Used as a pre-flight check before the server is started with a config the
    app did not necessarily write, and asserted by a test. A config carrying a
    real password would still work — which is exactly why it is worth noticing
    out loud rather than silently accepting.
    """
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    active = document.get("active_directory")
    if not isinstance(active, dict):
        return False
    return active.get("password") == CONFIG_PASSWORD_PLACEHOLDER


def password_is_only_in_environment(environment: Dict[str, str],
                                    password: str) -> bool:
    """Whether ``password`` appears in the environment only as the one variable.

    A helper for the leak test rather than for production: it makes "the secret
    reaches the child through exactly one channel" an assertion instead of a
    claim.
    """
    for name, value in environment.items():
        if name == PASSWORD_ENV_VAR:
            continue
        if isinstance(value, str) and password and password in value:
            return False
    return environment.get(PASSWORD_ENV_VAR) == password


def default_endpoint() -> Endpoint:
    """The app's default endpoint: loopback, the documented port and path.

    Loopback by default is a deliberate divergence from the server's own
    ``0.0.0.0``; see the module docstring and ``REPLATFORM_BRIEF.md`` §8.
    ``AD_MCP_APP_PORT`` overrides the port for anyone who has to run two
    instances, which also keeps the number out of the tests as a literal.
    """
    port = os.environ.get("AD_MCP_APP_PORT")
    try:
        resolved = int(port) if port else DEFAULT_PORT
    except ValueError:
        resolved = DEFAULT_PORT
    return Endpoint(host=DEFAULT_HOST, port=resolved, path=DEFAULT_PATH)


__all__ = [
    "CLAUDE_CODE_CONFIG_LOCATIONS",
    "CODEX_CONFIG_LOCATIONS",
    "DEFAULT_HOST",
    "EXPOSURE_RECOMMENDATION",
    "EXPOSURE_WARNING",
    "SERVER_KEY",
    "Endpoint",
    "ExposureAssessment",
    "ServerControlError",
    "ServerProcess",
    "assess_exposure",
    "claude_code_command",
    "claude_code_snippet",
    "codex_snippet",
    "config_uses_placeholder",
    "default_endpoint",
    "firewall_command",
    "password_is_only_in_environment",
    "port_is_in_use",
    "snippets",
]
