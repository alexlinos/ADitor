"""The pywebview window: create it, hand it the API object, run it.

**pywebview is imported lazily and only here.** That is what keeps the GUI an
optional extra: ``pip install -e .`` without ``[gui]`` installs and ``aditor
scan`` runs exactly as before, because nothing on the CLI's import path reaches
this module. :func:`require_webview` turns the ``ImportError`` into the
one-line install instruction rather than a traceback, and a test asserts that
the whole ``aditor.app`` package imports with ``webview`` absent.

pywebview rather than Electron: it uses the OS's own
web view (WebView2 on Windows, WebKit on macOS), which is one Python dependency
instead of a bundled browser, and it is what the eventual PyInstaller packaging
work package is planned around. Packaging is explicitly not this work package —
this must *run* via ``python -m aditor.app``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .api import AditorApi

WINDOW_TITLE = "ADitor — Active Directory hardening audit"

# Big enough for the three screens' content at the default zoom without
# horizontal scrolling, small enough for a 1366x768 laptop.
WINDOW_WIDTH = 1180
WINDOW_HEIGHT = 820
WINDOW_MIN_SIZE = (940, 620)

_INSTALL_HINT = (
    "The ADitor desktop app needs pywebview, which is an optional extra so "
    "that the command-line tool installs without it.\n\n"
    "    pip install -e \".[gui]\"\n\n"
    "The command-line scan is unaffected and can be run with:\n\n"
    "    aditor scan --config <config.json>")


class WebviewMissing(RuntimeError):
    """pywebview is not installed. The message is the install instruction."""


def web_root() -> Path:
    """The directory holding ``index.html``, ``app.css`` and ``app.js``.

    Resolved from this module's location rather than the working directory, so
    the app runs from anywhere — and so it keeps working when PyInstaller
    relocates the package into a bundle.
    """
    return Path(__file__).resolve().parent / "web"


def index_path() -> Path:
    return web_root() / "index.html"


def require_webview() -> Any:
    """Import ``webview``, or raise with the install command.

    Raises:
        WebviewMissing: pywebview is not installed.
    """
    try:
        import webview  # noqa: PLC0415  (lazy on purpose - see module docstring)
    except ImportError as exc:
        raise WebviewMissing(_INSTALL_HINT) from exc
    return webview


def run(directory: Optional[Path] = None, debug: bool = False,
        api: Optional[AditorApi] = None) -> None:
    """Open the window and block until it closes.

    Args:
        directory: Override the settings directory. For a second profile, and
            for tests that must not touch the real one.
        debug: Pass pywebview's ``debug`` flag, which enables the web view's
            developer tools.
        api: Inject the API object. Production passes nothing.
    """
    webview = require_webview()
    bridge = api or AditorApi(directory=directory)

    window = webview.create_window(
        WINDOW_TITLE,
        str(index_path()),
        js_api=bridge,
        width=WINDOW_WIDTH,
        height=WINDOW_HEIGHT,
        min_size=WINDOW_MIN_SIZE,
        # No text-select/right-click restrictions: an operator has to be able to
        # select a command and an error message.
        text_select=True,
    )

    # Forget the password when the window goes.
    try:
        window.events.closing += lambda: bridge.shutdown()
    except AttributeError:  # pragma: no cover - older pywebview event API
        pass

    try:
        webview.start(debug=debug)
    finally:
        bridge.shutdown()


__all__ = [
    "WINDOW_TITLE",
    "WebviewMissing",
    "index_path",
    "require_webview",
    "run",
    "web_root",
]
