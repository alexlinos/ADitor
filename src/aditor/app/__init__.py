"""The ADitor desktop app — four screens, none of them a write tool.

Run it with ``python -m aditor.app``. It needs the optional ``gui`` extra
(``pip install -e ".[gui]"``); everything else in this package imports without
pywebview, so the headless MCP server is unaffected.

The audience is a Windows administrator who is not comfortable in a terminal.
Until now ADitor was usable only through Claude Code or by driving Python
directly — precisely the audience it was never meant to require.

**Deliberately narrow.** The MCP server exposes 52 tools, 22 of which write to
the directory. The app exposes **none** of the write tools. Four jobs:

1. :mod:`aditor.app.connection` — enter and test read-only credentials, and on
   failure show the *real* LDAP error, because "invalid credentials",
   "certificate not trusted" and "host unreachable" have different fixes.
2. :mod:`aditor.app.scanning` — one button: run the read-only hardening scan
   through the existing ``write_hardening_snapshot`` path, once, and show the
   counts from **that** scan.
3. :mod:`aditor.app.history` — list snapshots, open a report, diff two, with the
   diff's ``attribution`` rendered first and an ``ambiguous`` verdict rendered
   as a warning rather than as a count of improvements.
4. :mod:`aditor.app.endpoint` — start and stop the MCP server, and generate the
   Claude Code and Codex config from the server's own live host, port and path,
   trailing slash included.

Supporting modules: :mod:`aditor.app.credentials` (the OS credential store, and
the refusal to persist without one), :mod:`aditor.app.settings` (the persisted
config, which holds ``${AD_MCP_PASSWORD}`` and never a secret),
:mod:`aditor.app.render` (every value that reaches HTML, escaped),
:mod:`aditor.app.api` (the object the page calls) and
:mod:`aditor.app.shell` (the pywebview window).

Version of the *app shell*, separate from the scan engine and report versions
so a UI change and a scan-logic change are not confused for one another.
"""

APP_VERSION = "0.1.0"

__all__ = ["APP_VERSION"]
