"""The ADitor desktop app — three screens, none of which can change the directory.

Run it with ``python -m aditor.app``. It needs the optional ``gui`` extra
(``pip install -e ".[gui]"``); everything else in this package imports without
pywebview, so the ``aditor`` command is unaffected.

The audience is a Windows administrator who is not comfortable in a terminal.

1. :mod:`aditor.app.connection` — enter and test read-only credentials, and on
   failure show the *real* LDAP error, because "invalid credentials",
   "certificate not trusted" and "host unreachable" have different fixes.
2. :mod:`aditor.app.scanning` — one button: run the read-only hardening scan
   once, write its snapshot, and show the counts from **that** scan.
3. :mod:`aditor.app.history` — list snapshots, open a report, diff two, with the
   diff's ``attribution`` rendered first and an ``ambiguous`` verdict rendered
   as a warning rather than as a count of improvements.

Supporting modules: :mod:`aditor.app.credentials` (the OS credential store, and
the refusal to persist without one), :mod:`aditor.app.settings` (the persisted
config, which holds ``${AD_MCP_PASSWORD}`` and never a secret),
:mod:`aditor.app.certificates`, :mod:`aditor.app.trust` and
:mod:`aditor.app.issuer` (establishing LDAPS trust),
:mod:`aditor.app.render` (every value that reaches HTML, escaped),
:mod:`aditor.app.api` (the object the page calls) and
:mod:`aditor.app.shell` (the pywebview window).

Version of the *app shell*, separate from the scan engine and report versions
so a UI change and a scan-logic change are not confused for one another.
"""

APP_VERSION = "0.1.1"

__all__ = ["APP_VERSION"]
