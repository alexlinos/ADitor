"""``python -m aditor.app`` — open the ADitor window.

Also ``--check``, which prints what the Connect screen would generate (the
endpoint, both client snippets, the exposure assessment) and exits. That exists
so the generated config can be inspected — and reviewed — without opening a
window, starting a server, or touching a domain controller.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .credentials import get_store
from .endpoint import Endpoint, assess_exposure, default_endpoint, snippets
from .shell import WebviewMissing, run


def _print_check(endpoint: Endpoint) -> None:
    """Everything the Connect screen would show, as plain text.

    Deliberately does not start the server or read the credential store's
    contents — it reports which store *would* be used, not what is in it.
    """
    data = snippets(endpoint)
    exposure = assess_exposure(endpoint)
    store = get_store()

    print("ADitor desktop app — configuration check\n")
    print(f"Endpoint URL      : {data['url']}")
    print(f"Trailing slash    : {data['trailing_slash']}")
    print(f"Bind address      : {endpoint.bind_description()}")
    print(f"Loopback only     : {exposure.loopback}")
    print(f"Credential store  : {store.name} "
          f"(available: {store.available()})")
    print("\n-- Exposure ------------------------------------------------\n")
    print(exposure.headline)
    print(exposure.detail)
    if exposure.warning:
        print(f"\nWARNING: {exposure.warning}")
        print(f"\n{exposure.firewall_command}")
        print(f"\n{exposure.firewall_note}")
    print(f"\n{exposure.recommendation}")
    for key in ("claude_code", "codex"):
        client = data[key]
        print(f"\n-- {client['label']} "
              f"({client['format']}) ---------------------------\n")
        for index, step in enumerate(client["steps"], start=1):
            print(f"  {index}. {step}")
        if client["command"]:
            print(f"\n  {client['command']}")
        print()
        print(client["snippet"])
        print("Config file location(s) on Windows:")
        for location in client["locations"]:
            print(f"  {location}")


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aditor.app",
        description="The ADitor desktop app: connect, scan, compare, and wire "
                    "up an MCP client. Read-only.")
    parser.add_argument(
        "--check", action="store_true",
        help="Print the generated endpoint, client snippets and exposure "
             "assessment, then exit. Opens no window and starts no server.")
    parser.add_argument(
        "--settings-dir", default=None,
        help="Use a different settings directory (default: the per-user "
             "application data directory).")
    parser.add_argument(
        "--host", default=None,
        help="Bind address for the MCP server the app starts. Defaults to "
             "loopback, which accepts connections only from this machine.")
    parser.add_argument("--port", type=int, default=None,
                        help="Port for the MCP server the app starts.")
    parser.add_argument("--debug", action="store_true",
                        help="Enable the web view's developer tools.")
    args = parser.parse_args(argv)

    endpoint = default_endpoint()
    if args.host or args.port:
        endpoint = Endpoint(host=args.host or endpoint.host,
                            port=args.port or endpoint.port,
                            path=endpoint.path)

    if args.check:
        _print_check(endpoint)
        return 0

    directory = Path(args.settings_dir) if args.settings_dir else None
    try:
        # Imported here so --check works with pywebview absent.
        from .api import AditorApi

        run(directory=directory, debug=args.debug,
            api=AditorApi(directory=directory, endpoint=endpoint))
    except WebviewMissing as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
