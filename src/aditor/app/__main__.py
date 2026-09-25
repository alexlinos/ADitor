"""``python -m aditor.app`` — open the ADitor window."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .shell import WebviewMissing, run


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aditor.app",
        description="The ADitor desktop app: connect, scan, and compare. "
                    "Read-only.")
    parser.add_argument(
        "--settings-dir", default=None,
        help="Use a different settings directory (default: the per-user "
             "application data directory).")
    parser.add_argument("--debug", action="store_true",
                        help="Enable the web view's developer tools.")
    args = parser.parse_args(argv)

    directory = Path(args.settings_dir) if args.settings_dir else None
    try:
        from .api import AditorApi

        run(directory=directory, debug=args.debug,
            api=AditorApi(directory=directory))
    except WebviewMissing as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
