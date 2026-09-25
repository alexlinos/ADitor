"""PyInstaller entry point for ``aditor-cli.exe`` (the command line)."""
import sys

from aditor.cli import main

sys.exit(main())
