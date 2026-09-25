"""PyInstaller entry point for ``aditor.exe`` (the command line)."""
import sys

from aditor.cli import main

sys.exit(main())
