"""PyInstaller entry point for ``ADitor.exe`` (the desktop app)."""
import sys

from aditor.app.__main__ import main

sys.exit(main())
