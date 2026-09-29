"""Write a PyInstaller version resource for one ADitor executable.

SignPath requires signed files to carry product metadata, so both exes get
ProductName "ADitor" and the package version:

    python packaging/version_info.py aditor-cli "ADitor command line" > cli-version.txt
    pyinstaller ... --version-file cli-version.txt
"""
import sys

from aditor import __version__


def version_info(name: str, description: str, version: str = __version__) -> str:
    parts = [int(p) for p in version.split(".")[:3]] + [0]
    numbers = tuple(parts[:4])
    strings = {
        "CompanyName": "Alex Linos",
        "FileDescription": description,
        "FileVersion": version,
        "InternalName": name,
        "LegalCopyright": "Copyright (c) 2026 Alex Linos. MIT License.",
        "OriginalFilename": f"{name}.exe",
        "ProductName": "ADitor",
        "ProductVersion": version,
    }
    entries = ",\n          ".join(f"StringStruct({k!r}, {v!r})" for k, v in strings.items())
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
          {entries}])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


if __name__ == "__main__":
    sys.stdout.write(version_info(sys.argv[1], sys.argv[2]))
