# ADitor

A read-only Active Directory / GPO hardening auditor.

ADitor reads a domain's Group Policy over LDAP and SYSVOL, checks it against a
versioned catalog of hardening controls, and writes a report you can hand to
someone. Run it again next month and diff the two scans to see what your fixes
changed and whether anything regressed. It never writes to the directory.

> **Status.** ADitor began as a fork of
> [ActiveDirectoryMCP](https://github.com/alpadalar/ActiveDirectoryMCP)
> (Alperen Adalar, MIT). The MCP server and its directory-management tools were
> removed; the last version with them is tagged `v-mcp-final`. The control
> catalog and its design are in [`docs/HARDENING_CATALOG.md`](docs/HARDENING_CATALOG.md).

## Requirements

- Python 3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- LDAP/LDAPS access to a domain controller, with a bind account that has read
  permissions
- SMB read access to the SYSVOL share

## Installation

```bash
git clone https://github.com/alexlinos/ADitor.git
cd ADitor

uv venv --python 3.12
source .venv/bin/activate

uv pip install -e ".[smb]"          # add ,gui for the desktop app
```

## Configuration

```bash
cp ad-config/config.example.json ad-config/config.json
chmod 600 ad-config/config.json
```

```json
{
  "active_directory": {
    "server": "ldaps://dc.example.com:636",
    "domain": "example.com",
    "base_dn": "DC=example,DC=com",
    "bind_dn": "EXAMPLE\\svc-aditor",
    "password": "${AD_MCP_PASSWORD}"
  },
  "security": {
    "validate_certificate": true
  }
}
```

Use `ldaps://` (port 636). ADitor binds with a simple bind and doesn't use
STARTTLS, so with plain `ldap://` the bind password crosses the network in clear
text; ADitor allows it but warns every time.

The `password` field supports `${ENV_VAR}` expansion, so the secret can be supplied
at runtime rather than stored on disk. If it is unset and you run `aditor scan`
from a terminal, you are prompted for it. `config.json` is gitignored.

On macOS, [`scan_keychain.sh`](scan_keychain.sh) pulls the password from the
Keychain (service `admcp-ldap`) and runs a scan with it.

## Usage

```bash
aditor scan --config ad-config/config.json --out ~/scans
aditor diff ~/scans/2026-08-20T193156Z-26f204f6 ~/scans/2026-08-24T184004Z-9d7d8ba2
```

| Exit code | Meaning |
|---|---|
| 0 | Nothing needs attention |
| 1 | The scan has a `fail` or `error` finding, or the diff has a regression |
| 2 | The command could not run (config, connection, or a refused file); nothing was written |

The exit codes let it run unattended from a scheduled task or an RMM agent.

### `aditor scan`

Runs the scan **once** and writes one dated folder:

```
<out>/2026-08-20T162647Z-b288e925/
    scan.json      <- the payload (source of truth)
    report.html    <- the rendered document
```

Both files come from the same scan, so they carry the same `scan_id`,
timestamp and findings. The folder name is the scan's own timestamp plus a
`scan_id` prefix, with no colon so it is legal on Windows. An existing folder is
never overwritten, and a failed write leaves no folder behind.

Each finding carries a result, a rollout state (not started / audit / enforced,
so a domain correctly mid-rollout does not read as failing), and evidence: the
expected value next to every value found, with the source GPO and its link path.
Controls come from the Devore AD Hardening Series, and each one cites its
article. Most read Group Policy; a few read the directory itself (service
accounts without AES, built-in privileged groups that should be empty, and
unconstrained delegation), with read-only LDAP queries. Policy precedence is not resolved: GPOs that disagree are reported as
conflicts. Controls whose exact expected value the source does not state are
reported but never scored or guessed.

The report is one self-contained HTML file (inline CSS, no scripts, no network)
that opens from a `file://` path and prints to PDF from a browser. It opens with
a "Start here" box (where you stand, and the first few things to do) and groups
findings by what you do with them: **Fix**, **Check by hand**, **Not covered
yet** and **Good**. Each finding shows found versus target, the fix and the safe
rollout order up front, with the evidence one click away. A warning about
unreadable GPOs always comes first. See [`examples/hardening-report-sample.html`](examples/hardening-report-sample.html),
rendered from synthetic data.

**Both files contain directory content** — GPO display names, registry values
and DNs. Treat them accordingly when sharing.

### `aditor diff OLD NEW`

Compares two scans, given as `scan.json` files or snapshot folders. It reads two
files and touches no directory.

It says first whether a difference is **the domain's** or **the tool's**. If
the two scans ran different catalog or engine versions, every difference may be
the scanner rather than the domain, and the diff says so before anything else.
This is not hypothetical: one control here went `fail` → `pass` between two real
scans only because the scanner learned to read Group Policy Preferences.

Regressions are listed before improvements. A rollout moving backwards
(`enforced` → `audit`) counts as a regression even when the result stays `pass`.
A control added to or removed from the catalog is never counted as either.

## The desktop app

For an administrator who would rather not use a terminal:

```bash
uv pip install -e ".[gui,smb]"
python -m aditor.app
```

| Screen | What it does |
|---|---|
| **Connection** | Enter and test read-only credentials. On failure it shows the *actual* LDAP error, and helps establish LDAPS certificate trust. |
| **Scan** | One button. Runs the same scan as `aditor scan`, shows its progress and counts, and opens the report. |
| **History** | The snapshot archive. Open a report, or pick two scans and diff them, with an ambiguous attribution shown as a warning. |

**Credentials.** The bind password is never written to disk. It goes to the OS
credential store — Windows Credential Manager or the macOS Keychain, under the
same `admcp-ldap` service name `scan_keychain.sh` uses — and the app's config
file holds the `${AD_MCP_PASSWORD}` placeholder. That file has the same shape
`aditor scan --config` reads. If no OS credential store is available, the app
says so and refuses to save.

`pywebview` is an optional extra (`gui`); the `aditor` command installs and runs
without it.

## Running it on a domain controller

It works, but run it from an admin workstation where you can. A DC is a Tier 0
host, and ADitor is an unsigned new executable that only needs a read-only
account and network access to a DC. If you do run it on one:

- Server Core has no WebView2, so the desktop app won't open; use
  `aditor-cli.exe`.
- Saving a connection in the desktop app stores the bind password in that
  machine's Credential Manager. On a DC, prefer `aditor-cli.exe` with the
  password supplied at run time.

The certificate helper's **Download the issuing CA certificate** works well on a
DC: it looks in the machine's own certificate stores first, and it never sends
a credential to find the file.

## Development

```bash
pytest
```

```
src/aditor/
  cli.py               # the aditor command: scan, diff
  hardening/           # catalog, collection, evaluator, report, snapshot, diff
  gpo/                 # pure GPO parsers (Registry.pol, GptTmpl.inf, Registry.xml)
  core/                # LDAP connection manager, logging
  config/              # configuration models and loader
  app/                 # the desktop app
tests/
docs/                  # design docs and the hardening control catalog
```

## License

MIT — see [LICENSE](LICENSE). ADitor is derived from ActiveDirectoryMCP by
Alperen Adalar (MIT); the original copyright is retained in the license file.
