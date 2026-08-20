# ADitor

An Active Directory / GPO auditing tool and MCP server for hardening your environment.

ADitor is a Python [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
server that exposes Active Directory — over LDAP and SYSVOL — to an MCP client such
as Claude Code. Its focus is **read-only auditing**: domain and password-policy
review, privileged-group and admin-account analysis, inactive-account detection,
and Group Policy inspection, including parsing a GPO's actual SYSVOL contents
(Registry.pol, Group Policy Preferences Registry.xml, security
templates, AppLocker rules). It also provides full
directory management — users, groups, computers, and organizational units — for
day-to-day administration.

> **Status.** ADitor began as a fork of
> [ActiveDirectoryMCP](https://github.com/alpadalar/ActiveDirectoryMCP)
> (Alperen Adalar, MIT) and is being reworked into a focused AD/GPO hardening
> auditor. A hardening-verification scanner — checking a domain against Microsoft's
> published Active Directory hardening guidance — is in design; the control catalog
> and architecture are in [`docs/`](docs/).

## Requirements

- Python 3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- LDAP/LDAPS access to a domain controller, with a bind account that has read
  permissions (and write permissions for management operations)
- SMB read access to the SYSVOL share, for Group Policy content inspection
  (`get_gpo_contents`)

## Installation

```bash
git clone https://github.com/alexlinos/ADitor.git
cd ADitor

uv venv --python 3.12
source .venv/bin/activate

uv pip install -e ".[dev,smb]"
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

The `password` field supports `${ENV_VAR}` expansion, so the secret can be supplied
at runtime rather than stored on disk. `config.json` is gitignored.

## Running

ADitor runs as an HTTP MCP server:

```bash
AD_MCP_PASSWORD='…' PYTHONPATH=src \
  .venv/bin/python -m aditor.server --transport http \
  --config ad-config/config.json
```

It serves on `http://localhost:8813/activedirectory-mcp/` by default (HTTP is the
default transport). The same server speaks stdio with `--transport stdio`.

### MCP client

Point the client at the HTTP endpoint (keep the trailing slash — a bare path
redirects):

```json
{
  "mcpServers": {
    "aditor": {
      "type": "http",
      "url": "http://localhost:8813/activedirectory-mcp/"
    }
  }
}
```

## Tools

**Auditing and security**
`get_domain_info`, `get_privileged_groups`, `audit_admin_accounts`,
`get_user_permissions`, `get_inactive_users`, `get_password_policy_violations`,
`check_password_policy`

**Group Policy**
`get_gpos`, `get_gpo`, `get_linked_gpos` (enforcement and inheritance),
`get_gpo_contents` (parses Registry.pol, Group Policy Preferences
Registry.xml, security templates, and AppLocker rules
from SYSVOL)

**Hardening scan**
`scan_hardening` — evaluates the domain's GPOs against a versioned control
catalog derived from the Devore AD Hardening Series, with each control citing
the specific article it comes from. Each finding
carries a result, a rollout state (not started / audit / enforced, so a domain
correctly mid-rollout does not read as failing), and evidence: expected value
next to every value found, with the source GPO DN and link path. Policy
precedence is not resolved — conflicting GPOs are reported as conflicts instead.
Controls whose exact expected value the source does not state are reported but
never scored or guessed.

`write_hardening_report` — runs the same read-only scan and writes it as a
single self-contained HTML file: inline CSS, no external assets, no JavaScript,
opens from a `file://` path, and a browser can print it to PDF. The JSON from
`scan_hardening` stays the source of truth; the document renders it and adds
nothing. It is ordered by actionability rather than catalog order — GPO read
failures and unknown verdicts first (an unreadable GPO makes an unset key
unknown, not clean), then failures with expected-vs-found evidence, the source
GPO DN, the catalog's remediation and the rollout order (the interim audit step
first where a control has one), then conflicts, then findings resting on a
documented Windows default framed as hardening opportunities rather than as
something Group Policy enforces, then unscored controls, then passes. Writing the
file is the only side effect; the directory is not modified. Note that the file
contains the domain's GPO display names, registry values and DNs. See
[`examples/hardening-report-sample.html`](examples/hardening-report-sample.html)
for the layout, rendered from synthetic data.

`write_hardening_scan` — the report tool's sibling: the same read-only scan,
written as the **JSON** payload rather than a rendered document, so two runs can
be compared later. Always covers the whole catalog and filters nothing, because
a scan that hid part of the catalog is indistinguishable from one whose catalog
was smaller. Like the report, the file contains the domain's GPO display names,
registry values and DNs.

`diff_hardening_scans` — compares two stored scans to answer "did my fix land,
and did anything regress?". Touches no directory: two files in, one diff out.

Its first job is to distinguish **the domain changing** from **the tool
changing**, and the payload's opening key is `attribution` for that reason.
`domain` means both scans ran the same catalog *and* engine version, so a
difference is the domain's. `ambiguous` means they did not, so every difference
may be the scanner or the baseline instead — and the diff refuses to present any
of it as domain progress, naming both version pairs and stamping the verdict on
every entry. This is not hypothetical: one control here went `fail` → `pass`
between two real scans purely because the scanner learned to read Group Policy
Preferences. The value had been set correctly the whole time and the domain never
changed; a naive diff would have announced a remediation that never happened.

Regressions are listed before improvements, because a regression matters more. A
rollout moving backwards (`enforced` → `audit` → `not_started`) counts as one
even when `result` stays `pass`. A control added to or removed from the catalog
goes to `catalog_changes` and is never counted as an improvement or a regression
— there is no before-and-after verdict for it — and the diff says whether an
absence really means the catalog changed or just that one scan did not evaluate
it. A control whose verdict held but whose *evidence* moved — a different value,
a different GPO delivering it, policy replaced by a preference (which tattoos, so
it is a weaker statement), a changed evidence source, or a conflict appearing or
clearing — is surfaced under `evidence_changes`. Diffing two scans of different
domains, or a file that is not a scan payload, fails with a clear error.

**Directory management**
- Users: `list_users`, `get_user`, `get_user_groups`, `create_user`, `modify_user`,
  `delete_user`, `enable_user`, `disable_user`, `reset_user_password`
- Groups: `list_groups`, `get_group`, `get_group_members`, `create_group`,
  `modify_group`, `delete_group`, `add_group_member`, `remove_group_member`
- Computers: `list_computers`, `get_computer`, `get_stale_computers`,
  `create_computer`, `modify_computer`, `delete_computer`, `enable_computer`,
  `disable_computer`, `reset_computer_password`
- Organizational units: `list_organizational_units`, `get_organizational_unit`,
  `get_organizational_unit_contents`, `create_organizational_unit`,
  `modify_organizational_unit`, `delete_organizational_unit`,
  `move_organizational_unit`

**System**
`test_connection`, `health`, `get_schema_info`

Management operations perform real directory writes and require a bind account with
the corresponding permissions.

## Development

```bash
pytest
```

Layout:

```
src/aditor/
  server.py            # unified MCP server (stdio or streamable-HTTP)
  registry.py          # single tool registry (declare each tool once)
  config/              # configuration models and loader
  core/                # LDAP connection manager, logging
  tools/               # user, group, computer, organizational_unit, security, gpo
tests/                 # unit and integration tests
docs/                  # design docs (re-platform brief, hardening control catalog)
```

## License

MIT — see [LICENSE](LICENSE). ADitor is derived from ActiveDirectoryMCP by
Alperen Adalar (MIT); the original copyright is retained in the license file.
