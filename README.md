# ADitor

An Active Directory / GPO auditing tool and MCP server for hardening your environment.

ADitor is a Python [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
server that exposes Active Directory — over LDAP and SYSVOL — to an MCP client such
as Claude Code. Its focus is **read-only auditing**: domain and password-policy
review, privileged-group and admin-account analysis, inactive-account detection,
and Group Policy inspection, including parsing a GPO's actual SYSVOL contents
(Registry.pol, security templates, AppLocker rules). It also provides full
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
uv pip install "mcp==1.9.0"    # pin the MCP SDK to a known-good release
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
`get_user_permissions`, `get_inactive_users`, `get_password_policy_violations`

**Group Policy**
`get_gpos`, `get_gpo`, `get_linked_gpos` (enforcement and inheritance),
`get_gpo_contents` (parses Registry.pol, security templates, and AppLocker rules
from SYSVOL)

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
