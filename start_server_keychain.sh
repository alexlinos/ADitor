#!/bin/bash
# Launch ActiveDirectoryMCP with the LDAP bind password pulled from the macOS
# Keychain at startup. config.json's password field is the placeholder
# ${AD_MCP_PASSWORD}, which the patched config loader expands from the
# environment — this script supplies it so the password never sits on disk
# or in shell history.
#
# One-time setup (prompts for the password interactively, stores it in your
# login keychain under service name "admcp-ldap"). Replace DOMAIN\binduser
# with your own bind account:
#
#   security add-generic-password -s admcp-ldap -a 'DOMAIN\binduser' -w
#
# To update it after a rotation, add -U to the same command.

set -euo pipefail
cd "$(dirname "$0")"

KEYCHAIN_SERVICE="${ADMCP_KEYCHAIN_SERVICE:-admcp-ldap}"

if [ ! -x .venv/bin/python ]; then
    echo "Virtual environment not found at .venv — run setup first." >&2
    exit 1
fi

if ! AD_MCP_PASSWORD="$(security find-generic-password -s "$KEYCHAIN_SERVICE" -w 2>/dev/null)"; then
    echo "No Keychain item found for service '$KEYCHAIN_SERVICE'." >&2
    echo "Create it with:" >&2
    echo "  security add-generic-password -s $KEYCHAIN_SERVICE -a 'DOMAIN\\binduser' -w" >&2
    exit 1
fi
export AD_MCP_PASSWORD

export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
exec .venv/bin/python -m aditor.server --transport http --config ad-config/config.json
