# Security policy

ADitor is pointed at domain controllers with a bind account, so a flaw in it
can matter. Please report one privately.

## Reporting a vulnerability

Use GitHub's private reporting: the repository's **Security** tab →
**Report a vulnerability**. Please don't open a public issue for a
vulnerability.

Include what you ran, what happened, and what you expected. Don't include real
domain data (GPO names, DNs, account names, `scan.json` or `report.html` from a
production domain); a redacted or synthetic reproduction is enough.

You should get a reply within a week. Fixes go into the next release, and the
advisory credits you unless you'd rather it didn't.

## In scope

- Anything that sends a credential somewhere it shouldn't go, or writes it to
  disk in clear text.
- Anything that writes to the directory or to SYSVOL. ADitor is read-only by
  design; a write is a bug.
- TLS or certificate-validation bypasses.
- A crafted directory object, GPO file or `scan.json` that makes ADitor run
  code, read files it shouldn't, or produce a report that runs script when
  opened.
- A finding reported as `pass` when the domain is not actually compliant.

## Out of scope

- Plain `ldap://` sending the bind password in clear text. It is documented and
  warned about every time; use `ldaps://`.
- The Windows executables being unsigned.
- Anything that needs an attacker who already controls the machine running
  ADitor or the domain being scanned.

## Supported versions

Only the latest release gets security fixes.
