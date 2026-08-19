# ADitor — AD Hardening Control Catalog

> **ADitor** — an Active Directory / GPO auditing tool and MCP server for
> hardening your environment. This is ADitor's Phase-2 scan-engine spec; the
> backend foundation is in [`REPLATFORM_BRIEF.md`](REPLATFORM_BRIEF.md).

**Baseline source:** Jerry Devore, "Active Directory Hardening Series," Microsoft
Core Infrastructure and Security Blog. Verified Aug 2026 — **8 parts, no Part 9.**

This catalog is the product spec: each control is a declarative, source-cited
assertion. It is the input to the scan engine, the fixture for offline tests, and
the row structure of the audit report.

**Dual-sourced by design:** Devore's posts give the *why* and the rollout order,
but frequently name only the friendly policy and defer to linked Microsoft docs
for the exact value. So each control cites **two** sources — Devore (rationale +
phasing) and a **Microsoft Security Baseline / CIS Benchmark** for the exact
assertable registry value. Values quoted directly from a post are marked as such;
anything a post does not state is flagged `NOT STATED IN POST` (fill from the
baseline source, never guess) — see "Build implications."

The 8 parts decompose into ~20 discrete checkable controls across **three check
types**: `gpo-security-template`, `gpo-registry-pol`, and `directory-state`.

---

## Control summary

| ID | Part | Check type | Deterministic value? |
|---|---|---|---|
| DEVORE-01-NTLM-LMCOMPATIBILITYLEVEL | 1 | gpo-security-template | ✅ 0–5 quoted |
| DEVORE-02-SMBV1-REMOVAL | 2 | directory-state | ⚠️ feature state, no reg |
| DEVORE-03-LDAP-SERVER-SIGNING | 3 | gpo-security-template | ✅ 1/2 quoted |
| DEVORE-03-LDAP-CLIENT-SIGNING | 3 | gpo-security-template | ✅ 0/1/2 quoted; os_default 1 |
| DEVORE-03-LDAP-DIAG-LOGGING | 3 | gpo-registry-pol | ✅ =2 (audit helper) |
| DEVORE-04-KERB-CONFIGURE-ENCTYPES | 4 | gpo-security-template | ❌ reg path not stated |
| DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES | 4 | gpo-registry-pol | ✅ 0x38 quoted |
| DEVORE-04-MSDS-SUPPORTEDENCTYPES | 4 | directory-state | ⚠️ per-account attribute |
| DEVORE-05-LDAP-CHANNEL-BINDING | 5 | gpo-security-template | ✅ path quoted; 0/1/2 from MS KB4034879 |
| DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS | 6 | gpo-security-template | ✅ =1 (MS smb-signing-overview) |
| DEVORE-06-SMB-SERVER-SIGNING-ALWAYS | 6 | gpo-security-template | ✅ =1 (MS smb-signing-overview) |
| DEVORE-06-LLMNR-DISABLE | 6 | gpo-registry-pol | ✅ =0 quoted |
| DEVORE-06-NBTNS-NODETYPE | 6 | gpo-registry-pol | ✅ =2 quoted |
| DEVORE-07-LEAST-PRIVILEGE | 7 | directory-state | ⚠️ membership/ACL/attr |
| DEVORE-08-NTLM-AUDIT-INCOMING | 8 | gpo-security-template | ✅ floor >=1 (MS option set) |
| DEVORE-08-NTLM-AUDIT-OUTGOING | 8 | gpo-security-template | ✅ floor >=1 (MS option set) |
| DEVORE-08-NTLM-AUDIT-INDOMAIN | 8 | gpo-security-template | ✅ floor >=1 (MS option set) |
| DEVORE-08-NTLM-BLOCK-INCOMING | 8 | gpo-security-template | ❌ block path not stated |
| DEVORE-08-NTLM-BLOCK-OUTGOING | 8 | gpo-security-template | ❌ deny numeric not stated |
| DEVORE-08-NTLM-BLOCK-INDOMAIN | 8 | gpo-security-template | ❌ block path not stated |
| DEVORE-08-PRINT-RPCNAMEDPIPE | 8 | gpo-registry-pol | ✅ 0x2 quoted |
| DEVORE-08-PROTECTED-USERS | 8 | directory-state | ⚠️ group membership |

---

## Build implications (read before scoping the engine)

1. **The posts are not a complete value source.** Devore frequently names only the
   friendly policy and defers to linked Microsoft articles — so SMB `RequireSecuritySignature`,
   the Kerberos client `SupportedEncryptionTypes`, the LDAP channel-binding 0/1/2
   mapping, and most NTLM *blocking* values are **not printed in the posts**. Three of
   those were closed from Microsoft documentation in P2-WP2 (SMB signing, the
   channel-binding numerics, the NTLM audit floor); the Kerberos client value and the
   NTLM blocking numerics are still open. To make checks deterministic you need a
   **secondary authoritative source for exact values** —
   the Microsoft Security Baselines (Security Compliance Toolkit) and/or CIS
   Benchmarks. Plan the catalog to cite two sources per control: Devore (the *why*
   / rollout) + baseline (the *exact value*).

2. **Three engines, two already exist.** `gpo-security-template` and
   `gpo-registry-pol` are served by `get_gpo_contents` (GptTmpl.inf `[Registry Values]`
   + Registry.pol). `directory-state` controls (SMBv1 feature, msDS-SupportedEncryptionTypes,
   Least Privilege, Protected Users) map onto tools you already have —
   `get_privileged_groups`, `audit_admin_accounts`, `get_user` — plus a couple of
   new directory queries. SMBv1 feature-state is the one genuinely new check kind.

3. **Pass/fail is not binary — it's phased.** Almost every network control is
   *audit-first, then enforce* with an interim and a final target (NTLM level 3→5,
   LDAP signing 1→2, channel binding 1→2, NTLM audit→deny). The report should show
   **rollout state** (Not started / Audit / Enforced) per control, not a bare
   pass/fail, or it will read as failing an org that is correctly mid-rollout.

4. **An unset key is not automatically a failure.** Some settings have a
   documented Windows default that is already partly compliant —
   `LdapClientIntegrity` is Negotiate (1) on a machine no GPO has touched. Those
   controls carry `os_default` (populated **only** where a Microsoft document
   states the default) and are judged against it when no GPO sets the key, with
   the evidence marked `source: os-default` so an assumed value never reads as
   GPO-enforced. Where there is no default to cite, the field stays absent:
   `LdapEnforceChannelBinding` has no key by default, which is exactly why
   setting it matters.

5. **Least Privilege (Part 7) is a mini-product of its own** — group membership
   that should be empty, URA-vs-baseline diff, delegation ACLs, `TrustedForDelegation`
   queries, Protected Users. Scope it as its own control group, not one check.

---

## Reports & evidence (the "proofs")

The report is the product's deliverable — an auditor/leadership-facing **proof**
of each control's state. It is not a score; it is evidence.

**Pipeline:** `scan → JSON (source of truth) → HTML (styled) → PDF (audit/leadership)`.
The JSON is also the machine-readable, versioned artifact (diff two scans over
time). HTML/JSON for reuse; **PDF is the primary hand-off format.**

**Every control row carries its proof — expected vs. found:**
- `result`: `pass | fail | not_applicable | error`
- `rollout_state`: `not_started | audit | enforced` (see build-implication #3 —
  never a bare pass/fail, or a correctly mid-rollout org reads as failing)
- `evidence`: the **actual value found** (the real registry line / AppLocker
  enforcement / group membership) next to the **expected** value — plus the
  **source GPO DN and link path** (which GPO delivered it, enforced/blocked). An
  auditor must see *what was checked and what was found*, not just a verdict.
- `evidence.source`: `gpo | os-default | not-configured` — what the verdict rests
  on. `os-default` means no GPO sets the key and the control was judged against a
  Microsoft-documented Windows default, with the value and its citation in
  `evidence.os_default`. **The report must render that distinctly:** an
  os-default pass is a hardening *opportunity* ("at the OS default, not raised"),
  never a claim that Group Policy enforces the value. `counts.os_default` gives
  the total, so a summary can keep assumed passes out of the enforced tally.

**Provenance header (required for auditability):** tool version; **baseline
version** (Devore series rev + Microsoft/CIS baseline rev the exact values came
from); scan timestamp; forest/domain + connection name; operator. A report that
can't state "against which baseline, when, which forest" is not audit-grade.

**PDF rendering — note the packaging interaction.** The renderer choice is
constrained by the PyInstaller bundling (see brief §Packaging):
- **WeasyPrint** (HTML/CSS → PDF, no browser): cleanest output, but its native
  deps (Pango/Cairo/GDK-PixBuf) are notoriously fiddly to bundle in PyInstaller.
- **Headless Chromium** (Playwright): most faithful, heaviest footprint.
- **ReportLab** (programmatic, no HTML): trivial to bundle, but you hand-build
  layout instead of reusing the HTML.
- **pywebview print-to-PDF:** the desktop app already has a webview; the OS
  print-to-PDF path can render the same HTML with no extra dependency.
  Likely the pragmatic default for the packaged app.
Decide this alongside packaging, not after — it is the one report requirement
that touches the build.

---

## Full catalog

```yaml
# PART 1 — Disabling NTLMv1
- id: DEVORE-01-NTLM-LMCOMPATIBILITYLEVEL
  title: Enforce NTLMv2 via LAN Manager authentication level
  source: { part: 1, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-1-%E2%80%93-disabling-ntlmv1/3934787" }
  scope: all                 # phased: clients/members first, DCs last
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: LAN Manager authentication level"
    registry_path: 'HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
    type: REG_DWORD
    interim_expected: 3      # "Send NTLMv2 response only" — phase 1 for ALL devices
    final_expected: 5        # "Refuse LM & NTLM" — DC/domain-wide final
    operator: gte            # members >=3 ; DCs final ==5
  severity: high
  caveats:
    - "PHASED: do not set DCs to 5 until every device is at 3+. At 5 a DC treats NTLMv1 as bad-password attempts -> lockouts (author saw 46 failed logons from one NTLMv1 SMB connection)."
    - "0-3 govern what the CLIENT requests; 4-5 govern what the SERVER/DC accepts."
    - "TATTOOING: key is outside HKLM\\SOFTWARE\\Policies, so setting then 'Not Defined' leaves the value; must clear per-device."
    - "Absent default is OS-dependent (Vista/2008+ = 3). Credential Guard ignores this / disables NTLMv1. No reboot."
  audit_before_enforce: "4624 (LmPackageName='NTLM V1') on members/endpoints; 4776 on DCs does NOT record NTLM version. Exclude ANONYMOUS LOGON."

# PART 2 — Removing SMBv1  *** directory-state, no GPO registry assertion ***
- id: DEVORE-02-SMBV1-REMOVAL
  title: Remove/disable SMBv1 (primarily on domain controllers)
  source: { part: 2, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-2-%E2%80%93-removing-smbv1/3988317" }
  scope: domain-controllers
  check_type: directory-state
  assert:
    note: "No registry key given. Feature-removal + audit, not a GPO line."
    what_to_check_instead:
      - "SMBv1 feature state: Get-WindowsOptionalFeature SMB1Protocol / Get-WindowsFeature FS-SMB1 = Disabled/Removed (DISM)."
      - "Live SMBv1 sessions: Get-SmbSession | Where Dialect -lt '2.0'."
      - "SMBServer audit event 3000 (Microsoft-Windows-SMBServer/Audit) logs client IP of negotiated SMBv1."
  severity: high
  caveats:
    - "Disabling SMBv1 on DCs breaks SYSVOL read for legacy clients (GPO processing stops), domain-join for non-SMB2 clients, some named-pipe sessions."
    - "Failure strings: 'The specified network name is no longer available', 'The network path was not found'. Event 3000 usually only has client IP."

# PART 3 — Enforcing LDAP Signing (server + client + audit helper)
- id: DEVORE-03-LDAP-SERVER-SIGNING
  title: Domain controller LDAP server signing
  source: { part: 3, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-3-%E2%80%93-enforcing-ldap-signing/4066233" }
  scope: domain-controllers
  check_type: gpo-security-template
  assert:
    friendly_policy: "Domain controller: LDAP signing requirements"
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
    type: REG_DWORD
    interim_expected: 1      # None (negotiate, don't require)
    final_expected: 2        # Require Signing
    operator: equals
  severity: high
  caveats:
    - "AUDIT-FIRST: don't set Require Signing until 2889 audit shows no unsigned binds."
    - "TLS-offload/bridging load balancers forward unsigned traffic and appear as the client IP in 2889."

- id: DEVORE-03-LDAP-CLIENT-SIGNING
  title: LDAP client signing requirement
  source: { part: 3, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-3-%E2%80%93-enforcing-ldap-signing/4066233" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: LDAP client signing requirements"
    registry_path: 'HKLM\System\CurrentControlSet\Services\LDAP\LdapClientIntegrity'
    type: REG_DWORD
    interim_expected: 1      # Negotiate signing
    final_expected: 2        # Require signing
    os_default: 1            # SOURCED: MS "Network security: LDAP client signing
                             # requirements" — effective default = Negotiate signing
    operator: gte
  severity: medium
  caveats:
    - "Windows default is already Negotiate (1); Windows SASL binds won't break on DC enforcement unless a GPO overrode the default."
    - "OS DEFAULT, NOT ENFORCEMENT: unset ⇒ judged against os_default and marked `source: os-default`. A pass at the Negotiate step, not proof a GPO holds it there."

- id: DEVORE-03-LDAP-DIAG-LOGGING     # audit enabler, not a hardening endpoint
  title: Enable LDAP Interface diagnostic logging (find unsigned binds)
  source: { part: 3, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-3-%E2%80%93-enforcing-ldap-signing/4066233" }
  scope: domain-controllers
  check_type: gpo-registry-pol
  assert:
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events'
    type: REG_DWORD
    expected: 2
    operator: equals
  severity: informational
  caveats: ["Generates 2889 (client IP + account + Binding Type). 2887=daily unsigned volume; 2888=rejected after enforcement."]

# PART 4 — Enforcing AES for Kerberos (GPO + explicit DC reg + directory-state)
- id: DEVORE-04-KERB-CONFIGURE-ENCTYPES
  title: Configure encryption types allowed for Kerberos (disable RC4 on devices)
  source: { part: 4, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-4-%E2%80%93-enforcing-aes-for-kerberos/4114965" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Configure encryption types allowed for Kerberos"
    registry_path: "NOT STATED IN POST"   # post names only the policy + msDS attribute
    type: REG_DWORD
    expected: "AES enabled; RC4 disabled only after 4768 audit confirms device advertises AES"
    operator: present
  severity: high
  caveats:
    - "REGISTRY PATH NOT GIVEN (needs baseline source). Remediate SERVICE ACCOUNTS before disabling RC4 on devices."

- id: DEVORE-04-KDC-DEFAULTDOMAINSUPPORTEDENCTYPES
  title: Disable RC4 at the domain level on DCs
  source: { part: 4, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-4-%E2%80%93-enforcing-aes-for-kerberos/4114965" }
  scope: domain-controllers
  check_type: gpo-registry-pol
  assert:
    registry_path: 'HKLM\System\CurrentControlSet\services\KDC\DefaultDomainSupportedEncTypes'
    type: REG_DWORD
    expected: 0x38           # quoted; disables RC4 (see KB5021131)
    operator: equals
  severity: high
  caveats: ["Post warns big-bang use is 'too aggressive for most'; treat as final lock-in after per-account remediation."]

- id: DEVORE-04-MSDS-SUPPORTEDENCTYPES   # *** directory-state ***
  title: Set AES on SPN-enabled service accounts (msDS-SupportedEncryptionTypes)
  source: { part: 4, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-4-%E2%80%93-enforcing-aes-for-kerberos/4114965" }
  scope: domain-root
  check_type: directory-state
  assert:
    note: "Verified by directory query of msDS-SupportedEncryptionTypes on SPN accounts, not GPO."
    what_to_check_instead:
      - "SPN service accounts should carry AES bits (blank => KDC defaults to RC4)."
      - "Find RC4-dependent devices via 4768 Ticket Encryption Type = RC4. Jan 2025 CU adds Advertised Etypes / Available Keys to 4768/4769."
  severity: high
  caveats: ["Computer objects self-update — don't hand-set. Skip non-SPN users and KRBTGT. ADMT-synced accounts may need a password reset for AES keys."]

# PART 5 — Enforcing LDAP Channel Binding
- id: DEVORE-05-LDAP-CHANNEL-BINDING
  title: DC LDAP server channel binding token requirement
  source: { part: 5, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-5-%E2%80%93-enforcing-ldap-channel-binding/4235497" }
  scope: domain-controllers
  check_type: gpo-security-template
  assert:
    friendly_policy: "Domain controller: LDAP server channel binding token requirements"
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
    type: REG_DWORD
    interim_expected: 1      # When supported
    final_expected: 2        # Always
    operator: equals
  severity: high
  caveats:
    - "NUMERIC 0/1/2 not in the post (names only: Never/When supported/Always); the mapping is sourced from Microsoft KB4034879, which is what makes this control scorable — reconfirm against a Security Baseline / CIS Benchmark."
    - "Key absent by default => OFF. Only affects SASL binds over TLS. TLS-bridging LBs break CBT; VIP FQDN must be in DC cert SAN."
    - "AUDIT-FIRST: Server 2019+ logs 3075; 2016- only logs 3039 on rejection. Needs '16 LDAP Interface Events' >= 2."

# PART 6 — Enforcing SMB Signing (+ LLMNR / NBT-NS)
- id: DEVORE-06-SMB-CLIENT-SIGNING-ALWAYS
  title: SMB client require signing (always)
  source: { part: 6, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%E2%80%93-enforcing-smb-signing/4272168" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Microsoft network client: Digitally sign communications (always)"
    registry_path: 'HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature'
    type: REG_DWORD
    final_expected: 1
    operator: equals
    value_source: MS "Overview of Server Message Block signing in Windows"
                  (smb-signing-overview) — key, value name, REG_DWORD, 0=disable/1=enable
  severity: high
  caveats:
    - "NOT THE LEGACY SETTING: EnableSecuritySignature ('if server agrees') is SMBv1-only, ignored by SMB2+, and does NOT satisfy this control."
    - "'(always)' applies to ALL SMB versions and terminates sessions if the peer can't sign."
    - "Win11 24H2 & Server 2025 require SMB signing by default, so no single os_default is asserted (version-dependent)."

- id: DEVORE-06-SMB-SERVER-SIGNING-ALWAYS
  title: SMB server require signing (always)
  source: { part: 6, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%E2%80%93-enforcing-smb-signing/4272168" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Microsoft network server: Digitally sign communications (always)"
    registry_path: 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
    type: REG_DWORD
    final_expected: 1
    operator: equals
    value_source: MS "Overview of Server Message Block signing in Windows"
                  (smb-signing-overview) — key, value name, REG_DWORD, 0=disable/1=enable
  severity: high
  caveats:
    - "NOT THE LEGACY SETTING: EnableSecuritySignature ('if client agrees') is SMBv1-only, ignored by SMB2+, and does NOT satisfy this control."
    - "Post: 'Don't just require SMB signing on domain controllers' — endpoints/member servers too. 3rd-party appliances & MFPs are the usual unsigned culprits."
    - "No os_default: MS gives DC effective default = Enabled but member/client = Disabled, so the default is role-dependent."

- id: DEVORE-06-LLMNR-DISABLE
  title: Turn off LLMNR (multicast name resolution)
  source: { part: 6, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%E2%80%93-enforcing-smb-signing/4272168" }
  scope: all
  check_type: gpo-registry-pol
  assert:
    friendly_policy: "Turn off multicast name resolution"
    registry_path: 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
    type: REG_DWORD
    expected: 0
    operator: equals
  severity: medium
  caveats: ["Explicit value in post. Reduces AiTM/Responder surface."]

- id: DEVORE-06-NBTNS-NODETYPE
  title: Disable NetBIOS-over-TCP name resolution (P-node)
  source: { part: 6, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%E2%80%93-enforcing-smb-signing/4272168" }
  scope: all
  check_type: gpo-registry-pol
  assert:
    friendly_policy: "MS Security Guide: NetBT NodeType configuration (SecGuide.admx)"
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType'
    type: REG_DWORD
    expected: 2              # P-node
    operator: equals
  severity: medium
  caveats: ["Explicit value in post. Needs SecGuide.admx from the Security Compliance Toolkit for a native GPO setting."]

# PART 7 — Implementing Least Privilege  *** entirely directory-state ***
- id: DEVORE-07-LEAST-PRIVILEGE
  title: Active Directory least-privilege / Tier 0 hardening
  source: { part: 7, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-7-%E2%80%93-implementing-least-privilege/4366626" }
  scope: domain-root
  check_type: directory-state
  assert:
    note: "No single registry line. Verify via directory queries below."
    what_to_check_instead:
      empty_recommended: [Account Operators, Backup Operators, Group Policy Creator Owners, Schema Admins, Server Operators, Print Operators, Replicator, Storage Replica Administrators, Incoming Forest Trust Builders]
      minimized: [Administrators, Domain Admins, Enterprise Admins, Remote Desktop Users, Key Admins, Enterprise Key Admins, DnsAdmins]
      user_rights_assignments: "Compare DC URA vs Windows Server 2022 Security Baseline (Policy Analyzer); remove Server/Print Operators URAs."
      unconstrained_delegation: "Get-ADComputer/-ADUser -Filter {TrustedForDelegation -eq $true} -> move to constrained/RBCD."
      sensitive_accounts: "'Account is sensitive and cannot be delegated' on privileged accounts; add admins to Protected Users."
      delegation_acls: "Review OU delegations for reset-password, join-domain, create objects, GPO link, DCSync (Replicating Directory Changes-All)."
      uac_baseline: "UAC Security Options per Server 2022 baseline — GPO settings, but post gives no registry values."
  severity: high
  caveats: ["Bulk of this part is membership/ACL/attribute state, not GPO content."]

# PART 8 — Disabling NTLM (audit paths quoted; block paths not; phased)
- id: DEVORE-08-NTLM-AUDIT-INCOMING
  title: Audit incoming NTLM traffic
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Restrict NTLM: Audit Incoming NTLM Traffic"
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic'
    type: REG_DWORD
    final_expected: 1        # FLOOR: >=1 = some auditing enabled; 0 = Disable
    operator: gte
    value_source: MS "Network security: Restrict NTLM: Audit incoming NTLM traffic"
                  — options Disable / domain accounts / all accounts; "Not defined ...
                  is the same as Disable, and it results in no auditing"
  severity: medium
  caveats:
    - "FLOOR, NOT LEVEL: numerics are not printed by MS, so domain-vs-all-accounts is evidence, not a verdict."
    - "TRAP: blogs conflate Audit*/Restrict* mappings. This audit policy 'doesn't actually block any traffic' (MS). Blocking = BLOCK-INCOMING (unscored)."
    - "Generates 8002/8003 in Microsoft/Windows/NTLM/Operational."

- id: DEVORE-08-NTLM-AUDIT-OUTGOING
  title: Audit outgoing NTLM traffic to remote servers
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers"
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic'
    type: REG_DWORD
    final_expected: 1        # FLOOR: >=1 = at least audited; Allow-all zero state fails
    operator: gte
    value_source: MS "Network security: Restrict NTLM: Outgoing NTLM traffic to remote
                  servers" — options Allow all / Audit all / Deny all; "Not defined ...
                  is the same as Allow all"
  severity: medium
  caveats:
    - "One value name for both audit and block: a pass here means 'at least audited', NOT blocked."
    - "The deny numeric is unsourced, so BLOCK-OUTGOING stays unscored with registry_key null."

- id: DEVORE-08-NTLM-AUDIT-INDOMAIN
  title: Audit NTLM authentication in this domain (DCs)
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: domain-controllers
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Restrict NTLM: Audit NTLM authentication in this domain"
    registry_path: 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain'
    type: REG_DWORD
    final_expected: 1        # FLOOR: >=1 = some auditing enabled; 0 = Disable
    operator: gte
    value_source: MS "Network security: Restrict NTLM: Audit NTLM authentication in this
                  domain" — options Disable + four Enable scopes; Disable "won't log events"
  severity: medium
  caveats:
    - "FLOOR, NOT LEVEL: five options, numerics not printed by MS; which Enable scope is set is evidence."
    - "Audit only — MS: 'doesn't actually block any traffic'. Generates 8004/8005/8006."

- id: DEVORE-08-NTLM-BLOCK-INCOMING
  title: Block incoming NTLM traffic (final phase)
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Restrict NTLM: Incoming NTLM traffic"
    registry_path: "NOT STATED IN POST"   # baseline: MSV1_0\RestrictReceivingNTLMTraffic
    type: REG_DWORD
    expected: "Deny all domain accounts (value not stated)"
    operator: present
  severity: high
  caveats:
    - "REGISTRY PATH NOT GIVEN for blocking (only audit paths printed)."
    - "Use 'Deny all domain accounts', not 'Deny all accounts' (breaks loopback/System). Pilot Tier 0/PAWs first; server-exception policies available. Block events 4001-4006 replace 8001-8006."

- id: DEVORE-08-NTLM-BLOCK-OUTGOING
  title: Block outgoing NTLM traffic to remote servers
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: all
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers"
    registry_path: "NOT ASSERTED"   # value name known (MSV1_0\RestrictSendingNTLMTraffic,
                                    # shared with the outgoing audit control) but the
                                    # 'Deny all' numeric is unsourced -> registry_key null
    type: REG_DWORD
    expected: null                  # status: needs_baseline_value
    operator: present
  severity: high
  caveats: ["Same value name as the outgoing audit control — audit vs deny is a value change."]

- id: DEVORE-08-NTLM-BLOCK-INDOMAIN
  title: Block NTLM authentication in this domain (DCs, project end)
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: domain-controllers
  check_type: gpo-security-template
  assert:
    friendly_policy: "Network security: Restrict NTLM: NTLM authentication in this domain"
    registry_path: "NOT STATED IN POST"   # baseline: Netlogon\Parameters\RestrictNTLMInDomain
    type: REG_DWORD
    expected: "Deny variant (value not stated)"
    operator: present
  severity: high
  caveats: ["PATH/VALUES NOT GIVEN. Deny variants differ by scope; applied at the very end, DCs only."]

- id: DEVORE-08-PRINT-RPCNAMEDPIPE
  title: Fix Print Spooler NTLM fallback (PrintNightmare artifact)
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: all
  check_type: gpo-registry-pol
  assert:
    friendly_policy: "Printers\\Configure RPC connection/listener settings (prefer RPC over TCP)"
    registry_path: 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\RpcNamedPipeAuthentication'
    type: REG_DWORD
    expected: 0x2            # only if RPC-over-named-pipes must be retained
    operator: equals
  severity: low
  caveats: ["Explicit value quoted. Prefer RPC-over-TCP. Related NTLM-fallback sources (RPC EPM, TryIPSPN, Kerberos LogLevel, MS-CHAPv2, DFS referrals) given without values."]

- id: DEVORE-08-PROTECTED-USERS      # directory-state supporting control
  title: Add privileged admins to Protected Users group
  source: { part: 8, url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782" }
  scope: domain-root
  check_type: directory-state
  assert:
    note: "Group membership, not GPO. Members can't use NTLM and don't retain the hash in LSASS."
    what_to_check_instead: "Protected Users membership for privileged admin accounts (NOT service or computer accounts)."
  severity: medium
  caveats: ["Add incrementally to catch compatibility issues. Never add service accounts or devices."]
```

---

## Notes from source research

- **Part 9 does not exist** (as of Aug 2026). The author page lists Parts 1–8 plus
  two non-series posts. The `adhardening` tag's "9 Topics" = 9 tagged posts (8 parts
  + a related article), not a Part 9. A search for `"Active Directory Hardening
  Series" "Part 9"` returns nothing.
- **Non-deterministic as a GPO check:** Part 2 (SMBv1 feature), Part 4
  msDS-SupportedEncryptionTypes (per-account attr), Part 7 (all of it), Part 8
  Protected Users. These use directory/feature queries, not GPO content.
- **Multi-value controls:** Part 3 (server + client), Part 6 (client + server +
  LLMNR + NBT-NS), Part 8 (audit and block share value names; outgoing uses one
  value for both).
- **Values quoted vs. not:** explicit in-post — LmCompatibilityLevel (0–5),
  LDAPServerIntegrity (1/2), LdapClientIntegrity (0/1/2), `16 LDAP Interface Events`=2,
  DefaultDomainSupportedEncTypes=0x38, EnableMulticast=0, NodeType=2, the three NTLM
  audit paths, RpcNamedPipeAuthentication=0x2. Closed from Microsoft documentation
  (P2-WP2): SMB `RequireSecuritySignature` (both keys, 0/1) from *Overview of Server
  Message Block signing in Windows*; the NTLM audit **floor** (>=1 — see the
  cited-vs-inferred bullet below; the floor rests on an inference, not a quoted
  numeric) from the three *Restrict NTLM* policy references; the
  `LdapClientIntegrity` OS default (Negotiate = 1) from *Network security: LDAP
  client signing requirements*; the `LdapEnforceChannelBinding` 0/1/2 mapping
  (Never / When supported / Always) from Microsoft **KB4034879**, which
  `DEVORE-05-LDAP-CHANNEL-BINDING` is `status: active` and scores on — the Devore
  post names the settings but not the numbers, and the control's caveats say the
  mapping should be reconfirmed against a Security Baseline or CIS Benchmark. Still
  not stated (need a baseline source): Kerberos client SupportedEncryptionTypes, NTLM
  **blocking** value names/numbers.
- **The NTLM numerics trap.** Third-party write-ups routinely conflate the `Audit*`
  and `Restrict*` mappings and will assert that `AuditReceivingNTLMTraffic=2` means
  "deny all". It does not: Microsoft is explicit that the audit policies **cannot
  block traffic at all**, so no value of this setting denies anything. Microsoft does
  **not** print which numeric is which enabling level, so this document must not name
  one either — an earlier revision of this paragraph asserted that Microsoft is
  explicit that `2` is "Enable auditing for all accounts", which is the same numeric
  conflation the paragraph warns against, one sentence later. Hence: `value_source`
  cites Microsoft/CIS or the value is not scored, and the audit controls assert only a
  **floor** (off vs not-off), reporting the exact level as evidence rather than
  scoring it.
- **Cited vs. inferred (the NTLM audit floor).** The floor itself is not a quoted
  numeric — Microsoft prints none. What is **cited** is the option set, that the
  unset policy behaves as the off option ("Not defined … is the same as Disable"),
  and that audit policies cannot block. What is **inferred** is that the off option
  is stored as `0` and every other option is `≥ 1`; the quoted sentence is about the
  *unset* case and on its own says nothing about a configured `0`. Each control's
  `value_source` labels the two halves and states why a floor — and only a floor —
  is safe to rest on that inference. This is also why
  `DEVORE-08-NTLM-BLOCK-OUTGOING` stays `needs_baseline_value` on the *same*
  registry value name that `DEVORE-08-NTLM-AUDIT-OUTGOING` scores: a floor needs
  only the zero point and the ordering, while "Deny all" is one specific numeric out
  of three that no floor can express (`gte 1` is equally satisfied by "Audit all").
