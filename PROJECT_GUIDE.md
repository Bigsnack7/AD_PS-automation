# AD_PS-automation

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-5391D5?logo=powershell&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Automation-2DDE98?logo=microsoft&logoColor=white)
![Scope](https://img.shields.io/badge/Scope-Lab%20%2F%20Test-FF6B6B)

AD_PS-automation is a PowerShell toolkit for safely provisioning department-based Active Directory OU structures, groups, users, and scoped delegation; performing supported user lifecycle actions; and producing security, audit, and user reports. A shared `ADAutoX` module centralizes the public API, provisioning preflight, lifecycle protections, verification, audit records, and rollback ledger, while command scripts provide canonical and compatibility entry points.

> **Scope:** built for lab, test, and controlled administrative use. Anything beyond a lab should go through your organization's change control and security review.

> **Testing status:** `mark42.ps1` has been tested successfully in the lab. Testing of the remaining scripts is in progress; live-domain integration testing has not yet been verified.

<!-- Add a terminal screenshot or short demo GIF here, for example:
![Provisioning run](docs/demo.gif)
-->

[Highlights](#highlights) · [Architecture](#architecture) · [Quick start](#quick-start) · [Provisioning](#how-a-provisioning-run-works) · [Lifecycle](#user-lifecycle) · [Safety features](#safety-features) · [Audit](#audit-logging) · [Testing](#testing) · [Reference](#reference)

## Highlights

| Principle | What it means in practice |
| --- | --- |
| **Previewable** | Commands that declare `SupportsShouldProcess` use PowerShell's native `-WhatIf` / `-Confirm`; check command help to confirm support. |
| **Gated** | Applicable high-impact operations need an explicit switch such as `-AllowDestructiveOperation`, and live cleanup also needs the exact target DN. |
| **Verified** | Operations with implemented post-change checks re-query AD for outcomes such as group membership, enabled state, and password state. |
| **Auditable** | Provisioning and lifecycle commands write JSONL records for the actions they instrument, including failures and verification outcomes. |
| **Rerun-safe** | Existing matching identities are detected before creation, so repeating a run does not create duplicate or colliding accounts. |
| **Least privilege** | Department administrators get narrowly scoped create/delete and read rights; sensitive attribute writes are reserved for separately reviewed delegation. |
| **Reversible where possible** | Run-scoped rollback for failed provisioning, plus a session ledger that can undo eligible lifecycle changes. |

## Architecture

```mermaid
flowchart TD
    subgraph Entry["Entry points"]
        Console["ControlConsole.ps1"]
        Scripts["Cmdlets entry scripts"]
        Wrappers["Compatibility wrappers"]
    end
    subgraph API["Modules/ADAutoX.psd1 - ADAutoX API"]
        Core["ADAutoX.psm1<br/>shared APIs and ledger"]
        Lifecycle["ADAutoX.Lifecycle.psm1<br/>lifecycle API and guard"]
        Operations["AD-Operations.psm1<br/>AD context, helpers, audit"]
    end
    Preflight["Invoke-ADAutoXPreflight<br/>provisioning checks"]
    Provision["Provisioning<br/>mark42.ps1 / module"]
    LifecycleActions["Lifecycle actions"]
    Verify["Post-change verification<br/>where implemented"]
    Records["JSONL audit, reports<br/>and in-memory rollback ledger"]
    AD[("Active Directory")]

    Console --> Scripts
    Wrappers --> Scripts
    Scripts --> Core
    Scripts --> Lifecycle
    Core --> Preflight
    Preflight --> Provision
    Lifecycle --> LifecycleActions
    Provision --> AD
    LifecycleActions --> AD
    AD --> Verify
    Provision --> Records
    LifecycleActions --> Records
    Verify --> Records
    Operations -.-> Core
    Operations -.-> Lifecycle
```

`Invoke-ADAutoXPreflight` is the one provisioning-preflight implementation; the older `Test-ADProvisioningPreflight` entry delegates to it. Lifecycle actions use their own target checks and protected-account guard, not the provisioning preflight.

AD object ACL reads and writes resolve the exact distinguished name on the pinned domain controller before using the shared `DirectoryServices` LDAP helper; they do not depend on the `AD:` provider path. Planned OUs that are not present yet are reported as pending creation during preflight. To diagnose a DC-specific ACL issue, run `.\Tests\Diagnose-ADAcl.ps1` from the repository root, optionally specifying `-Server`, `-DistinguishedName`, and `-Credential`.

```text
AD_PS-automation/
├── Cmdlets/   command scripts (mark42.ps1 is the canonical provisioner)
├── Modules/   ADAutoX.psd1 manifest and implementation modules
├── Data/      sample-names.txt
├── Tests/     validate_repo.ps1, Run-OfflineTests.ps1, Diagnose-ADAcl.ps1
├── README.md  short project overview
└── PROJECT_GUIDE.md  detailed technical documentation
```

Run command scripts from the repository root using their `.\Cmdlets\...` paths.

### Compatibility wrappers

These legacy scripts preserve older command names or parameter interfaces and forward work to the listed canonical script or module function. They are adapters, not separate implementations of the forwarded operation. `ActiveDirectory-Provisioner.ps1` and `Generate-ADUsers.ps1` retain legacy provisioning defaults, so review their parameter descriptions before use.

| Legacy script | Forwards to |
| --- | --- |
| [`ActiveDirectory-Provisioner.ps1`](./Cmdlets/ActiveDirectory-Provisioner.ps1) | Canonical [`mark42.ps1`](./Cmdlets/mark42.ps1) |
| [`Generate-ADUsers.ps1`](./Cmdlets/Generate-ADUsers.ps1) | Canonical [`mark42.ps1`](./Cmdlets/mark42.ps1), with legacy defaults |
| [`Manage-ADAutoXUser.ps1`](./Cmdlets/Manage-ADAutoXUser.ps1) | `Invoke-ADAutoXUserAction`; `-AllowProtectedAccount` is forwarded for guarded actions |
| [`Remove-Test-Users.ps1`](./Cmdlets/Remove-Test-Users.ps1) | [`2_RESET_TEST_USERS.ps1`](./Cmdlets/2_RESET_TEST_USERS.ps1) |
| [`Reset-ADAutoXEnvironment.ps1`](./Cmdlets/Reset-ADAutoXEnvironment.ps1) | `Invoke-ADAutoXLedgerRollback` with `-RollbackLedger`; otherwise [`Remove-Test-Users.ps1`](./Cmdlets/Remove-Test-Users.ps1) |
| [`Script_AD_Audit_Report.ps1`](./Cmdlets/Script_AD_Audit_Report.ps1) | `Get-ADAutoXAuditReport` |
| [`Script_AD_Security_Report.ps1`](./Cmdlets/Script_AD_Security_Report.ps1) | `Get-ADAutoXSecurityScan` |
| [`Script_Add_User_to_Group.ps1`](./Cmdlets/Script_Add_User_to_Group.ps1) | `Set-ADAutoXUserGroupMembership` (add action) |
| [`Script_Delete_User.ps1`](./Cmdlets/Script_Delete_User.ps1) | `Remove-ADAutoXUser` |
| [`Script_Disable_Inactive_Users.ps1`](./Cmdlets/Script_Disable_Inactive_Users.ps1) | `Disable-ADAutoXUser` when `-Identity` is supplied; otherwise `Disable-ADAutoXInactiveUsers` |
| [`Script_Disable_User.ps1`](./Cmdlets/Script_Disable_User.ps1) | `Disable-ADAutoXUser` |
| [`Script_Enable_User.ps1`](./Cmdlets/Script_Enable_User.ps1) | `Enable-ADAutoXUser` |
| [`Script_Find_Locked-Out_Users.ps1`](./Cmdlets/Script_Find_Locked-Out_Users.ps1) | `Get-ADAutoXLockedOutUsers` |
| [`Script_Move_User.ps1`](./Cmdlets/Script_Move_User.ps1) | `Move-ADAutoXUser` |
| [`Script_Remove_User_from_Group.ps1`](./Cmdlets/Script_Remove_User_from_Group.ps1) | `Set-ADAutoXUserGroupMembership` (remove action) |
| [`Script_Reset_User_Passwords.ps1`](./Cmdlets/Script_Reset_User_Passwords.ps1) | `Reset-ADAutoXUserPassword` |
| [`Script_Terminate_User.ps1`](./Cmdlets/Script_Terminate_User.ps1) | `Stop-ADAutoXUser` |
| [`Script_Unlock_User_Account.ps1`](./Cmdlets/Script_Unlock_User_Account.ps1) | `Unlock-ADAutoXUser` |

Use the `ADAutoX` module or canonical `Cmdlets` commands for new automation, and check command help because parameters and defaults can differ across wrappers.

## Quick start

**Requirements**

- Windows PowerShell 5.1 or PowerShell 7+
- The `ActiveDirectory` module (install RSAT if `Import-Module ActiveDirectory` fails)
- Network access to a writable domain controller
- An account with the delegated rights you intend to use
- A dedicated test OU and an approved change window

**Run it**

```powershell
# 1. From the repository root, confirm AD connectivity
Import-Module ActiveDirectory
Get-ADDomain

# 2. Preview guarded changes; read-only AD queries and preview records may still occur
.\Cmdlets\mark42.ps1 -AccountCount 5 -WhatIf

# Preview an individual lifecycle action
.\Cmdlets\Manage-ADAutoXUser.ps1 -Identity 'jdoe' -Action Disable -WhatIf

# Preview cleanup before deciding whether to apply it
.\Cmdlets\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -WhatIf

# Read-only audit review
.\Cmdlets\Script_AD_Audit_Report.ps1

# Preview cleanup; do not apply until the target DN and plan have been reviewed
.\Cmdlets\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -WhatIf
```

For any approved live change, rerun the reviewed command without `-WhatIf` and supply any required destructive-operation switch and exact target confirmation. A preview is not an offline simulation: read-only Active Directory queries can still run.

In multi-DC environments, pass `-Server <dc>` to choose the writable DC. If you omit it, one writable DC is resolved at startup and reused for the whole run, including verification and delegation changes.

## How a provisioning run works

```mermaid
flowchart LR
    A["Resolve one<br/>writable DC"] --> B["Preflight checks<br/>OU, admin group, delegation"]
    B --> C["Create OUs and<br/>department groups"]
    C --> D["Apply scoped<br/>delegation"]
    D --> E["Create users<br/>collision-safe names"]
    E --> F["Verify attributes<br/>and group membership"]
    F --> G["CSV report +<br/>JSONL audit"]
```

1. **Preflight:** resolves a writable DC, checks dependencies, validates department names and passwords, detects naming conflicts, and checks that existing groups have the expected scope and delegation.
2. **Provision:** creates missing OUs, department groups, administrator accounts, standard accounts, memberships, and scoped delegation. Compatible existing resources are reused, not recreated.
3. **Verify:** re-queries created accounts and checks department, UPN, OU, enabled state, required password change, and group membership.
4. **Report:** prints a run summary and writes the CSV report and JSONL audit events. The report includes execution context (domain, forest, DC, operator, timestamp, PowerShell version, OS).

Standard users are assigned to departments round-robin and placed in the department's `Users` OU. Department administrator accounts go in its `Administrators` OU. Generated account names are checked against existing AD accounts and names from the same run, then given a numeric suffix if needed.

For a stricter sequence, add `-EnableAccountsAfterVerification`: accounts are created disabled, verified, then enabled and verified again.

### Default OU layout

```text
Company
  Staff
    IT / HR / Finance / Sales        (default departments)
      Users
      Administrators
```

Use `-Departments` and `-OrganizationalUnitName` to change the layout, and `-CreateDepartmentAdministrators:$false` to skip administrator accounts.

### Delegation model

| Role | Can | Cannot |
| --- | --- | --- |
| `Department-Administrators` | Create and delete users in their department `Users` OU; list and read user objects there | Broad property writes |
| `Department-Attribute-Admins` | Reserved for explicitly reviewed attribute rights (currently granted nothing) | Password reset, enable/disable, unlock, or anything not individually granted |
| Audit and report consumers | Read the JSONL log and reports | Should have read-only access |

- Administrator groups are validated by expected name, location, security category, Global scope, and SID.
- New delegation is granted only to a group **created during the current run**. A pre-existing group is accepted only if a SID-matched delegation entry already exists.
- Create/delete-child rights apply directly to the department `Users` OU; list/read rights are scoped separately to descendant user objects.

### More provisioning examples

```powershell
# Custom departments
.\Cmdlets\mark42.ps1 -AccountCount 20 -Departments 'Engineering','Support','Operations' -WhatIf

# Custom names file and OU name
.\Cmdlets\mark42.ps1 -NamesPath '.\custom-names.txt' -OrganizationalUnitName '_LAB-USERS' -WhatIf

# Administrators only, with generated names like deptadmin-IT
.\Cmdlets\mark42.ps1 -AdministratorsOnly -AdministratorUsername 'deptadmin-{0}' -WhatIf

# Pin a DC and choose report and audit locations
.\Cmdlets\mark42.ps1 -AccountCount 10 -Server 'dc01.example.com' `
    -ReportPath '.\reports\provisioning.csv' -AuditLogPath '.\logs\operations.jsonl' -WhatIf

# One shared password, prompted securely
$securePassword = Read-Host 'Shared lab password' -AsSecureString
.\Cmdlets\mark42.ps1 -AccountCount 5 -Password $securePassword -WhatIf

# Preview provisioning with an opt-in DPAPI-protected credential export
.\Cmdlets\mark42.ps1 -AccountCount 5 -ExportPasswords -PasswordFile '.\user-passwords.clixml' -WhatIf
```

## User lifecycle

Lifecycle commands resolve an identity by SAM account name or distinguished name, verify the outcome where supported, and restore shared AD context in `finally`. Disable, terminate, delete, and group-removal actions require `-AllowDestructiveOperation` on top of preview and confirmation.

```powershell
# Preview an individual lifecycle action
.\Cmdlets\Manage-ADAutoXUser.ps1 -Identity 'jdoe' -Action Disable -WhatIf

# Preview a move and a termination
.\Cmdlets\Manage-ADAutoXUser.ps1 -Identity 'jdoe' -Action Move `
    -TargetOU 'OU=Users,OU=HR,OU=Staff,OU=Company,DC=example,DC=com' -WhatIf
.\Cmdlets\Manage-ADAutoXUser.ps1 -Identity 'jdoe' -Action Terminate `
    -Reason 'Employment ended' -TargetOU 'OU=Disabled,OU=Company,DC=example,DC=com' -WhatIf

# Find and clear locked accounts, scan for risky accounts
.\Cmdlets\Script_Find_Locked-Out_Users.ps1 -CsvPath '.\reports\locked.csv'
.\Cmdlets\Script_Unlock_User_Account.ps1 -Identity 'jdoe' -WhatIf
.\Cmdlets\Get-ADAutoXSecurityScan.ps1 -InactiveDays 90
```

### The ADAutoX module

`Modules\ADAutoX.psd1` is the supported module entry point. Import it once to use the shared provisioning, lifecycle, context, credential-export, and audit functions:

```powershell
Import-Module .\Modules\ADAutoX.psd1
Get-Command -Module ADAutoX

Invoke-ADAutoXProvision -AccountCount 5 -WhatIf
Move-ADAutoXUser -Identity 'jdoe' -TargetPath 'OU=Users,OU=IT,OU=Staff,OU=Company,DC=example,DC=com' -WhatIf
Disable-ADAutoXUser -Identity 'jdoe' -AllowDestructiveOperation -WhatIf
```

The [compatibility wrapper list](#compatibility-wrappers) maps each legacy script to its module function or canonical script. `Terminate-ADAutoXUser` remains available as a compatibility alias for `Stop-ADAutoXUser`, and `Manage-ADAutoXUser` remains an alias for `Invoke-ADAutoXUserAction`. Module imports resolve relative to the importing script, so the repository can be cloned anywhere.

### Rollback ledger

Successful reversible lifecycle changes are recorded in a session-scoped ledger: enablement state, moves, direct group membership, termination descriptions, and department/company updates. Rollback checks that each object still has the state produced by the recorded change before restoring it, so it avoids overwriting later changes. Lifecycle entries are processed newest-first; created resources are removed in dependency order (users, delegation, groups, then deepest OUs). Ledger entries are removed after successful rollback processing.

```powershell
# Review pending entries, then preview the reversal in the same session
Get-ADAutoXLedger
.\Cmdlets\Reset-ADAutoXEnvironment.ps1 -RollbackLedger `
    -ExpectedDistinguishedName 'OU=Company,DC=example,DC=com' -WhatIf
```

`Add-ADAutoXLedgerEntry` is the shared writer for resource and lifecycle entries. `Invoke-ADAutoXLedgerRollback` handles eligible OU, group, user, delegation, and lifecycle undo entries. The ledger lives only in the current PowerShell session. Password resets, unlocks, and deletions cannot be restored by it, and it never deletes the environment OU.

## Safety features

**Before a change**

- **Single preflight:** `Invoke-ADAutoXPreflight` contains the provisioning preflight logic. The compatibility function `Test-ADProvisioningPreflight` delegates to it. It performs non-mutating dependency, domain, input, OU, group, and delegation checks applicable to the requested provisioning run. Lifecycle commands resolve and validate their targets, but do not run this provisioning preflight.
- **Protected-account guard:** applicable lifecycle actions refuse accounts with `AdminCount = 1`, membership in the configured protected groups, `IsCriticalSystemObject = $true`, built-in SAM names (`Administrator`, `Guest`, `krbtgt`), or the account running the script. Accidental-deletion protection is checked for termination and deletion. An explicit `-AllowProtectedAccount` bypass logs a warning and audit entry; use it only with specific approval. The check is not a substitute for reviewing the target and change.
- **`-WhatIf` / `-Confirm`:** commands that declare `SupportsShouldProcess` can preview or confirm their guarded changes. Read-only AD queries and preflight checks may still run during `-WhatIf`; it is not an offline simulation. Check command help rather than assuming every script supports these common parameters.
- **Pinned AD provider drive:** the tools create `AD:` for the selected domain controller and refuse an unowned pre-existing `AD:` drive whose server cannot be verified. On systems where the ActiveDirectory module auto-mounts that drive, remove it before starting the automation in a clean session. ACL paths retain the DN and escape Active Directory provider path separators.
- Cleanup commands refuse protected built-in targets (such as `Domain Controllers`), check the exact target DN before live deletion, and process descendants before parents.
- Bulk inactivity scans over the whole domain require `-AllowDomainWide`.

**Rollback**

- **Unified rollback ledger:** `Add-ADAutoXLedgerEntry` is the shared writer for run-created OUs, groups, users, exact delegation entries, and supported reversible lifecycle changes. `Invoke-ADAutoXLedgerRollback` processes eligible entries, checks current state before undoing, and processes lifecycle undo entries before created resources. It does not restore password resets, unlocks, or deletions, and the ledger does not survive the PowerShell session.
- `-RollbackCreatedAccountsOnFailure` (aliases `-RollbackOnFailure`, `-RollbackAccountsOnFailure`) removes only accounts created by the current run.
- `-RollbackCreatedResourcesOnFailure`, used by the ADAutoX provisioning adapter, also attempts to remove run-created groups, the exact delegation entries added by the run, and empty OUs carrying the provisioner marker. It never recursively deletes an OU, and pre-existing resources are kept.
- Rollback is best-effort. Verify the directory and logs afterwards.

**Audit**

- **JSONL audit:** instrumented provisioning and lifecycle actions write structured JSON Lines records to `AD-Operations.jsonl` by default (or the supplied `-AuditLogPath`). Coverage is per command/action; do not assume every read or mutation is logged.

**Credentials**

- Passwords are generated randomly per account by default and are **not** stored unless you opt in.
- `-ExportPasswords` writes a DPAPI-protected CLIXML credential export on Windows. The staged file is ACL-restricted to the current Windows identity before publication; an existing destination is not replaced without `-OverwritePasswordFile`. This is not a credential vault: restrict access and set a retention policy.
- `-IncludePasswordInReport` writes **plaintext** passwords to the CSV. Use it only for a specific, approved, short-lived need and delete the report promptly.
- Keep plaintext credentials out of scripts, shell history, and shared folders.

**Operational**

- Audit logs and reports contain operator, machine, account, and OU data. Keep them local, access-controlled, and out of version control.
- Use a dedicated test OU and confirm the domain, OU path, and naming before any live run.
- Provisioning reuses matching existing OUs and groups. A retry may grant missing delegation to an existing administrator group only when the JSONL audit log contains a successful `CreateGroup` record for that exact group DN; otherwise the pre-existing-group safety guard still refuses the grant.

## Audit logging

Records are written as JSON Lines to `AD-Operations.jsonl` by default, with these fields:

`Timestamp`, `Actor`, `Computer`, `Action`, `Target`, `TargetType`, `Status`, `Message`, `Details`, `Source`, `CorrelationId`

```powershell
.\Cmdlets\Script_AD_Audit_Report.ps1                                        # summary
.\Cmdlets\Script_AD_Audit_Report.ps1 -Identity 'jdoe'                       # one identity
.\Cmdlets\Script_AD_Audit_Report.ps1 -Action 'CreateUser' -Status 'Failed'  # filtered
.\Cmdlets\Get-ADAutoXAuditReport.ps1 -Status 'Failed'                       # module-based report
```

Both report scripts share the same parser and filters; the legacy script keeps its summary/JSON output and strict handling of malformed records. Previews and declined confirmations are logged differently from attempted changes. If a change was attempted but a later step failed, the status can be `CompletedWithErrors`: **inspect the target object before retrying**, because part of the change may already have taken effect.

## Testing

The Mark 42 provisioning script has been tested successfully in the lab. Testing of the remaining scripts is in progress. The offline checks below do not require an AD connection and do not make changes to Active Directory:

```powershell
.\Tests\validate_repo.ps1      # parse every .ps1 and .psm1; exits nonzero on parser errors
.\Tests\Run-OfflineTests.ps1   # offline regression suite
```

Run the regression suite from the repository root in Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\Tests\Run-OfflineTests.ps1
# Or explicitly:
powershell.exe -NoProfile -File .\Tests\Run-OfflineTests.ps1
```

The offline suite exercises pure helpers and checks implementation wiring and safety contracts without connecting to AD or faking AD responses. The separate `Run-ADIntegrationTests.ps1` is opt-in and requires `-RunLive`; it is intended only for a disposable test domain. It has **not yet been verified in a live domain**. To attempt that integration test in an authorized test environment:

```powershell
.\Tests\Run-ADIntegrationTests.ps1 -RunLive -ExpectedDomainDnsRoot 'lab.example.test'
```

It securely prompts for a temporary password, verifies that the connected domain matches the supplied DNS root before changes, then provisions uniquely named test resources and rolls back only entries created by that test run. A writable DC and sufficient OU/group/delegation rights are required. The test stops if the current session ledger is not empty. It is not part of the offline suite.

The suite covers LDAP/DN escaping, identity and error classification, inactivity cutoffs, termination notes, safe file publishing, credential-export guards, wrapper forwarding and rollback, audit filtering and correlation IDs, lifecycle ledger behavior, provisioning and name handling, password generation and patterns, context cleanup, group validation, and delegated ACL scope.

**Not covered:** AD provider behavior, Windows ACL enforcement, permissions, replication, domain policy, and live rollback. Verify those in an authorized lab with a writable DC and a dedicated test OU.

## Limitations

- **Canonical rollback is account-only.** `mark42.ps1 -RollbackCreatedAccountsOnFailure` removes accounts created by the run; guarded resource cleanup is available through the ADAutoX adapter's `-RollbackOnFailure`, and non-empty or unmarked OUs are left in place.
- **Batches continue after a single failure.** The canonical rollback removes only the failing account; the ADAutoX adapter lets the batch finish, then rolls back all run-created resources if anything failed. Unexpected run-level failures trigger rollback immediately.
- **The ledger is in memory** and does not survive a PowerShell restart.
- **`Department-Attribute-Admins` is a placeholder:** the group is created but granted no rights until you add reviewed ones.
- **Windows only** for credential export and ACL handling.
- **Inactivity data is approximate.** `LastLogonDate` comes from replicated `lastLogonTimestamp` and can lag by up to 14 days.

## Cleanup

Live cleanup requires `-ExpectedDistinguishedName` to match the target OU DN printed by the `-WhatIf` preview exactly. Replace the example domain with the DN from your preview.

```powershell
.\Cmdlets\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -WhatIf
.\Cmdlets\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -RemoveAllObjects `
    -RemoveOrganizationalUnit -WhatIf
.\Cmdlets\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -DeleteEverything -WhatIf
```

These are previews only. After reviewing the output and confirming the exact DN, an approved live cleanup must be rerun with the required destructive-operation switch and `-ExpectedDistinguishedName`.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| AD module unavailable | `Get-Module -ListAvailable ActiveDirectory`, then install RSAT and `Import-Module ActiveDirectory` |
| Access denied | The account's delegated rights and reachability of the target DC |
| Names file not found | Confirm the custom `-NamesPath` exists; the default is `Data\sample-names.txt` |
| User creation fails | Read the emitted failure details. Usual causes: naming collisions, password-policy violations, missing permissions, DC reachability, or conflicting existing objects |

## Reference

Details for every script, parameter, and module. Click a heading to expand.

<details>
<summary><strong><code>mark42.ps1</code> parameters</strong></summary>

&nbsp;

The default live run requests 20 standard users, creates department administrator accounts, and writes the CSV report and JSONL audit log at the repository root. Relative paths you supply are resolved from the PowerShell location where you run the command; built-in defaults are based on the repository location.

| Parameter | Default | Description |
| --- | --- | --- |
| `-AccountCount` | `20` | Standard users to request (0–1000). `0` means every valid name in the names file; if fewer valid names exist, the count is reduced with a warning. |
| `-OrganizationalUnitName` | `Company` | Top-level OU created beneath the domain root. |
| `-StaffNamesOrganizationalUnitName` | `Staff` | OU beneath the top-level OU that holds department OUs. |
| `-Departments` | `IT`, `HR`, `Finance`, `Sales` | Departments to provision, assigned round-robin. Names are validated first. |
| `-NamesPath` | `Data\sample-names.txt` | UTF-8 names file. Each nonblank line is a first name followed by a surname. |
| `-AdministratorsOnly` | Off | Provision only department administrator OUs, groups, and accounts; skips the names file. |
| `-CreateDepartmentAdministrators` | On | Create an administrator account and groups per department. Pass `:$false` to opt out. |
| `-AdministratorUsername` | `<department>.admin` | Administrator SAM-account-name template. Use `{0}` for the department name, e.g. `deptadmin-{0}`. Required when one custom base name spans several departments. |
| `-Password` | Random per account | Optional `SecureString` shared by all accounts in the run. Takes precedence over patterns. |
| `-PasswordPattern` | None | Per-account pattern for standard users. `{0}` is the username; `{1}`/`{2}` are the one-based account token. Escape literal braces as `{{` and `}}`. Preflight checks are best-effort; AD enforces the real policy at creation. |
| `-AdministratorPasswordPattern` | None | Pattern for department administrators. `{0}` is the administrator username (and `{1}`/`{2}` resolve to it too). |
| `-EnableAccountsAfterVerification` | Off | Create accounts disabled, verify attributes and memberships, then enable and re-verify. |
| `-Server` | Auto-resolved | Domain controller to use; one writable DC is reused for the whole run. |
| `-Credential` | Current context | `PSCredential` for AD operations. |
| `-UPNSuffix` | Domain DNS root | UPN suffix for created accounts. |
| `-ReportPath` | `AD-Provisioning-Report.csv` at repo root | UTF-8 CSV destination; parent folders are created. |
| `-AuditLogPath` | `AD-Operations.jsonl` at repo root | JSONL audit destination. |
| `-CorrelationId` | New GUID | ID that ties this run's audit records together. |
| `-RollbackCreatedAccountsOnFailure` | Off | Remove accounts created by this run when verification or membership fails. |
| `-RollbackCreatedResourcesOnFailure` | Off | Guarded rollback of run-created accounts, groups, exact delegation entries, and empty provisioner-marked OUs. |
| `-ExportPasswords` | Off | Opt in to the DPAPI-protected CLIXML credential export. |
| `-PasswordFile` | `user-passwords.clixml` when exporting | Export destination. Error if given without `-ExportPasswords`. |
| `-OverwritePasswordFile` | Off | Allow replacing an existing export. |
| `-IncludePasswordInReport` | Off | Add **plaintext** passwords to the CSV. See [Safety features](#safety-features). |
| `-WhatIf` / `-Confirm` / `-Verbose` | | Standard PowerShell preview, confirmation, and diagnostic output. |

Two hidden compatibility parameters, `-TreatZeroAccountCountAsNone` and `-DisableDepartmentAdministratorsByDefault`, exist for the wrapper scripts and are not meant for direct use. Notably, `-AccountCount 0` on `mark42.ps1` means "all valid names", while the `Generate-ADUsers.ps1` wrapper keeps its older meaning of "no standard users" and makes administrator creation opt-in. `ActiveDirectory-Provisioner.ps1` requires an explicit `-PasswordFile` for credential export.

The CSV report records domain, forest, DC, operator, computer, PowerShell version, run time, and per-account username, name, department, role, target OU, status, stage, timestamp, and error details. A password column exists only with `-IncludePasswordInReport`. Run status distinguishes preview, success, skipped, failed, and partial outcomes, so check the report and audit log before retrying a partial run.

</details>

<details>
<summary><strong>Script reference</strong></summary>

&nbsp;

Run from the repository root. Most AD commands also accept `-Server`, `-Credential`, and `-AuditLogPath`. A command supports `-WhatIf` only where it declares it.

**Provisioning and users**

| Script | Purpose | Key inputs |
| --- | --- | --- |
| [`mark42.ps1`](./Cmdlets/mark42.ps1) | Canonical bulk provisioner | See the parameter table above |
| [`ActiveDirectory-Provisioner.ps1`](./Cmdlets/ActiveDirectory-Provisioner.ps1) | Legacy-interface wrapper around `mark42.ps1` | Same provisioning inputs; credential export needs `-PasswordFile` |
| [`Generate-ADUsers.ps1`](./Cmdlets/Generate-ADUsers.ps1) | Legacy generator wrapper keeping older defaults | Similar to `mark42.ps1`; `-AccountCount 0` means no standard users |
| [`Invoke-ADAutoXProvision.ps1`](./Cmdlets/Invoke-ADAutoXProvision.ps1) | Module-backed provisioning adapter | `-CompanyOuName`, `-StaffOuName`, `-RollbackOnFailure`, plus the common provisioning options |
| [`New_User_Script.ps1`](./Cmdlets/New_User_Script.ps1) | Create and verify one user | Required: `-GivenName`, `-Surname`, `-SamAccountName`, `-Path`. Optional: `-UserPrincipalName`, secure `-Password`, `-Department`, `-Title`, `-Description`, `-Disabled`, `-NoChangePasswordAtLogon`. Rejects duplicate SAM/UPN values and never silently deletes a user whose verification failed |
| [`ControlConsole.ps1`](./Cmdlets/ControlConsole.ps1) | Interactive menu: provisioning, audit review, security scan, user management, reset preview, offline tests | No parameters. Passwords are collected as `SecureString`; destructive flows need typed confirmation |

**Export and cleanup**

| Script | Purpose | Key inputs |
| --- | --- | --- |
| [`Export-Test-Users.ps1`](./Cmdlets/Export-Test-Users.ps1) | CSV snapshot of users under an OU | `-OrganizationalUnitName` (default `Company`), `-OutputPath`, `-IncludeGroupMembership`. CSV text is escaped against spreadsheet formula injection |
| [`Remove-Test-Users.ps1`](./Cmdlets/Remove-Test-Users.ps1) | Friendly cleanup wrapper | `-RemoveOrganizationalUnit`, `-RemoveAllObjects`, `-DeleteEverything`; live runs need `-AllowDestructiveOperation` and `-ExpectedDistinguishedName`; `-Force` skips per-object prompts only |
| [`2_RESET_TEST_USERS.ps1`](./Cmdlets/2_RESET_TEST_USERS.ps1) | Performs the scoped cleanup | Same switches; `-RemoveAllObjects` requires `-RemoveOrganizationalUnit`; `-DeleteEverything` implies both |
| [`Reset-ADAutoXEnvironment.ps1`](./Cmdlets/Reset-ADAutoXEnvironment.ps1) | Reverts the session ledger or forwards to guarded cleanup | `-RollbackLedger` with `-ExpectedDistinguishedName`; otherwise `-CompanyOuName` and the cleanup safety switches |

**User lifecycle and groups**

| Script | Purpose | Key inputs |
| --- | --- | --- |
| [`Manage-ADAutoXUser.ps1`](./Cmdlets/Manage-ADAutoXUser.ps1) | Preferred adapter | `-Identity`, `-Action` (`Disable`, `Enable`, `Unlock`, `Move`, `RemoveFromGroup`, `ResetPassword`, `Terminate`), optional `-TargetOU`, `-Group`, `-Reason`, secure `-NewPassword`, `-MustChangeAtLogon`, `-AllowProtectedAccount` |
| [`Invoke-ADAutoXUserLifecycle.ps1`](./Cmdlets/Invoke-ADAutoXUserLifecycle.ps1) | General dispatcher | `-Action` (adds `Delete` and `AddToGroup`), `-Identity`, `-TargetPath`, `-Group`, `-Reason`, `-AllowProtectedAccount` |
| `Script_Enable_User.ps1`, `Script_Unlock_User_Account.ps1` | Enable or unlock one account | `-Identity` |
| `Script_Disable_User.ps1`, `Script_Delete_User.ps1` | Disable or delete one account | `-Identity`, `-AllowDestructiveOperation`, optional `-AllowProtectedAccount` |
| `Script_Terminate_User.ps1` | Disable, optionally move to `-TerminationOU`, and append `-TerminationReason` to the description | `-Identity`, `-AllowDestructiveOperation`, optional `-AllowProtectedAccount`. Existing description text is kept and length is checked |
| `Script_Move_User.ps1` | Move one account | `-Identity`, `-TargetPath`, optional `-AllowProtectedAccount` |
| `Script_Add_User_to_Group.ps1`, `Script_Remove_User_from_Group.ps1` | Change group membership (verified) | `-Identity`, `-Group`, optional `-AllowProtectedAccount`; removal also needs `-AllowDestructiveOperation` |
| `Script_Reset_User_Passwords.ps1` | Set a password | `-Identity`, secure `-NewPassword`, `-MustChangeAtLogon`, optional `-AllowProtectedAccount` |

All of the `Script_*.ps1` files above live in [`Cmdlets/`](./Cmdlets).

**Account health and reporting**

| Script | Purpose | Key inputs |
| --- | --- | --- |
| `Script_Disable_Inactive_Users.ps1`, [`Disable-ADAutoXInactiveUsers.ps1`](./Cmdlets/Disable-ADAutoXInactiveUsers.ps1) | Disable one account or run the bulk inactivity workflow | `-InactiveDays` (default 90, 1–3650), `-SearchBase`, `-IncludeNeverLoggedOn`, `-CsvPath`; domain-wide scans need `-AllowDomainWide`; applying needs `-AllowDestructiveOperation`; optional `-AllowProtectedAccount` |
| `Script_Find_Locked-Out_Users.ps1`, [`Get-ADAutoXLockedOutUsers.ps1`](./Cmdlets/Get-ADAutoXLockedOutUsers.ps1) | Find locked-out accounts | `-SearchBase`, `-CsvPath` |
| [`Get-ADAutoXSecurityScan.ps1`](./Cmdlets/Get-ADAutoXSecurityScan.ps1) | Structured posture scan: locked-out, password-never-expires, inactive | `-SearchBase`, `-InactiveDays`. Read-only |
| `Script_AD_Security_Report.ps1` | Human-readable security summary including privileged users and department administrator counts | `-SearchBase`, `-DomainName`, `-Departments`, `-OrganizationalUnitName`. Without `-SearchBase` it falls back to a domain-wide scan, so set a scope deliberately |
| [`Update-ADAutoXUserDepartments.ps1`](./Cmdlets/Update-ADAutoXUserDepartments.ps1) | Derive department attributes from the OU layout | Required `-SearchBase`; `-CompanyName` (default `Company`); supports `-WhatIf` |
| `Script_AD_Audit_Report.ps1` | Read-only JSONL audit summary and timeline (no AD connection needed) | `-AuditLogPath`, `-Identity`, `-Action`, `-Status` (`Started`, `Succeeded`, `Failed`, `Skipped`, `Preview`, `CompletedWithErrors`), `-OutputPath`, `-AsJson` |
| [`Get-ADAutoXAuditReport.ps1`](./Cmdlets/Get-ADAutoXAuditReport.ps1) | Module-based audit filter and CSV export | Adds `-Actor` to the filters above |

</details>

<details>
<summary><strong>Module API</strong></summary>

&nbsp;

Import the manifest rather than the implementation files. It requires PowerShell 5.1 or later, loads the implementation modules, exports the public functions, and provides `Terminate-ADAutoXUser` as an alias for `Stop-ADAutoXUser`. Use `Get-Command -Module ADAutoX` for the exact exported names.

| Module file | Responsibility |
| --- | --- |
| [`ADAutoX.psd1`](./Modules/ADAutoX.psd1) | Supported manifest: minimum PowerShell version, function and alias exports |
| [`ADAutoX.psm1`](./Modules/ADAutoX.psm1) | Loader and facade: provisioning, lifecycle entry points, security scan, audit report, context and preflight, rollback ledger, password/identity/LDAP/ACL/credential/log helpers |
| [`ADAutoX.Lifecycle.psm1`](./Modules/ADAutoX.Lifecycle.psm1) | Shared lifecycle dispatcher and guarded actions (enable, disable, unlock, reset, move, terminate, delete, group changes), inactivity and locked-out workflows, department updates, audit and ledger support |
| [`AD-Operations.psm1`](./Modules/AD-Operations.psm1) | AD module loading, server/credential context with restoration, safe identity and OU resolution, LDAP/DN escaping, preflight checks, secure file publishing, CSV helpers, structured audit output |
| [`AD-Provisioning.psm1`](./Modules/AD-Provisioning.psm1) | Provisioning validation, password generation and patterns, collision-safe names, OU/group/user creation and verification, delegation, reports, rollback helpers |

</details>

## Disclaimer

Outside `-WhatIf`, these scripts make real changes to Active Directory: creating accounts, resetting passwords, changing group membership, and deleting objects. Use them only where you are authorized, and always:

1. Preview with `-WhatIf`
2. Test on a small batch
3. Review the audit log
4. Confirm the domain, OU path, and naming
5. Follow change control for anything beyond a lab

For a concise project overview, see [README.md](./README.md).
