# AD_PS-automation

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-5391D5?logo=powershell&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Automation-2DDE98?logo=microsoft&logoColor=white)
![Scope](https://img.shields.io/badge/Scope-Lab%20%2F%20Controlled%20Use-FF6B6B)

AD_PS-automation is a PowerShell toolkit for repeatable Active Directory provisioning, user lifecycle operations, security and audit reporting, and controlled lab cleanup. Its `ADAutoX` module provides the public API and shared context, validation, safety, verification, logging, and rollback services. Module-backed commands import it directly; compatibility wrappers forward to a canonical script or module function.

> **Scope:** Designed for lab, test, and carefully controlled administrative use. Production use requires your organization's security review, authorization, and change-control process.

## Contents

- [Capabilities](#capabilities)
- [Requirements and setup](#requirements-and-setup)
- [Quick start](#quick-start)
- [Provisioning model](#provisioning-model)
- [User lifecycle and reports](#user-lifecycle-and-reports)
- [Safety, audit, and rollback](#safety-audit-and-rollback)
- [Modules at a glance](#modules-at-a-glance)
- [Command reference](#command-reference)
- [Testing and verification](#testing-and-verification)
- [Repository layout](#repository-layout)
- [Detailed technical guide](#detailed-technical-guide)

## Capabilities

- Provision department-based OUs, security groups, standard users, department administrator accounts, and scoped delegation.
- Perform user lifecycle actions: enable, disable, unlock, reset password, move, terminate, delete, and change group membership.
- Find locked accounts, scan account posture, update department attributes, and export user data.
- Produce structured provisioning reports and JSONL audit logs, plus filtered audit summaries and security reports.
- Preview supported changes with PowerShell `-WhatIf` and `-Confirm`; gate applicable high-impact operations with explicit approval switches.
- Verify outcomes where implemented and roll back eligible run-created or lifecycle changes.

## Requirements and setup

- Windows PowerShell 5.1 or PowerShell 7 on Windows.
- The Active Directory PowerShell module (RSAT) available to the selected PowerShell session.
- Network access to an appropriate domain controller and an account with the rights needed for the requested operation.
- For provisioning, use a dedicated test OU or disposable test domain until the exact plan and permissions have been reviewed.

From the repository root, confirm the Active Directory module and domain are available:

```powershell
Import-Module ActiveDirectory
Get-ADDomain
```

The supported module entry point is `Modules\ADAutoX.psd1`:

```powershell
Import-Module .\Modules\ADAutoX.psd1
Get-Command -Module ADAutoX
```

Module-backed scripts load project modules relative to their own location, while compatibility wrappers locate their target script relative to themselves. Run commands from the repository root using `.\Cmdlets\...` paths. Relative paths supplied as command parameters are resolved from the current PowerShell location unless a command documents otherwise.

## Quick start

Validate the repository and run the offline regression suite:

```powershell
.\Tests\validate_repo.ps1
.\Tests\Run-OfflineTests.ps1
```

Preview provisioning without making provisioning changes:

```powershell
.\Cmdlets\mark42.ps1 -AccountCount 5 -WhatIf
```

Preview a lifecycle action. Disable, terminate, delete, and group-removal actions also require their explicit destructive-operation switch, including for preview:

```powershell
.\Cmdlets\Script_Disable_User.ps1 -Identity 'jdoe' -AllowDestructiveOperation -WhatIf
.\Cmdlets\Script_Move_User.ps1 -Identity 'jdoe' `
    -TargetPath 'OU=Users,OU=IT,OU=Staff,OU=Company,DC=example,DC=com' -WhatIf
```

Review the command output, target distinguished name, audit record, and any generated report before approving a live operation. `-WhatIf` is not an offline simulation: read-only Active Directory queries and preflight checks can still run.

## Provisioning model

[`mark42.ps1`](./Cmdlets/mark42.ps1) is the canonical bulk provisioner. By default, it requests 20 standard users, uses the departments IT, HR, Finance, and Sales, creates department administrator accounts, and builds this OU layout beneath the domain:

```text
Company
└── Staff
    ├── IT
    │   ├── Users
    │   └── Administrators
    ├── HR
    │   ├── Users
    │   └── Administrators
    ├── Finance
    │   ├── Users
    │   └── Administrators
    └── Sales
        ├── Users
        └── Administrators
```

Names are read from [`Data/sample-names.txt`](./Data/sample-names.txt) by default. Standard users are distributed across departments; generated account names are checked for collisions. Existing compatible resources are reused rather than recreated.

Provisioning follows four stages:

1. **Preflight:** resolve a writable domain controller; check dependencies, inputs, domain, naming conflicts, OUs, groups, permissions, and applicable delegation.
2. **Provision:** create the requested OUs, groups, users, memberships, and scoped delegation.
3. **Verify:** re-query created accounts and verify configured attributes, locations, enablement, and memberships where supported.
4. **Report:** emit a console summary, CSV report, and structured audit records.

Useful options include `-Departments`, `-OrganizationalUnitName`, `-NamesPath`, `-AdministratorsOnly`, `-CreateDepartmentAdministrators:$false`, `-Server`, `-Credential`, `-ReportPath`, and `-AuditLogPath`. `-EnableAccountsAfterVerification` creates accounts disabled, verifies them, then enables and verifies them. Passwords are generated per account by default; review the [technical guide](./PROJECT_GUIDE.md) for password patterns, export controls, rollback options, and the complete parameter reference.

## User lifecycle and reports

Use the named scripts for a single task or [`Manage-ADAutoXUser.ps1`](./Cmdlets/Manage-ADAutoXUser.ps1) for common lifecycle actions. The general dispatcher, [`Invoke-ADAutoXUserLifecycle.ps1`](./Cmdlets/Invoke-ADAutoXUserLifecycle.ps1), additionally exposes delete and group-add actions. The guide's [dispatcher reference](./PROJECT_GUIDE.md#compatibility-wrappers) describes their differing action sets and parameter names.

| Action | Script or entry point |
| --- | --- |
| Enable, disable, unlock, reset password, move, terminate, delete | `Script_Enable_User.ps1`, `Script_Disable_User.ps1`, `Script_Unlock_User_Account.ps1`, `Script_Reset_User_Passwords.ps1`, `Script_Move_User.ps1`, `Script_Terminate_User.ps1`, `Script_Delete_User.ps1` |
| Add or remove group membership | `Script_Add_User_to_Group.ps1`, `Script_Remove_User_from_Group.ps1` |
| Find locked accounts | `Script_Find_Locked-Out_Users.ps1` |
| Disable inactive accounts | `Script_Disable_Inactive_Users.ps1` or `Disable-ADAutoXInactiveUsers.ps1` |
| Security posture report | `Script_AD_Security_Report.ps1` or `Get-ADAutoXSecurityScan.ps1` |
| Audit report | `Script_AD_Audit_Report.ps1` or `Get-ADAutoXAuditReport.ps1` |
| Update department attributes | `Update-ADAutoXUserDepartments.ps1` |
| Create and verify one account | `New_User_Script.ps1` |
| Export users to CSV | `Export-Test-Users.ps1` |

Locked-account discovery uses `Search-ADAccount -LockedOut -UsersOnly` and then retrieves the user properties required for the report. Security reporting supports an optional `-SearchBase`; when omitted it uses the configured company OU when found, otherwise the domain scope. Review the report command's help and parameters before using a broad search.

## Safety, audit, and rollback

- **Preview and confirmation:** only commands declaring `SupportsShouldProcess` accept `-WhatIf` and `-Confirm`. Check `Get-Help <command> -Full`; common parameters are not guaranteed on every script.
- **Destructive-operation gates:** applicable actions require explicit switches such as `-AllowDestructiveOperation`. Cleanup additionally checks the exact target DN; `-Force` does not replace these safeguards.
- **Protected-account checks:** lifecycle operations guard privileged, critical, built-in, and current-operator accounts. `-AllowProtectedAccount` is an explicit, audited bypass where supported.
- **Pinned domain controller:** an operation resolves or accepts a DC and uses a consistent AD context. An unowned pre-existing `AD:` provider drive that cannot be verified is rejected; start a clean session or remove the conflicting drive as appropriate.
- **Audit trail:** instrumented operations append JSONL records to `AD-Operations.jsonl` by default. Use `-AuditLogPath` to select another destination. Audit coverage is action-specific; it is not a record of every read.
- **Rollback:** the in-memory session ledger can reverse eligible lifecycle operations and remove eligible resources created during a run. It is not durable across PowerShell restarts and cannot restore password resets, unlocks, or deletions. Rollback is best-effort; inspect AD and the audit log afterward.
- **Credential handling:** credential export is opt-in and Windows DPAPI-protected. `-IncludePasswordInReport` explicitly writes plaintext passwords to CSV and should be avoided unless specifically approved and securely handled.
- **Scoped delegation:** department administrators receive narrowly scoped permissions. Sensitive attribute rights are not granted by default.

Reports and logs can contain account names, distinguished names, operator details, and machine information. Store them with appropriate access controls, exclude sensitive output from source control, and follow your retention policy.

## Modules at a glance

Import [`ADAutoX.psd1`](./Modules/ADAutoX.psd1), the supported module entry point. Its public API is divided across these implementation files:

| Module file | Responsibility |
| --- | --- |
| [`ADAutoX.psd1`](./Modules/ADAutoX.psd1) | Manifest, PowerShell minimum version, exported functions, and aliases. |
| [`ADAutoX.psm1`](./Modules/ADAutoX.psm1) | Module loader and facade for provisioning, security scans, shared context, preflight, and rollback. |
| [`ADAutoX.Lifecycle.psm1`](./Modules/ADAutoX.Lifecycle.psm1) | Guarded user lifecycle actions, inactivity and locked-account workflows, department updates, audit, and lifecycle ledger operations. |
| [`AD-Operations.psm1`](./Modules/AD-Operations.psm1) | AD context, identity and OU resolution, LDAP/DN helpers, preflight support, safe file/CSV operations, and audit writing. |
| [`AD-Provisioning.psm1`](./Modules/AD-Provisioning.psm1) | Provisioning validation, password and account-name generation, OU/group/user creation, verification, delegation, reports, and rollback helpers. |

For exported function names and detailed behavior, use `Get-Command -Module ADAutoX` and see the [module reference](./PROJECT_GUIDE.md#reference).

## Command reference

Every script in `Cmdlets\` is indexed below. Run commands from the repository root; review each script's help and the [technical reference](./PROJECT_GUIDE.md#reference) for full parameters, defaults, and safeguards.

| Script | Purpose and notes |
| --- | --- |
| [`mark42.ps1`](./Cmdlets/mark42.ps1) | Canonical bulk provisioner for department OUs, groups, users, administrator accounts, scoped delegation, verification, reports, and eligible rollback. |
| [`Invoke-ADAutoXProvision.ps1`](./Cmdlets/Invoke-ADAutoXProvision.ps1) | Module-backed provisioning entry point with company/staff OU options and run rollback. |
| [`ActiveDirectory-Provisioner.ps1`](./Cmdlets/ActiveDirectory-Provisioner.ps1) | Legacy provisioning wrapper; retains older interface conventions. |
| [`Generate-ADUsers.ps1`](./Cmdlets/Generate-ADUsers.ps1) | Legacy generator wrapper; retains legacy defaults, including the meaning of `-AccountCount 0`. |
| [`New_User_Script.ps1`](./Cmdlets/New_User_Script.ps1) | Create and verify one user account. |
| [`Manage-ADAutoXUser.ps1`](./Cmdlets/Manage-ADAutoXUser.ps1) | Lifecycle convenience dispatcher for common user actions. |
| [`Invoke-ADAutoXUserLifecycle.ps1`](./Cmdlets/Invoke-ADAutoXUserLifecycle.ps1) | General lifecycle dispatcher, including delete and group-add actions. |
| [`Script_Enable_User.ps1`](./Cmdlets/Script_Enable_User.ps1) | Enable one user account. |
| [`Script_Disable_User.ps1`](./Cmdlets/Script_Disable_User.ps1) | Disable one user account; protected by the applicable destructive-operation gate. |
| [`Script_Unlock_User_Account.ps1`](./Cmdlets/Script_Unlock_User_Account.ps1) | Unlock one user account. |
| [`Script_Reset_User_Passwords.ps1`](./Cmdlets/Script_Reset_User_Passwords.ps1) | Reset one user's password, with secure password input and optional change-at-logon. |
| [`Script_Move_User.ps1`](./Cmdlets/Script_Move_User.ps1) | Move one user to a specified OU. |
| [`Script_Terminate_User.ps1`](./Cmdlets/Script_Terminate_User.ps1) | Disable a user, optionally move the account, and record a termination reason. |
| [`Script_Delete_User.ps1`](./Cmdlets/Script_Delete_User.ps1) | Delete one user; protected by the applicable destructive-operation gate. |
| [`Script_Add_User_to_Group.ps1`](./Cmdlets/Script_Add_User_to_Group.ps1) | Add a user to a group. |
| [`Script_Remove_User_from_Group.ps1`](./Cmdlets/Script_Remove_User_from_Group.ps1) | Remove a user from a group; requires the applicable destructive-operation approval. |
| [`Script_Disable_Inactive_Users.ps1`](./Cmdlets/Script_Disable_Inactive_Users.ps1) | Disable one identified user or run the inactivity workflow. |
| [`Disable-ADAutoXInactiveUsers.ps1`](./Cmdlets/Disable-ADAutoXInactiveUsers.ps1) | Module-backed bulk inactivity workflow with scoping and approval safeguards. |
| [`Script_Find_Locked-Out_Users.ps1`](./Cmdlets/Script_Find_Locked-Out_Users.ps1) | Find and optionally export locked-out users. |
| [`Get-ADAutoXLockedOutUsers.ps1`](./Cmdlets/Get-ADAutoXLockedOutUsers.ps1) | Module-backed locked-account query. |
| [`Get-ADAutoXSecurityScan.ps1`](./Cmdlets/Get-ADAutoXSecurityScan.ps1) | Structured scan for locked-out, inactive, and password-never-expires accounts. |
| [`Script_AD_Security_Report.ps1`](./Cmdlets/Script_AD_Security_Report.ps1) | Human-readable security report; set a deliberate search scope. |
| [`Update-ADAutoXUserDepartments.ps1`](./Cmdlets/Update-ADAutoXUserDepartments.ps1) | Update department attributes from the configured OU layout. |
| [`Script_AD_Audit_Report.ps1`](./Cmdlets/Script_AD_Audit_Report.ps1) | Read and filter JSONL audit records; does not require an AD connection. |
| [`Get-ADAutoXAuditReport.ps1`](./Cmdlets/Get-ADAutoXAuditReport.ps1) | Module-backed audit filtering and report export. |
| [`Export-Test-Users.ps1`](./Cmdlets/Export-Test-Users.ps1) | Export users under an OU to CSV. |
| [`Remove-Test-Users.ps1`](./Cmdlets/Remove-Test-Users.ps1) | Friendly, guarded wrapper for scoped test-resource cleanup. |
| [`2_RESET_TEST_USERS.ps1`](./Cmdlets/2_RESET_TEST_USERS.ps1) | Perform scoped test-resource cleanup; destructive options require explicit safeguards. |
| [`Reset-ADAutoXEnvironment.ps1`](./Cmdlets/Reset-ADAutoXEnvironment.ps1) | Roll back the current session ledger or invoke guarded test cleanup. |
| [`ControlConsole.ps1`](./Cmdlets/ControlConsole.ps1) | Interactive menu for provisioning, reports, account management, cleanup preview, and offline tests. |

Compatibility wrappers can preserve older names, parameter shapes, or defaults. Prefer the canonical command or module API for new automation; inspect the wrapper's help before use rather than assuming its behavior matches the canonical entry point.

## Testing and verification

| Test or diagnostic script | Purpose | AD impact |
| --- | --- | --- |
| [`validate_repo.ps1`](./Tests/validate_repo.ps1) | Parse PowerShell source and fail on syntax errors. | No AD connection. |
| [`Run-OfflineTests.ps1`](./Tests/Run-OfflineTests.ps1) | Check helper behavior, exports, wrapper wiring, audit/rollback contracts, and safety regressions. | No AD connection. |
| [`Run-ADIntegrationTests.ps1`](./Tests/Run-ADIntegrationTests.ps1) | Opt-in integration test; requires `-RunLive`, the expected DNS root, and a disposable test domain; creates and rolls back uniquely named resources. | Makes live changes in the explicitly selected test domain. |
| [`Diagnose-ADAcl.ps1`](./Tests/Diagnose-ADAcl.ps1) | Diagnose AD provider, domain-controller, OU lookup, and ACL-read behavior; accepts optional `-Server`, `-DistinguishedName`, and `-Credential`. | Performs AD reads; intended for troubleshooting. |

The formal integration suite has not yet been verified in a live domain.

Current manual test evidence:

- The table records the manual evidence currently available for every command script. Screenshot-based claims are operator-confirmed; the image contents have not been independently reviewed here.
- A `-WhatIf` preview or guard screenshot is not evidence that a live disable or deletion completed. The formal live-domain integration suite has not yet been verified.

| Command script | Manual evidence status |
| --- | --- |
| `2_RESET_TEST_USERS.ps1` | Reached through `Remove-Test-Users.ps1`; the cleanup workflow has preview and completion screenshots. |
| `ActiveDirectory-Provisioner.ps1` | Testing in progress; no manual result recorded. |
| `ControlConsole.ps1` | Testing in progress; no manual result recorded. |
| `Disable-ADAutoXInactiveUsers.ps1` | Testing in progress; no manual result recorded. |
| `Export-Test-Users.ps1` | Testing in progress; no manual result recorded. |
| `Generate-ADUsers.ps1` | Testing in progress; no manual result recorded. |
| `Get-ADAutoXAuditReport.ps1` | Testing in progress; no manual result recorded. |
| `Get-ADAutoXLockedOutUsers.ps1` | Testing in progress; no manual result recorded. |
| `Get-ADAutoXSecurityScan.ps1` | Testing in progress; no manual result recorded. |
| `Invoke-ADAutoXProvision.ps1` | Testing in progress; no manual result recorded. |
| `Invoke-ADAutoXUserLifecycle.ps1` | Testing in progress; no manual result recorded. |
| `Manage-ADAutoXUser.ps1` | Testing in progress; no manual result recorded. |
| `mark42.ps1` | Manual provisioning run against real AD, confirmed by the operator; see `mark42-tested.png`. |
| `New_User_Script.ps1` | Real-AD duplicate rejection followed by successful creation of another user; see `New_User_Script.png`. |
| `Remove-Test-Users.ps1` | Real-AD workflow exercised; screenshots show a `-WhatIf` preview and completion output. |
| `Reset-ADAutoXEnvironment.ps1` | Reset workflow preview and completion output confirmed; see its two screenshots. |
| `Script_Add_User_to_Group.ps1` | Successful real-AD group addition confirmed; see `Script_Add_User_to_Group.png`. |
| `Script_AD_Audit_Report.ps1` | Produced an audit summary from the JSONL log; see `Script_AD_Audit_Report.png`. |
| `Script_AD_Security_Report.ps1` | Report completed against real AD; see `Script_AD_Security_Report.png`. |
| `Script_Delete_User.ps1` | Guard and `-WhatIf` preview only; completed live deletion is not evidenced. |
| `Script_Disable_Inactive_Users.ps1` | Testing in progress; no manual result recorded. |
| `Script_Disable_User.ps1` | Guard and `-WhatIf` preview only; completed live disable is not evidenced. |
| `Script_Enable_User.ps1` | Successful operation against real AD; see `Script_Enable_User.png`. |
| `Script_Find_Locked-Out_Users.ps1` | Testing in progress; no manual result recorded. |
| `Script_Move_User.ps1` | Successful operation against real AD; see `Script_Move_User.png`. |
| `Script_Remove_User_from_Group.ps1` | Testing in progress; no manual result recorded. |
| `Script_Reset_User_Passwords.ps1` | Successful operation against real AD; see `Script_Reset_User_Passwords.png`. |
| `Script_Terminate_User.ps1` | Real-AD run with a `-WhatIf` preview followed by approved execution; see `Script_Terminate_User.png`. |
| `Script_Unlock_User_Account.ps1` | Testing in progress; no manual result recorded. |
| `Update-ADAutoXUserDepartments.ps1` | Testing in progress; no manual result recorded. |

Manual runs do not establish coverage of every parameter combination, AD topology, policy, or permission set.

Screenshots are supplied as-is and may contain account names, directory identifiers, or local filesystem paths; review them before sharing. The reset and test-user cleanup workflows are destructive; review their scope and use `-WhatIf` before approving a run:

![mark42.ps1 manual provisioning evidence](./docs/mark42-tested.png)

![Script_Terminate_User.ps1 preview and run](./docs/Script_Terminate_User.png)

![Script_Reset_User_Passwords.ps1 successful run](./docs/Script_Reset_User_Passwords.png)

![Script_Move_User.ps1 successful run](./docs/Script_Move_User.png)

![Script_Enable_User.ps1 successful run](./docs/Script_Enable_User.png)

![Script_Disable_User.ps1 guard and WhatIf preview](./docs/Script_Disable_User.png)

![Script_Delete_User.ps1 guard and WhatIf preview](./docs/Script_Delete_User.png)

![Script_AD_Security_Report.ps1 completed against a real AD domain](./docs/Script_AD_Security_Report.png)

![Script_AD_Audit_Report.ps1 audit summary](./docs/Script_AD_Audit_Report.png)

![Script_Add_User_to_Group.ps1 successful real-AD group addition](./docs/Script_Add_User_to_Group.png)

![Reset-ADAutoXEnvironment.ps1 reset preview](./docs/Reset-ADAutoXEnvironment-WhatIf.png)

![Reset-ADAutoXEnvironment.ps1 completion](./docs/Reset-ADAutoXEnvironment-Completed.png)

![Remove-Test-Users.ps1 cleanup preview](./docs/Remove-Test-Users-WhatIf.png)

![Remove-Test-Users.ps1 cleanup completion](./docs/Remove-Test-Users-Completed.png)

![New_User_Script.ps1 real-AD duplicate check and successful user creation](./docs/New_User_Script.png)

## Repository layout

```text
AD_PS-automation/
├── Cmdlets/       User-facing command scripts and compatibility wrappers
├── Modules/       ADAutoX manifest, shared operations, provisioning, and lifecycle modules
├── Tests/         Offline, parser, diagnostic, and opt-in AD integration tests
├── Data/          Sample provisioning names
├── docs/          Project and manual-test screenshots
├── .gitignore     Ignores credentials, audit logs, reports, and local output
├── README.md      Project overview, setup, safety, and command index
├── PROJECT_GUIDE.md
│                  Detailed operational and technical reference
```

`AD-Operations.jsonl` may be generated locally by a run. It is ignored by `.gitignore` and is not committed.

## Detailed technical guide

[`PROJECT_GUIDE.md`](./PROJECT_GUIDE.md) documents the module architecture, provisioning workflow and parameters, lifecycle safeguards, delegation model, rollback behavior, audit schema, testing instructions, troubleshooting, limitations, and detailed script/module references.

## Disclaimer

Outside preview mode, these scripts can make real directory changes, including creating accounts, changing passwords or group membership, disabling or deleting accounts, and removing lab resources. Use them only with explicit authorization. Review the target domain and distinguished name, preview first, test with a small scope, inspect reports and audit records, and follow formal change control for production environments.
