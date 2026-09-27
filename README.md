# AD_PS

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-5391D5?logo=powershell&logoColor=white" alt="PowerShell" />
  <img src="https://img.shields.io/badge/Active%20Directory-Identity%20Automation-2DDE98?logo=microsoft&logoColor=white" alt="Active Directory" />
  <img src="https://img.shields.io/badge/Lab%20Provisioning-Audit%20Ready-FF6B6B" alt="Lab Provisioning" />
  <img src="https://img.shields.io/badge/Focus-AD%20Security%20%26%20Operations-8B5CF6" alt="AD Security" />
</p>

<p align="center"><strong>A PowerShell toolkit for Active Directory provisioning, lifecycle administration, and operational reporting — built for controlled test and lab environments, with the safety and audit discipline of a production system.</strong></p>

---

## Table of Contents

- [Overview](#overview)
- [Why This Toolkit](#why-this-toolkit)
- [Repository Contents](#repository-contents)
- [Key Capabilities](#key-capabilities)
- [Requirements](#requirements)
- [Validation and Smoke Testing](#validation-and-smoke-testing)
- [Quick Start](#quick-start)
- [Default Provisioning Layout](#default-provisioning-layout)
- [Role Model and Delegation](#role-model-and-delegation)
- [Core Usage Examples](#core-usage-examples)
- [Audit Logging](#audit-logging)
- [Security Notes](#security-notes)
- [Administrative Script Catalog](#administrative-script-catalog)
- [Input File Format](#input-file-format)
- [Troubleshooting](#troubleshooting)
- [Cleanup and Reset](#cleanup-and-reset)
- [Recommended Execution Flow](#recommended-execution-flow)
- [Project Notes](#project-notes)
- [Disclaimer](#disclaimer)

---

## Overview

**AD_PS** is a professional PowerShell-based toolkit for automating Active Directory provisioning, lifecycle administration, and operational reporting in controlled test and lab environments.

It brings together provisioning logic, administrative lifecycle scripts, JSONL audit logging, and reporting tools under a set of consistent, safety-conscious conventions. The project is designed to demonstrate — and to actually practice — the habits that separate a credible AD automation toolkit from a collection of ad hoc scripts:

- identity automation with department-based OU modeling
- explicit, reviewed attribute management rather than broad standing access
- secure password handling, including optional DPAPI-protected exports
- structured, machine-readable audit logging for every operation
- native PowerShell `-WhatIf` / `-Confirm` semantics throughout, rather than a bespoke dry-run flag

> This toolkit is intended for lab, test, and controlled administrative use. Production usage should always align with your organization's change control, approval processes, and security review requirements.

## Why This Toolkit

Most "AD automation script" collections skip the parts that matter once you're operating against a real directory: consistent audit trails, safe re-runs, explicit approval gates for destructive changes, and verification that a change actually took effect rather than just assuming the cmdlet succeeded. AD_PS is built around those habits from the ground up:

- **Auditable by default** — every operational script writes structured JSONL records before and after the action it takes, not just on failure.
- **Verified, not assumed** — lifecycle scripts re-query the directory after a change (group membership, enabled state, password state) rather than trusting that a cmdlet returning without error means the change is fully in effect.
- **Destructive actions require explicit intent** — `-WhatIf` previews are always available, and irreversible operations require an additional, explicit approval switch on top of PowerShell's native confirmation model.
- **Rerun-safe by design** — provisioning detects existing matching identities before creating new ones, so the same invocation can be run repeatedly without producing duplicate or colliding accounts.

## Repository Contents

| File | Purpose |
| --- | --- |
| `mark42.ps1` | Bulk provisioning script for test users, department OUs, administrator accounts, and CSV reporting. |
| `ActiveDirectory-Provisioner.ps1` | Core provisioner for creating department OUs, users, and admin accounts in a repeatable way. |
| `Export-Test-Users.ps1` | Exports a CSV snapshot of generated users from the target OU for review or cleanup. |
| `Remove-Test-Users.ps1` | Lab-friendly cleanup script for removing generated users and optionally the test OU hierarchy. |
| `AD-Operations.psm1` | Shared helper module for AD targeting, identity resolution, audit logging, CSV utilities, and reporting. |
| `AD-Provisioning.psm1` | Provisioning logic and support functions used across the automation workflow. |
| `Script_AD_Audit_Report.ps1` | Reads the JSONL audit log, filters by identity/action/status, and exports summaries or CSV output. |
| `Script_AD_Security_Report.ps1` | Produces a high-level AD security summary, including locked accounts, inactive accounts, and department coverage. |
| `New_User_Script.ps1` | Creates a single user with explicit attributes. |
| `Script_Reset_User_Passwords.ps1` | Resets one or more user passwords. |
| `Script_Unlock_User_Account.ps1` | Unlocks a locked AD account. |
| `Script_Add_User_to_Group.ps1` | Adds a user to a group. |
| `Script_Remove_User_from_Group.ps1` | Removes a user from a group. |
| `Script_Disable_User.ps1` | Disables a specific user account. |
| `Script_Enable_User.ps1` | Enables a specific user account. |
| `Script_Move_User.ps1` | Moves a user to a target OU. |
| `Script_Delete_User.ps1` | Deletes a user account. |
| `Script_Terminate_User.ps1` | Disables a user, optionally moves the account, and applies a termination reason. |
| `Script_Disable_Inactive_Users.ps1` | Disables accounts inactive beyond a configurable threshold. |
| `Script_Find_Locked-Out_Users.ps1` | Lists locked accounts and supports CSV export. |
| `2_RESET_TEST_USERS.ps1` | Removes generated test users, department groups, and optionally the test OU hierarchy. |
| `nigerian-names.txt` | Default name source for generated test-user identities. |

## Key Capabilities

### Provisioning

- Bulk creation of users across department-specific OUs
- Department-specific `Users` and `Administrators` OUs
- Automatic creation of per-department security groups
- Scoped OU delegation for departmental lifecycle administrators
- Reserved `Department-Attribute-Admins` group for explicit, reviewed attribute changes
- Username collision prevention using existing AD account names and generated SAM names
- Rerun-safe identity detection that skips existing matching users before suffixing
- CSV report generation for provisioning outcomes and failures
- Execution context reporting, including domain, forest, DC, operator, timestamp, PowerShell version, and OS
- Structured error metadata capture for AD and PowerShell failures
- Verification of new OUs and post-create account attributes on the configured DC
- Default lab behavior that enables accounts and validates required department attributes immediately after creation

### Security and Safe Defaults

- Random passwords are generated by default
- Live runs automatically export generated passwords to `user-passwords.clixml` beside the script; use `-PasswordFile` to choose another path
- Encrypted credential export uses `Export-Clixml`
- Password ACLs are restricted to the current Windows identity
- Destructive operations require explicit approval switches in addition to `-WhatIf`
- Preview behavior is driven by native PowerShell `-WhatIf` semantics
- Preflight validation checks the expected OU, administrator group, and delegation state before creating accounts
- A single writable DC is resolved and reused for the full provisioning run
- Audit actions are written to JSONL for review and incident response

> The project intentionally avoids a custom dry-run switch. Use `-WhatIf` and `SupportsShouldProcess` to preview operations the standard PowerShell way.

### Administration and Lifecycle

- User enable and disable workflows
- Group membership management
- User move operations
- User delete and termination workflows
- Inactive-user cleanup support
- Security and audit summary reporting

## Requirements

Run the scripts from a machine that meets the following requirements:

1. Windows PowerShell 5.1 or PowerShell 7+
2. The Active Directory PowerShell module installed
3. Network reachability to a domain controller
4. An appropriately delegated account with the required permissions
5. An approved change window with a defined audit retention process

## Validation and Smoke Testing

This repository has been validated locally **without executing destructive AD operations**:

- `validate_repo.ps1` parses the full repository and confirms all PowerShell files are syntactically valid.
- Shared module imports and helper-level smoke tests pass for the LDAP escaping and provisioning input validation logic.
- The audit report script successfully reads the existing JSONL log in read-only mode.

Live AD tests remain environment-dependent. In the most recent validation session, the test machine was unable to discover a domain controller, so no production or lab AD changes were performed. Only run these scripts on a domain-joined machine with a reachable writable DC and an approved test OU.

## Quick Start

### 1. Open the project folder

```powershell
Set-Location 'C:\Path\To\AD_PS-master\AD_PS-master'
```

### 2. Validate Active Directory connectivity

```powershell
Import-Module ActiveDirectory
Get-ADDomain
```

If `Import-Module ActiveDirectory` fails, install the RSAT Active Directory tools first.

### 3. Preview bulk user creation

```powershell
.\mark42.ps1 -AccountCount 5 -WhatIf
```

This preview shows the operations that would occur without modifying Active Directory.

For multi-DC environments, pass a specific writable domain controller with `-Server` when needed. If `-Server` is omitted, the provisioning module resolves one writable DC at startup and reuses it for the remainder of the run, including post-create verification and delegation ACL changes.

### 4. Create test users

```powershell
.\mark42.ps1 -AccountCount 5
```

By default, this creates users under the `Company` OU, builds departmental OUs beneath `Staff`, and creates `Users` and `Administrators` OUs under each department.

Department administrator accounts and their groups are created by default. To create regular users without departmental admin resources, disable that behavior explicitly:

```powershell
.\mark42.ps1 -AccountCount 5 -CreateDepartmentAdministrators:$false
```

### 5. Export a snapshot of generated users

```powershell
.\Export-Test-Users.ps1 -OrganizationalUnitName 'Company'
```

This exports a CSV snapshot of the users under the target OU so you can preserve an inventory before running a security exercise or deleting the environment.

### 6. Review the generated audit log

```powershell
.\Script_AD_Audit_Report.ps1
.\Script_AD_Audit_Report.ps1 -Identity 'chinedu.okafor'
.\Script_AD_Audit_Report.ps1 -Action 'CreateUser' -Status 'Failed'
```

The audit report script reads `AD-Operations.jsonl`, summarizes the log, and can export filtered result sets to CSV or JSON.

## Default Provisioning Layout

The default model creates the following structure under the domain root:

```text
Company
  Staff
    IT
      Users
      Administrators
    HR
      Users
      Administrators
    Finance
      Users
      Administrators
    Sales
      Users
      Administrators
```

Employees are created in the department `Users` OU, while department administrator accounts are created in the department `Administrators` OU by default.

## Role Model and Delegation

The provisioning flow distinguishes between several administrative roles:

**`Department-Administrators`**
- Create and delete users in the department `Users` OU
- List and read user objects within the scoped OU
- Support standard departmental lifecycle workflows
- Do not receive broad property-write access by default

**`Department-Attribute-Admins`**
- Reserved for future explicit, reviewed delegation of specific user attributes
- Do not automatically receive password-reset, enable/disable, unlock, or other privileged attribute-management rights
- Should be granted only the exact rights needed for approved operations
- Should not be treated as a generic catch-all admin group

**Audit and report consumers**
- Use the JSONL audit log and reporting scripts for visibility and evidence collection
- Should operate with read-only access wherever possible

This separation is intentional: the automation demonstrates tightly scoped user lifecycle delegation while keeping attribute changes explicit and auditable.

## Core Usage Examples

**Create users with a custom department list**

```powershell
.\mark42.ps1 -AccountCount 20 -Departments 'Engineering','Support','Operations'
```

**Use a custom names file**

```powershell
.\mark42.ps1 -NamesPath 'C:\Path\To\custom-names.txt'
```

**Use a custom organizational unit name**

```powershell
.\mark42.ps1 -OrganizationalUnitName '_LAB-USERS'
```

**Supply a deterministic password pattern**

```powershell
.\mark42.ps1 -AccountCount 10 -PasswordPattern 'Training-{0}-Strong!'
```

**Supply a single secure password for all accounts**

```powershell
$securePassword = ConvertTo-SecureString 'Use-A-Strong-Lab-Password' -AsPlainText -Force
.\mark42.ps1 -AccountCount 5 -Password $securePassword
```

**Export encrypted passwords to a custom path**

```powershell
.\mark42.ps1 -AccountCount 5 -PasswordFile '.\user-passwords.clixml'
```

The export is created automatically for live runs and contains sensitive credential material. If the target file already exists, provide `-OverwritePasswordFile` only when you intentionally want to replace it. Protect the file with restricted access and a clear retention policy.

## Audit Logging

The toolkit writes JSON Lines records to `AD-Operations.jsonl` by default. Each audit entry includes structured metadata such as:

- Timestamp
- Actor / Operator
- Computer
- Action
- Target
- Target Type
- Status
- Message
- Details
- Source
- Correlation ID

This structure supports operational review, incident response, and post-change analysis, and is consumed directly by `Script_AD_Audit_Report.ps1`.

## Security Notes

### Password handling

- Random passwords are generated by default
- `-PasswordPattern` and `-AdministratorPasswordPattern` are used only when explicitly supplied
- Custom password patterns are preflight-validated against the domain default policy and available fine-grained policy metadata before creation begins
- Fine-grained password policies are discovered and summarized for visibility, but final validation still occurs during the AD creation operation
- Live runs export generated passwords by default; `-PasswordFile` changes the destination and `-OverwritePasswordFile` allows intentional replacement
- Password export material is written using `Export-Clixml` and is restricted to the current Windows user/machine context
- Saved password exports are sensitive and should be protected with strict access control and retention policies

### WhatIf and approval controls

- `-WhatIf` is supported throughout the provisioning and lifecycle scripts
- Destructive operations require explicit approval switches such as `-AllowDestructiveOperation`
- Attribute changes should be reviewed and granted through explicit allow-listed rights rather than broad delegated property writes
- `-RollbackCreatedAccountsOnFailure` is intentionally scoped to account rollback only

### Rollback scope and safety

The provisioning script is designed for repeated lab runs and controlled AD automation. The built-in rollback switch removes only the accounts created by the current invocation. It does not remove existing OUs, groups, memberships, or delegated ACLs unless you explicitly perform a separate destructive reset.

Account-level verification and group-membership failures do not stop the remaining batch when rollback is enabled. They are reported as partial failures, the affected account is removed, and remaining accounts continue processing. A failure outside an account-processing block can still abort the run and roll back any remaining accounts created by that invocation.

The script also maintains an in-memory resource ledger that records each discovered or created object with `CreatedByThisRun = $true/$false`. This ledger underpins safer future cleanup logic: run-created resources may be removed, while pre-existing objects are never touched automatically.

### Operational discipline

- Review the domain, OU path, and naming before running live commands
- Use dedicated test OUs for lab or portfolio scenarios
- Keep audit logs in an access-controlled location with a documented retention schedule
- Avoid storing plaintext credentials in scripts, command history, or shared folders

## Administrative Script Catalog

### User lifecycle

| Script | Purpose |
| --- | --- |
| `Script_Disable_User.ps1` | Disable a user account |
| `Script_Enable_User.ps1` | Enable a user account |
| `Script_Move_User.ps1` | Move a user to a target OU |
| `Script_Delete_User.ps1` | Delete a user account |
| `Script_Terminate_User.ps1` | Disable a user and apply a termination reason, optionally moving the account |

### Group and account management

| Script | Purpose |
| --- | --- |
| `Script_Add_User_to_Group.ps1` | Add a user to a group |
| `Script_Remove_User_from_Group.ps1` | Remove a user from a group |
| `Script_Reset_User_Passwords.ps1` | Reset one or more passwords |
| `Script_Unlock_User_Account.ps1` | Unlock a locked account |
| `Script_Find_Locked-Out_Users.ps1` | Identify locked accounts and export results if needed |

### Reporting and review

| Script | Purpose |
| --- | --- |
| `Script_AD_Audit_Report.ps1` | Summarize audit records and export filtered results |
| `Script_AD_Security_Report.ps1` | Summarize security posture and targeted account conditions |

## Input File Format

Each non-empty line in `nigerian-names.txt` should contain a first name and a surname:

```text
Chinedu Okafor
Adaeze Nwosu
Olumide Adeyemi
```

The parser accepts extra whitespace and treats everything after the first whitespace-separated value as part of the surname. Blank or invalid lines are skipped with a warning.

## Troubleshooting

**Active Directory module is unavailable**

```powershell
Get-Module -ListAvailable ActiveDirectory
Import-Module ActiveDirectory
```

**Access denied**

Verify that the current account has the required delegated rights, and confirm that the target domain controller is reachable.

**Names file not found**

Use an absolute path with `-NamesPath`, or confirm that the file is present in the same directory as the script.

**User creation fails**

Review the emitted warning or failure details. Common causes include:

- Invalid naming or duplicate account collisions
- Password-policy violations
- Insufficient permissions
- Domain reachability issues
- Existing objects with conflicting identities

## Cleanup and Reset

Use `Remove-Test-Users.ps1` for the simplest lab cleanup flow. It wraps the existing removal logic in `2_RESET_TEST_USERS.ps1`, providing the same removal behavior with a clearer entry point.

**Preview cleanup**

```powershell
.\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -WhatIf
```

**Remove generated accounts**

```powershell
.\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -AllowDestructiveOperation
```

**Remove the OU hierarchy as well**

```powershell
.\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -RemoveOrganizationalUnit -AllowDestructiveOperation
```

**Remove everything under the test OU**

```powershell
.\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -DeleteEverything -AllowDestructiveOperation
```

## Recommended Execution Flow

```powershell
Set-Location 'C:\Path\To\AD_PS-master\AD_PS-master'

.\mark42.ps1 -AccountCount 10 -WhatIf
.\mark42.ps1 -AccountCount 10

.\Export-Test-Users.ps1 -OrganizationalUnitName 'Company'
.\Script_AD_Audit_Report.ps1

.\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -WhatIf
.\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -AllowDestructiveOperation
```

This workflow provides a clear pattern for preview, execute, audit, and clean up.

## Project Notes

This repository is structured to demonstrate a credible Active Directory administration toolkit, with emphasis on:

- Safe automation patterns
- Operational transparency
- Security-conscious defaults
- Reusable PowerShell module design
- Auditability and reviewability

The code intentionally separates reusable AD helpers (`AD-Operations.psm1`, `AD-Provisioning.psm1`) from operation-specific scripts, making the project easier to extend and easier to present as a professional automation solution.

## Disclaimer

This toolkit performs real changes against Active Directory when run outside of `-WhatIf` mode, including account creation, password resets, group membership changes, and account deletion. Use it only in environments you are authorized to modify, and always:

1. Preview with `-WhatIf` first
2. Validate against a small test batch
3. Review the generated audit log
4. Confirm the target domain, OU path, and naming before proceeding
5. Follow your organization's change control and approval process for anything beyond a lab environment

Start with preview mode, validate the expected behavior, and scale only after you're confident in the outcome.
