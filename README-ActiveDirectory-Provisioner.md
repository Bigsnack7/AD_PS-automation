# ActiveDirectory-Provisioner.ps1

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-5391D5?logo=powershell&logoColor=white" alt="PowerShell" />
  <img src="https://img.shields.io/badge/Active%20Directory-Departmental%20Provisioning-2DDE98?logo=microsoft&logoColor=white" alt="Active Directory" />
  <img src="https://img.shields.io/badge/Use-Lab%20%26%20Test%20Environments-FF6B6B" alt="Lab Automation" />
</p>

`ActiveDirectory-Provisioner.ps1` is a PowerShell automation script for provisioning structured Active Directory lab environments. It creates department-based organizational units, security groups, standard users, and department administrator accounts in a consistent, auditable, and repeatable way.

## Overview

This script is built for controlled lab, demo, and validation environments where a realistic AD structure is required. It automates the following:

- creation of department-specific OUs
- creation of department security groups
- provisioning of standard user accounts
- provisioning of department administrator accounts
- repeat-safe execution with collision detection
- preflight validation before AD changes are applied
- CSV and JSONL audit/report output
- optional DPAPI-protected password export

The script uses PowerShell's native `SupportsShouldProcess` behavior and `-WhatIf` preview support instead of introducing a second dry-run mechanism.

## Why Use This Script?

This tool is valuable when you need to:

- create realistic AD test environments quickly
- model departmental structures consistently
- establish role-based OU organization
- generate user identities for training or validation activities
- build repeatable lab environments with clear operational reporting

## Requirements

Before running the script, ensure that:

1. Windows PowerShell 5.1 or PowerShell 7+ is installed
2. The Active Directory module is available
3. The machine can reach a writable domain controller
4. The executing identity has sufficient AD permissions
5. The activity is approved and performed within a controlled change window

> This script is intended for lab, test, and controlled operational use. Production changes should always follow your organization’s approval, change control, and security review processes.

## Quick Start

Change to the repository folder:

```powershell
Set-Location 'C:\Users\OLUDEMI JOSHUA\Downloads\AD_PS-master\AD_PS-master'
```

Validate AD connectivity:

```powershell
Import-Module ActiveDirectory
Get-ADDomain
```

Preview a provisioning run without changing anything:

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 5 -WhatIf
```

Create a small batch of users:

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 5
```

Create users across a custom department list:

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 20 -Departments 'Engineering','Support','Operations'
```

Create only department administrator accounts:

```powershell
.\ActiveDirectory-Provisioner.ps1 -AdministratorsOnly -Departments 'IT','HR'
```

## Common Parameters

### `-AccountCount`
Defines how many user accounts to create.

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 50
```

If the requested count exceeds the number of valid names available, the script reduces the effective count and warns instead of failing abruptly.

### `-OrganizationalUnitName`
Sets the top-level OU name. The default is `Company`.

```powershell
.\ActiveDirectory-Provisioner.ps1 -OrganizationalUnitName '_LAB-USERS'
```

### `-Departments`
Defines which department OUs and sub-structures should be created.

```powershell
.\ActiveDirectory-Provisioner.ps1 -Departments 'IT','HR','Finance'
```

### `-NamesPath`
Uses a custom names file instead of the default repository list.

```powershell
.\ActiveDirectory-Provisioner.ps1 -NamesPath 'C:\Path\To\custom-names.txt'
```

### `-CreateDepartmentAdministrators`
Enables or disables the creation of department administrator accounts and their associated OU structure.

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 5 -CreateDepartmentAdministrators:$false
```

### `-PasswordPattern` and `-AdministratorPasswordPattern`
Allows deterministic password patterns for regular users and department administrators.

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 10 -PasswordPattern 'Welcome!{0}'
```

These patterns are validated against domain password policy metadata when available, but final policy enforcement still occurs during the AD creation process.

### `-ExportPasswords` and `-PasswordFile`
Exports generated credentials to a DPAPI-protected XML file associated with the current Windows user and machine context.

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 10 -ExportPasswords -PasswordFile 'C:\Temp\ad-user-passwords.xml'
```

This output contains sensitive credential material and must be treated with the same protection and access controls as other privileged secrets.

### `-Server`
Targets a specific domain controller when needed.

```powershell
.\ActiveDirectory-Provisioner.ps1 -AccountCount 10 -Server 'DC01.contoso.local'
```

### `-Credential`
Uses an explicit credential object instead of the current session identity.

```powershell
$cred = Get-Credential
.\ActiveDirectory-Provisioner.ps1 -AccountCount 10 -Credential $cred
```

## Default Provisioning Layout

The script creates a department-based OU structure similar to the following:

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

This model organizes users and departmental admin accounts into clean, logical administrative boundaries.

## Safety, Validation, and Audit Controls

The script includes a set of operational safeguards designed to improve reliability and traceability:

- preview mode through `-WhatIf` and `SupportsShouldProcess`
- duplicate identity detection for rerun-safe execution
- preflight validation before mutation
- structured CSV and JSONL reporting
- explicit password export controls
- controlled handling of account, OU, and group creation workflows

## Output Artifacts

The script generates report artifacts in the project directory by default, including:

- `AD-Provisioning-Report.csv`
- `AD-Operations.jsonl`

These resources support operational review, validation, troubleshooting, and audit workflows.

## Example Full Run

```powershell
.\ActiveDirectory-Provisioner.ps1 `
  -AccountCount 25 `
  -OrganizationalUnitName 'Company' `
  -Departments 'IT','HR','Finance','Sales' `
  -PasswordPattern 'Welcome!{0}' `
  -ExportPasswords `
  -PasswordFile 'C:\Temp\ad-password-export.xml' `
  -ReportPath 'C:\Temp\AD-Provisioning-Report.csv'
```

## Summary

`ActiveDirectory-Provisioner.ps1` provides a practical and repeatable foundation for building Active Directory test environments with controlled provisioning, clean departmental structure, and operational traceability. It is especially useful for labs, demonstrations, and internal identity validation workflows where consistency and auditability are important.
