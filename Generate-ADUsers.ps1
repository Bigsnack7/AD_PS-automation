<#
.SYNOPSIS
    Compatibility entry point for the canonical mark42.ps1 provisioner.

.DESCRIPTION
    Preserves the Generate-ADUsers.ps1 command-line interface and forwards work to
    mark42.ps1. The optional -EnableAccountsAfterVerification workflow creates
    accounts disabled and enables them only after provisioning checks succeed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateRange(0, 1000)]
    [int]$AccountCount = 20,

    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [ValidateNotNullOrEmpty()]
    [string]$StaffNamesOrganizationalUnitName = 'Staff',

    [string]$NamesPath = '',

    [ValidateNotNullOrEmpty()]
    [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),

    [string]$AdministratorUsername = '',

    [switch]$CreateDepartmentAdministrators,

    [switch]$AdministratorsOnly,

    [switch]$EnableAccountsAfterVerification,

    [AllowNull()]
    [string]$PasswordPattern,

    [string]$AdministratorPasswordPattern,

    [string]$PasswordFile,

    [switch]$ExportPasswords,

    [switch]$OverwritePasswordFile,

    [string]$ReportPath = '',

    [Alias('RollbackOnFailure', 'RollbackAccountsOnFailure')]
    [switch]$RollbackCreatedAccountsOnFailure,

    [SecureString]$Password,

    [string]$Server,

    [string]$UPNSuffix = '',

    [PSCredential]$Credential,

    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($AdministratorsOnly -and -not $CreateDepartmentAdministrators) {
    throw '-AdministratorsOnly requires -CreateDepartmentAdministrators.'
}

if (-not $WhatIfPreference -and -not $Password -and [string]::IsNullOrWhiteSpace($PasswordPattern)) {
    throw 'A live Generate-ADUsers run requires -Password or -PasswordPattern.'
}

$canonicalScriptPath = Join-Path $PSScriptRoot 'mark42.ps1'
if (-not (Test-Path -LiteralPath $canonicalScriptPath -PathType Leaf)) {
    throw "Canonical provisioning script not found: $canonicalScriptPath"
}

$forwardArguments = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $forwardArguments[$parameterName] = $PSBoundParameters[$parameterName]
}

if ($PSBoundParameters.ContainsKey('AccountCount') -and $AccountCount -eq 0) {
    $forwardArguments['TreatZeroAccountCountAsNone'] = $true
}

$forwardArguments['DisableDepartmentAdministratorsByDefault'] = $true

& $canonicalScriptPath @forwardArguments
