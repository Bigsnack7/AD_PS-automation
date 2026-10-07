<#
.SYNOPSIS
    Compatibility entry point for the canonical mark42.ps1 provisioner.

.DESCRIPTION
    Forwards the legacy ActiveDirectory-Provisioner.ps1 command line to mark42.ps1.
    Provisioning logic, safety checks, audit behavior, and credential handling live in
    the canonical script so fixes are applied in one place.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateRange(0, 1000)]
    [int]$AccountCount = 20,

    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [ValidateNotNullOrEmpty()]
    [string]$StaffNamesOrganizationalUnitName = 'Staff',

    [ValidateNotNullOrEmpty()]
    [string]$NamesPath = '',

    [ValidateNotNullOrEmpty()]
    [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),

    [string]$AdministratorUsername = '',

    [switch]$CreateDepartmentAdministrators,

    [switch]$AdministratorsOnly,

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

    [ValidateNotNullOrEmpty()]
    [string]$UPNSuffix,

    [PSCredential]$Credential,

    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $WhatIfPreference -and -not $Password -and
    [string]::IsNullOrWhiteSpace($PasswordPattern)) {
    throw 'A live ActiveDirectory-Provisioner run requires -Password or -PasswordPattern.'
}

if ($ExportPasswords -and [string]::IsNullOrWhiteSpace($PasswordFile)) {
    throw 'Use -PasswordFile with -ExportPasswords to write credential material.'
}

$canonicalScriptPath = Join-Path $PSScriptRoot 'mark42.ps1'
if (-not (Test-Path -LiteralPath $canonicalScriptPath -PathType Leaf)) {
    throw "Canonical provisioning script not found: $canonicalScriptPath"
}

$forwardArguments = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $forwardArguments[$parameterName] = $PSBoundParameters[$parameterName]
}

& $canonicalScriptPath @forwardArguments
