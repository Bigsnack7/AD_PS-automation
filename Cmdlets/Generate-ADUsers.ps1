<#
.SYNOPSIS
    Compatibility entry point for the canonical mark42.ps1 provisioner.

.DESCRIPTION
    Preserves the Generate-ADUsers.ps1 command-line interface and forwards work to
    mark42.ps1. The optional -EnableAccountsAfterVerification workflow creates
    accounts disabled and enables them only after provisioning checks succeed.

    Only parameters explicitly supplied by the caller are forwarded, so every default
    comes from mark42.ps1 alone. Department administrators are always created
    disabled by default (DisableDepartmentAdministratorsByDefault), and an explicit
    -AccountCount 0 is forwarded as TreatZeroAccountCountAsNone.
    The exit code of mark42.ps1 is propagated to the caller.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateRange(0, 1000)]
    [int]$AccountCount,

    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName,

    [ValidateNotNullOrEmpty()]
    [string]$StaffNamesOrganizationalUnitName,

    [string]$NamesPath,

    [ValidateNotNullOrEmpty()]
    [string[]]$Departments,

    [string]$AdministratorUsername,

    [switch]$CreateDepartmentAdministrators,

    [switch]$AdministratorsOnly,

    [switch]$EnableAccountsAfterVerification,

    [AllowNull()]
    [string]$PasswordPattern,

    [string]$AdministratorPasswordPattern,

    [string]$PasswordFile,

    [switch]$ExportPasswords,

    [switch]$OverwritePasswordFile,

    [string]$ReportPath,

    [Alias('RollbackOnFailure', 'RollbackAccountsOnFailure')]
    [switch]$RollbackCreatedAccountsOnFailure,

    [SecureString]$Password,

    [string]$Server,

    [string]$UPNSuffix,

    [PSCredential]$Credential,

    [string]$AuditLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($AdministratorsOnly -and -not $CreateDepartmentAdministrators) {
    throw '-AdministratorsOnly requires -CreateDepartmentAdministrators.'
}

# --- Locate the canonical script -------------------------------------------------------
$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDirectory) -and $MyInvocation.MyCommand.Path) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrEmpty($scriptDirectory)) {
    throw 'Cannot determine the script directory. Run this file from disk, not pasted into a console.'
}

$canonicalScriptPath = Join-Path $scriptDirectory 'mark42.ps1'
if (-not (Test-Path -LiteralPath $canonicalScriptPath -PathType Leaf)) {
    throw "Canonical provisioning script not found: $canonicalScriptPath"
}

# Guard against infinite recursion if this file is ever copied over/renamed to mark42.ps1.
if ($PSCommandPath -and
    ((Resolve-Path -LiteralPath $canonicalScriptPath).ProviderPath -eq
     (Resolve-Path -LiteralPath $PSCommandPath).ProviderPath)) {
    throw 'The wrapper and the canonical script resolve to the same file.'
}

# --- Password requirements -------------------------------------------------------------
# With -AdministratorsOnly, the administrator pattern alone is a valid password source.
if (-not $WhatIfPreference -and -not $Password) {
    $hasUserPattern  = -not [string]::IsNullOrWhiteSpace($PasswordPattern)
    $hasAdminPattern = -not [string]::IsNullOrWhiteSpace($AdministratorPasswordPattern)
    $satisfied = if ($AdministratorsOnly) { $hasAdminPattern -or $hasUserPattern } else { $hasUserPattern }
    if (-not $satisfied) {
        throw 'A live Generate-ADUsers run requires -Password or -PasswordPattern (or -AdministratorPasswordPattern with -AdministratorsOnly).'
    }
}

# --- Password export: fail fast, before any account is created -------------------------
if ($ExportPasswords) {
    if ([string]::IsNullOrWhiteSpace($PasswordFile)) {
        throw 'Use -PasswordFile with -ExportPasswords to write credential material.'
    }
    $passwordDirectory = Split-Path -Parent $PasswordFile
    if ([string]::IsNullOrEmpty($passwordDirectory)) { $passwordDirectory = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $passwordDirectory -PathType Container)) {
        throw "Directory for -PasswordFile does not exist: $passwordDirectory"
    }
    if ((Test-Path -LiteralPath $PasswordFile) -and -not $OverwritePasswordFile) {
        throw "Password file already exists (use -OverwritePasswordFile to replace it): $PasswordFile"
    }
}

# --- Build the forwarded argument set --------------------------------------------------
$forwardArguments = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $forwardArguments[$parameterName] = $PSBoundParameters[$parameterName]
}

if ($PSBoundParameters.ContainsKey('AccountCount') -and $AccountCount -eq 0) {
    $forwardArguments['TreatZeroAccountCountAsNone'] = $true
}

$forwardArguments['DisableDepartmentAdministratorsByDefault'] = $true

# Verify mark42.ps1 accepts everything we are about to pass, including the two
# wrapper-injected switches, so an incompatible canonical script fails before any work.
$canonicalCommand = Get-Command -Name $canonicalScriptPath -CommandType ExternalScript -ErrorAction Stop
$commonParameters = @([System.Management.Automation.PSCmdlet]::CommonParameters) +
                    @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
foreach ($parameterName in $forwardArguments.Keys) {
    if ($commonParameters -notcontains $parameterName -and
        -not $canonicalCommand.Parameters.ContainsKey($parameterName)) {
        throw "mark42.ps1 does not support the -$parameterName parameter."
    }
}

# --- Run and propagate the exit code ---------------------------------------------------
$global:LASTEXITCODE = 0
& $canonicalScriptPath @forwardArguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
