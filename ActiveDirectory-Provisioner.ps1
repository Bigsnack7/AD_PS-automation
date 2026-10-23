<#
.SYNOPSIS
    Compatibility entry point for the canonical mark42.ps1 provisioner.

.DESCRIPTION
    Forwards the legacy ActiveDirectory-Provisioner.ps1 command line to mark42.ps1.
    Provisioning logic, safety checks, audit behavior, and credential handling live in
    the canonical script so fixes are applied in one place.

    Only parameters explicitly supplied by the caller are forwarded, so every default
    (account count, OU names, departments, paths) comes from mark42.ps1 alone.
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

    [ValidateNotNullOrEmpty()]
    [string]$NamesPath,

    [ValidateNotNullOrEmpty()]
    [string[]]$Departments,

    [string]$AdministratorUsername,

    [switch]$CreateDepartmentAdministrators,

    [switch]$AdministratorsOnly,

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

    [ValidateNotNullOrEmpty()]
    [string]$UPNSuffix,

    [PSCredential]$Credential,

    [string]$AuditLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Locate the canonical script -------------------------------------------------------
# $PSScriptRoot is empty when the code is pasted or dot-sourced; fail clearly instead of
# letting Join-Path throw an unhelpful binding error (or silently using the CWD).
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
# A live run needs some password source. With -AdministratorsOnly, the administrator
# pattern alone is a valid source (the original check wrongly rejected that combination).
if (-not $WhatIfPreference -and -not $Password) {
    $hasUserPattern  = -not [string]::IsNullOrWhiteSpace($PasswordPattern)
    $hasAdminPattern = -not [string]::IsNullOrWhiteSpace($AdministratorPasswordPattern)
    $satisfied = if ($AdministratorsOnly) { $hasAdminPattern -or $hasUserPattern } else { $hasUserPattern }
    if (-not $satisfied) {
        throw 'A live ActiveDirectory-Provisioner run requires -Password or -PasswordPattern (or -AdministratorPasswordPattern with -AdministratorsOnly).'
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

# --- Forward only what the caller supplied, after checking the target accepts it -----------
$canonicalCommand = Get-Command -LiteralPath $canonicalScriptPath -CommandType ExternalScript
$commonParameters = @([System.Management.Automation.PSCmdlet]::CommonParameters) +
                    @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)

$forwardArguments = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    if ($commonParameters -notcontains $parameterName -and
        -not $canonicalCommand.Parameters.ContainsKey($parameterName)) {
        throw "mark42.ps1 does not support the -$parameterName parameter."
    }
    $forwardArguments[$parameterName] = $PSBoundParameters[$parameterName]
}

# --- Run and propagate the exit code ---------------------------------------------------
$global:LASTEXITCODE = 0
& $canonicalScriptPath @forwardArguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
