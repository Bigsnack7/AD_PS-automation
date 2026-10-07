<#
.SYNOPSIS
    Removes generated test users and optionally cleans up the Company OU hierarchy.

.DESCRIPTION
    This script provides a friendly, lab-focused cleanup entry point for the existing
    AD provisioning toolkit. It forwards requests to 2_RESET_TEST_USERS.ps1 so that
    the authoritative reset logic remains in one place while the cleanup command is
    easier to discover and use.

    Unlike the individual operational scripts in this repo, this wrapper intentionally
    does not run the shared Assert-ADOperationsDependencies validation itself because its
    purpose is to dispatch into the dedicated reset workflow and preserve a single,
    centralized cleanup implementation.

.EXAMPLE
    .\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -WhatIf

.EXAMPLE
    .\Remove-Test-Users.ps1 -OrganizationalUnitName 'Company' -DeleteEverything -AllowDestructiveOperation
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [switch]$RemoveOrganizationalUnit,

    [switch]$RemoveAllObjects,

    [switch]$DeleteEverything,

    [switch]$AllowDestructiveOperation,

    [string]$Server,

    [PSCredential]$Credential,

    [string]$AuditLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$resetScriptPath = Join-Path $scriptDirectory '2_RESET_TEST_USERS.ps1'

if (-not (Test-Path -LiteralPath $resetScriptPath -PathType Leaf)) {
    throw "Required reset script not found: $resetScriptPath"
}

# Only forward parameters the caller actually supplied, so downstream
# defaults/validation aren't silently overridden by this wrapper's own defaults.
$resetArguments = @{
    OrganizationalUnitName = $OrganizationalUnitName
}

foreach ($name in 'RemoveOrganizationalUnit','RemoveAllObjects','DeleteEverything','AllowDestructiveOperation','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) {
        $resetArguments[$name] = $PSBoundParameters[$name]
    }
}

if ($DeleteEverything) {
    $resetArguments['RemoveAllObjects'] = $true
    $resetArguments['RemoveOrganizationalUnit'] = $true
}

# Forward the actual common-parameter values instead of relying on preference
# variable inheritance through the nested script invocation.
if ($PSBoundParameters.ContainsKey('Confirm')) {
    $resetArguments['Confirm'] = [bool]$PSBoundParameters['Confirm']
}
& $resetScriptPath @resetArguments -WhatIf:$WhatIfPreference