[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()][string]$CompanyOuName = 'Company',
    [string]$ExpectedDistinguishedName,
    [switch]$RollbackLedger,
    [switch]$AllowDestructiveOperation,
    [switch]$Force,
    [string]$AuditLogPath,
    [string]$Server,
    [PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
if ($RollbackLedger) {
    $moduleManifest = Join-Path $rootDirectory 'Modules\ADAutoX.psd1'
    if (-not (Test-Path -LiteralPath $moduleManifest -PathType Leaf)) {
        throw "Required ADAutoX module manifest not found: $moduleManifest"
    }
    Import-Module $moduleManifest -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($ExpectedDistinguishedName)) {
        throw '-ExpectedDistinguishedName is required when rolling back ledger entries; use the approved OU DN as the rollback boundary.'
    }

    $rollbackArguments = @{
        AllowedRoot = $ExpectedDistinguishedName
        AllowDestructiveOperation = $AllowDestructiveOperation
        Server = $Server
        Credential = $Credential
    }
    $rollbackArguments.LogPath = if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        Join-Path $rootDirectory 'AD-Operations.jsonl'
    }
    else {
        $AuditLogPath
    }
    if ($WhatIfPreference) { $rollbackArguments.WhatIf = $true }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $rollbackArguments.Confirm = $PSBoundParameters['Confirm'] }
    Invoke-ADAutoXLedgerRollback @rollbackArguments
    return
}

$cleanupScript = Join-Path $PSScriptRoot 'Remove-Test-Users.ps1'
if (-not (Test-Path -LiteralPath $cleanupScript -PathType Leaf)) {
    throw "Required cleanup implementation not found: $cleanupScript"
}

$arguments = @{
    OrganizationalUnitName = $CompanyOuName
    DeleteEverything = $true
}
foreach ($name in 'ExpectedDistinguishedName','AllowDestructiveOperation','Force','AuditLogPath','Server','Credential') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
& $cleanupScript @arguments
