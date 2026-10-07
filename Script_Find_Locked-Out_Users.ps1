<#
.SYNOPSIS
    Lists currently locked-out Active Directory user accounts.

.DESCRIPTION
    Searches the requested scope for locked-out users, optionally exports the results to CSV,
    and writes structured audit records for review. This script is read-only and does not change
    account state; it is intended as a safe discovery and reporting workflow.
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$CsvPath,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath=''
)

if ($PSBoundParameters.ContainsKey('SearchBase') -and [string]::IsNullOrWhiteSpace($SearchBase)) {
    throw 'SearchBase cannot be blank when supplied.'
}
if ($PSBoundParameters.ContainsKey('CsvPath') -and [string]::IsNullOrWhiteSpace($CsvPath)) {
    throw 'CsvPath cannot be blank when supplied.'
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}

$operationsModule = Join-Path $scriptDirectory 'AD-Operations.psm1'

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

Import-Module $operationsModule -Force
Assert-ADOperationsDependencies
Import-ADTools

$auditTarget = if ($SearchBase) { $SearchBase } else { 'Domain' }

# Everything from here on establishes and relies on process-wide AD context
# (Set-ADToolContext), so it must always be unwound via Clear-ADToolContext -
# on success, and on any failure, including one from Set-ADToolContext itself.
try {
    Set-ADToolContext -Server $Server -Credential $Credential
    $adContext = Get-ADToolContextParameters

    Write-ADAuditRecord -Path $AuditLogPath -Action 'FindLockedAccounts' -Target $auditTarget -Status 'Started'

    $params = @{ Filter = 'LockedOut -eq $true'; Properties = 'LastLogonDate','Department','EmailAddress','DistinguishedName' }
    if ($SearchBase) { $params.SearchBase = $SearchBase; $params.SearchScope = 'Subtree' }
    $locked = @(Get-ADUser @adContext @params | Select-Object Name,SamAccountName,UserPrincipalName,LastLogonDate,Department,EmailAddress,DistinguishedName)
    if ($CsvPath) { Export-ADResults -Results $locked -Path $CsvPath } else { $locked | Format-Table -AutoSize }
    Write-ADAuditRecord -Path $AuditLogPath -Action 'FindLockedAccounts' -Target $auditTarget -Status 'Succeeded' -Message "Found $($locked.Count) locked accounts."
    Write-Host "Locked accounts found: $($locked.Count)" -ForegroundColor Yellow
}
catch {
    $originalError = $_
    try {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'FindLockedAccounts' -Target $auditTarget -Status 'Failed' -Message $originalError.Exception.Message
    }
    catch {
        Write-Warning "Failed to write audit record: $($_.Exception.Message)"
    }
    throw $originalError
}
finally {
    Clear-ADToolContext
}