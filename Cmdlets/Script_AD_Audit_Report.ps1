<#
.SYNOPSIS
    Produces a summary report from the JSONL audit log created by the AD toolkit.

.DESCRIPTION
    Reads the shared ADAutoX audit log, applies optional filters, and prints a human-readable
    summary. When -OutputPath is supplied, the filtered records are exported as JSON or CSV.
    This read-only report does not require Active Directory connectivity.
#>
[CmdletBinding()]
param(
    [string]$AuditLogPath = '',
    [string]$Identity,
    [string]$Action,
    [ValidateSet('Started', 'Succeeded', 'Failed', 'Skipped', 'Preview', 'CompletedWithErrors')]
    [string]$Status,
    [string]$OutputPath,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $PSScriptRoot
$resolvedAuditLogPath = if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    Join-Path $scriptDirectory 'AD-Operations.jsonl'
}
else {
    $AuditLogPath
}
$resolvedAuditLogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($resolvedAuditLogPath)

$modulePath = Join-Path $scriptDirectory 'Modules\ADAutoX.psd1'
Import-Module $modulePath -ErrorAction Stop
$reportParameters = @{
    LogPath = $resolvedAuditLogPath
    Summary = $true
    ErrorOnMalformedEntries = $true
}
foreach ($parameterName in @('Identity', 'Action', 'Status')) {
    if ($PSBoundParameters.ContainsKey($parameterName)) {
        $reportParameters[$parameterName] = $PSBoundParameters[$parameterName]
    }
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $reportParameters.OutputPath = $OutputPath
    $reportParameters.AsJson = [bool]$AsJson
}

$summary = Get-ADAutoXAuditReport @reportParameters -ErrorAction Stop

function Write-ADAuditSummaryToConsole {
    param(
        [Parameter(Mandatory)][psobject]$Summary,
        [string]$IdentityFilter,
        [string]$ActionFilter,
        [string]$StatusFilter
    )

    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ' Active Directory Audit Summary' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan

    if ($IdentityFilter -or $ActionFilter -or $StatusFilter) {
        Write-Host ''
        Write-Host 'Applied filters:' -ForegroundColor Yellow
        if ($IdentityFilter) { Write-Host "  - Identity: $IdentityFilter" -ForegroundColor Yellow }
        if ($ActionFilter) { Write-Host "  - Action: $ActionFilter" -ForegroundColor Yellow }
        if ($StatusFilter) { Write-Host "  - Status: $StatusFilter" -ForegroundColor Yellow }
    }

    Write-Host ''
    Write-Host "Audit log      : $($Summary.AuditLogPath)" -ForegroundColor Gray
    Write-Host "Total records  : $($Summary.TotalRecords)" -ForegroundColor Gray
    Write-Host "Unique actors  : $($Summary.UniqueActors)" -ForegroundColor Gray
    Write-Host "Unique targets : $($Summary.UniqueTargets)" -ForegroundColor Gray
    Write-Host "First event    : $($Summary.FirstTimestamp)" -ForegroundColor Gray
    Write-Host "Last event     : $($Summary.LastTimestamp)" -ForegroundColor Gray

    Write-Host ''
    Write-Host 'Status summary:' -ForegroundColor Yellow
    if ($Summary.StatusCounts.Count -eq 0) {
        Write-Host '  No records matched the current filters.' -ForegroundColor DarkGray
    }
    else {
        foreach ($item in $Summary.StatusCounts) {
            Write-Host ("  {0,-17} : {1}" -f $item.Status, $item.Count) -ForegroundColor Gray
        }
    }

    Write-Host ''
    Write-Host 'Action summary:' -ForegroundColor Yellow
    if ($Summary.ActionCounts.Count -eq 0) {
        Write-Host '  No actions recorded for the current selection.' -ForegroundColor DarkGray
    }
    else {
        foreach ($item in $Summary.ActionCounts) {
            Write-Host ("  {0,-20} : {1}" -f $item.Action, $item.Count) -ForegroundColor Gray
        }
    }

    Write-Host ''
    Write-Host 'Failed events:' -ForegroundColor Yellow
    if ($Summary.FailedRecords.Count -eq 0) {
        Write-Host '  No failed events found.' -ForegroundColor DarkGray
    }
    else {
        foreach ($failed in $Summary.FailedRecords) {
            Write-Host ("  [{0}] {1} | {2} | {3}" -f $failed.Timestamp, $failed.Action, $failed.Target, $failed.Message) -ForegroundColor Red
        }
    }

    Write-Host '========================================' -ForegroundColor Cyan
}

if ($AsJson) {
    $summary | ConvertTo-Json -Depth 8
}
else {
    Write-ADAuditSummaryToConsole -Summary $summary -IdentityFilter $Identity -ActionFilter $Action -StatusFilter $Status

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-Host "Detailed audit export written to: $OutputPath" -ForegroundColor Green
    }
}
