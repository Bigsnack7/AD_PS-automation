<#
.SYNOPSIS
    Produces a summary report from the JSONL audit log created by the AD toolkit.

.DESCRIPTION
    Reads AD-Operations.jsonl (or a supplied audit log path) through the shared ADAutoX audit
    reader, normalizes the records, applies optional filters, and prints a human-readable summary
    to the console. When -OutputPath is supplied, it also exports the filtered records as a CSV
    timeline.

    This read-only report does not require Active Directory connectivity.

.EXAMPLE
    .\Cmdlets\Script_AD_Audit_Report.ps1

.EXAMPLE
    .\Cmdlets\Script_AD_Audit_Report.ps1 -AuditLogPath .\AD-Operations.jsonl -Identity jdoe -OutputPath .\jdoe-audit.csv
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

$scriptDirectory = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }

function Get-JsonRecordValue {
    param(
        [Parameter(Mandatory)][psobject]$Record,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ''
    }
    return [string]$property.Value
}

function Get-ADAuditRecordObject {
    param(
        [Parameter(Mandatory)][psobject]$Record
    )

    [pscustomobject]@{
        Timestamp     = Get-JsonRecordValue -Record $Record -Name 'Timestamp'
        Actor         = Get-JsonRecordValue -Record $Record -Name 'Actor'
        Operator      = Get-JsonRecordValue -Record $Record -Name 'Operator'
        Computer      = Get-JsonRecordValue -Record $Record -Name 'Computer'
        Action        = Get-JsonRecordValue -Record $Record -Name 'Action'
        Target        = Get-JsonRecordValue -Record $Record -Name 'Target'
        TargetType    = Get-JsonRecordValue -Record $Record -Name 'TargetType'
        Status        = Get-JsonRecordValue -Record $Record -Name 'Status'
        Message       = Get-JsonRecordValue -Record $Record -Name 'Message'
        Details       = Get-JsonRecordValue -Record $Record -Name 'Details'
        Source        = Get-JsonRecordValue -Record $Record -Name 'Source'
        CorrelationId = Get-JsonRecordValue -Record $Record -Name 'CorrelationId'
    }
}

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

$resolvedAuditLogPath = if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    Join-Path $scriptDirectory 'AD-Operations.jsonl'
}
else {
    $AuditLogPath
}

$resolvedAuditLogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($resolvedAuditLogPath)
Import-Module (Join-Path $scriptDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop
$rawRecords = @(
    Get-ADAutoXAuditReport -LogPath $resolvedAuditLogPath -Identity $Identity -Action $Action -Status $Status -ErrorOnMalformedEntries |
        ForEach-Object { Get-ADAuditRecordObject -Record $_ }
)

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
}

$summary = [pscustomobject]@{
    AuditLogPath = $resolvedAuditLogPath
    TotalRecords = $rawRecords.Count
    UniqueActors = @($rawRecords | Select-Object -ExpandProperty Actor -Unique).Count
    UniqueTargets = @($rawRecords | Select-Object -ExpandProperty Target -Unique).Count
    FirstTimestamp = ''
    LastTimestamp = ''
    StatusCounts = @()
    ActionCounts = @()
    FailedRecords = @()
}

if ($rawRecords.Count -gt 0) {
    $timestampValues = @($rawRecords | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Timestamp) } | Select-Object -ExpandProperty Timestamp)
    if ($timestampValues.Count -gt 0) {
        $sortedTimestamps = @($timestampValues | Sort-Object)
        $summary.FirstTimestamp = $sortedTimestamps[0]
        $summary.LastTimestamp = $sortedTimestamps[-1]
    }

    $summary.StatusCounts = @(
        foreach ($statusName in @('Started', 'Succeeded', 'Failed', 'Skipped', 'Preview', 'CompletedWithErrors')) {
            $count = @($rawRecords | Where-Object { $_.Status -ieq $statusName }).Count
            if ($count -gt 0) {
                [pscustomobject]@{
                    Status = $statusName
                    Count = $count
                }
            }
        }
    )

    $summary.ActionCounts = @(
        $rawRecords |
            Group-Object -Property Action |
            Sort-Object -Property Count -Descending |
            Select-Object @{Name = 'Action'; Expression = { $_.Name } }, Count
    )

    $summary.FailedRecords = @(
        $rawRecords |
            Where-Object { $_.Status -ieq 'Failed' } |
            Select-Object Timestamp, Actor, Action, Target, Message, Details
    )
}

if ($AsJson) {
    $summary | ConvertTo-Json -Depth 8
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }
}
else {
    Write-ADAuditSummaryToConsole -Summary $summary -IdentityFilter $Identity -ActionFilter $Action -StatusFilter $Status

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $rawRecords |
            Select-Object Timestamp, Actor, Operator, Computer, Action, Target, TargetType, Status, Message, Details, Source, CorrelationId |
            Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Force -Encoding UTF8

        Write-Host "Detailed audit export written to: $OutputPath" -ForegroundColor Green
    }
}