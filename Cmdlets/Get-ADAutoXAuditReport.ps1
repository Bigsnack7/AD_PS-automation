[CmdletBinding()]
param(
    [string]$AuditLogPath = '',
    [string]$Identity = '',
    [string]$Action = '',
    [string]$Status = '',
    [string]$Actor = '',
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $rootDirectory 'AD-Operations.jsonl'
}
$results = Get-ADAutoXAuditReport -LogPath $AuditLogPath -Identity $Identity -Action $Action -Status $Status -Actor $Actor -OutputPath $OutputPath
if ($results.Count -gt 0) {
    Write-ADAutoXConsole -Message "Displaying $($results.Count) matching audit entries:" -Level Phase
    $results | Format-Table -Property Timestamp,Action,Target,Status,Actor,CorrelationId -AutoSize
}
else {
    Write-ADAutoXConsole -Message 'No matching audit log entries found.' -Level Warning
}
