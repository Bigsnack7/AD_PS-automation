[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$CsvPath,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\ADAutoX.psd1') -ErrorAction Stop
$arguments = @{}
foreach ($name in 'SearchBase','CsvPath','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
Get-ADAutoXLockedOutUsers @arguments
