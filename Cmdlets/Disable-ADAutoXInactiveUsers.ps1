[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [string]$SearchBase,
    [switch]$AllowDomainWide,
    [switch]$IncludeNeverLoggedOn,
    [switch]$AllowDestructiveOperation,
    [switch]$AllowProtectedAccount,
    [string]$CsvPath,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop
$arguments = @{}
foreach ($name in 'InactiveDays','SearchBase','AllowDomainWide','IncludeNeverLoggedOn','AllowDestructiveOperation','AllowProtectedAccount','CsvPath','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Disable-ADAutoXInactiveUsers @arguments
