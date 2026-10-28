[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [ValidateNotNullOrEmpty()][string]$Identity,
    [ValidateNotNullOrEmpty()][string]$SearchBase,
    [switch]$AllowDomainWide,
    [switch]$IncludeNeverLoggedOn,
    [ValidateNotNullOrEmpty()][string]$CsvPath,
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\ADAutoX.psd1') -ErrorAction Stop

if ($Identity) {
    $arguments = @{ Identity = $Identity }
    foreach ($name in 'AllowDestructiveOperation','Server','Credential','AuditLogPath') {
        if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
    }
    if ($WhatIfPreference) { $arguments.WhatIf = $true }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
    $result = Disable-ADAutoXUser @arguments
    if ($CsvPath) {
        Export-ADResults -Results @($result) -Path $CsvPath -WhatIf:$WhatIfPreference
    }
    return $result
}

$arguments = @{}
foreach ($name in 'InactiveDays','SearchBase','AllowDomainWide','IncludeNeverLoggedOn','AllowDestructiveOperation','CsvPath','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Disable-ADAutoXInactiveUsers @arguments
