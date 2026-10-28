[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [ValidateNotNullOrEmpty()][string]$TerminationOU,
    [ValidateNotNullOrEmpty()][string]$TerminationReason = 'Terminated',
    [switch]$AllowDestructiveOperation,
    [switch]$AllowProtectedAccount,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\ADAutoX.psd1') -ErrorAction Stop
$arguments = @{
    Identity = $Identity
    Reason = $TerminationReason
}
if ($PSBoundParameters.ContainsKey('TerminationOU')) { $arguments.TargetPath = $TerminationOU }
foreach ($name in 'AllowDestructiveOperation','AllowProtectedAccount','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Stop-ADAutoXUser @arguments
