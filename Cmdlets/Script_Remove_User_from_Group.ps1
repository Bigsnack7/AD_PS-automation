[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Group,
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\ADAutoX.psd1') -ErrorAction Stop
$arguments = @{ Operation = 'Remove'; Identity = $Identity; Group = $Group }
foreach ($name in 'AllowDestructiveOperation','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Set-ADAutoXUserGroupMembership @arguments
