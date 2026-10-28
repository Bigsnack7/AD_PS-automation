[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [SecureString]$NewPassword,
    [switch]$MustChangeAtLogon,
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
    MustChangeAtLogon = $MustChangeAtLogon
    AllowProtectedAccount = $AllowProtectedAccount
}
foreach ($name in 'Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($PSBoundParameters.ContainsKey('NewPassword')) { $arguments.NewPassword = $NewPassword }
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Reset-ADAutoXUserPassword @arguments
