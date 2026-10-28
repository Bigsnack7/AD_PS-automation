[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [Parameter(Mandatory)]
    [ValidateSet('Disable', 'Enable', 'Unlock', 'Move', 'RemoveFromGroup', 'ResetPassword', 'Terminate')]
    [string]$Action,
    [string]$TargetOU,
    [string]$Group,
    [string]$Reason = 'Terminated',
    [SecureString]$NewPassword,
    [switch]$MustChangeAtLogon,
    [switch]$AllowDestructiveOperation,
    [switch]$AllowProtectedAccount,
    [string]$AuditLogPath = '',
    [string]$Server,
    [PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop
$arguments = @{
    Action = $Action
    Identity = $Identity
    Reason = $Reason
    MustChangeAtLogon = $MustChangeAtLogon
    AllowDestructiveOperation = $AllowDestructiveOperation
    AllowProtectedAccount = $AllowProtectedAccount
}
if ($PSBoundParameters.ContainsKey('TargetOU')) { $arguments.TargetPath = $TargetOU }
if ($PSBoundParameters.ContainsKey('Group')) { $arguments.Group = $Group }
foreach ($name in 'AuditLogPath','Server','Credential') {
    if ($PSBoundParameters.ContainsKey($name)) { $arguments[$name] = $PSBoundParameters[$name] }
}
if ($PSBoundParameters.ContainsKey('NewPassword')) { $arguments.NewPassword = $NewPassword }
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Invoke-ADAutoXUserAction @arguments
