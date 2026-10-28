[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Enable', 'Disable', 'Unlock', 'ResetPassword', 'Move', 'Terminate', 'Delete', 'AddToGroup', 'RemoveFromGroup')]
    [string]$Action,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [string]$TargetPath,
    [string]$Group,
    [string]$Reason = 'Terminated',
    [SecureString]$NewPassword,
    [switch]$MustChangeAtLogon,
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop

$arguments = @{
    Action = $Action
    Identity = $Identity
    TargetPath = $TargetPath
    Group = $Group
    Reason = $Reason
    MustChangeAtLogon = $MustChangeAtLogon
    AllowDestructiveOperation = $AllowDestructiveOperation
    Server = $Server
    Credential = $Credential
    AuditLogPath = $AuditLogPath
}
if ($PSBoundParameters.ContainsKey('NewPassword')) { $arguments.NewPassword = $NewPassword }
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Invoke-ADAutoXUserLifecycle @arguments
