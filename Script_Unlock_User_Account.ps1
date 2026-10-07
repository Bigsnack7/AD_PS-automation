<#
.SYNOPSIS
    Unlocks a locked Active Directory user account.

.DESCRIPTION
    Resolves the target account, logs the unlock request, and verifies that the account is no
    longer locked after the operation. Preview the action with -WhatIf before making a live change.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath=''
)

if ($PSBoundParameters.ContainsKey('Identity') -and [string]::IsNullOrWhiteSpace($Identity)) {
    throw 'Identity cannot be blank.'
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}

$operationsModule = Join-Path $scriptDirectory 'AD-Operations.psm1'

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

Import-Module $operationsModule -Force
Assert-ADOperationsDependencies
Import-ADTools
Set-ADToolContext -Server $Server -Credential $Credential
$adContext = Get-ADToolContextParameters
$user=Resolve-ADIdentitySafe $Identity -Server $Server -Credential $Credential

# BUGFIX: same gap as the other single-account scripts — Resolve-ADIdentitySafe's name implies
# a failed lookup returns nothing rather than throwing, but that was never checked. An
# unresolved -Identity used to fall straight through to $user.DistinguishedName ($null) and
# eventually into Unlock-ADAccount with a null -Identity, instead of a clear "not found" error.
if (-not $user) {
    throw "No Active Directory user could be resolved for identity '$Identity'."
}

Write-ADAuditRecord -Path $AuditLogPath -Action 'UnlockAccount' -Target $user.DistinguishedName -TargetType 'User' -Status 'Started' -Details "Unlock requested for user '$($user.SamAccountName)'."
if ($PSCmdlet.ShouldProcess($user.SamAccountName,'Unlock account')) {
    try {
        Unlock-ADAccount @adContext -Identity $user -ErrorAction Stop

        $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties LockedOut -ErrorAction Stop
        if ($verifiedUser.LockedOut) {
            throw "Unlock verification failed for '$($user.SamAccountName)': the account is still locked."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'UnlockAccount' -Target $user.DistinguishedName -TargetType 'User' -Status 'Succeeded' -Details "Unlocked and verified user '$($user.SamAccountName)'."; Write-Host "Unlocked $($user.SamAccountName)" -ForegroundColor Green
    }
    catch { Write-ADAuditRecord -Path $AuditLogPath -Action 'UnlockAccount' -Target $user.DistinguishedName -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Unlock failed for user '$($user.SamAccountName)'."; throw }
}
else { Write-ADAuditRecord -Path $AuditLogPath -Action 'UnlockAccount' -Target $user.DistinguishedName -TargetType 'User' -Status 'Preview' -Details "Preview only: would unlock user '$($user.SamAccountName)'." }