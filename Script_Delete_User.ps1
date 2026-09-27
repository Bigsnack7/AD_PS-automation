<#
.SYNOPSIS
    Deletes a specific Active Directory user account.

.DESCRIPTION
    Removes a user account after requiring explicit destructive-operation approval. The script
    logs the action, verifies the user no longer exists, and supports preview mode through
    ShouldProcess. Use -WhatIf before the change and only pass -AllowDestructiveOperation when the
    deletion is intentionally approved.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [switch]$AllowDestructiveOperation,
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
if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
    throw 'Refusing to delete user accounts without -AllowDestructiveOperation. Preview with -WhatIf first.'
}

# BUGFIX: -AllowDestructiveOperation is documented as the explicit approval mechanism for this
# destructive script, but it never actually suppressed PowerShell's own ShouldProcess
# confirmation prompt (ConfirmImpact='High' + the default $ConfirmPreference of 'High' means
# every live deletion still stops for an interactive "Are you sure?" regardless of this switch).
# That makes unattended/automated use impossible even though the switch's whole purpose is to
# say "this deletion is intentionally approved." Only relax it when the caller didn't explicitly
# ask for a prompt themselves via -Confirm, so an explicit -Confirm still wins.
if ($AllowDestructiveOperation -and -not $PSBoundParameters.ContainsKey('Confirm')) {
    $ConfirmPreference = 'None'
}

$user = Resolve-ADIdentitySafe $Identity -Server $Server -Credential $Credential

# BUGFIX: Resolve-ADIdentitySafe's name implies it reports a failed lookup by returning nothing
# rather than throwing, but the result was never checked. An unresolved Identity used to fall
# straight through to Write-ADAuditRecord with a $null Target and then to Remove-ADUser with a
# $null -Identity, producing a confusing failure deep inside cmdlets that aren't about lookup at
# all, instead of a clear error naming the identity that couldn't be found.
if (-not $user) {
    throw "No Active Directory user could be resolved for identity '$Identity'."
}

Write-ADAuditRecord -Path $AuditLogPath -Action 'DeleteUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Started' -Details "Deleting user '$($user.SamAccountName)'."
if ($PSCmdlet.ShouldProcess($user.SamAccountName,'Delete Active Directory user')) {
    try {
        Remove-ADUser @adContext -Identity $user -Confirm:$false -ErrorAction Stop

        if (Test-ADUserExists -Identity $user.SamAccountName -Server $Server -Credential $Credential) {
            throw "Delete verification failed for '$($user.SamAccountName)': the account still exists after removal."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'DeleteUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Succeeded' -Details "Deleted user '$($user.SamAccountName)' and verified the account no longer exists."
        Write-Host "Deleted $($user.SamAccountName)" -ForegroundColor Red
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'DeleteUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Delete failed for user '$($user.SamAccountName)'."
        throw
    }
}
else {
    Write-ADAuditRecord -Path $AuditLogPath -Action 'DeleteUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Preview' -Details "Preview only: would delete user '$($user.SamAccountName)'."
}