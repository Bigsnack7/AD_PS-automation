<#
.SYNOPSIS
    Removes a user from a specified Active Directory group.

.DESCRIPTION
    Resolves the target user and group, requires explicit destructive-operation approval, and
    verifies the user is no longer present in the group after the change. Preview the action with
    -WhatIf before making a live removal, and use -AllowDestructiveOperation only when the change
    is intentionally approved.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Group,
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath=''
)

if ([string]::IsNullOrWhiteSpace($Identity)) {
    throw 'Identity cannot be blank.'
}
if ([string]::IsNullOrWhiteSpace($Group)) {
    throw 'Group cannot be blank.'
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
try {
Set-ADToolContext -Server $Server -Credential $Credential
$adContext = Get-ADToolContextParameters

# Use the resolved context consistently for every AD call, including identity
# resolution, so the user lookup can't silently target a different server/
# credential than the group operations that follow.
$user = Resolve-ADIdentitySafe -Identity $Identity @adContext
$group = Get-ADGroup @adContext -Identity $Group -ErrorAction Stop
$target = "$($user.DistinguishedName) -> $($group.DistinguishedName)"

if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
    # This is a destructive, high-impact action being blocked by policy — that's
    # worth an audit record in its own right, not just a silent throw. Every
    # other outcome in this script (started/succeeded/failed/skipped/preview)
    # is logged; a refused attempt shouldn't be the one exception.
    $refusalMessage = 'Refusing group membership removal without -AllowDestructiveOperation.'
    Write-ADAuditRecord -Path $AuditLogPath -Action 'RemoveGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Failed' -Message $refusalMessage -Details "Blocked removal of user '$($user.SamAccountName)' from group '$($group.Name)': -AllowDestructiveOperation was not specified."
    throw $refusalMessage
}

if ($PSCmdlet.ShouldProcess($user.SamAccountName,"Remove from group $($group.Name)")) {
    # Only record "Started" once we know the change is actually going to be
    # attempted — logging it unconditionally before the ShouldProcess check
    # would make -WhatIf runs and declined confirmations look like they began
    # real work.
    Write-ADAuditRecord -Path $AuditLogPath -Action 'RemoveGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Started' -Details "Removing user '$($user.SamAccountName)' from group '$($group.Name)'."

    try {
        Remove-ADGroupMember @adContext -Identity $group -Members $user -Confirm:$false -ErrorAction Stop

        $groupMembers = @(Get-ADGroupMember @adContext -Identity $group -ErrorAction Stop)
        $isMember = $groupMembers | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
        if ($isMember) {
            throw "RemoveGroupMember verification failed for '$($user.SamAccountName)': the user is still present in group '$($group.Name)'."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'RemoveGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Succeeded' -Details "Removed and verified user '$($user.SamAccountName)' is no longer a member of group '$($group.Name)'."
        Write-Host "Removed $($user.SamAccountName) from $($group.Name)" -ForegroundColor Green
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'RemoveGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to remove user '$($user.SamAccountName)' from group '$($group.Name)'."
        throw
    }
}
else {
    # ShouldProcess returns $false for two different reasons: a -WhatIf dry
    # run, or a user actively declining a confirmation prompt. The audit
    # schema has distinct statuses for these ('Preview' vs 'Skipped') — don't
    # collapse them into one.
    $notProceedingStatus = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
    $notProceedingVerb = if ($WhatIfPreference) { 'Preview only: would remove' } else { 'Skipped: declined to remove' }
    Write-ADAuditRecord -Path $AuditLogPath -Action 'RemoveGroupMember' -Target $target -TargetType 'GroupMembership' -Status $notProceedingStatus -Details "$notProceedingVerb user '$($user.SamAccountName)' from group '$($group.Name)'."
}
}
finally {
    Clear-ADToolContext
}