<#
.SYNOPSIS
    Adds a user to a specified Active Directory group.

.DESCRIPTION
    Resolves the target user and group, logs the operation, and verifies that the membership
    change was applied successfully. Preview the action with -WhatIf before running it in a live
    environment. Use the script only when the target group and account are already known.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Group,
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

if ($PSCmdlet.ShouldProcess($user.SamAccountName,"Add to group $($group.Name)")) {
    # Only record "Started" once we know the change is actually going to be
    # attempted — logging it unconditionally (before the ShouldProcess check)
    # would make -WhatIf runs and declined confirmations look like they began
    # real work.
    Write-ADAuditRecord -Path $AuditLogPath -Action 'AddGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Started' -Details "Adding user '$($user.SamAccountName)' to group '$($group.Name)'."

    try {
        # -Confirm:$false: consent was already obtained via $PSCmdlet.ShouldProcess
        # above; without this, a caller running with -Confirm (or a lowered
        # $ConfirmPreference) would be prompted a second time for the same action.
        Add-ADGroupMember @adContext -Identity $group -Members $user -Confirm:$false -ErrorAction Stop

        $groupMembers = @(Get-ADGroupMember @adContext -Identity $group -ErrorAction Stop)
        $isMember = $groupMembers | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
        if (-not $isMember) {
            throw "AddGroupMember verification failed for '$($user.SamAccountName)': the user was not found in group '$($group.Name)'."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'AddGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Succeeded' -Details "Added and verified user '$($user.SamAccountName)' is a member of group '$($group.Name)'."
        Write-Host "Added $($user.SamAccountName) to $($group.Name)" -ForegroundColor Green
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'AddGroupMember' -Target $target -TargetType 'GroupMembership' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to add user '$($user.SamAccountName)' to group '$($group.Name)'."
        throw
    }
}
else {
    # ShouldProcess returns $false for two different reasons: a -WhatIf dry
    # run, or a user actively declining a confirmation prompt. The audit
    # schema has distinct statuses for these ('Preview' vs 'Skipped') — don't
    # collapse them into one.
    $notProceedingStatus = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
    $notProceedingVerb = if ($WhatIfPreference) { 'Preview only: would add' } else { 'Skipped: declined to add' }
    Write-ADAuditRecord -Path $AuditLogPath -Action 'AddGroupMember' -Target $target -TargetType 'GroupMembership' -Status $notProceedingStatus -Details "$notProceedingVerb user '$($user.SamAccountName)' to group '$($group.Name)'."
}
}
finally {
    Clear-ADToolContext
}