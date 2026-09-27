<#
.SYNOPSIS
    Moves a user account to a target Active Directory OU.

.DESCRIPTION
    Resolves the source user and destination OU, performs the move when approved, and verifies
    that the final distinguished name reflects the new location. Preview the action with -WhatIf
    before making a live change and confirm the destination OU is correct.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TargetPath,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath=''
)

if ($PSBoundParameters.ContainsKey('Identity') -and [string]::IsNullOrWhiteSpace($Identity)) {
    throw 'Identity cannot be blank.'
}
if ($PSBoundParameters.ContainsKey('TargetPath') -and [string]::IsNullOrWhiteSpace($TargetPath)) {
    throw 'TargetPath cannot be blank.'
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
$user = Resolve-ADIdentitySafe $Identity -Server $Server -Credential $Credential

# BUGFIX: same issue as the delete script — Resolve-ADIdentitySafe's name implies a failed
# lookup comes back as nothing rather than a thrown error, but that was never checked here. An
# unresolved -Identity used to fall straight through to $user.DistinguishedName ($null) and
# eventually into Move-ADObject with a null -Identity, instead of a clear "not found" error.
if (-not $user) {
    throw "No Active Directory user could be resolved for identity '$Identity'."
}

$targetOu = Get-TargetOU -Path $TargetPath -Server $Server -Credential $Credential
$target = "$($user.DistinguishedName) -> $($targetOu.DistinguishedName)"

# BUGFIX: "is the user already in the target OU" was decided with
# $user.DistinguishedName.EndsWith(",$($targetOu.DistinguishedName)"). EndsWith on a raw DN
# string is a substring check, not a parent-container check — a user one or more sub-OUs BELOW
# the target (e.g. user in "OU=Sub,OU=IT,...", target "OU=IT,...") has a DN that legitimately
# ends with ",OU=IT,..." too, so they were wrongly reported as "already in the target OU" and
# the move was silently skipped. The same broken comparison was reused to verify the move
# afterward, so it could also report success when the object actually landed one level deeper
# than intended. Compare the user's *immediate* parent DN for an exact match instead.
function Get-ParentDistinguishedName {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    # Strips the leading RDN (e.g. "CN=Jane Doe,") while respecting backslash-escaped
    # characters (including escaped commas) inside that RDN's value.
    return ($DistinguishedName -replace '^(?:[^,\\]|\\.)*,', '')
}

$userParentDn = Get-ParentDistinguishedName -DistinguishedName $user.DistinguishedName
if ($userParentDn.Equals($targetOu.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
    Write-ADAuditRecord -Path $AuditLogPath -Action 'MoveUser' -Target $target -TargetType 'User' -Status 'Skipped' -Message 'User is already in the target OU.' -Details "User '$($user.SamAccountName)' is already located in OU '$($targetOu.DistinguishedName)'."
    Write-Host "User $($user.SamAccountName) is already in $($targetOu.DistinguishedName)." -ForegroundColor Yellow
    return
}
Write-ADAuditRecord -Path $AuditLogPath -Action 'MoveUser' -Target $target -TargetType 'User' -Status 'Started' -Details "Moving user '$($user.SamAccountName)' from current OU to '$($targetOu.DistinguishedName)'."
if ($PSCmdlet.ShouldProcess($user.SamAccountName,"Move user to $($targetOu.DistinguishedName)")) {
    try {
        Move-ADObject @adContext -Identity $user -TargetPath $targetOu.DistinguishedName -ErrorAction Stop

        $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties DistinguishedName -ErrorAction Stop
        $verifiedParentDn = Get-ParentDistinguishedName -DistinguishedName $verifiedUser.DistinguishedName
        if (-not $verifiedParentDn.Equals($targetOu.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Move verification failed for '$($user.SamAccountName)': the account is still not located in '$($targetOu.DistinguishedName)'. Current DN: '$($verifiedUser.DistinguishedName)'."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'MoveUser' -Target $target -TargetType 'User' -Status 'Succeeded' -Details "Moved user '$($user.SamAccountName)' to OU '$($targetOu.DistinguishedName)' and verified the new location."
        Write-Host "Moved $($user.SamAccountName) to $($targetOu.DistinguishedName)" -ForegroundColor Green
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'MoveUser' -Target $target -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Move failed for user '$($user.SamAccountName)'."
        throw
    }
}
else {
    Write-ADAuditRecord -Path $AuditLogPath -Action 'MoveUser' -Target $target -TargetType 'User' -Status 'Preview' -Details "Preview only: would move user '$($user.SamAccountName)' to OU '$($targetOu.DistinguishedName)'."
}