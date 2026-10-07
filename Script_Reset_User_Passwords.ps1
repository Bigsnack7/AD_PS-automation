<#
.SYNOPSIS
    Resets a user password in Active Directory.

.DESCRIPTION
    Resets a target account password, optionally sets the ChangePasswordAtLogon flag, logs the
    operation, and verifies the requested password-policy state. Use -WhatIf to preview the change,
    and confirm that the target account and password reset are intentionally approved before running
    this in production.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [SecureString]$NewPassword,
    [switch]$MustChangeAtLogon,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath=''
)

if ([string]::IsNullOrWhiteSpace($Identity)) {
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
try {
Set-ADToolContext -Server $Server -Credential $Credential
$adContext = Get-ADToolContextParameters

if (-not $PSBoundParameters.ContainsKey('NewPassword')) {
    if ($WhatIfPreference) {
        # Only ever assigned on the -WhatIf path, where ShouldProcess always
        # returns $false, so this value structurally cannot reach
        # Set-ADAccountPassword. Kept inert by construction rather than by
        # relying on the surrounding control flow staying the same.
        $NewPassword = ConvertTo-SecureString 'PreviewOnly-Not-Used-1!' -AsPlainText -Force
    }
    else {
        $NewPassword = Read-Host 'New password' -AsSecureString
    }
}

# Defense in depth: fail loudly rather than silently proceeding if a real
# (non-preview) run somehow reaches this point without a usable password.
if (-not $WhatIfPreference -and ($null -eq $NewPassword -or $NewPassword.Length -eq 0)) {
    throw 'A new password is required (supply -NewPassword or enter one when prompted).'
}

# Use the resolved context consistently for every AD call, including identity
# resolution, so the user lookup can't silently target a different server/
# credential than the reset/verify calls that follow.
$user = Resolve-ADIdentitySafe $Identity @adContext
if (-not $user) { throw "Unable to resolve user '$Identity'." }

# Resolve the target once and reuse it everywhere, so every record for this
# operation (Started/Succeeded/Failed/Preview/Skipped) refers to the same
# value instead of mixing the raw -Identity string with the resolved DN.
$target = $user.DistinguishedName
$mutationAttempted = $false

if ($PSCmdlet.ShouldProcess($user.SamAccountName,'Reset password')) {
    # Only record "Started" once we know the change is actually going to be
    # attempted — logging it unconditionally before the ShouldProcess check
    # would make -WhatIf runs and declined confirmations look like they began
    # real work.
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetPassword' -Target $target -TargetType 'User' -Status 'Started' -Details "Resetting password for user '$($user.SamAccountName)'."

    try {
        # -Confirm:$false on both calls: consent was already obtained via
        # $PSCmdlet.ShouldProcess above; without this, a caller running with
        # -Confirm (or a lowered $ConfirmPreference) would be prompted again
        # for the same logical action.
        $mutationAttempted = $true
        Set-ADAccountPassword @adContext -Identity $user -Reset -NewPassword $NewPassword -Confirm:$false -ErrorAction Stop
        if ($MustChangeAtLogon) { Set-ADUser @adContext -Identity $user -ChangePasswordAtLogon $true -Confirm:$false -ErrorAction Stop }

        $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties pwdLastSet -ErrorAction Stop

        if ($MustChangeAtLogon) {
            if ($verifiedUser.pwdLastSet -ne 0) {
                throw "Password reset verification failed for '$($user.SamAccountName)': ChangePasswordAtLogon is not enabled."
            }
        }
        elseif ($verifiedUser.pwdLastSet -eq 0) {
            # pwdLastSet has coarse timestamp granularity; comparing it with a
            # pre-reset read can falsely fail when both operations occur in
            # the same timestamp interval. For a normal reset, ensure the
            # account is not left in the must-change-at-logon state instead.
            throw "Password reset verification failed for '$($user.SamAccountName)': the account is still marked to change its password at next logon."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetPassword' -Target $target -TargetType 'User' -Status 'Succeeded' -Details "Password reset completed for user '$($user.SamAccountName)' and verified the requested password-change-at-logon state."
        Write-Host "Password reset for $($user.SamAccountName)" -ForegroundColor Green
    }
    catch {
        $failureStatus = if ($mutationAttempted) { 'CompletedWithErrors' } else { 'Failed' }
        $failureDetails = "Password reset failed for user '$($user.SamAccountName)'."
        if ($mutationAttempted) {
            $failureDetails += ' The password may already have been changed; verify the account state and communicate securely with the user before retrying.'
        }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetPassword' -Target $target -TargetType 'User' -Status $failureStatus -Message $_.Exception.Message -Details $failureDetails
        throw
    }
}
else {
    # ShouldProcess returns $false for two different reasons: a -WhatIf dry
    # run, or a user actively declining a confirmation prompt. The audit
    # schema has distinct statuses for these ('Preview' vs 'Skipped') — don't
    # collapse them into one.
    $notProceedingStatus = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
    $notProceedingVerb = if ($WhatIfPreference) { 'Preview only: would reset' } else { 'Skipped: declined to reset' }
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetPassword' -Target $target -TargetType 'User' -Status $notProceedingStatus -Details "$notProceedingVerb password for user '$($user.SamAccountName)'."
}
}
finally {
    Clear-ADToolContext
}