<#
.SYNOPSIS
    Enables a specific Active Directory user account.

.DESCRIPTION
    Resolves the target user, logs the enable operation, and verifies that the account is enabled
    before reporting success. Preview the action with -WhatIf before making a live change.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
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
Set-ADToolContext -Server $Server -Credential $Credential
$adContext = Get-ADToolContextParameters

# Use the resolved context consistently for every AD call, including identity
# resolution, so the user lookup can't silently target a different server/
# credential than the enable/verify calls that follow.
$user = Resolve-ADIdentitySafe $Identity @adContext

if ($user.Enabled) {
    Write-ADAuditRecord -Path $AuditLogPath -Action 'EnableUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Skipped' -Message 'Account is already enabled.' -Details "User '$($user.SamAccountName)' is already enabled."
    Write-Host "User $($user.SamAccountName) is already enabled." -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess($user.SamAccountName,'Enable Active Directory account')) {
    # Only record "Started" once we know the change is actually going to be
    # attempted — logging it unconditionally before the ShouldProcess check
    # would make -WhatIf runs and declined confirmations look like they began
    # real work.
    Write-ADAuditRecord -Path $AuditLogPath -Action 'EnableUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Started' -Details "Enabling user '$($user.SamAccountName)'."

    try {
        # -Confirm:$false: consent was already obtained via $PSCmdlet.ShouldProcess
        # above; without this, a caller running with -Confirm (or a lowered
        # $ConfirmPreference) would be prompted a second time for the same action.
        Enable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop

        $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties Enabled -ErrorAction Stop
        if (-not $verifiedUser.Enabled) {
            throw "Enable verification failed for '$($user.SamAccountName)': the account is still disabled."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'EnableUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Succeeded' -Details "Enabled user '$($user.SamAccountName)' and verified the account is enabled."
        Write-Host "Enabled $($user.SamAccountName)" -ForegroundColor Green
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'EnableUser' -Target $user.DistinguishedName -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Enable failed for user '$($user.SamAccountName)'."
        throw
    }
}
else {
    # ShouldProcess returns $false for two different reasons: a -WhatIf dry
    # run, or a user actively declining a confirmation prompt. The audit
    # schema has distinct statuses for these ('Preview' vs 'Skipped') — don't
    # collapse them into one.
    $notProceedingStatus = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
    $notProceedingVerb = if ($WhatIfPreference) { 'Preview only: would enable' } else { 'Skipped: declined to enable' }
    Write-ADAuditRecord -Path $AuditLogPath -Action 'EnableUser' -Target $user.DistinguishedName -TargetType 'User' -Status $notProceedingStatus -Details "$notProceedingVerb user '$($user.SamAccountName)'."
}