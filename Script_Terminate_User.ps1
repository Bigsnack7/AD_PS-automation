<#
.SYNOPSIS
    Terminates an Active Directory user account by disabling it and applying a termination state.

.DESCRIPTION
    Disables the target account, optionally moves it to a termination OU, applies the provided
    termination reason, and verifies the updated state before reporting success. This operation is
    destructive and must be explicitly approved with -AllowDestructiveOperation; preview with
    -WhatIf before making a live change.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [string]$TerminationOU,
    [string]$TerminationReason = 'Terminated',
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath=''
)

if ($PSBoundParameters.ContainsKey('Identity') -and [string]::IsNullOrWhiteSpace($Identity)) {
    throw 'Identity cannot be blank.'
}
if ($PSBoundParameters.ContainsKey('TerminationOU') -and [string]::IsNullOrWhiteSpace($TerminationOU)) {
    throw 'TerminationOU cannot be blank when supplied.'
}
if ($PSBoundParameters.ContainsKey('TerminationReason') -and [string]::IsNullOrWhiteSpace($TerminationReason)) {
    throw 'TerminationReason cannot be blank.'
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

# Pure parameter validation - none of this touches AD state, so it runs before
# Set-ADToolContext. Failing fast here means a bad invocation never has to be
# unwound.
if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
    throw 'Refusing to terminate a user without -AllowDestructiveOperation. Preview with -WhatIf first.'
}

# Initialized up front (rather than only on the success path) so the catch
# block below can safely reference them under Set-StrictMode no matter how
# early a failure occurs.
$target = $Identity
$user = $null
$targetOU = $null
$mutationAttempted = $false

# Everything from here on establishes and relies on process-wide AD context
# (Set-ADToolContext), so it must always be unwound via Clear-ADToolContext -
# on success, on preview, and on any failure, wherever it occurs.
try {
    Set-ADToolContext -Server $Server -Credential $Credential
    $adContext = Get-ADToolContextParameters

    $user = Resolve-ADIdentitySafe $Identity -Server $Server -Credential $Credential
    if (-not $user) { throw "Unable to resolve user '$Identity'." }
    if ($TerminationOU) {
        $targetOU = Get-TargetOU -Path $TerminationOU -Server $Server -Credential $Credential
    }
    $target = if ($targetOU) { "$($user.DistinguishedName) -> $($targetOU.DistinguishedName)" } else { $user.DistinguishedName }
    $userWithDescription = Get-ADUser @adContext -Identity $user -Properties Description -ErrorAction Stop
    $terminationDescription = New-ADTerminationDescription -ExistingDescription $userWithDescription.Description -Reason $TerminationReason

    if ($PSCmdlet.ShouldProcess($user.SamAccountName,'Terminate Active Directory user')) {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'TerminateUser' -Target $target -TargetType 'User' -Status 'Started' -Details "Terminating user '$($user.SamAccountName)' with reason '$TerminationReason'."
        $mutationAttempted = $true
        Disable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop
        if ($targetOU) {
            Move-ADObject @adContext -Identity $user -TargetPath $targetOU.DistinguishedName -Confirm:$false -ErrorAction Stop
        }
        Set-ADUser @adContext -Identity $user -Description $terminationDescription -Confirm:$false -ErrorAction Stop

        $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties Enabled, DistinguishedName, Description -ErrorAction Stop
        $verificationIssues = [System.Collections.Generic.List[string]]::new()

        if ($verifiedUser.Enabled) {
            $verificationIssues.Add("expected the account to be disabled after termination.")
        }

        if ($targetOU -and
            -not (Get-ADDistinguishedNameParent -DistinguishedName $verifiedUser.DistinguishedName).Equals(
                $targetOU.DistinguishedName,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            $verificationIssues.Add("expected the account to be moved to '$($targetOU.DistinguishedName)' but found '$($verifiedUser.DistinguishedName)'.")
        }

        if ($verifiedUser.Description -ne $terminationDescription) {
            $verificationIssues.Add("expected the termination description to be '$terminationDescription' but found '$($verifiedUser.Description)'.")
        }

        if ($verificationIssues.Count -gt 0) {
            throw "Termination verification failed for '$($user.SamAccountName)': $($verificationIssues -join ' ' )"
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'TerminateUser' -Target $target -TargetType 'User' -Status 'Succeeded' -Details "Terminated user '$($user.SamAccountName)', verified the disabled state, verified the OU location, and preserved the existing description while recording the termination reason."
        Write-Host "Terminated $($user.SamAccountName)" -ForegroundColor Yellow
    }
    else {
        $notProceedingStatus = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
        $notProceedingDetails = if ($WhatIfPreference) {
            "Preview only: would terminate user '$($user.SamAccountName)'."
        }
        else {
            "Termination of user '$($user.SamAccountName)' was declined."
        }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'TerminateUser' -Target $target -TargetType 'User' -Status $notProceedingStatus -Details $notProceedingDetails
    }
}
catch {
    $originalError = $_
    $failureDetails = if ($user) { "Termination failed for user '$($user.SamAccountName)'." } else { "Termination failed while resolving '$Identity'." }
    $failureStatus = if ($mutationAttempted) { 'CompletedWithErrors' } else { 'Failed' }
    if ($mutationAttempted) {
        $failureDetails += ' One or more changes may already have been applied; inspect the account and reconcile its state before retrying.'
    }
    try {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'TerminateUser' -Target $target -TargetType 'User' -Status $failureStatus -Message $originalError.Exception.Message -Details $failureDetails
    }
    catch {
        Write-Warning "Failed to write audit record: $($_.Exception.Message)"
    }
    throw $originalError
}
finally {
    Clear-ADToolContext
}