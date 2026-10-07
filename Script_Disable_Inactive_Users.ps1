<#
.SYNOPSIS
    Disables inactive Active Directory user accounts in a controlled scope.

.DESCRIPTION
    Finds enabled user accounts whose last logon or creation date falls outside the configured
    threshold, optionally skips protected accounts, and disables the remaining candidates after
    explicit approval. With -Identity, the same verified workflow disables one explicitly selected
    account. Results can be written to CSV for reporting. Preview the change with -WhatIf first,
    and require -AllowDestructiveOperation before a live disable action is permitted.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [ValidateNotNullOrEmpty()][string]$Identity,
    [ValidateNotNullOrEmpty()][string]$SearchBase,
    [switch]$AllowDomainWide,
    [switch]$IncludeNeverLoggedOn,
    [ValidateNotNullOrEmpty()][string]$CsvPath,
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)
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
if ($PSBoundParameters.ContainsKey('Identity') -and [string]::IsNullOrWhiteSpace($Identity)) {
    throw 'Identity cannot be blank when supplied.'
}
if ($PSBoundParameters.ContainsKey('SearchBase') -and [string]::IsNullOrWhiteSpace($SearchBase)) {
    throw 'SearchBase cannot be blank when supplied.'
}
if ($PSBoundParameters.ContainsKey('CsvPath') -and [string]::IsNullOrWhiteSpace($CsvPath)) {
    throw 'CsvPath cannot be blank when supplied.'
}
if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
    throw 'Refusing to disable accounts without -AllowDestructiveOperation. Preview with -WhatIf first.'
}
if (-not $Identity -and -not $SearchBase -and -not $AllowDomainWide) {
    throw 'SearchBase is required. Use -AllowDomainWide only after approving a domain-wide operation.'
}

$auditAction = if ($Identity) { 'DisableUser' } else { 'DisableInactiveUsers' }
$auditTarget = if ($Identity) { $Identity } elseif ($SearchBase) { $SearchBase } else { 'Domain' }

# Everything from here on establishes and relies on process-wide AD context
# (Set-ADToolContext), so it must always be unwound via Clear-ADToolContext,
# and any unexpected failure should still leave an audit trail.
try {
    Set-ADToolContext -Server $Server -Credential $Credential
    $adContext = Get-ADToolContextParameters

    $cutoff = (Get-Date).AddDays(-$InactiveDays)
    $query = @{
        Filter = 'Enabled -eq $true'
        Properties = 'LastLogonDate','WhenCreated','Department','DistinguishedName','adminCount','ServicePrincipalName'
    }
    if ($SearchBase -and -not $Identity) {
        $query.SearchBase = $SearchBase
        $query.SearchScope = 'Subtree'
    }

    $alreadyDisabled = @()
    if ($Identity) {
        $selectedUser = Resolve-ADIdentitySafe -Identity $Identity -Server $Server -Credential $Credential
        $selectedUser = Get-ADUser @adContext -Identity $selectedUser -Properties LastLogonDate,WhenCreated,Department,DistinguishedName,adminCount,ServicePrincipalName,Enabled -ErrorAction Stop
        $olderUsers = @($selectedUser)
        $candidates = @(if ($selectedUser.Enabled) { @($selectedUser) } else { @() })
        $skipped = @()
        if (-not $selectedUser.Enabled) { $alreadyDisabled = @($selectedUser) }
    }
    else {
        $olderUsers = @(Get-ADUser @adContext @query | Where-Object {
            $_.WhenCreated -lt $cutoff -and
            ((-not $_.LastLogonDate -and $IncludeNeverLoggedOn) -or ($_.LastLogonDate -and $_.LastLogonDate -lt $cutoff))
        })
        $candidates = @($olderUsers | Where-Object { -not $_.adminCount -and -not $_.ServicePrincipalName })
        $skipped = @($olderUsers | Where-Object { $_.adminCount -or $_.ServicePrincipalName })
    }
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($user in $alreadyDisabled) {
        $results.Add([pscustomobject]@{
                Identity = $user.SamAccountName
                LastLogonDate = $user.LastLogonDate
                Status = 'Skipped'
                Error = 'Account is already disabled.'
            })
    }

    foreach ($user in $skipped) {
        $reason = if ($user.adminCount -and $user.ServicePrincipalName) {
            'Account is protected (adminCount set) and has a service principal name; skipped.'
        }
        elseif ($user.adminCount) {
            'Account is protected (adminCount set); skipped.'
        }
        else {
            'Account has a service principal name (likely a service account); skipped.'
        }
        $results.Add([pscustomobject]@{
                Identity = $user.SamAccountName
                LastLogonDate = $user.LastLogonDate
                Status = 'Skipped'
                Error = $reason
            })
    }

    foreach ($user in $candidates) {
        $status = 'Preview'
        $errorMessage = ''
        try {
            $operationDescription = if ($Identity) { 'Disable Active Directory account' } else { 'Disable inactive account' }
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, $operationDescription)) {
                Disable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop
                $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties Enabled -ErrorAction Stop
                if ($verifiedUser.Enabled) {
                    throw "Disable verification failed for '$($user.SamAccountName)': the account is still enabled."
                }
                Write-Host "Disabled $($user.SamAccountName)" -ForegroundColor Yellow
                $status = 'Disabled'
            }
        }
        catch {
            $status = 'Failed'
            $errorMessage = $_.Exception.Message
        }
        $results.Add([pscustomobject]@{
                Identity = $user.SamAccountName
                LastLogonDate = $user.LastLogonDate
                Status = $status
                Error = $errorMessage
            })
    }

    if ($CsvPath) {
        Export-ADResults -Results $results.ToArray() -Path $CsvPath
    }

    $failedCount = @($results | Where-Object Status -eq 'Failed').Count
    $disabledCount = @($results | Where-Object Status -eq 'Disabled').Count
    $auditStatus = if ($WhatIfPreference) { 'Preview' } elseif ($failedCount -gt 0) { 'CompletedWithErrors' } else { 'Succeeded' }
    Write-ADAuditRecord -Path $AuditLogPath -Action $auditAction -Target $auditTarget -Status $auditStatus -Message "Disabled $disabledCount; failed $failedCount; skipped $($skipped.Count + $alreadyDisabled.Count) accounts."
    if ($Identity) {
        Write-Host "Account processed: $Identity; status: $(@($results)[0].Status)" -ForegroundColor Green
    }
    else {
        Write-Host "Inactive accounts found: $($candidates.Count); protected/service accounts skipped: $($skipped.Count)" -ForegroundColor Green
    }
}
catch {
    $originalError = $_
    try {
        Write-ADAuditRecord -Path $AuditLogPath -Action $auditAction -Target $auditTarget -Status 'Failed' -Message $originalError.Exception.Message
    }
    catch {
        Write-Warning "Failed to write audit record: $($_.Exception.Message)"
    }
    throw $originalError
}
finally {
    Clear-ADToolContext
}