<#
.SYNOPSIS
    Removes generated test users and, optionally, the complete test OU hierarchy.

.DESCRIPTION
    Destructive. Always preview first with -WhatIf. A real run requires BOTH
    -AllowDestructiveOperation and -ExpectedDistinguishedName set to the exact DN of the
    target OU (printed by the -WhatIf preview), so a mistyped OU name cannot be deleted by accident.

    All safety checks run before the first deletion. Failures are written to the audit log.

.PARAMETER ExpectedDistinguishedName
    Exact DN of the OU you intend to reset. Required for real (non -WhatIf) runs.

.PARAMETER Force
    Suppresses the per-object confirmation prompts (ConfirmImpact is High). Ignored with -WhatIf.

.EXAMPLE
    .\2_RESET_TEST_USERS.ps1 -DeleteEverything -WhatIf

.EXAMPLE
    .\2_RESET_TEST_USERS.ps1 -DeleteEverything -AllowDestructiveOperation `
        -ExpectedDistinguishedName 'OU=Company,DC=example,DC=com' -Force
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
    [string]$OrganizationalUnitName = 'Company',

    [switch]$RemoveOrganizationalUnit,

    [switch]$RemoveAllObjects,

    [switch]$DeleteEverything,

    [switch]$AllowDestructiveOperation,

    [string]$ExpectedDistinguishedName,

    [switch]$Force,

    [string]$Server,

    [PSCredential]$Credential,

    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}

Import-Module ActiveDirectory -ErrorAction Stop
$operationsModule = Join-Path $scriptDirectory 'AD-Operations.psm1'

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

Import-Module $operationsModule -Force
Assert-ADOperationsDependencies

# Counts unescaped commas, so a shallow OU with a long name is never mistaken for a deeper object.
# Scans character by character so both "CN=O\,Brien" (escaped comma) and a name ending in an
# escaped backslash ("CN=a\\,OU=x") are handled correctly.
function Get-DistinguishedNameDepth {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    $depth = 1
    $escaped = $false
    foreach ($character in $DistinguishedName.ToCharArray()) {
        if ($escaped) { $escaped = $false; continue }
        if ($character -eq '\') { $escaped = $true; continue }
        if ($character -eq ',') { $depth++ }
    }
    return $depth
}

if ($Force -and -not $WhatIfPreference) { $ConfirmPreference = 'None' }

$auditStarted = $false
$removedUsers = 0
$removedOUs = 0
$removedOtherObjects = 0

try {
    Set-ADToolContext -Server $Server -Credential $Credential
    $adContext = Get-ADToolContextParameters

    if ($DeleteEverything) {
        $RemoveAllObjects = $true
        $RemoveOrganizationalUnit = $true
    }
    if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
        throw 'Refusing to delete AD objects without -AllowDestructiveOperation. Preview with -WhatIf first.'
    }
    if ($RemoveAllObjects -and -not $RemoveOrganizationalUnit) {
        throw 'RemoveAllObjects requires -RemoveOrganizationalUnit so the selected test OU is fully reset.'
    }
    if ($OrganizationalUnitName -eq 'Domain Controllers') {
        throw "Refusing to operate on the built-in 'Domain Controllers' OU."
    }

    Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status 'Started'
    $auditStarted = $true

    $domain = Get-ADDomain @adContext -ErrorAction Stop
    $domainRoot = $domain.DistinguishedName
    $safeOrganizationalUnitName = ConvertTo-LdapFilterValue $OrganizationalUnitName
    $organizationalUnits = @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeOrganizationalUnitName)" `
        -SearchBase $domainRoot -SearchScope OneLevel -ErrorAction Stop)
    if ($organizationalUnits.Count -gt 1) {
        throw "More than one OU named '$OrganizationalUnitName' was found below '$domainRoot'. Use a unique OU name."
    }

    if ($organizationalUnits.Count -eq 0) {
        Write-Host "OU '$OrganizationalUnitName' was not found. Nothing to reset." -ForegroundColor Yellow
        Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status 'Skipped' -Message 'Target OU was not found.'
        return
    }

    $ouPath = $organizationalUnits[0].DistinguishedName
    Write-Host "Target OU: $ouPath" -ForegroundColor Cyan

    if ($domain.PSObject.Properties['DomainControllersContainer'] -and $ouPath -eq $domain.DomainControllersContainer) {
        throw "Refusing to operate on the domain controllers OU '$ouPath'."
    }
    if (-not $WhatIfPreference) {
        if ([string]::IsNullOrWhiteSpace($ExpectedDistinguishedName) -or $ExpectedDistinguishedName -ne $ouPath) {
            throw "Refusing to continue: -ExpectedDistinguishedName must exactly match the target OU '$ouPath'."
        }
    }

    # One enumeration, deepest objects first, so children are always removed before their parents.
    $allObjects = @(Get-ADObject @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * -ErrorAction Stop |
        Where-Object { $_.DistinguishedName -ne $ouPath } |
        Sort-Object -Property @{ Expression = { Get-DistinguishedNameDepth $_.DistinguishedName }; Descending = $true })
    $users = @($allObjects | Where-Object { $_.ObjectClass -eq 'user' })
    $childOUs = @($allObjects | Where-Object { $_.ObjectClass -eq 'organizationalUnit' })
    $otherObjects = @($allObjects | Where-Object { $_.ObjectClass -notin @('user', 'organizationalUnit') })

    # Preflight: every refusal happens here, BEFORE anything is deleted.
    if ($RemoveOrganizationalUnit -and -not $RemoveAllObjects -and $otherObjects.Count -gt 0) {
        $objectList = $otherObjects | Select-Object -ExpandProperty DistinguishedName
        throw "Refusing to remove '$ouPath' because it contains non-user objects: $($objectList -join '; ')"
    }

    Write-Host ("Found {0} user(s), {1} child OU(s), {2} other object(s) under '{3}'." -f
        $users.Count, $childOUs.Count, $otherObjects.Count, $ouPath) -ForegroundColor Cyan

    # OUs are created protected from accidental deletion by default; deletion fails unless cleared.
    if ($RemoveOrganizationalUnit) {
        $protectedOUs = @(Get-ADOrganizationalUnit @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * `
            -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop |
            Where-Object { $_.ProtectedFromAccidentalDeletion })
        foreach ($protectedOU in $protectedOUs) {
            if ($PSCmdlet.ShouldProcess($protectedOU.DistinguishedName, 'Clear accidental-deletion protection')) {
                Set-ADObject @adContext -Identity $protectedOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
            }
        }
    }

    if ($RemoveAllObjects) {
        foreach ($object in $allObjects) {
            if ($PSCmdlet.ShouldProcess($object.DistinguishedName, "Remove $($object.ObjectClass)")) {
                Remove-ADObject @adContext -Identity $object.DistinguishedName -Confirm:$false -ErrorAction Stop
                switch ($object.ObjectClass) {
                    'user' { $removedUsers++ }
                    'organizationalUnit' { $removedOUs++ }
                    default { $removedOtherObjects++ }
                }
                Write-Host "Removed: $($object.DistinguishedName)" -ForegroundColor Cyan
            }
        }
    }
    else {
        if ($users.Count -eq 0) {
            Write-Host "No user accounts found in '$ouPath' or its child OUs." -ForegroundColor Yellow
        }
        foreach ($user in $users) {
            if ($PSCmdlet.ShouldProcess($user.DistinguishedName, 'Remove Active Directory user')) {
                Remove-ADUser @adContext -Identity $user.DistinguishedName -Confirm:$false -ErrorAction Stop
                $removedUsers++
                Write-Host "Removed user: $($user.DistinguishedName)" -ForegroundColor Cyan
            }
        }
        if ($RemoveOrganizationalUnit) {
            foreach ($childOU in $childOUs) {
                if ($PSCmdlet.ShouldProcess($childOU.DistinguishedName, 'Remove child organizational unit')) {
                    Remove-ADOrganizationalUnit @adContext -Identity $childOU.DistinguishedName -Confirm:$false -ErrorAction Stop
                    $removedOUs++
                    Write-Host "Removed OU: $($childOU.DistinguishedName)" -ForegroundColor Cyan
                }
            }
        }
    }

    if ($RemoveOrganizationalUnit) {
        if ($PSCmdlet.ShouldProcess($ouPath, 'Remove organizational unit')) {
            Remove-ADOrganizationalUnit @adContext -Identity $ouPath -Confirm:$false -ErrorAction Stop
            $removedOUs++
            Write-Host "Removed OU: $ouPath" -ForegroundColor Cyan
        }
    }

    Write-Host 'Reset completed.' -ForegroundColor Green
    if ($WhatIfPreference) {
        $resetStatus = 'Preview'
        $resetMessage = "Preview of '$ouPath': $($users.Count) user(s), $($childOUs.Count) child OU(s), $($otherObjects.Count) other object(s) in scope."
    }
    else {
        $resetStatus = 'Succeeded'
        $resetMessage = "Removed from '$ouPath': $removedUsers user(s), $removedOUs OU(s), $removedOtherObjects other object(s)."
    }
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status $resetStatus -Message $resetMessage
}
catch {
    $failureMessage = $_.Exception.Message
    if ($auditStarted) {
        try {
            Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status 'Failed' `
                -Message "$failureMessage (removed before failure: $removedUsers user(s), $removedOUs OU(s), $removedOtherObjects other object(s))"
        }
        catch {
            Write-Warning "Could not write the failure audit record: $($_.Exception.Message)"
        }
    }
    throw
}
finally {
    Clear-ADToolContext
}
