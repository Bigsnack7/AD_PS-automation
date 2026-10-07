<#
.SYNOPSIS
    Removes generated users and optionally the complete Company OU hierarchy.

.EXAMPLE
    .\2_RESET_TEST_USERS.ps1 -DeleteEverything -WhatIf

.EXAMPLE
    .\2_RESET_TEST_USERS.ps1 -DeleteEverything -AllowDestructiveOperation
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [switch]$RemoveOrganizationalUnit,

    [switch]$RemoveAllObjects,

    [switch]$DeleteEverything,

    [switch]$AllowDestructiveOperation,

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
Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status 'Started'

$domain = Get-ADDomain @adContext -ErrorAction Stop
$domainRoot = $domain.DistinguishedName
$safeOrganizationalUnitName = ConvertTo-LdapFilterValue $OrganizationalUnitName
$organizationalUnit = @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeOrganizationalUnitName)" `
    -SearchBase $domainRoot -SearchScope OneLevel -ErrorAction Stop
)
if ($organizationalUnit.Count -gt 1) {
    throw "More than one OU named '$OrganizationalUnitName' was found below '$domainRoot'. Use a unique OU name."
}

if (-not $organizationalUnit) {
    Write-Host "OU '$OrganizationalUnitName' was not found. Nothing to reset." -ForegroundColor Yellow
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status 'Skipped' -Message 'Target OU was not found.'
    return
}

# Sorts by DN component depth (descending) rather than raw string length, so a shallow OU with a
# long name (e.g. "OU=Finance-And-Accounting-Department") is never mistaken for a deeper object.
# The negative lookbehind avoids splitting on commas escaped inside a name (e.g. "CN=O\,Brien").
function Get-DistinguishedNameDepth {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    return ($DistinguishedName -split '(?<!\\),').Count
}

$ouPath = $organizationalUnit.DistinguishedName
$users = @(Get-ADUser @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * -ErrorAction Stop)
$childOUs = @(Get-ADOrganizationalUnit @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * -ErrorAction Stop |
    Where-Object { $_.DistinguishedName -ne $ouPath } |
    Sort-Object { Get-DistinguishedNameDepth $_.DistinguishedName } -Descending)

if ($RemoveAllObjects) {
    $allObjects = @(Get-ADObject @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * -ErrorAction Stop |
        Where-Object { $_.DistinguishedName -ne $ouPath } |
        Sort-Object { Get-DistinguishedNameDepth $_.DistinguishedName } -Descending)
    foreach ($object in $allObjects) {
        if ($PSCmdlet.ShouldProcess($object.DistinguishedName, "Remove $($object.ObjectClass)")) {
            Remove-ADObject @adContext -Identity $object -Confirm:$false -ErrorAction Stop
            Write-Host "Removed: $($object.DistinguishedName)" -ForegroundColor Cyan
        }
    }
    $users = @()
    $childOUs = @()
}

if ($users.Count -eq 0) {
    Write-Host "No user accounts found in '$ouPath' or its child OUs." -ForegroundColor Yellow
}
else {
    foreach ($user in $users) {
        if ($PSCmdlet.ShouldProcess($user.DistinguishedName, 'Remove Active Directory user')) {
            Remove-ADUser @adContext -Identity $user -Confirm:$false -ErrorAction Stop
            Write-Host "Removed: $($user.SamAccountName)" -ForegroundColor Cyan
        }
    }
}

if ($RemoveOrganizationalUnit) {
    $allChildObjects = @(Get-ADObject @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * -ErrorAction Stop |
        Where-Object { $_.DistinguishedName -ne $ouPath })
    if (-not $RemoveAllObjects) {
        $unexpectedObjects = @($allChildObjects | Where-Object {
            $_.ObjectClass -notcontains 'user' -and $_.ObjectClass -notcontains 'organizationalUnit'
        })
        if ($unexpectedObjects.Count -gt 0) {
            $objectList = $unexpectedObjects | Select-Object -ExpandProperty DistinguishedName
            throw "Refusing to remove '$ouPath' because it contains non-user objects: $($objectList -join '; ')"
        }
    }

    foreach ($childOU in $childOUs) {
        if ($PSCmdlet.ShouldProcess($childOU.DistinguishedName, 'Remove child organizational unit')) {
            Remove-ADOrganizationalUnit @adContext -Identity $childOU -Confirm:$false -ErrorAction Stop
            Write-Host "Removed OU: $($childOU.DistinguishedName)" -ForegroundColor Cyan
        }
    }
    if ($PSCmdlet.ShouldProcess($ouPath, 'Remove organizational unit')) {
        Remove-ADOrganizationalUnit @adContext -Identity $organizationalUnit -Confirm:$false -ErrorAction Stop
        Write-Host "Removed OU: $ouPath" -ForegroundColor Cyan
    }
}

Write-Host 'Reset completed.' -ForegroundColor Green
$resetStatus = if ($WhatIfPreference) { 'Preview' } else { 'Succeeded' }
Write-ADAuditRecord -Path $AuditLogPath -Action 'ResetTestUsers' -Target $OrganizationalUnitName -Status $resetStatus
}
finally {
    Clear-ADToolContext
}