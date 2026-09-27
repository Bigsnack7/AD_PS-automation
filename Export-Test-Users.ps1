<#
.SYNOPSIS
    Exports generated test users from the target organization unit to CSV.

.DESCRIPTION
    This script provides a straightforward export path for lab or test environments.
    It locates the target OU, enumerates the users beneath it, and writes a CSV
    snapshot that can be reviewed, archived, or used as input for later cleanup.

.EXAMPLE
    .\Export-Test-Users.ps1 -OrganizationalUnitName 'Company'

.EXAMPLE
    .\Export-Test-Users.ps1 -OrganizationalUnitName 'Company' -OutputPath '.\company-users.csv'

.EXAMPLE
    .\Export-Test-Users.ps1 -OrganizationalUnitName 'Company' -IncludeGroupMembership
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [string]$OutputPath = '',

    [switch]$IncludeGroupMembership,

    [string]$Server,

    [PSCredential]$Credential,

    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$operationsModule = Join-Path $scriptDirectory 'AD-Operations.psm1'

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module $operationsModule -Force
Assert-ADOperationsDependencies

# Everything from here on touches process-wide AD defaults (and may mount an AD:
# PSDrive) via Set-ADToolContext, so it must always be unwound - on success, on an
# early "nothing to do" return, and on any error - via Clear-ADToolContext in finally.
try {
    Set-ADToolContext -Server $Server -Credential $Credential
    $adContext = Get-ADToolContextParameters

    Write-Verbose "Resolving target OU '$OrganizationalUnitName'."
    $domain = Get-ADDomain @adContext -ErrorAction Stop
    $domainRoot = $domain.DistinguishedName
    $safeOrganizationalUnitName = ConvertTo-LdapFilterValue $OrganizationalUnitName
    $organizationalUnit = @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeOrganizationalUnitName)" -SearchBase $domainRoot -SearchScope OneLevel -ErrorAction Stop)

    if ($organizationalUnit.Count -gt 1) {
        throw "More than one OU named '$OrganizationalUnitName' was found below '$domainRoot'. Use a unique OU name."
    }

    if (-not $organizationalUnit) {
        Write-Host "OU '$OrganizationalUnitName' was not found. Nothing to export." -ForegroundColor Yellow
        Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Skipped' -Message 'Target OU was not found.'
        return
    }

    $ouPath = $organizationalUnit.DistinguishedName
    Write-Verbose "Found OU '$ouPath'. Enumerating descendant users."

    $properties = @(
        'SamAccountName',
        'UserPrincipalName',
        'Name',
        'DisplayName',
        'GivenName',
        'Surname',
        'Department',
        'DistinguishedName',
        'Enabled',
        'LockedOut',
        'PasswordNeverExpires',
        'LastLogonDate',
        'WhenCreated',
        'WhenChanged'
    )

    if ($IncludeGroupMembership) {
        $properties += 'MemberOf'
    }

    $users = @(Get-ADUser @adContext -SearchBase $ouPath -SearchScope Subtree -Filter * -Properties $properties -ErrorAction Stop |
        Sort-Object SamAccountName)

    if ($users.Count -eq 0) {
        Write-Host "No user accounts found under '$ouPath'." -ForegroundColor Yellow
        Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Skipped' -Message 'No users were found in the target OU.'
        return
    }

    Write-Verbose "Found $($users.Count) users under '$ouPath'. Building CSV export rows."

    $exportRecords = foreach ($user in $users) {
        [pscustomobject]@{
            SamAccountName = $user.SamAccountName
            UserPrincipalName = $user.UserPrincipalName
            Name = $user.Name
            DisplayName = $user.DisplayName
            GivenName = $user.GivenName
            Surname = $user.Surname
            Department = $user.Department
            DistinguishedName = $user.DistinguishedName
            Enabled = $user.Enabled
            LockedOut = $user.LockedOut
            PasswordNeverExpires = $user.PasswordNeverExpires
            LastLogonDate = $user.LastLogonDate
            WhenCreated = $user.WhenCreated
            WhenChanged = $user.WhenChanged
            MemberOf = if ($IncludeGroupMembership) {
                if ($user.MemberOf) { $user.MemberOf -join '; ' } else { '' }
            }
            else {
                ''
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $scriptDirectory ("Test-Users-Export-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date))
    }

    Export-ADResults -Results $exportRecords -Path $OutputPath
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Succeeded' -Message "Exported $($users.Count) users from '$ouPath' to '$OutputPath'."
}
catch {
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Failed' -Message $_.Exception.Message
    throw
}
finally {
    Clear-ADToolContext
}