<#
.SYNOPSIS
    Exports generated test users from the target organization unit to CSV.

.DESCRIPTION
    This script provides a straightforward export path for lab or test environments.
    It locates the target OU, enumerates the users beneath it, and writes a CSV
    snapshot that can be reviewed, archived, or used as input for later cleanup.

    Text values that begin with a spreadsheet formula character (= + - @ tab CR) are
    prefixed with a single quote so the CSV cannot execute formulas when opened in Excel.
    Note that LastLogonDate is derived from lastLogonTimestamp and can lag by up to 14 days.

.EXAMPLE
    .\Cmdlets\Export-Test-Users.ps1 -OrganizationalUnitName 'Company'

.EXAMPLE
    .\Cmdlets\Export-Test-Users.ps1 -OrganizationalUnitName 'Company' -OutputPath '.\company-users.csv'

.EXAMPLE
    .\Cmdlets\Export-Test-Users.ps1 -OrganizationalUnitName 'Company' -IncludeGroupMembership
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

$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDirectory) -and $MyInvocation.MyCommand.Path) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrEmpty($scriptDirectory)) {
    throw 'Cannot determine the script directory. Run this file from disk, not pasted into a console.'
}
$repositoryRoot = Split-Path -Parent $scriptDirectory
$operationsModule = Join-Path $repositoryRoot 'Modules\AD-Operations.psm1'
$scriptDirectory = $repositoryRoot

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

# Resolve user-supplied relative paths NOW, against the caller's current location.
# Set-ADToolContext may mount an AD: PSDrive; resolving later could anchor relative
# paths to the wrong provider/location.
function Resolve-FullPath {
    param([Parameter(Mandatory)][string]$Path)
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}
else {
    $AuditLogPath = Resolve-FullPath $AuditLogPath
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $scriptDirectory ("Test-Users-Export-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date))
}
else {
    $OutputPath = Resolve-FullPath $OutputPath
}

# Neutralise CSV/formula injection (user-controlled attributes such as DisplayName).
function ConvertTo-SafeCsvValue {
    param($Value)
    if ($Value -is [string] -and $Value.Length -gt 0 -and
        (@('=', '+', '-', '@', "`t", "`r") -contains $Value.Substring(0, 1))) {
        return "'" + $Value
    }
    return $Value
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

    if ($organizationalUnit.Count -eq 0) {
        Write-Host "OU '$OrganizationalUnitName' was not found. Nothing to export." -ForegroundColor Yellow
        Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Skipped' -Message 'Target OU was not found.'
        return
    }

    $ouPath = $organizationalUnit[0].DistinguishedName
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

    # @() keeps this an array even when exactly one user is found.
    $exportRecords = @(foreach ($user in $users) {
        [pscustomobject]@{
            SamAccountName       = ConvertTo-SafeCsvValue $user.SamAccountName
            UserPrincipalName    = ConvertTo-SafeCsvValue $user.UserPrincipalName
            Name                 = ConvertTo-SafeCsvValue $user.Name
            DisplayName          = ConvertTo-SafeCsvValue $user.DisplayName
            GivenName            = ConvertTo-SafeCsvValue $user.GivenName
            Surname              = ConvertTo-SafeCsvValue $user.Surname
            Department           = ConvertTo-SafeCsvValue $user.Department
            DistinguishedName    = ConvertTo-SafeCsvValue $user.DistinguishedName
            Enabled              = $user.Enabled
            LockedOut            = $user.LockedOut
            PasswordNeverExpires = $user.PasswordNeverExpires
            LastLogonDate        = $user.LastLogonDate
            WhenCreated          = $user.WhenCreated
            WhenChanged          = $user.WhenChanged
            MemberOf             = if ($IncludeGroupMembership -and $user.MemberOf) {
                ConvertTo-SafeCsvValue ($user.MemberOf -join '; ')
            }
            else {
                ''
            }
        }
    })

    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }

    Export-ADResults -Results $exportRecords -Path $OutputPath
    Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Succeeded' -Message "Exported $($users.Count) users from '$ouPath' to '$OutputPath'."
}
catch {
    $originalError = $_
    try {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'ExportTestUsers' -Target $OrganizationalUnitName -Status 'Failed' -Message $originalError.Exception.Message
    }
    catch {
        # Never let an audit-write failure mask the real error.
        Write-Warning "Could not write the failure audit record: $($_.Exception.Message)"
    }
    throw $originalError
}
finally {
    try {
        Clear-ADToolContext
    }
    catch {
        # A cleanup failure must not replace the original exception.
        Write-Warning "Clear-ADToolContext failed: $($_.Exception.Message)"
    }
}
