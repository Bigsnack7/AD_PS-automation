<#
.SYNOPSIS
    Produces a high-level Active Directory security summary.

.DESCRIPTION
    Builds a human-readable security report covering privileged users, disabled and locked
    accounts, password-never-expires usage, inactive accounts, and department administrator counts.
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$DomainName,
    [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),
    # BUGFIX: the report used to hardcode 'Company' as the OU it auto-detects when -SearchBase
    # isn't given, even though the provisioning scripts accept a configurable
    # -OrganizationalUnitName. A domain provisioned under a different OU name would silently
    # fall back to scanning the whole domain instead of the intended container.
    [string]$OrganizationalUnitName = 'Company',
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

$reportTarget = if ($SearchBase) { $SearchBase } else { 'Domain' }
Write-ADAuditRecord -Path $AuditLogPath -Action 'SecurityReport' -Target $reportTarget -Status 'Started'

try {
    $domain = Get-ADDomain @adContext -ErrorAction Stop
    $resolvedDomainName = if ($DomainName) { $DomainName } else { $domain.DNSRoot }

    $effectiveSearchBase = if ($SearchBase) {
        $SearchBase
    }
    else {
        $companyOuFilter = "(ou=$(Escape-LdapFilterValue $OrganizationalUnitName))"
        $companyOu = @(Get-ADOrganizationalUnit @adContext -LDAPFilter $companyOuFilter -SearchBase $domain.DistinguishedName -SearchScope OneLevel -ErrorAction Stop)
        if ($companyOu.Count -gt 0) {
            $companyOu[0].DistinguishedName
        }
        else {
            $domain.DistinguishedName
        }
    }

    # BUGFIX (performance): the original script issued six separate Get-ADUser calls over the
    # same search base and scope (one inside Get-ReportUserSet just to check department
    # membership, plus one each for disabled/locked/password-never-expires/inactive/accounts-
    # created), fetching the same user set from AD repeatedly. Fetch it once here and derive
    # every metric from the single result set.
    $usersInScope = @(Get-ADUser @adContext -SearchBase $effectiveSearchBase -SearchScope Subtree -Filter * -Properties SamAccountName,Department,DistinguishedName,Enabled,LockedOut,PasswordNeverExpires,LastLogonDate,WhenChanged,WhenCreated)

    function Get-ReportGroupMembers {
        param(
            [Parameter(Mandatory)]
            [string]$GroupName
        )

        try {
            $group = Get-ADGroup @adContext -Identity $GroupName -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            return @()
        }

        return @(Get-ADGroupMember @adContext -Identity $group -Recursive -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'user' })
    }

    function Get-ReportUserSet {
        param(
            [Parameter(Mandatory)][psobject[]]$UsersInScope,
            [string[]]$AdditionalGroupNames = @()
        )

        $allUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $privilegedGroups = @(
            'Administrators',
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Backup Operators'
        ) + $AdditionalGroupNames

        foreach ($groupName in $privilegedGroups) {
            $members = @(Get-ReportGroupMembers -GroupName $groupName)
            foreach ($member in $members) {
                if ($member.SamAccountName) {
                    [void]$allUsers.Add($member.SamAccountName)
                }
            }
        }

        foreach ($user in $UsersInScope) {
            if ($user.Department -and ($user.Department -in $Departments)) {
                $departmentGroupName = "$($user.Department)-Administrators"
                $admins = @(Get-ReportGroupMembers -GroupName $departmentGroupName)
                foreach ($admin in $admins) {
                    if ($admin.SamAccountName) {
                        [void]$allUsers.Add($admin.SamAccountName)
                    }
                }
            }
        }

        @($allUsers | Sort-Object)
    }

    # BUGFIX: keep the real privileged-user count separate from the display list. The display
    # list below gets a placeholder ('None') substituted in when it's empty so the report has
    # something to print, but the audit-log line at the end used to report $privilegedUsers.Count
    # *after* that substitution — so an empty result was logged as a count of 1 ("None").
    $privilegedUsers = @(Get-ReportUserSet -UsersInScope $usersInScope)
    $privilegedUserCount = $privilegedUsers.Count
    $privilegedUsersDisplay = if ($privilegedUsers.Count -eq 0) { @('None') } else { $privilegedUsers }

    $disabledAccounts = @($usersInScope | Where-Object { $_.Enabled -eq $false }).Count
    $lockedAccounts = @($usersInScope | Where-Object { $_.LockedOut -eq $true }).Count
    $passwordNeverExpires = @($usersInScope | Where-Object { $_.PasswordNeverExpires -eq $true }).Count

    $inactiveCutoff = (Get-Date).AddDays(-90)
    $inactiveAccounts = @($usersInScope | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $inactiveCutoff }).Count

    $departmentAdminCounts = @{}
    foreach ($department in $Departments) {
        $groupName = "$department-Administrators"
        # Expand nested membership consistently with the privileged-user set.
        $departmentAdminCounts[$department] = @(Get-ReportGroupMembers -GroupName $groupName).Count
    }

    $recentWindow = (Get-Date).AddDays(-7)
    # BUGFIX: "Accounts Created" used to just be a count of every account currently in scope
    # (Get-ADUser -Filter * with no date filter) — i.e. a mislabeled total, not a count of
    # accounts actually created recently. It now mirrors "Accounts Modified" and counts
    # accounts whose WhenCreated falls inside the same reporting window.
    $accountsCreated = @($usersInScope | Where-Object { $_.WhenCreated -and $_.WhenCreated -ge $recentWindow }).Count
    $accountsModified = @($usersInScope | Where-Object { $_.WhenChanged -and $_.WhenChanged -ge $recentWindow }).Count
    $totalAccounts = $usersInScope.Count

    $reportLines = @(
        'ACTIVE DIRECTORY SECURITY REPORT',
        '================================',
        '',
        "Domain: $resolvedDomainName",
        '',
        'Privileged Users:'
    )
    $reportLines += @($privilegedUsersDisplay | ForEach-Object { "  $_" })

    $reportLines += @(
        '',
        'Total Accounts In Scope:',
        "  $totalAccounts",
        '',
        "Disabled Accounts:",
        "  $disabledAccounts",
        '',
        "Locked Accounts:",
        "  $lockedAccounts",
        '',
        "Password Never Expires:",
        "  $passwordNeverExpires",
        '',
        "Inactive Accounts (90+ days):",
        "  $inactiveAccounts",
        '',
        'Department Administrators:'
    )

    foreach ($department in $Departments) {
        $reportLines += @(("  {0}: {1}" -f $department, $departmentAdminCounts[$department]))
    }

    $reportLines += @(
        '',
        'Accounts Created (last 7 days):',
        "  $accountsCreated",
        '',
        'Accounts Modified (last 7 days):',
        "  $accountsModified",
        '',
        'Report Generated:',
        "  $(Get-Date -Format 'yyyy-MM-dd')"
    )

    $reportLines | Write-Output

    Write-ADAuditRecord -Path $AuditLogPath -Action 'SecurityReport' -Target $reportTarget -Status 'Succeeded' -Message "Privileged users: $privilegedUserCount; disabled: $disabledAccounts; locked: $lockedAccounts; password-never-expires: $passwordNeverExpires; inactive: $inactiveAccounts; accounts created: $accountsCreated; accounts modified: $accountsModified."
}
catch {
    Write-ADAuditRecord -Path $AuditLogPath -Action 'SecurityReport' -Target $reportTarget -Status 'Failed' -Message $_.Exception.Message
    throw
}
}
finally {
    Clear-ADToolContext
}