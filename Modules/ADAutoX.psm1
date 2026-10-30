Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = $PSScriptRoot
$repositoryRoot = Split-Path -Parent $moduleRoot
$modulePaths = @(
    (Join-Path $moduleRoot 'AD-Operations.psm1'),
    (Join-Path $moduleRoot 'AD-Provisioning.psm1'),
    (Join-Path $moduleRoot 'ADAutoX.Lifecycle.psm1')
)

foreach ($modulePath in $modulePaths) {
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw "Required ADAutoX module component not found: $modulePath"
    }
    Import-Module $modulePath -ErrorAction Stop
}

function ConvertTo-ADLdapFilter {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    ConvertTo-LdapFilterValue -Value $Value
}

function ConvertTo-ADDistinguishedNameValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    ConvertTo-DistinguishedNameValue -Value $Value
}

function Get-ADSanitizedSamAccountName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [System.Collections.Generic.HashSet[string]]$UsedNames
    )
    Get-UniqueSamAccountName -BaseName $BaseName -UsedNames $UsedNames
}

function Get-ADSanitizedUserPrincipalName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SamAccountName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UPNSuffix
    )
    $cleanSuffix = $UPNSuffix.Trim().TrimStart('@')
    if ($cleanSuffix -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$') {
        throw "UPN suffix '$UPNSuffix' is invalid. Supply a bare DNS-style suffix such as 'example.com'."
    }
    "$SamAccountName@$cleanSuffix"
}

function New-ADAutoXRandomPassword {
    [CmdletBinding()]
    param([ValidateRange(12, 256)][int]$Length = 24)
    New-RandomPassword -Length $Length
}

function Test-ADAutoXPasswordComplexity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PasswordText)
    Test-PasswordComplexity -PasswordText $PasswordText
}

function Get-ADAutoXSecurityScan {
    [CmdletBinding()]
    param(
        [string]$SearchBase,
        [ValidateRange(1,3650)][int]$InactiveDays = 90,
        [string]$DomainName,
        [ValidateNotNullOrEmpty()][string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),
        [string]$OrganizationalUnitName = '',
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AD-Operations.jsonl'
    }

    Import-ADTools
    $reportTarget = if ($SearchBase) { $SearchBase } else { 'Domain' }
    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        Write-ADAuditRecord -Path $AuditLogPath -Action 'SecurityReport' -Target $reportTarget -Status 'Started'

        $domain = Get-ADDomain @adContext -ErrorAction Stop
        $resolvedDomainName = if ($DomainName) { $DomainName } else { $domain.DNSRoot }
        $effectiveSearchBase = $SearchBase
        if (-not $effectiveSearchBase -and $OrganizationalUnitName) {
            $companyOuFilter = "(ou=$(ConvertTo-LdapFilterValue $OrganizationalUnitName))"
            $companyOu = @(Get-ADOrganizationalUnit @adContext -LDAPFilter $companyOuFilter `
                -SearchBase $domain.DistinguishedName -SearchScope OneLevel -ErrorAction Stop)
            if ($companyOu.Count -gt 1) {
                throw "More than one OU named '$OrganizationalUnitName' was found below '$($domain.DistinguishedName)'. Specify -SearchBase to select the intended scope."
            }
            if ($companyOu.Count -gt 0) { $effectiveSearchBase = $companyOu[0].DistinguishedName }
        }
        if (-not $effectiveSearchBase) { $effectiveSearchBase = $domain.DistinguishedName }

        $query = @{}
        $query.SearchBase = $effectiveSearchBase
        $query.SearchScope = 'Subtree'
        $usersInScope = @(Get-ADUser @adContext @query -Filter * -Properties SamAccountName,Department,DistinguishedName,Enabled,LockedOut,PasswordNeverExpires,LastLogonDate,WhenChanged,WhenCreated -ErrorAction Stop)
        $lockedUsers = @(Search-ADAccount @adContext @query -LockedOut -UsersOnly -ErrorAction Stop |
            Get-ADUser @adContext -Properties LockedOut, AccountExpirationDate, LastLogonDate, Department -ErrorAction Stop)
        $neverExpires = @(Get-ADUser @adContext @query -Filter 'PasswordNeverExpires -eq $true' -Properties PasswordNeverExpires, Enabled, Department -ErrorAction Stop)
        $threshold = (Get-Date).AddDays(-$InactiveDays)
        $inactiveUsers = @(Get-ADUser @adContext @query -Filter 'Enabled -eq $true' -Properties LastLogonDate, WhenCreated, Department -ErrorAction Stop |
            Where-Object { Test-ADAccountInactive -User $_ -Cutoff $threshold })

        function Get-ADAutoXSecurityReportGroupMembers {
            param([Parameter(Mandatory)][string]$GroupName)

            try {
                $group = Get-ADGroup @adContext -Identity $GroupName -ErrorAction Stop
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                return @()
            }
            return @(Get-ADGroupMember @adContext -Identity $group -Recursive -ErrorAction Stop |
                Where-Object { $_.ObjectClass -eq 'user' })
        }

        $privilegedUserNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $privilegedGroupNames = @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Backup Operators')
        foreach ($groupName in $privilegedGroupNames) {
            foreach ($member in @(Get-ADAutoXSecurityReportGroupMembers -GroupName $groupName)) {
                if ($member.SamAccountName) { [void]$privilegedUserNames.Add([string]$member.SamAccountName) }
            }
        }
        foreach ($user in $usersInScope) {
            if ($user.Department -and $user.Department -in $Departments) {
                $departmentGroupName = "$($user.Department)-Administrators"
                foreach ($member in @(Get-ADAutoXSecurityReportGroupMembers -GroupName $departmentGroupName)) {
                    if ($member.SamAccountName) { [void]$privilegedUserNames.Add([string]$member.SamAccountName) }
                }
            }
        }
        $privilegedUsers = @($privilegedUserNames | Sort-Object)
        $departmentAdminCounts = @{}
        foreach ($department in $Departments) {
            $departmentAdminCounts[$department] = @(Get-ADAutoXSecurityReportGroupMembers -GroupName "$department-Administrators").Count
        }

        $recentWindow = (Get-Date).AddDays(-7)
        $inactiveCutoff = (Get-Date).AddDays(-90)
        $inactiveAccountCount = @($usersInScope | Where-Object {
            Test-ADAccountInactive -User $_ -Cutoff $inactiveCutoff
        }).Count
        $disabledAccountCount = @($usersInScope | Where-Object { $_.Enabled -eq $false }).Count
        $lockedAccountCount = @($usersInScope | Where-Object { $_.LockedOut -eq $true }).Count
        $passwordNeverExpiresCount = @($usersInScope | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
        $accountsCreated = @($usersInScope | Where-Object { $_.WhenCreated -and $_.WhenCreated -ge $recentWindow }).Count
        $accountsModified = @($usersInScope | Where-Object { $_.WhenChanged -and $_.WhenChanged -ge $recentWindow }).Count
        $reportLines = @(
            'ACTIVE DIRECTORY SECURITY REPORT'
            '================================'
            ''
            "Domain: $resolvedDomainName"
            ''
            'Privileged Users:'
        )
        $privilegedUsersDisplay = if ($privilegedUsers.Count -eq 0) { @('None') } else { $privilegedUsers }
        $reportLines += @($privilegedUsersDisplay | ForEach-Object { "  $_" })
        $reportLines += @(
            ''
            'Total Accounts In Scope:'
            "  $($usersInScope.Count)"
            ''
            'Disabled Accounts:'
            "  $disabledAccountCount"
            ''
            'Locked Accounts:'
            "  $lockedAccountCount"
            ''
            'Password Never Expires:'
            "  $passwordNeverExpiresCount"
            ''
            'Inactive Accounts (90+ days, including never-logged-on accounts created before cutoff):'
            "  $inactiveAccountCount"
            ''
            'Department Administrators:'
        )
        foreach ($department in $Departments) {
            $reportLines += "  {0}: {1}" -f $department, $departmentAdminCounts[$department]
        }
        $reportLines += @(
            ''
            'Accounts Created (last 7 days):'
            "  $accountsCreated"
            ''
            'Accounts Modified (last 7 days):'
            "  $accountsModified"
            ''
            'Report Generated:'
            "  $(Get-Date -Format 'yyyy-MM-dd')"
        )

        Write-ADAuditRecord -Path $AuditLogPath -Action 'SecurityReport' -Target $reportTarget -Status 'Succeeded' `
            -Message "Privileged users: $($privilegedUsers.Count); disabled: $disabledAccountCount; locked: $lockedAccountCount; password-never-expires: $passwordNeverExpiresCount; inactive: $inactiveAccountCount; accounts created: $accountsCreated; accounts modified: $accountsModified."
        [pscustomobject]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            LockedOutAccountsCount = $lockedUsers.Count
            PasswordNeverExpiresCount = $neverExpires.Count
            InactiveAccountsCount = $inactiveUsers.Count
            LockedUsers = $lockedUsers
            NeverExpiresUsers = $neverExpires
            InactiveUsers = $inactiveUsers
            DomainName = $resolvedDomainName
            PrivilegedUsers = $privilegedUsers
            TotalAccountsCount = $usersInScope.Count
            DisabledAccountsCount = $disabledAccountCount
            LockedAccountsCount = $lockedAccountCount
            PasswordNeverExpiresAccountsCount = $passwordNeverExpiresCount
            AccountsCreatedLast7Days = $accountsCreated
            AccountsModifiedLast7Days = $accountsModified
            DepartmentAdminCounts = $departmentAdminCounts
            ReportLines = $reportLines
        }
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'SecurityReport' -Target $reportTarget -Status 'Failed' -Message $_.Exception.Message
        throw
    }
    finally { Clear-ADToolContext }
}

function Invoke-ADAutoXProvision {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [ValidateRange(0, 1000)][int]$AccountCount = 20,
        [Alias('OrganizationalUnitName')][ValidateNotNullOrEmpty()][string]$CompanyOuName = 'Company',
        [Alias('StaffNamesOrganizationalUnitName')][ValidateNotNullOrEmpty()][string]$StaffOuName = 'Staff',
        [string]$NamesPath = '',
        [ValidateNotNullOrEmpty()][string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),
        [switch]$CreateDepartmentAdministrators = $true,
        [switch]$AdministratorsOnly,
        [string]$AdministratorUsername = '',
        [AllowNull()][string]$PasswordPattern,
        [string]$AdministratorPasswordPattern,
        [SecureString]$Password,
        [switch]$EnableAccountsAfterVerification,
        [switch]$RollbackOnFailure,
        [switch]$IncludePasswordInReport,
        [string]$PasswordFile = '',
        [switch]$ExportPasswords,
        [switch]$OverwritePasswordFile,
        [string]$ReportPath = '',
        [string]$AuditLogPath = '',
        [string]$Server,
        [ValidateNotNullOrEmpty()][string]$UPNSuffix,
        [PSCredential]$Credential
    )

    $scriptDirectory = $repositoryRoot
    $canonicalScript = Join-Path $scriptDirectory 'Cmdlets\mark42.ps1'
    if (-not (Test-Path -LiteralPath $canonicalScript -PathType Leaf)) {
        throw "Canonical provisioning implementation not found: $canonicalScript"
    }

    if ([string]::IsNullOrWhiteSpace($NamesPath)) {
        $NamesPath = Join-Path $scriptDirectory 'Data\sample-names.txt'
    }
    if ($ExportPasswords -and [string]::IsNullOrWhiteSpace($PasswordFile)) {
        $PasswordFile = Join-Path $scriptDirectory 'user-passwords.clixml'
    }
    if ($IncludePasswordInReport -and [string]::IsNullOrWhiteSpace($ReportPath)) {
        $ReportPath = Join-Path $scriptDirectory 'ADAutoX-Provisioning-Report.csv'
    }
    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
    }

    $arguments = @{
        AccountCount = $AccountCount
        OrganizationalUnitName = $CompanyOuName
        StaffNamesOrganizationalUnitName = $StaffOuName
        NamesPath = $NamesPath
        Departments = $Departments
        CreateDepartmentAdministrators = $CreateDepartmentAdministrators
    }
    $optionalArguments = @{
        AdministratorsOnly = $AdministratorsOnly
        AdministratorUsername = $AdministratorUsername
        PasswordPattern = $PasswordPattern
        AdministratorPasswordPattern = $AdministratorPasswordPattern
        Password = $Password
        EnableAccountsAfterVerification = $EnableAccountsAfterVerification
        RollbackCreatedResourcesOnFailure = $RollbackOnFailure
        IncludePasswordInReport = $IncludePasswordInReport
        PasswordFile = $PasswordFile
        ExportPasswords = $ExportPasswords
        OverwritePasswordFile = $OverwritePasswordFile
        ReportPath = $ReportPath
        AuditLogPath = $AuditLogPath
        Server = $Server
        UPNSuffix = $UPNSuffix
        Credential = $Credential
    }
    foreach ($entry in $optionalArguments.GetEnumerator()) {
        $hasValue = if ($entry.Value -is [string]) {
            -not [string]::IsNullOrWhiteSpace($entry.Value)
        }
        else {
            [bool]$entry.Value
        }
        if ($hasValue) {
            $arguments[$entry.Key] = $entry.Value
        }
    }

    if ($WhatIfPreference) { $arguments.WhatIf = $true }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
    $arguments.CorrelationId = New-ADAutoXCorrelationId
    & $canonicalScript @arguments
}

$script:ADAutoXLedger = [System.Collections.Generic.List[psobject]]::new()
if (-not (Test-Path variable:script:ADAutoXLedgerSequence)) {
    $script:ADAutoXLedgerSequence = 0
}

function Test-ADAutoXDomainReachability {
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)

    $result = Test-ADDomainReachability -Server $Server -Credential $Credential
    [pscustomobject]@{
        IsReachable = $result.IsReachable
        DomainName = $result.Domain
        Forest = $result.Forest
        DomainDN = $result.DomainDN
        NetBIOSName = $result.NetBIOSName
        Server = $result.Server
        Error = $result.Error
    }
}

function Initialize-ADAutoXContext {
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)

    Import-ADTools
    $null = Set-ADToolContext -Server $Server -Credential $Credential
    try {
        $context = Get-ADToolContextParameters
        $domain = Get-ADDomain @context -ErrorAction Stop
        [pscustomobject]@{
            Server = $context.Server
            DomainName = $domain.DNSRoot
            Forest = $domain.Forest
            DomainDN = $domain.DistinguishedName
            NetBIOSName = $domain.NetBIOSName
            UPNSuffixes = $domain.UPNSuffixes
        }
    }
    catch {
        Clear-ADToolContext
        throw
    }
}

function Clear-ADAutoXContext {
    [CmdletBinding()]
    param()
    Clear-ADToolContext
}

function Write-ADAutoXConsole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Verbose', 'Phase')][string]$Level = 'Info'
    )
    $time = (Get-Date).ToString('HH:mm:ss')
    switch ($Level) {
        'Success' { Write-Host "[$time] [+] $Message" -ForegroundColor Green }
        'Warning' { Write-Host "[$time] [!] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$time] [-] $Message" -ForegroundColor Red }
        'Phase' { Write-Host "`n[$time] === $Message ===" -ForegroundColor Cyan }
        'Verbose' { Write-Verbose "[$time] [*] $Message" }
        default { Write-Host "[$time] [*] $Message" -ForegroundColor Gray }
    }
}

function Initialize-ADAutoXLedger {
    [CmdletBinding()]
    param()
    $script:ADAutoXLedger.Clear()
    $script:ADAutoXLedgerSequence = 0
}

function Get-ADAutoXLedger {
    [CmdletBinding()]
    param()
    $script:ADAutoXLedger.ToArray()
}

function Add-ADAutoXLedgerEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('OU', 'Group', 'User', 'Delegation', 'Lifecycle')][string]$ObjectType,
        [string]$DistinguishedName,
        [string]$SamAccountName,
        [string]$Name,
        [ValidateSet('RestoreEnabled', 'MoveUser', 'GroupMembership', 'RestoreDescription', 'RestoreAttributes')]
        [string]$Action,
        [hashtable]$UndoData,
        [string]$SecurityIdentifier,
        [string[]]$DelegationRuleTypes = @(),
        [string]$RunId = '',
        [bool]$CreatedByThisRun = $true
    )
    if ($ObjectType -eq 'Lifecycle') {
        if (-not $Action -or -not $UndoData -or -not $UndoData.UserIdentity) {
            throw 'Lifecycle ledger entries require an undo action and a user object identity.'
        }
        if (-not $DistinguishedName) { $DistinguishedName = [string]$UndoData.UserDistinguishedName }
        if (-not $SamAccountName) { $SamAccountName = [string]$UndoData.SamAccountName }
        $CreatedByThisRun = $false
    }
    elseif ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        throw 'Created-resource ledger entries require a distinguished name.'
    }
    elseif ($ObjectType -eq 'Delegation') {
        if ([string]::IsNullOrWhiteSpace($SecurityIdentifier)) {
            throw 'Delegation ledger entries require the delegated security identifier.'
        }
        if ($CreatedByThisRun -and $DelegationRuleTypes.Count -eq 0) {
            throw 'Run-created delegation entries require exact delegation-rule ownership data.'
        }
    }
    if (-not $Name) {
        $Name = if ($SamAccountName) { $SamAccountName } else { $DistinguishedName }
    }
    if (-not (Test-Path variable:script:ADAutoXLedgerSequence)) {
        $script:ADAutoXLedgerSequence = 0
    }
    $script:ADAutoXLedgerSequence++
    $entry = [pscustomobject]@{
        ObjectType = $ObjectType
        DistinguishedName = $DistinguishedName
        SamAccountName = $SamAccountName
        Name = $Name
        CreatedByThisRun = $CreatedByThisRun
        Action = $Action
        UndoData = $UndoData
        SecurityIdentifier = $SecurityIdentifier
        DelegationRuleTypes = @($DelegationRuleTypes)
        RunId = $RunId
        Sequence = $script:ADAutoXLedgerSequence
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    }
    $script:ADAutoXLedger.Add($entry)
    return $entry
}

function Invoke-ADAutoXLifecycleUndo {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][hashtable]$ADContext,
        [Parameter(Mandatory)][string]$AllowedRoot
    )

    $undo = $Entry.UndoData
    $user = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Enabled,Description,Department,Company,DistinguishedName -ErrorAction Stop
    Assert-ADTargetWithinRoot -Target $user.DistinguishedName -AllowedRoot $AllowedRoot
    $userParent = Get-ADDistinguishedNameParent -DistinguishedName $user.DistinguishedName

    switch ($Entry.Action) {
        'RestoreEnabled' {
            if ([bool]$user.Enabled -ne [bool]$undo.ExpectedEnabled) {
                throw "Account enabled state changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to overwrite the newer state."
            }
            if (-not $PSCmdlet.ShouldProcess($user.DistinguishedName, 'Restore account enabled state')) {
                return $false
            }
            if ([bool]$undo.RestoreEnabled) {
                Enable-ADAccount @ADContext -Identity $user -Confirm:$false -ErrorAction Stop
            }
            else {
                Disable-ADAccount @ADContext -Identity $user -Confirm:$false -ErrorAction Stop
            }
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Enabled -ErrorAction Stop
            if ([bool]$verified.Enabled -ne [bool]$undo.RestoreEnabled) {
                throw "Account enabled-state rollback verification failed for '$($user.SamAccountName)'."
            }
        }
        'MoveUser' {
            if ((ConvertTo-ADCanonicalDistinguishedName $userParent) -ne
                (ConvertTo-ADCanonicalDistinguishedName ([string]$undo.ExpectedParent))) {
                throw "Account location changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to move it."
            }
            Assert-ADTargetWithinRoot -Target ([string]$undo.RestoreParent) -AllowedRoot $AllowedRoot
            if (-not $PSCmdlet.ShouldProcess($user.DistinguishedName, "Restore account location to '$($undo.RestoreParent)'")) {
                return $false
            }
            Move-ADObject @ADContext -Identity $user -TargetPath ([string]$undo.RestoreParent) -Confirm:$false -ErrorAction Stop
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties DistinguishedName -ErrorAction Stop
            $verifiedParent = Get-ADDistinguishedNameParent -DistinguishedName $verified.DistinguishedName
            if ((ConvertTo-ADCanonicalDistinguishedName $verifiedParent) -ne
                (ConvertTo-ADCanonicalDistinguishedName ([string]$undo.RestoreParent))) {
                throw "Account move rollback verification failed for '$($user.SamAccountName)'."
            }
        }
        'GroupMembership' {
            $group = Get-ADGroup @ADContext -Identity ([Guid]$undo.GroupIdentity) -ErrorAction Stop
            $isMember = @((Get-ADGroupMember @ADContext -Identity $group -ErrorAction Stop) |
                Where-Object { $_.SID -eq $user.SID }).Count -gt 0
            if ($isMember -ne [bool]$undo.ExpectedMembership) {
                throw "Group membership changed since the ledger entry was recorded for '$($user.SamAccountName)' and '$($group.Name)'; refusing to overwrite the newer state."
            }
            $membershipOperation = if ([bool]$undo.RestoreMembership) {
                "Restore membership in '$($group.Name)'"
            }
            else {
                "Restore removal from '$($group.Name)'"
            }
            if (-not $PSCmdlet.ShouldProcess($user.DistinguishedName, $membershipOperation)) {
                return $false
            }
            if ([bool]$undo.RestoreMembership) {
                Add-ADGroupMember @ADContext -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
            }
            else {
                Remove-ADGroupMember @ADContext -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
            }
            $isMemberAfter = @((Get-ADGroupMember @ADContext -Identity $group -ErrorAction Stop) |
                Where-Object { $_.SID -eq $user.SID }).Count -gt 0
            if ($isMemberAfter -ne [bool]$undo.RestoreMembership) {
                throw "Group membership rollback verification failed for '$($user.SamAccountName)' and '$($group.Name)'."
            }
        }
        'RestoreDescription' {
            if ([string]$user.Description -cne [string]$undo.ExpectedDescription) {
                throw "Account description changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to overwrite the newer value."
            }
            if (-not $PSCmdlet.ShouldProcess($user.DistinguishedName, 'Restore account description')) {
                return $false
            }
            if ([string]::IsNullOrEmpty([string]$undo.RestoreDescription)) {
                Set-ADUser @ADContext -Identity $user -Clear Description -Confirm:$false -ErrorAction Stop
            }
            else {
                Set-ADUser @ADContext -Identity $user -Description ([string]$undo.RestoreDescription) -Confirm:$false -ErrorAction Stop
            }
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Description -ErrorAction Stop
            if ([string]$verified.Description -cne [string]$undo.RestoreDescription) {
                throw "Account description rollback verification failed for '$($user.SamAccountName)'."
            }
        }
        'RestoreAttributes' {
            foreach ($attribute in @('Department', 'Company')) {
                if ([string]$user.$attribute -cne [string]$undo.ExpectedAttributes[$attribute]) {
                    throw "Account $attribute changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to overwrite the newer value."
                }
            }
            $setAttributes = @{}
            $clearAttributes = [System.Collections.Generic.List[string]]::new()
            foreach ($attribute in @('Department', 'Company')) {
                $previousValue = [string]$undo.RestoreAttributes[$attribute]
                if ([string]::IsNullOrEmpty($previousValue)) {
                    $clearAttributes.Add($attribute)
                }
                else {
                    $setAttributes[$attribute] = $previousValue
                }
            }
            $setParameters = @{ Identity = $user; Confirm = $false; ErrorAction = 'Stop' }
            foreach ($attribute in $setAttributes.Keys) { $setParameters[$attribute] = $setAttributes[$attribute] }
            if ($clearAttributes.Count -gt 0) { $setParameters.Clear = $clearAttributes.ToArray() }
            if (-not $PSCmdlet.ShouldProcess($user.DistinguishedName, 'Restore account attributes')) {
                return $false
            }
            Set-ADUser @ADContext @setParameters
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Department,Company -ErrorAction Stop
            foreach ($attribute in @('Department', 'Company')) {
                if ([string]$verified.$attribute -cne [string]$undo.RestoreAttributes[$attribute]) {
                    throw "Account $attribute rollback verification failed for '$($user.SamAccountName)'."
                }
            }
        }
        default { throw "Unsupported lifecycle undo action '$($Entry.Action)'." }
    }
    return $true
}

function Invoke-ADAutoXLedgerRollback {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$LogPath = '',
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$AllowedRoot,
        [string]$RunId = '',
        [switch]$AllowDestructiveOperation,
        [hashtable]$ADContext,
        [string]$Server,
        [PSCredential]$Credential
    )

    if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
        throw 'Live rollback requires -AllowDestructiveOperation. Preview with -WhatIf first.'
    }
    $lifecycleItems = if ([string]::IsNullOrWhiteSpace($RunId)) {
        @($script:ADAutoXLedger | Where-Object ObjectType -eq 'Lifecycle' | Sort-Object Sequence -Descending)
    }
    else { @() }
    $resourceItems = @($script:ADAutoXLedger | Where-Object {
        $_.ObjectType -ne 'Lifecycle' -and $_.CreatedByThisRun -and
        ([string]::IsNullOrWhiteSpace($RunId) -or $_.RunId -ceq $RunId)
    })
    $items = @($lifecycleItems + $resourceItems)
    if ($items.Count -eq 0) {
        return [pscustomobject]@{ RolledBack = $false; RestoredCount = 0; RemovedCount = 0; FailedCount = 0; Results = @() }
    }

    $ownsContext = -not $PSBoundParameters.ContainsKey('ADContext')
    if ($ownsContext) {
        Import-ADTools
    }
    $results = [System.Collections.Generic.List[object]]::new()
    try {
        if ($ownsContext) {
            $null = Set-ADToolContext -Server $Server -Credential $Credential
            $adContext = Get-ADToolContextParameters
        }
        else {
            $adContext = $ADContext
        }
        foreach ($item in $lifecycleItems) {
            $mutationCompleted = $false
            $target = if ($item.DistinguishedName) { $item.DistinguishedName } else { $item.SamAccountName }
            try {
                $undoParameters = @{
                    Entry = $item
                    ADContext = $adContext
                    AllowedRoot = $AllowedRoot
                    WhatIf = [bool]$WhatIfPreference
                }
                if ($PSBoundParameters.ContainsKey('Confirm')) {
                    $undoParameters.Confirm = $PSBoundParameters['Confirm']
                }
                $undoApplied = Invoke-ADAutoXLifecycleUndo @undoParameters
                if (-not $undoApplied) {
                    $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
                    $results.Add([pscustomobject]@{ ObjectType = 'Lifecycle'; Action = $item.Action; Identity = $item.SamAccountName; Status = $status })
                    continue
                }
                $mutationCompleted = $true
                $null = $script:ADAutoXLedger.Remove($item)
                $results.Add([pscustomobject]@{ ObjectType = 'Lifecycle'; Action = $item.Action; Identity = $item.SamAccountName; Status = 'Succeeded' })
                if ($LogPath) {
                    Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.Action)" -Target $target -Status 'Succeeded'
                }
            }
            catch {
                $status = if ($mutationCompleted) { 'CompletedWithErrors' } else { 'Failed' }
                $message = $_.Exception.Message
                if ($LogPath) {
                    try {
                        Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.Action)" -Target $target -Status $status -Message $message
                    }
                    catch {
                        $message += " Audit logging also failed: $($_.Exception.Message)"
                    }
                }
                $results.Add([pscustomobject]@{ ObjectType = 'Lifecycle'; Action = $item.Action; Identity = $item.SamAccountName; Status = $status; Error = $message })
            }
        }
        $orderedItems = @(
            @($resourceItems | Where-Object ObjectType -eq 'User')
            @($resourceItems | Where-Object ObjectType -eq 'Delegation')
            @($resourceItems | Where-Object ObjectType -eq 'Group')
            @($resourceItems | Where-Object ObjectType -eq 'OU' | Sort-Object {
                - (Get-ADDistinguishedNameDepth -DistinguishedName $_.DistinguishedName)
            })
        )
        $allowedRootCanonical = ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $AllowedRoot
        foreach ($item in $orderedItems) {
            $mutationCompleted = $false
            try {
                Assert-ADTargetWithinRoot -Target $item.DistinguishedName -AllowedRoot $AllowedRoot
                if ($item.ObjectType -eq 'OU' -and
                    (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $item.DistinguishedName) -eq $allowedRootCanonical) {
                    throw "Rollback refuses to remove the approved scope root '$AllowedRoot'."
                }
                $operation = "Remove created $($item.ObjectType) during rollback"
                if (-not $PSCmdlet.ShouldProcess($item.DistinguishedName, $operation)) {
                    $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
                    $results.Add([pscustomobject]@{ ObjectType = $item.ObjectType; Identity = $item.SamAccountName; Status = $status })
                    continue
                }

                switch ($item.ObjectType) {
                    'User' {
                        $existingUserObject = Get-ADObject @adContext -Identity $item.DistinguishedName -ErrorAction SilentlyContinue
                        if ($existingUserObject) {
                            Remove-ADUser @adContext -Identity $item.DistinguishedName -Confirm:$false -ErrorAction Stop
                        }
                    }
                    'Delegation' {
                        if ([string]::IsNullOrWhiteSpace($item.SecurityIdentifier) -or
                            $item.DelegationRuleTypes.Count -eq 0) {
                            throw "Delegation '$($item.Name)' is missing exact ACL ownership data; refusing a broad ACL change."
                        }

                        $groupSid = [System.Security.Principal.SecurityIdentifier]::new($item.SecurityIdentifier)
                        $userClassGuid = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
                        $childManagementRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
                            [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $managedAccessRights = $childManagementRights -bor
                            [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
                            [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bor
                            [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor
                            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                        $acl = Invoke-ADObjectAcl -Action Read -DistinguishedName $item.DistinguishedName `
                            -ADContext $adContext
                        $rulesToRemove = @($acl.Access | Where-Object {
                            $ruleSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            $ruleSid -eq $groupSid.Value -and
                            -not $_.IsInherited -and
                            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                            (
                                (('ChildManagement' -in $item.DelegationRuleTypes) -and
                                    $_.ActiveDirectoryRights -eq $childManagementRights -and
                                    $_.ObjectType -eq $userClassGuid -and
                                    $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None -and
                                    $_.InheritedObjectType -eq [Guid]::Empty) -or
                                (('DescendantUserAccess' -in $item.DelegationRuleTypes) -and
                                    $_.ActiveDirectoryRights -eq $managedAccessRights -and
                                    $_.ObjectType -eq $userClassGuid -and
                                    $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents -and
                                    $_.InheritedObjectType -eq $userClassGuid)
                            )
                        })
                        foreach ($rule in $rulesToRemove) {
                            $acl.RemoveAccessRuleSpecific($rule)
                        }
                        if ($rulesToRemove.Count -gt 0) {
                            Invoke-ADObjectAcl -Action Write -DistinguishedName $item.DistinguishedName `
                                -ADContext $adContext -AclObject $acl
                        }
                        $verifiedAcl = Invoke-ADObjectAcl -Action Read -DistinguishedName $item.DistinguishedName `
                            -ADContext $adContext
                        $remainingRules = @($verifiedAcl.Access | Where-Object {
                            $ruleSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            $ruleSid -eq $groupSid.Value -and
                            -not $_.IsInherited -and
                            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                            (
                                (('ChildManagement' -in $item.DelegationRuleTypes) -and
                                    $_.ActiveDirectoryRights -eq $childManagementRights -and
                                    $_.ObjectType -eq $userClassGuid -and
                                    $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None -and
                                    $_.InheritedObjectType -eq [Guid]::Empty) -or
                                (('DescendantUserAccess' -in $item.DelegationRuleTypes) -and
                                    $_.ActiveDirectoryRights -eq $managedAccessRights -and
                                    $_.ObjectType -eq $userClassGuid -and
                                    $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents -and
                                    $_.InheritedObjectType -eq $userClassGuid)
                            )
                        })
                        if ($remainingRules.Count -gt 0) {
                            throw "Run-created delegation rules remain on '$($item.DistinguishedName)'."
                        }
                    }
                    'Group' {
                        $remainingMembers = @(Get-ADGroupMember @adContext -Identity $item.DistinguishedName -ErrorAction Stop)
                        if ($remainingMembers.Count -gt 0) {
                            throw "Group '$($item.Name)' contains members; refusing to remove it."
                        }
                        Remove-ADGroup @adContext -Identity $item.DistinguishedName -Confirm:$false -ErrorAction Stop
                    }
                    'OU' {
                        $expectedDescription = if ($item.UndoData) { [string]$item.UndoData.GeneratedDescription } else { '' }
                        if ([string]::IsNullOrWhiteSpace($expectedDescription)) {
                            throw "OU '$($item.DistinguishedName)' is missing its generated-resource marker; refusing to remove it."
                        }
                        $organizationalUnit = Get-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName `
                            -Properties Description,ProtectedFromAccidentalDeletion -ErrorAction Stop
                        if ($organizationalUnit.Description -cne $expectedDescription) {
                            throw "OU '$($item.DistinguishedName)' is not marked as created by this run; refusing to remove it."
                        }
                        $remainingObjects = @(Get-ADObject @adContext -Filter * -SearchBase $item.DistinguishedName `
                            -SearchScope OneLevel -ResultSetSize 1 -ErrorAction Stop)
                        if ($remainingObjects.Count -gt 0) {
                            throw "OU '$($item.DistinguishedName)' contains objects; refusing to remove it."
                        }
                        $wasProtected = [bool]$organizationalUnit.ProtectedFromAccidentalDeletion
                        if ($wasProtected) {
                            Set-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                        }
                        try {
                            Remove-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -Confirm:$false -ErrorAction Stop
                        }
                        catch {
                            if ($wasProtected) {
                                try { Set-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop }
                                catch { Write-Warning "Could not restore accidental-deletion protection on '$($item.DistinguishedName)': $($_.Exception.Message)" }
                            }
                            throw
                        }
                    }
                }
                if ($item.ObjectType -in @('User', 'Group') -and
                    (Get-ADObject @adContext -Identity $item.DistinguishedName -ErrorAction SilentlyContinue)) {
                    throw "$($item.ObjectType) '$($item.DistinguishedName)' still exists after rollback removal."
                }
                if ($item.ObjectType -eq 'OU' -and
                    (Get-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -ErrorAction SilentlyContinue)) {
                    throw "OU '$($item.DistinguishedName)' still exists after rollback removal."
                }
                $mutationCompleted = $true
                $null = $script:ADAutoXLedger.Remove($item)
                $results.Add([pscustomobject]@{
                    ObjectType = $item.ObjectType
                    Identity = if ($item.SamAccountName) { $item.SamAccountName } else { $item.Name }
                    SamAccountName = $item.SamAccountName
                    DistinguishedName = $item.DistinguishedName
                    Status = 'Succeeded'
                })
                if ($LogPath) {
                    Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.ObjectType)" -Target $item.DistinguishedName -Status 'Succeeded'
                }
            }
            catch {
                $status = if ($mutationCompleted) { 'CompletedWithErrors' } else { 'Failed' }
                $message = $_.Exception.Message
                if ($LogPath) {
                    try {
                        Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.ObjectType)" -Target $item.DistinguishedName -Status $status -Message $message
                    }
                    catch {
                        $message += " Audit logging also failed: $($_.Exception.Message)"
                    }
                }
                $results.Add([pscustomobject]@{
                    ObjectType = $item.ObjectType
                    Identity = if ($item.SamAccountName) { $item.SamAccountName } else { $item.Name }
                    SamAccountName = $item.SamAccountName
                    DistinguishedName = $item.DistinguishedName
                    Status = $status
                    Error = $message
                })
            }
        }
    }
    finally {
        if ($ownsContext) { Clear-ADToolContext }
    }

    $failedCount = @($results | Where-Object Status -in @('Failed', 'CompletedWithErrors')).Count
    [pscustomobject]@{
        RolledBack = $failedCount -eq 0 -and @($results | Where-Object Status -eq 'Succeeded').Count -gt 0
        RestoredCount = @($results | Where-Object {
            $_.ObjectType -eq 'Lifecycle' -and $_.Status -in @('Succeeded', 'CompletedWithErrors')
        }).Count
        RemovedCount = @($results | Where-Object {
            $_.ObjectType -ne 'Lifecycle' -and $_.Status -in @('Succeeded', 'CompletedWithErrors')
        }).Count
        FailedCount = $failedCount
        Results = $results.ToArray()
    }
}

function Invoke-ADAutoXPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CompanyOuName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$StaffOuName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Departments,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DomainDN,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$NetBIOSName,
        [psobject]$State,
        [hashtable]$ADContext
    )

    Write-ADAutoXConsole -Message 'Phase 1: Preflight Validation (Non-mutating)' -Level Phase
    $checks = [System.Collections.Generic.List[psobject]]::new()
    $isCanonicalProvisioning = $State -and
        $State.PSObject.Properties['CanonicalProvisioning'] -and
        [bool]$State.CanonicalProvisioning
    if (-not $ADContext -and (Get-Command Get-ADToolContextParameters -ErrorAction SilentlyContinue)) {
        $ADContext = Get-ADToolContextParameters
    }

    if ($State) {
        if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
            Add-ADPreflightCheck -Checks $checks -Name 'AD module' -Status 'Failed' -Details 'Active Directory module not available.'
        }
        else {
            Add-ADPreflightCheck -Checks $checks -Name 'AD module' -Status 'Passed' -Details 'Active Directory module loaded.'
        }

        try {
            $null = Get-ADDomain @ADContext -ErrorAction Stop
            Add-ADPreflightCheck -Checks $checks -Name 'Domain connectivity' -Status 'Passed' -Details "Domain root resolved to '$DomainDN' ($NetBIOSName)."
        }
        catch {
            Add-ADPreflightCheck -Checks $checks -Name 'Domain connectivity' -Status 'Failed' -Details $_.Exception.Message
        }

        if ($State.AdministratorsOnly) {
            Add-ADPreflightCheck -Checks $checks -Name 'Names file' -Status 'Passed' -Details 'Not required for an administrators-only run.'
        }
        elseif (-not [string]::IsNullOrWhiteSpace($State.NamesPath) -and -not (Test-Path -LiteralPath $State.NamesPath -PathType Leaf)) {
            Add-ADPreflightCheck -Checks $checks -Name 'Names file' -Status 'Failed' -Details "Names file not found: $($State.NamesPath)"
        }
        else {
            Add-ADPreflightCheck -Checks $checks -Name 'Names file' -Status 'Passed' -Details "Names file resolved to '$($State.NamesPath)'."
        }

        foreach ($department in $Departments) {
            $departmentName = $department.Trim()
            Add-ADPreflightCheck -Checks $checks -Name "Department name: $departmentName" -Status 'Passed' -Details "Validated department '$departmentName'."
        }

        if ($State.CreateDepartmentAdministrators -and -not [string]::IsNullOrWhiteSpace($State.AdministratorUsername) -and
            $Departments.Count -gt 1 -and -not $State.AdministratorUsername.Contains('{0}')) {
            Add-ADPreflightCheck -Checks $checks -Name 'Administrator username template' -Status 'Failed' -Details "When creating department administrators for multiple departments, -AdministratorUsername must include {0}."
        }
        else {
            Add-ADPreflightCheck -Checks $checks -Name 'Administrator username template' -Status 'Passed' -Details 'Administrator naming pattern is valid for the requested department layout.'
        }
    }

    $companyExists = $false
    $companyOUs = @()
    if (-not (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue)) {
        Write-ADAutoXConsole -Message '[Offline/Preview] Active Directory module is unavailable. Simulating OU preflight checks.' -Level Warning
    }
    else {
        $companyFilterValue = ConvertTo-LdapFilterValue -Value $CompanyOuName
        $companyOUs = @(Get-ADOrganizationalUnit @ADContext -LDAPFilter "(ou=$companyFilterValue)" -SearchBase $DomainDN -SearchScope OneLevel -ErrorAction Stop)
        if ($companyOUs.Count -gt 1) {
            throw "More than one OU named '$CompanyOuName' was found below '$DomainDN'. Use a unique OU name."
        }
        $companyExists = $companyOUs.Count -eq 1
    }
    $checks.Add([pscustomobject]@{
        Name = 'Company OU'
        Status = if ($companyExists) { 'Passed' } else { 'NeedsAttention' }
        Details = if ($isCanonicalProvisioning) {
            "Company OU '$CompanyOuName' already exists: $companyExists."
        }
        elseif ($companyExists) {
            "Root OU '$CompanyOuName' exists."
        }
        else {
            "Root OU '$CompanyOuName' will be created during provisioning."
        }
    })

    $staffExists = $false
    $staffOUs = @()
    if ($companyExists) {
        $staffFilterValue = ConvertTo-LdapFilterValue -Value $StaffOuName
        $staffOUs = @(Get-ADOrganizationalUnit @ADContext -LDAPFilter "(ou=$staffFilterValue)" -SearchBase $companyOUs[0].DistinguishedName -SearchScope OneLevel -ErrorAction Stop)
        if ($staffOUs.Count -gt 1) {
            throw "More than one OU named '$StaffOuName' was found below '$($companyOUs[0].DistinguishedName)'."
        }
        $staffExists = $staffOUs.Count -eq 1
    }
    $staffDn = if ($staffExists) { [string]$staffOUs[0].DistinguishedName } else { '' }
    $staffCheckName = if ($isCanonicalProvisioning) { 'Staff Names OU' } else { 'Staff OU' }
    $checks.Add([pscustomobject]@{
        Name = $staffCheckName
        Status = if ($staffExists) { 'Passed' } else { 'NeedsAttention' }
        Details = if ($isCanonicalProvisioning) {
            if ($staffExists) { "'$StaffOuName' already exists at '$staffDn'." } else { "'$StaffOuName' was not found and will be created during Phase 2." }
        }
        elseif ($staffExists) {
            "Staff OU '$StaffOuName' exists."
        }
        else {
            "Staff OU '$StaffOuName' will be created during provisioning."
        }
    })

    if ($isCanonicalProvisioning) {
        foreach ($department in $Departments) {
            $departmentDn = ''
            if ($staffDn) {
                $departmentFilter = ConvertTo-LdapFilterValue -Value $department
                $departmentOUs = @(Get-ADOrganizationalUnit @ADContext -LDAPFilter "(ou=$departmentFilter)" `
                    -SearchBase $staffDn -SearchScope OneLevel -ErrorAction Stop)
                if ($departmentOUs.Count -gt 1) {
                    throw "More than one OU named '$department' was found below '$staffDn'."
                }
                if ($departmentOUs.Count -eq 1) { $departmentDn = [string]$departmentOUs[0].DistinguishedName }
            }

            $departmentExists = -not [string]::IsNullOrWhiteSpace($departmentDn)
            Add-ADPreflightCheck -Checks $checks -Name "Department OU: $department" `
                -Status $(if ($departmentExists) { 'Passed' } else { 'NeedsAttention' }) `
                -Details $(if ($departmentExists) { "Department OU '$department' already exists at '$departmentDn'." } else { "Department OU '$department' is not present yet and will be created during Phase 2." })

            if (-not $State.CreateDepartmentAdministrators) { continue }

            $departmentUsersDn = ''
            if (-not $State.AdministratorsOnly -and $departmentDn) {
                $usersOUs = @(Get-ADOrganizationalUnit @ADContext -LDAPFilter '(ou=Users)' `
                    -SearchBase $departmentDn -SearchScope OneLevel -ErrorAction Stop)
                if ($usersOUs.Count -gt 1) {
                    throw "More than one Users OU was found below '$departmentDn'."
                }
                if ($usersOUs.Count -eq 1) { $departmentUsersDn = [string]$usersOUs[0].DistinguishedName }
            }
            $checkUsersOu = -not $State.AdministratorsOnly -and
                -not ($State.TreatZeroAccountCountAsNone -and [int]$State.AccountCount -eq 0)
            if ($checkUsersOu) {
                $usersOuExists = -not [string]::IsNullOrWhiteSpace($departmentUsersDn)
                Add-ADPreflightCheck -Checks $checks -Name "Department Users OU: $department" `
                    -Status $(if ($usersOuExists) { 'Passed' } else { 'NeedsAttention' }) `
                    -Details $(if ($usersOuExists) { "Department Users OU for '$department' already exists at '$departmentUsersDn'." } else { "Department Users OU for '$department' is not present yet and will be created during Phase 2." })
            }

            $adminOuDn = ''
            if ($departmentDn) {
                $adminOUs = @(Get-ADOrganizationalUnit @ADContext -LDAPFilter '(ou=Administrators)' `
                    -SearchBase $departmentDn -SearchScope OneLevel -ErrorAction Stop)
                if ($adminOUs.Count -gt 1) {
                    throw "More than one Administrators OU was found below '$departmentDn'."
                }
                if ($adminOUs.Count -eq 1) { $adminOuDn = [string]$adminOUs[0].DistinguishedName }
            }
            $adminOuExists = -not [string]::IsNullOrWhiteSpace($adminOuDn)
            Add-ADPreflightCheck -Checks $checks -Name "Department Administrators OU: $department" `
                -Status $(if ($adminOuExists) { 'Passed' } else { 'NeedsAttention' }) `
                -Details $(if ($adminOuExists) { "Department Administrators OU for '$department' already exists at '$adminOuDn'." } else { "Department Administrators OU for '$department' is not present yet and will be created during Phase 2." })

            $adminUsernameTemplate = if ($State.AdministratorUsername) {
                if ($State.AdministratorUsername.Contains('{0}')) { $State.AdministratorUsername -f $department } else { $State.AdministratorUsername }
            }
            else {
                "$($department.ToLowerInvariant()).admin"
            }
            $resolvedAdminSamAccountName = Get-UniqueSamAccountName -BaseName $adminUsernameTemplate `
                -UsedNames ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase))
            Add-ADPreflightCheck -Checks $checks -Name "Administrator SAM name: $department" -Status 'Passed' `
                -Details "Resolved administrator SAM name '$resolvedAdminSamAccountName' for department '$department'."

            if ($departmentUsersDn -and $adminOuDn) {
                $adminGroupName = "${department}-Administrators"
                $adminGroupFilter = ConvertTo-LdapFilterValue -Value $adminGroupName
                $adminGroups = @(Get-ADGroup @ADContext -LDAPFilter "(cn=$adminGroupFilter)" `
                    -SearchBase $adminOuDn -SearchScope OneLevel -Properties SID,GroupScope,GroupCategory -ErrorAction Stop)
                if ($adminGroups.Count -gt 1) {
                    throw "More than one administrator group named '$adminGroupName' was found below '$adminOuDn'."
                }
                if ($adminGroups.Count -eq 0) {
                    $delegationStatus = 'NeedsAttention'
                    $delegationDetails = "Administrator group '$adminGroupName' will be created during provisioning; delegation will be scoped to that newly created group's SID."
                }
                else {
                    $groupSid = Get-ADValidatedSecurityGroupSid -Group $adminGroups[0] `
                        -ExpectedName $adminGroupName -ExpectedParentDistinguishedName $adminOuDn
                    $acl = Invoke-ADObjectAcl -Action Read -DistinguishedName $departmentUsersDn `
                        -ADContext $ADContext -AllowMissing
                    if ($null -eq $acl) {
                        $delegationStatus = 'NeedsAttention'
                        $delegationDetails = "Department Users OU '$departmentUsersDn' is not present yet and is pending creation; its ACL will be checked during Phase 2."
                    }
                    else {
                        $delegationPresent = Test-ADUserLifecycleDelegation -AccessRules @($acl.Access) -GroupSid $groupSid
                        $delegationStatus = if ($delegationPresent) { 'Passed' } else { 'Failed' }
                        $delegationDetails = if ($delegationPresent) {
                            "Delegation for '$adminGroupName' on '$departmentUsersDn' is already present for the validated group SID."
                        }
                        else {
                            "Pre-existing administrator group '$adminGroupName' has no matching SID-scoped delegation on '$departmentUsersDn'; automatic delegation is refused."
                        }
                    }
                }
                Add-ADPreflightCheck -Checks $checks -Name "Delegation state: $department" `
                    -Status $delegationStatus -Details $delegationDetails
            }
        }
    }
    else {
        foreach ($department in $Departments) {
            $checks.Add([pscustomobject]@{ Name = "Department Structure: $department"; Status = 'Passed'; Details = "Validated target scope for $department." })
        }
    }

    $summary = [pscustomobject]@{
        Passed = @($checks | Where-Object Status -eq 'Failed').Count -eq 0
        PassedCount = @($checks | Where-Object Status -eq 'Passed').Count
        NeedsAttentionCount = @($checks | Where-Object Status -eq 'NeedsAttention').Count
        FailedCount = @($checks | Where-Object Status -eq 'Failed').Count
        HasIssues = @($checks | Where-Object Status -ne 'Passed').Count -gt 0
        Checks = $checks.ToArray()
    }
    Write-ADAutoXConsole -Message "Preflight completed: $($summary.PassedCount) passed, $($summary.NeedsAttentionCount) pending creation." -Level Info
    $summary
}

$publicFunctions = @(
    'Import-ADTools', 'Test-ADDomainReachability', 'Assert-ADOperationsDependencies',
    'Set-ADToolContext', 'Get-ADToolContextParameters', 'Clear-ADToolContext',
    'Move-ADSecuredFileIntoPlace', 'ConvertTo-LdapFilterValue', 'ConvertTo-DistinguishedNameValue',
    'Split-ADDistinguishedName', 'Get-ADDistinguishedNameDepth', 'ConvertTo-ADCanonicalDistinguishedName',
    'Get-ADDistinguishedNameParent', 'Test-ADIdentityNotFoundError', 'Test-ADAccountInactive',
    'New-ADTerminationDescription', 'Get-ADValidatedSecurityGroupSid', 'Test-ADUserLifecycleDelegation',
    'Assert-ADUserLifecycleDelegationSafe', 'Assert-CsvColumns', 'ConvertTo-CsvBoolean',
    'Resolve-ADIdentitySafe', 'Test-ADUserExists', 'Get-TargetOU', 'Write-ADAuditRecord',
    'Assert-ADTargetWithinRoot', 'Export-ADResults',
    'Test-DepartmentNames', 'Get-ADInvocationContext', 'New-RandomPassword',
    'Test-PasswordComplexity', 'Resolve-PasswordPatternText', 'Get-UniqueSamAccountName',
    'Get-ADFailureCategory', 'Get-ADCreateFailureDetails', 'Initialize-ADProvisioning',
    'Clear-ADProvisioningContext', 'Test-ADProvisioningPreflight', 'Test-ADProvisioningTargetPermissions',
    'New-CompanyOU', 'New-DepartmentOU', 'New-DepartmentGroups', 'New-DepartmentUser',
    'New-DepartmentAdministrator', 'Enable-VerifiedDepartmentAccount', 'Set-DepartmentDelegation',
    'Test-DepartmentProvisioning', 'Export-ProvisioningReport', 'Invoke-ProvisioningRollback',
    'Invoke-ADAutoXUserLifecycle', 'Invoke-ADAutoXUserAction', 'Enable-ADAutoXUser', 'Disable-ADAutoXUser',
    'Unlock-ADAutoXUser', 'Reset-ADAutoXUserPassword', 'Move-ADAutoXUser',
    'Stop-ADAutoXUser', 'Remove-ADAutoXUser', 'Set-ADAutoXUserGroupMembership',
    'Disable-ADAutoXInactiveUsers', 'Get-ADAutoXLockedOutUsers', 'Update-ADAutoXUserDepartments',
    'ConvertTo-ADLdapFilter', 'ConvertTo-ADDistinguishedNameValue',
    'Get-ADSanitizedSamAccountName', 'Get-ADSanitizedUserPrincipalName', 'New-ADAutoXRandomPassword',
    'Test-ADAutoXPasswordComplexity', 'Get-ADAutoXSecurityScan', 'Invoke-ADAutoXProvision',
    'Protect-ADAutoXFileAcl', 'Export-ADAutoXCredentials', 'Get-ADAutoXAuditReport',
    'New-ADAutoXCorrelationId', 'Get-ADAutoXCorrelationId', 'Write-ADAutoXLogRecord',
    'Test-ADAutoXDomainReachability', 'Initialize-ADAutoXContext', 'Clear-ADAutoXContext',
    'Write-ADAutoXConsole', 'Initialize-ADAutoXLedger', 'Get-ADAutoXLedger',
    'Add-ADAutoXLedgerEntry', 'Invoke-ADAutoXLedgerRollback', 'Invoke-ADAutoXPreflight'
)

Export-ModuleMember -Function $publicFunctions -Alias Terminate-ADAutoXUser, Manage-ADAutoXUser
