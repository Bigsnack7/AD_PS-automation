<#
.SYNOPSIS
    Runs the departmental AD provisioning flow using native PowerShell preview semantics.

.DESCRIPTION
    This orchestration wrapper intentionally uses the built-in PowerShell `-WhatIf` / `ShouldProcess`
    pattern for preview behavior. It does not expose a separate `-DryRun` parameter, because the
    standard PowerShell mechanism already provides the correct behavior without creating a redundant
    second preview mode.

.EXAMPLE
    .\Generate-ADUsers.ps1 -AccountCount 20 -WhatIf

.NOTES
    Preview mode is controlled by PowerShell's native `-WhatIf` support and `SupportsShouldProcess`.
    Use -EnableAccountsAfterVerification for the safer disabled-create workflow.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(0, 1000)]
    [int]$AccountCount = 20,

    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [ValidateNotNullOrEmpty()]
    [string]$StaffNamesOrganizationalUnitName = 'Staff',

    [string]$NamesPath = '',

    [ValidateNotNullOrEmpty()]
    [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),

    [string]$AdministratorUsername = '',

    [switch]$CreateDepartmentAdministrators,

    [switch]$AdministratorsOnly,

    [switch]$EnableAccountsAfterVerification,

    [AllowNull()]
    [string]$PasswordPattern,

    [string]$AdministratorPasswordPattern,

    [string]$PasswordFile,

    [switch]$ExportPasswords,

    [switch]$OverwritePasswordFile,

    [string]$ReportPath = '',

    [Alias('RollbackOnFailure', 'RollbackAccountsOnFailure')]
    [switch]$RollbackCreatedAccountsOnFailure,

    [SecureString]$Password,

    [string]$Server,

    [string]$UPNSuffix = '',

    [PSCredential]$Credential,

    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($AdministratorsOnly -and -not $CreateDepartmentAdministrators) {
    throw "-AdministratorsOnly was specified without -CreateDepartmentAdministrators. That combination would create OUs and groups but zero accounts. Pass -CreateDepartmentAdministrators as well, or drop -AdministratorsOnly."
}

$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$modulePath = Join-Path $scriptDirectory 'AD-Provisioning.psm1'
Import-Module $modulePath -Force
$operationsModulePath = Join-Path $scriptDirectory 'AD-Operations.psm1'
if (-not (Test-Path -LiteralPath $operationsModulePath -PathType Leaf)) {
    throw "Required module not found: $operationsModulePath"
}
Import-Module $operationsModulePath -Force -ErrorAction Stop

$state = Initialize-ADProvisioning -Departments $Departments -OrganizationalUnitName $OrganizationalUnitName -StaffNamesOrganizationalUnitName $StaffNamesOrganizationalUnitName -NamesPath $NamesPath -ReportPath $ReportPath -AuditLogPath $AuditLogPath -PasswordFile $PasswordFile -ExportPasswords:$ExportPasswords -OverwritePasswordFile:$OverwritePasswordFile -AdministratorUsername $AdministratorUsername -CreateDepartmentAdministrators:$CreateDepartmentAdministrators -AdministratorsOnly:$AdministratorsOnly -EnableAccountsAfterVerification:$EnableAccountsAfterVerification -AccountCount $AccountCount -Server $Server -Credential $Credential -UPNSuffix $UPNSuffix -Password $Password -PasswordPattern $PasswordPattern -AdministratorPasswordPattern $AdministratorPasswordPattern -WhatIf:$WhatIfPreference

try {
$preflight = Test-ADProvisioningPreflight -State $state
if (-not $preflight.Passed -and $preflight.FailedCount -gt 0) {
    $failureMessages = @($preflight.Checks | Where-Object { $_.Status -eq 'Failed' } | ForEach-Object { $_.Details })
    throw "Preflight failed: $($failureMessages -join '; ')"
}

# Read the names file once, up front, rather than once per department - the
# contents don't change between iterations.
$userNames = if (-not $state.AdministratorsOnly -and $state.AccountCount -gt 0) {
    @(Get-Content -LiteralPath $state.NamesPath -ErrorAction Stop |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -First $state.AccountCount)
}
else {
    @()
}
if (-not $state.AdministratorsOnly -and $state.AccountCount -gt 0 -and $userNames.Count -eq 0) {
    throw "The names file '$($state.NamesPath)' contains no non-blank account names; refusing to begin provisioning."
}

$userPlans = [System.Collections.Generic.List[psobject]]::new()
$usedSamNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$adminUsernames = @{}
$adContext = $state.ADContext

if ($state.CreateDepartmentAdministrators) {
    foreach ($department in $state.Departments) {
        $adminTemplate = if ($AdministratorUsername) {
            if ($AdministratorUsername.Contains('{0}')) { $AdministratorUsername -f $department } else { $AdministratorUsername }
        }
        else {
            "$($department.ToLowerInvariant()).admin"
        }
        $adminUsername = Get-UniqueSamAccountName -BaseName $adminTemplate -UsedNames $usedSamNames
        $safeAdminUsername = ConvertTo-LdapFilterValue -Value $adminUsername
        $existingAdminUsers = @(Get-ADUser @adContext -LDAPFilter "(sAMAccountName=$safeAdminUsername)" `
            -SearchBase $state.DomainRoot -SearchScope Subtree -ErrorAction Stop)
        if ($existingAdminUsers.Count -gt 0) {
            throw "Administrator account '$adminUsername' already exists in the domain; refusing to reuse or overwrite it."
        }
        $adminUsernames[$department] = $adminUsername

        $adminPattern = if (-not [string]::IsNullOrWhiteSpace($AdministratorPasswordPattern)) {
            $AdministratorPasswordPattern
        }
        elseif (-not [string]::IsNullOrWhiteSpace($state.AdministratorPasswordPattern)) {
            $state.AdministratorPasswordPattern
        }
        else {
            $state.PasswordPattern
        }
        if (-not [string]::IsNullOrWhiteSpace($adminPattern)) {
            $samplePassword = Resolve-PasswordPatternText -Pattern $adminPattern -Username $adminUsername -Token $department
            if (-not (Test-PasswordComplexity -PasswordText $samplePassword)) {
                throw "Administrator password pattern for '$department' does not meet the required character-category complexity."
            }
        }
    }
}

$userIndex = 0
foreach ($line in $userNames) {
    $trimmed = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
    $parts = $trimmed -split '\s+', 2
    $firstName = $parts[0]
    $lastName = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    $samBase = if ($lastName) { "$firstName.$lastName" } else { $firstName }
    $username = Get-UniqueSamAccountName -BaseName $samBase -UsedNames $usedSamNames
    $department = $state.Departments[$userIndex % $state.Departments.Count]
    $userIndex++
    $safeSamAccountName = ConvertTo-LdapFilterValue -Value $username
    $existingUsers = @(Get-ADUser @adContext -LDAPFilter "(sAMAccountName=$safeSamAccountName)" `
        -SearchBase $state.DomainRoot -SearchScope Subtree -ErrorAction Stop)
    if ($existingUsers.Count -gt 0) {
        $plannedDepartmentOu = "OU=$(ConvertTo-DistinguishedNameValue -Value $department),OU=$(ConvertTo-DistinguishedNameValue -Value $state.StaffNamesOrganizationalUnitName),OU=$(ConvertTo-DistinguishedNameValue -Value $state.OrganizationalUnitName),$($state.DomainRoot)"
        $state.ReportRecords.Add([pscustomobject]@{
            Username = $username
            Department = $department
            Role = 'User'
            OU = "OU=Users,$plannedDepartmentOu"
            Status = 'Skipped (Already Exists)'
            Stage = 'Preflight'
            ErrorCategory = ''
            Error = ''
        })
        if ($WhatIfPreference) {
            Write-Host "WhatIf: existing account '$username' would be skipped in '$department'." -ForegroundColor Yellow
        }
        else {
            Write-Warning "Skipping existing account '$username' in '$department'."
            Write-ADAuditRecord -Path $state.AuditLogPath -Action 'CreateUser' -Target $username `
                -TargetType 'User' -Status 'Skipped' -Message "Account already exists; no changes were made."
        }
        continue
    }

    if (-not [string]::IsNullOrWhiteSpace($PasswordPattern)) {
        $samplePassword = Resolve-PasswordPatternText -Pattern $PasswordPattern -Username $username -Token $username
        if (-not (Test-PasswordComplexity -PasswordText $samplePassword)) {
            throw "Password pattern for '$username' does not meet the required character-category complexity."
        }
    }
    $userPlans.Add([pscustomobject]@{
        Username = $username
        Department = $department
        FirstName = $firstName
        LastName = $lastName
    })
}

try {
    $companyOu = New-CompanyOU -State $state
    $state.CompanyOuDistinguishedName = $companyOu.DistinguishedName

    foreach ($department in $state.Departments) {
        $departmentOu = New-DepartmentOU -State $state -Department $department -ParentDistinguishedName $state.CompanyOuDistinguishedName
        $state.DepartmentOUs[$department] = $departmentOu.DistinguishedName

        $departmentUserOu = New-DepartmentOU -State $state -Department 'Users' -ParentDistinguishedName $departmentOu.DistinguishedName
        $state.DepartmentUserOUs[$department] = $departmentUserOu.DistinguishedName

        $departmentAdminOu = New-DepartmentOU -State $state -Department 'Administrators' -ParentDistinguishedName $departmentOu.DistinguishedName
        $state.DepartmentAdministratorOUs[$department] = $departmentAdminOu.DistinguishedName

        $groupResult = New-DepartmentGroups -State $state -Department $department -DepartmentOU $departmentOu.DistinguishedName
        $state.DepartmentUserGroups[$department] = $groupResult.UserGroup
        $state.DepartmentAdministratorGroups[$department] = $groupResult.AdministratorGroup
        $state.DepartmentAdministratorGroupCreatedByThisRun[$department] = $groupResult.AdministratorGroupCreatedByThisRun
        $state.DepartmentAttributeAdministratorGroups[$department] = $groupResult.AttributeAdministratorGroup
    }

    $permissionPreflight = Test-ADProvisioningTargetPermissions -State $state
    if (-not $permissionPreflight.Passed) {
        $permissionFailures = @($permissionPreflight.Checks | Where-Object { $_.Status -eq 'Failed' } | ForEach-Object { $_.Details })
        throw "Permission preflight failed before account creation: $($permissionFailures -join '; ')"
    }

    if (-not $WhatIfPreference -and $state.CreateDepartmentAdministrators) {
        foreach ($department in $state.Departments) {
            $groupName = "$department-Administrators"
            $groupSid = Get-ADValidatedSecurityGroupSid -Group $state.DepartmentAdministratorGroups[$department] `
                -ExpectedName $groupName `
                -ExpectedParentDistinguishedName $state.DepartmentOUs[$department]
            $ouPath = "$($state.AclDriveName):\$($state.DepartmentUserOUs[$department])"
            $acl = Get-Acl -LiteralPath $ouPath -ErrorAction Stop
            $existingDelegation = Test-ADUserLifecycleDelegation -AccessRules @($acl.Access) -GroupSid $groupSid
            Assert-ADUserLifecycleDelegationSafe -GroupSid $groupSid `
                -CreatedByThisRun ([bool]$state.DepartmentAdministratorGroupCreatedByThisRun[$department]) `
                -ExistingDelegation $existingDelegation
        }
    }

    foreach ($department in $state.Departments) {
        $departmentAdminOu = [pscustomobject]@{ DistinguishedName = $state.DepartmentAdministratorOUs[$department] }
        if ($state.CreateDepartmentAdministrators) {
            $adminUser = New-DepartmentAdministrator -State $state -Department $department `
                -TargetOuDistinguishedName $departmentAdminOu.DistinguishedName `
                -Username $adminUsernames[$department] `
                -PasswordPattern $AdministratorPasswordPattern `
                -PasswordToken $department
            $state.CreatedAccounts.Add([pscustomobject]@{ SamAccountName = $adminUser.User.SamAccountName; DistinguishedName = $adminUser.User.DistinguishedName })
            $null = Enable-VerifiedDepartmentAccount -State $state -Account $adminUser.User -Department $department

            $delegation = Set-DepartmentDelegation -State $state `
                -Group $state.DepartmentAdministratorGroups[$department] `
                -GroupName "$department-Administrators" `
                -ExpectedGroupParentDistinguishedName $state.DepartmentOUs[$department] `
                -CreatedByThisRun ([bool]$state.DepartmentAdministratorGroupCreatedByThisRun[$department]) `
                -TargetOuDistinguishedName $state.DepartmentUserOUs[$department]
            if ($delegation.Status -eq 'Granted') {
                Write-Host "Granted delegation for '$($delegation.GroupName)' on '$($delegation.TargetOuDistinguishedName)'." -ForegroundColor Yellow
            }
        }

    }

    foreach ($userPlan in $userPlans) {
        $department = $userPlan.Department
        $safeSamAccountName = ConvertTo-LdapFilterValue -Value $userPlan.Username
        $adContext = $state.ADContext
        $existingUsers = @(Get-ADUser @adContext -LDAPFilter "(sAMAccountName=$safeSamAccountName)" `
            -SearchBase $state.DomainRoot -SearchScope Subtree -ErrorAction Stop)
        if ($existingUsers.Count -gt 0) {
            $state.ReportRecords.Add([pscustomobject]@{
                Username = $userPlan.Username
                Department = $department
                Role = 'User'
                OU = $state.DepartmentUserOUs[$department]
                Status = 'Skipped (Already Exists)'
                Stage = 'Preflight'
                ErrorCategory = ''
                Error = ''
            })
            if ($WhatIfPreference) {
                Write-Host "WhatIf: account '$($userPlan.Username)' appeared after preflight and would be skipped." -ForegroundColor Yellow
            }
            else {
                Write-Warning "Account '$($userPlan.Username)' appeared after preflight and will be skipped."
                Write-ADAuditRecord -Path $state.AuditLogPath -Action 'CreateUser' -Target $userPlan.Username `
                    -TargetType 'User' -Status 'Skipped' -Message 'Account appeared after preflight; no changes were made.'
            }
            continue
        }

        $user = New-DepartmentUser -State $state -Department $department `
            -TargetOuDistinguishedName $state.DepartmentUserOUs[$department] `
            -Username $userPlan.Username `
            -GivenName $userPlan.FirstName `
            -Surname $userPlan.LastName `
            -PasswordPattern $PasswordPattern `
            -PasswordToken $userPlan.Username
        $state.CreatedAccounts.Add([pscustomobject]@{ SamAccountName = $user.User.SamAccountName; DistinguishedName = $user.User.DistinguishedName })
        $null = Enable-VerifiedDepartmentAccount -State $state -Account $user.User -Department $department
    }

    $report = Export-ProvisioningReport -State $state -OutputPath $state.ReportPath
    Write-Host "Provisioning orchestration completed. Report: $($report.OutputPath)" -ForegroundColor Green
}
catch {
    if ($RollbackCreatedAccountsOnFailure -and $state.CreatedAccounts.Count -gt 0) {
        Write-Warning "Provisioning failed after creating $($state.CreatedAccounts.Count) account(s). Rolling back..."
        $removeContext = @{}
        if ($Server) { $removeContext.Server = $Server }
        if ($Credential) { $removeContext.Credential = $Credential }

        foreach ($account in $state.CreatedAccounts) {
            try {
                Remove-ADUser @removeContext -Identity $account.DistinguishedName -Confirm:$false -ErrorAction Stop
                Write-Warning "Rolled back account '$($account.SamAccountName)'."
            }
            catch {
                Write-Warning "Failed to roll back account '$($account.SamAccountName)': $($_.Exception.Message)"
            }
        }
    }
    throw
}
}
finally {
    if ($state.AclDriveName -and (Get-PSDrive -Name $state.AclDriveName -ErrorAction SilentlyContinue)) {
        try {
            Remove-PSDrive -Name $state.AclDriveName -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to remove temporary Active Directory drive '$($state.AclDriveName)': $($_.Exception.Message)"
        }
    }
    Clear-ADProvisioningContext
}