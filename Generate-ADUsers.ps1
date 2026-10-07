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

$state = Initialize-ADProvisioning -Departments $Departments -OrganizationalUnitName $OrganizationalUnitName -StaffNamesOrganizationalUnitName $StaffNamesOrganizationalUnitName -NamesPath $NamesPath -ReportPath $ReportPath -AuditLogPath $AuditLogPath -PasswordFile $PasswordFile -ExportPasswords:$ExportPasswords -OverwritePasswordFile:$OverwritePasswordFile -AdministratorUsername $AdministratorUsername -CreateDepartmentAdministrators:$CreateDepartmentAdministrators -AdministratorsOnly:$AdministratorsOnly -EnableAccountsAfterVerification:$EnableAccountsAfterVerification -AccountCount $AccountCount -Server $Server -Credential $Credential -UPNSuffix $UPNSuffix -Password $Password -PasswordPattern $PasswordPattern -AdministratorPasswordPattern $AdministratorPasswordPattern -WhatIf:$WhatIfPreference

$preflight = Test-ADProvisioningPreflight -State $state
if (-not $preflight.Passed -and $preflight.FailedCount -gt 0) {
    $failureMessages = @($preflight.Checks | Where-Object { $_.Status -eq 'Failed' } | ForEach-Object { $_.Details })
    throw "Preflight failed: $($failureMessages -join '; ')"
}

# Read the names file once, up front, rather than once per department - the
# contents don't change between iterations.
$userNames = if ($NamesPath) { @(Get-Content -LiteralPath $NamesPath -ErrorAction Stop) } else { @() }

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
        $state.DepartmentAttributeAdministratorGroups[$department] = $groupResult.AttributeAdministratorGroup
    }

    $permissionPreflight = Test-ADProvisioningTargetPermissions -State $state
    if (-not $permissionPreflight.Passed) {
        $permissionFailures = @($permissionPreflight.Checks | Where-Object { $_.Status -eq 'Failed' } | ForEach-Object { $_.Details })
        throw "Permission preflight failed before account creation: $($permissionFailures -join '; ')"
    }

    foreach ($department in $state.Departments) {
        $departmentAdminOu = [pscustomobject]@{ DistinguishedName = $state.DepartmentAdministratorOUs[$department] }
        $departmentUserOu = [pscustomobject]@{ DistinguishedName = $state.DepartmentUserOUs[$department] }

        if ($state.CreateDepartmentAdministrators) {
            $adminTemplate = if ($AdministratorUsername) {
                if ($AdministratorUsername.Contains('{0}')) { $AdministratorUsername -f $department } else { $AdministratorUsername }
            }
            else {
                "$($department.ToLowerInvariant()).admin"
            }

            $adminUser = New-DepartmentAdministrator -State $state -Department $department -TargetOuDistinguishedName $departmentAdminOu.DistinguishedName -Username $adminTemplate
            $state.CreatedAccounts.Add([pscustomobject]@{ SamAccountName = $adminUser.User.SamAccountName; DistinguishedName = $adminUser.User.DistinguishedName })
            $null = Enable-VerifiedDepartmentAccount -State $state -Account $adminUser.User -Department $department

            $delegation = Set-DepartmentDelegation -State $state -GroupName "$department-Administrators" -TargetOuDistinguishedName $state.DepartmentUserOUs[$department] -DomainNetBIOSName $state.DomainNetBIOSName
            if ($delegation.Status -eq 'Granted') {
                Write-Host "Granted delegation for '$($delegation.GroupName)' on '$($delegation.TargetOuDistinguishedName)'." -ForegroundColor Yellow
            }
        }

        if (-not $state.AdministratorsOnly -and $userNames.Count -gt 0) {
            foreach ($line in $userNames) {
                $trimmed = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
                $parts = $trimmed -split '\s+', 2
                if ($parts.Count -lt 2) { continue }

                $username = ($parts[0] + '.' + $parts[1]).ToLowerInvariant() -replace '[^a-z0-9.]', ''
                if (-not $username) { continue }

                $user = New-DepartmentUser -State $state -Department $department -TargetOuDistinguishedName $departmentUserOu.DistinguishedName -Username $username
                $state.CreatedAccounts.Add([pscustomobject]@{ SamAccountName = $user.User.SamAccountName; DistinguishedName = $user.User.DistinguishedName })
                $null = Enable-VerifiedDepartmentAccount -State $state -Account $user.User -Department $department
            }
        }
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