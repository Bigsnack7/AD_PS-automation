@{
    RootModule = 'ADAutoX.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'e8f7a9d2-b432-4e56-9a21-789fcd123456'
    Author = 'AD_PS-automation contributors'
    CompanyName = 'AD_PS-automation'
    Copyright = '(c) 2026. All rights reserved.'
    Description = 'Modular Active Directory provisioning, lifecycle operations, security, and audit automation.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
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
        'Get-ADSanitizedSamAccountName', 'Get-ADSanitizedUserPrincipalName',
        'New-ADAutoXRandomPassword', 'Test-ADAutoXPasswordComplexity',
        'Get-ADAutoXSecurityScan',
        'Invoke-ADAutoXProvision', 'Protect-ADAutoXFileAcl', 'Export-ADAutoXCredentials',
        'Get-ADAutoXAuditReport', 'New-ADAutoXCorrelationId', 'Get-ADAutoXCorrelationId',
        'Write-ADAutoXLogRecord', 'Test-ADAutoXDomainReachability',
        'Initialize-ADAutoXContext', 'Clear-ADAutoXContext', 'Write-ADAutoXConsole',
        'Initialize-ADAutoXLedger', 'Get-ADAutoXLedger', 'Add-ADAutoXLedgerEntry',
        'Invoke-ADAutoXLedgerRollback', 'Invoke-ADAutoXPreflight'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @('Terminate-ADAutoXUser', 'Manage-ADAutoXUser')
}
