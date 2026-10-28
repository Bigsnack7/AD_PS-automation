[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateRange(0,1000)][int]$AccountCount = 20,
    [Alias('OrganizationalUnitName')][ValidateNotNullOrEmpty()][string]$CompanyOuName = 'Company',
    [Alias('StaffNamesOrganizationalUnitName')][ValidateNotNullOrEmpty()][string]$StaffOuName = 'Staff',
    [string]$NamesPath = '',
    [ValidateNotNullOrEmpty()][string[]]$Departments = @('IT','HR','Finance','Sales'),
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop

$arguments = @{}
foreach ($name in $PSBoundParameters.Keys) {
    if ($name -notin @('WhatIf','Confirm')) {
        $arguments[$name] = $PSBoundParameters[$name]
    }
}
if ($WhatIfPreference) { $arguments.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Invoke-ADAutoXProvision @arguments
