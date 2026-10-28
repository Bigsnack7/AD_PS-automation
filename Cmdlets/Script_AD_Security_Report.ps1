<#
.SYNOPSIS
    Produces a high-level Active Directory security summary.
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$DomainName,
    [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),
    [string]$OrganizationalUnitName = 'Company',
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\ADAutoX.psd1'
Import-Module $modulePath -ErrorAction Stop

$scanParameters = @{
    Departments = $Departments
    OrganizationalUnitName = $OrganizationalUnitName
}
foreach ($parameterName in @('SearchBase', 'DomainName', 'Server', 'Credential', 'AuditLogPath')) {
    if ($PSBoundParameters.ContainsKey($parameterName)) {
        $scanParameters[$parameterName] = $PSBoundParameters[$parameterName]
    }
}

$scan = Get-ADAutoXSecurityScan @scanParameters -ErrorAction Stop
$scan.ReportLines | Write-Output
