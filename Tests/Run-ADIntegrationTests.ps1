<#
.SYNOPSIS
    Runs an opt-in provision-and-rollback integration test against a disposable AD domain.

.DESCRIPTION
    Creates one uniquely named company OU, department, user, administrator, groups, and scoped
    delegation using the real provisioning script, then removes only resources recorded under
    this test's correlation ID. Requires explicit live-test opt-in and an expected domain DNS root.

.EXAMPLE
    .\Tests\Run-ADIntegrationTests.ps1 -RunLive `
        -ExpectedDomainDnsRoot 'lab.example.test' `
        -Server 'dc01.lab.example.test' `
        -Credential (Get-Credential) `
        -Password (Read-Host 'Temporary test-account password' -AsSecureString)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [switch]$RunLive,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedDomainDnsRoot,

    [string]$Server,

    [PSCredential]$Credential,

    [SecureString]$Password,

    [ValidateNotNullOrEmpty()]
    [string]$CompanyOuName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repositoryRoot 'Modules\ADAutoX.psd1'
$provisioningScript = Join-Path $repositoryRoot 'Cmdlets\mark42.ps1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Required module not found: $modulePath"
}
if (-not (Test-Path -LiteralPath $provisioningScript -PathType Leaf)) {
    throw "Required provisioning script not found: $provisioningScript"
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module $modulePath -ErrorAction Stop

$adContext = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $adContext.Server = $Server }
if ($Credential) { $adContext.Credential = $Credential }
$domain = Get-ADDomain @adContext -ErrorAction Stop
if ($domain.DNSRoot -ine $ExpectedDomainDnsRoot) {
    throw "Connected domain '$($domain.DNSRoot)' does not match -ExpectedDomainDnsRoot '$ExpectedDomainDnsRoot'. No changes were made."
}

$runId = [Guid]::NewGuid().ToString()
$nameSuffix = $runId.Replace('-', '').Substring(0, 10)
if ([string]::IsNullOrWhiteSpace($CompanyOuName)) {
    $CompanyOuName = "ADAutoX-RT-$nameSuffix"
}
if ($CompanyOuName.Length -gt 64 -or $CompanyOuName -match '[,+=<>;"\\/:*?()\x00-\x1F]') {
    throw 'CompanyOuName must be at most 64 characters and contain no AD OU special characters.'
}
$departmentName = "QA-$nameSuffix"
$administratorUsername = "adrt-$nameSuffix.admin"
$companyFilter = ConvertTo-LdapFilterValue -Value $CompanyOuName
$existingCompanyOus = @(Get-ADOrganizationalUnit @adContext `
    -LDAPFilter "(ou=$companyFilter)" -SearchBase $domain.DistinguishedName `
    -SearchScope OneLevel -ErrorAction Stop)
if ($existingCompanyOus.Count -gt 0) {
    throw "The test OU '$CompanyOuName' already exists beneath '$($domain.DistinguishedName)'. Choose another -CompanyOuName. No changes were made."
}
if (-not $Password) {
    $Password = Read-Host 'Enter a temporary password for the test user and administrator' -AsSecureString
}
if ($Password.Length -eq 0) {
    throw 'The integration test requires a non-empty temporary password.'
}

$existingLedgerEntries = @(Get-ADAutoXLedger)
if ($existingLedgerEntries.Count -gt 0) {
    throw 'The ADAutoX rollback ledger is not empty. Refusing to clear or mix existing entries with this integration test.'
}
Initialize-ADAutoXLedger

$tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "ADAutoX-Integration-$runId"
$null = New-Item -ItemType Directory -Path $tempDirectory -ErrorAction Stop
$reportPath = Join-Path $tempDirectory 'provisioning.csv'
$auditLogPath = Join-Path $tempDirectory 'provisioning.jsonl'
$rollbackLogPath = Join-Path $tempDirectory 'rollback.jsonl'
$rollbackSucceeded = $false

try {
    $builtInAdministratorSid = '{0}-500' -f [string]$domain.DomainSID
    $builtInAdministrator = Get-ADUser @adContext -Identity $builtInAdministratorSid `
        -Properties Enabled -ErrorAction Stop
    $enabledBeforeProtectedCheck = [bool]$builtInAdministrator.Enabled
    $protectedActionError = ''
    try {
        Disable-ADAutoXUser -Identity $builtInAdministrator.SamAccountName `
            -AllowDestructiveOperation -AuditLogPath $auditLogPath `
            -Server $Server -Credential $Credential -WhatIf -Confirm:$false | Out-Null
    }
    catch {
        $protectedActionError = $_.Exception.Message
    }
    $protectedActionAudit = @()
    if (Test-Path -LiteralPath $auditLogPath -PathType Leaf) {
        $protectedActionAudit = @(Get-Content -LiteralPath $auditLogPath -ErrorAction Stop |
            ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop } |
            Where-Object {
                $_.Action -eq 'DisableUser' -and
                $_.Status -eq 'Failed' -and
                $_.Message -like '*Refusing action*protected account*'
            })
    }
    $enabledAfterProtectedCheck = (Get-ADUser @adContext -Identity $builtInAdministrator `
        -Properties Enabled -ErrorAction Stop).Enabled
    if ($protectedActionError -notmatch 'Refusing action.*protected account' -or
        $protectedActionAudit.Count -eq 0 -or
        [bool]$enabledAfterProtectedCheck -ne $enabledBeforeProtectedCheck) {
        throw 'Real-AD protected-account check did not refuse and audit the built-in Administrator without changing its enabled state.'
    }

    & $provisioningScript `
        -AccountCount 1 `
        -OrganizationalUnitName $CompanyOuName `
        -StaffNamesOrganizationalUnitName 'Staff' `
        -Departments @($departmentName) `
        -AdministratorUsername $administratorUsername `
        -Password $Password `
        -CreateDepartmentAdministrators `
        -ReportPath $reportPath `
        -AuditLogPath $auditLogPath `
        -RollbackCreatedResourcesOnFailure `
        -Server $Server `
        -Credential $Credential `
        -CorrelationId $runId `
        -Confirm:$false | Out-Null

    $runEntries = @(Get-ADAutoXLedger | Where-Object {
        $_.RunId -ceq $runId -and $_.CreatedByThisRun
    })
    $runTypes = @($runEntries | Select-Object -ExpandProperty ObjectType -Unique)
    foreach ($requiredType in @('OU', 'Group', 'User', 'Delegation')) {
        if ($requiredType -notin $runTypes) {
            throw "Provisioning did not create a run-scoped '$requiredType' ledger entry; found types: $($runTypes -join ', ')."
        }
    }

    $rollback = Invoke-ADAutoXLedgerRollback `
        -AllowedRoot $domain.DistinguishedName `
        -RunId $runId `
        -LogPath $rollbackLogPath `
        -AllowDestructiveOperation `
        -Server $Server `
        -Credential $Credential `
        -Confirm:$false
    if (-not $rollback.RolledBack -or $rollback.FailedCount -gt 0 -or
        $rollback.RemovedCount -ne $runEntries.Count) {
        throw "Rollback did not report complete success. Removed=$($rollback.RemovedCount), expected=$($runEntries.Count), failed=$($rollback.FailedCount)."
    }

    foreach ($entry in $runEntries) {
        if ($entry.ObjectType -eq 'Delegation') {
            continue
        }

        $remainingObject = Get-ADObject @adContext -Identity $entry.DistinguishedName `
            -ErrorAction SilentlyContinue
        if ($remainingObject) {
            throw "$($entry.ObjectType) '$($entry.DistinguishedName)' still exists after rollback."
        }
    }

    $remainingLedgerEntries = @(Get-ADAutoXLedger | Where-Object RunId -ceq $runId)
    if ($remainingLedgerEntries.Count -gt 0) {
        throw "$($remainingLedgerEntries.Count) run-scoped ledger entries remain after rollback."
    }

    $rollbackSucceeded = $true
    [pscustomobject]@{
        Domain = $domain.DNSRoot
        Server = $Server
        CompanyOuName = $CompanyOuName
        Department = $departmentName
        ProvisionedEntryCount = $runEntries.Count
        RolledBackEntryCount = $rollback.RemovedCount
        FailedCount = $rollback.FailedCount
        VerifiedNoTrackedResourcesRemain = $true
        Status = 'Passed'
    }
}
catch {
    $testError = $_
    $remainingRunEntries = @(Get-ADAutoXLedger | Where-Object {
        $_.RunId -ceq $runId -and $_.CreatedByThisRun
    })
    if ($remainingRunEntries.Count -gt 0) {
        try {
            $cleanupResult = Invoke-ADAutoXLedgerRollback `
                -AllowedRoot $domain.DistinguishedName `
                -RunId $runId `
                -LogPath $rollbackLogPath `
                -AllowDestructiveOperation `
                -Server $Server `
                -Credential $Credential `
                -Confirm:$false
            if (-not $cleanupResult.RolledBack -or $cleanupResult.FailedCount -gt 0) {
                Write-Warning "Automatic cleanup was incomplete. Inspect the remaining run-scoped entries and logs in '$tempDirectory'."
            }
        }
        catch {
            Write-Warning "Automatic cleanup failed: $($_.Exception.Message). Inspect the remaining run-scoped entries and logs in '$tempDirectory'."
        }
    }
    throw $testError
}
finally {
    if ($rollbackSucceeded) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction Stop
    }
    else {
        Write-Warning "Integration-test logs retained at '$tempDirectory'."
    }
}
