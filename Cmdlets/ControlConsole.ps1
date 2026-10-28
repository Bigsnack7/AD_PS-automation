[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop

function Read-PositiveCount {
    param([string]$Prompt, [int]$DefaultValue)
    $value = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($value)) { return $DefaultValue }
    $count = 0
    if (-not [int]::TryParse($value, [ref]$count) -or $count -lt 1) {
        throw 'Enter a positive whole number.'
    }
    return $count
}

while ($true) {
    Clear-Host
    Write-Host '====================================================================' -ForegroundColor Cyan
    Write-Host '          ADAutoX Active Directory Administration Console' -ForegroundColor Cyan
    Write-Host '====================================================================' -ForegroundColor Cyan
    Write-Host ' 1. Preview provisioning'
    Write-Host ' 2. Run provisioning'
    Write-Host ' 3. View/filter audit records'
    Write-Host ' 4. Run security posture scan'
    Write-Host ' 5. Manage a user account'
    Write-Host ' 6. Preview or reset the lab OU'
    Write-Host ' 7. Run offline regression tests'
    Write-Host ' 8. Exit'
    Write-Host '====================================================================' -ForegroundColor Cyan
    $choice = Read-Host 'Select an option [1-8]'

    try {
        switch ($choice) {
            '1' {
                $count = Read-PositiveCount -Prompt 'Accounts to preview (default 5)' -DefaultValue 5
                & (Join-Path $rootDirectory 'Cmdlets\Invoke-ADAutoXProvision.ps1') -AccountCount $count -PasswordPattern 'Preview-{0}-Strong!' -WhatIf
            }
            '2' {
                $count = Read-PositiveCount -Prompt 'Accounts to provision (default 10)' -DefaultValue 10
                $password = Read-Host 'Shared test-account password' -AsSecureString
                if ($password.Length -eq 0) { throw 'A non-empty password is required.' }
                & (Join-Path $rootDirectory 'Cmdlets\Invoke-ADAutoXProvision.ps1') -AccountCount $count -Password $password
            }
            '3' {
                & (Join-Path $rootDirectory 'Cmdlets\Get-ADAutoXAuditReport.ps1')
            }
            '4' {
                Get-ADAutoXSecurityScan
            }
            '5' {
                $identity = Read-Host 'Target SamAccountName or distinguished name'
                $action = Read-Host 'Action (Enable, Disable, Unlock, ResetPassword, Move, Terminate)'
                if ([string]::IsNullOrWhiteSpace($identity) -or
                    $action -notin @('Enable', 'Disable', 'Unlock', 'ResetPassword', 'Move', 'Terminate')) {
                    throw 'A valid identity and supported action are required.'
                }
                $arguments = @{ Identity = $identity; Action = $action }
                if ($action -in @('Disable', 'Terminate')) {
                    if ((Read-Host "Type ALLOW to approve the destructive '$action' action") -cne 'ALLOW') {
                        Write-Host 'Action cancelled.' -ForegroundColor Yellow
                        break
                    }
                    $arguments.AllowDestructiveOperation = $true
                }
                if ($action -in @('Move', 'Terminate')) {
                    $targetOU = Read-Host 'Target OU distinguished name (blank to skip moving for termination)'
                    if ($action -eq 'Move' -and [string]::IsNullOrWhiteSpace($targetOU)) {
                        throw 'Move requires a target OU distinguished name.'
                    }
                    if ($targetOU) { $arguments.TargetOU = $targetOU }
                }
                if ($action -eq 'Terminate') {
                    $reason = Read-Host 'Termination reason (blank uses "Terminated")'
                    if ($reason) { $arguments.Reason = $reason }
                }
                & (Join-Path $rootDirectory 'Cmdlets\Manage-ADAutoXUser.ps1') @arguments
            }
            '6' {
                $companyOU = Read-Host 'Company OU name (default Company)'
                if ([string]::IsNullOrWhiteSpace($companyOU)) { $companyOU = 'Company' }
                & (Join-Path $rootDirectory 'Cmdlets\Reset-ADAutoXEnvironment.ps1') -CompanyOuName $companyOU -WhatIf
                $expectedDN = Read-Host 'Exact OU distinguished name shown in preview (blank cancels)'
                if ([string]::IsNullOrWhiteSpace($expectedDN)) { break }
                if ((Read-Host 'Type DELETE to confirm the lab OU reset') -cne 'DELETE') {
                    Write-Host 'Reset cancelled.' -ForegroundColor Yellow
                    break
                }
                & (Join-Path $rootDirectory 'Cmdlets\Reset-ADAutoXEnvironment.ps1') `
                    -CompanyOuName $companyOU -ExpectedDistinguishedName $expectedDN -AllowDestructiveOperation
            }
            '7' {
                & (Join-Path $rootDirectory 'Tests\Run-OfflineTests.ps1')
            }
            '8' { return }
            default { Write-Host 'Choose a number from 1 through 8.' -ForegroundColor Yellow }
        }
    }
    catch {
        Write-Host "Operation failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($choice -ne '8') { [void](Read-Host 'Press Enter to return to the menu') }
}
