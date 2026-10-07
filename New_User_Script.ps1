<#
.SYNOPSIS
    Creates a single Active Directory user in a target OU.

.DESCRIPTION
    Creates one user with the supplied identity and optional department, title, description,
    and password settings. The script validates the module dependency chain, logs operations,
    and verifies the resulting user object before reporting success.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GivenName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Surname,
    [Parameter(Mandatory)][ValidateLength(1,20)][ValidatePattern('^[A-Za-z0-9._$-]+$')][string]$SamAccountName,
    [string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$Path,
    [SecureString]$Password,
    [string]$Department,
    [string]$Title,
    [string]$Description,
    [switch]$Disabled,
    [switch]$NoChangePasswordAtLogon,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}

$operationsModule = Join-Path $scriptDirectory 'AD-Operations.psm1'

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

Import-Module $operationsModule -Force
Assert-ADOperationsDependencies
Import-ADTools
Set-ADToolContext -Server $Server -Credential $Credential
$adContext = Get-ADToolContextParameters
if (-not $Password -and -not $WhatIfPreference) { $Password = Read-Host 'Initial password' -AsSecureString }
if (-not $Password) { $Password = ConvertTo-SecureString 'PreviewOnly-Not-Used-1!' -AsPlainText -Force }
Get-TargetOU $Path -Server $Server -Credential $Credential | Out-Null
if (-not $UserPrincipalName) { $UserPrincipalName = "$SamAccountName@$((Get-ADDomain @adContext).DNSRoot)" }

# BUGFIX: the expected Enabled state depends on -Disabled, so compute it once and verify
# against it rather than hardcoding "must be enabled" below.
$expectedEnabled = -not $Disabled.IsPresent

$params = @{
    GivenName = $GivenName
    Surname = $Surname
    SamAccountName = $SamAccountName
    UserPrincipalName = $UserPrincipalName
    Name = "$GivenName $Surname"
    DisplayName = "$GivenName $Surname"
    Path = $Path
    AccountPassword = $Password
    Enabled = $expectedEnabled
    ChangePasswordAtLogon = (-not $NoChangePasswordAtLogon.IsPresent)
    ErrorAction = 'Stop'
}
foreach ($name in 'Department','Title','Description') { if ($PSBoundParameters.ContainsKey($name)) { $params[$name]=$PSBoundParameters[$name] } }
Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Started' -Details "Creating user '$SamAccountName' in OU '$Path'."
if ($PSCmdlet.ShouldProcess($SamAccountName,'Create Active Directory user')) {
    try {
        New-ADUser @adContext @params

        $verifiedUser = Get-ADUser @adContext -Identity $SamAccountName -Properties Enabled,UserPrincipalName,Department,Title,Description,DistinguishedName -ErrorAction Stop
        $verificationIssues = [System.Collections.Generic.List[string]]::new()

        # BUGFIX: this used to unconditionally require $verifiedUser.Enabled -eq $true, so
        # every call made with -Disabled (i.e. every account intentionally created disabled)
        # failed verification and threw, even though New-ADUser had done exactly what was
        # asked. Compare against the expected state instead of assuming "enabled" is always
        # correct.
        if ($verifiedUser.Enabled -ne $expectedEnabled) {
            $verificationIssues.Add("the account Enabled state is '$($verifiedUser.Enabled)' rather than the expected '$expectedEnabled'.")
        }
        if ($verifiedUser.UserPrincipalName -ne $UserPrincipalName) {
            $verificationIssues.Add("the UPN is '$($verifiedUser.UserPrincipalName)' rather than '$UserPrincipalName'.")
        }
        if ($PSBoundParameters.ContainsKey('Department') -and $verifiedUser.Department -ne $Department) {
            $verificationIssues.Add("the Department is '$($verifiedUser.Department)' rather than '$Department'.")
        }
        if ($PSBoundParameters.ContainsKey('Title') -and $verifiedUser.Title -ne $Title) {
            $verificationIssues.Add("the Title is '$($verifiedUser.Title)' rather than '$Title'.")
        }
        if ($PSBoundParameters.ContainsKey('Description') -and $verifiedUser.Description -ne $Description) {
            $verificationIssues.Add("the Description is '$($verifiedUser.Description)' rather than '$Description'.")
        }

        if ($verificationIssues.Count -gt 0) {
            throw "Create verification failed for '$SamAccountName': $($verificationIssues -join ' ' )"
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Succeeded' -Details "Created and verified user '$SamAccountName' in OU '$Path'."
        Write-Host "Created $SamAccountName" -ForegroundColor Green
    }
    catch {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to create user '$SamAccountName' in OU '$Path'."
        throw
    }
}
else { Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Preview' -Details "Preview only: would create user '$SamAccountName' in OU '$Path'." }