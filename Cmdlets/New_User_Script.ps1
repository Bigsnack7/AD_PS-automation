<#
.SYNOPSIS
    Creates a single Active Directory user in a target OU.

.DESCRIPTION
    Creates one user with the supplied identity and optional department, title, description,
    and password settings. The script validates the module dependency chain, logs operations,
    and verifies the resulting user object before reporting success.

    Pre-flight checks reject a SamAccountName or UPN that already exists. If post-create
    verification fails, the account HAS been created; the error says so and the account
    needs manual review (the script never deletes accounts on its own).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][ValidatePattern('\S')][string]$GivenName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][ValidatePattern('\S')][string]$Surname,
    # \z (not $) so a trailing newline cannot slip through; AD forbids a trailing period.
    [Parameter(Mandatory)][ValidateLength(1,20)][ValidatePattern('^(?!.*\.\z)[A-Za-z0-9._$-]+\z')][string]$SamAccountName,
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

$scriptDirectory = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
if ([string]::IsNullOrEmpty($scriptDirectory) -and $MyInvocation.MyCommand.Path) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrEmpty($scriptDirectory)) {
    throw 'Cannot determine the script directory. Run this file from disk, not pasted into a console.'
}

# Resolve a relative audit path against the caller's location before any AD context
# (which may mount an AD: drive) is established.
if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}
else {
    $AuditLogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AuditLogPath)
}

$operationsModule = Join-Path $scriptDirectory 'Modules\AD-Operations.psm1'

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

# Cheap input checks before touching AD.
$displayName = ("$GivenName $Surname").Trim()
if ($displayName.Length -gt 64) {
    throw "The name '$displayName' is $($displayName.Length) characters; Active Directory limits it to 64."
}
if ($UserPrincipalName -and $UserPrincipalName -notmatch '^[^@\s]+@[^@\s]+\z') {
    throw "UserPrincipalName '$UserPrincipalName' is not in the form user@suffix."
}

Import-Module $operationsModule -Force
Assert-ADOperationsDependencies
Import-ADTools

try {
    Set-ADToolContext -Server $Server -Credential $Credential
    $adContext = Get-ADToolContextParameters

    # Only a real run prompts. An empty SecureString is a non-null object, so test its
    # length explicitly. No placeholder password is ever invented for previews.
    if (-not $Password -and -not $WhatIfPreference) {
        $Password = Read-Host 'Initial password' -AsSecureString
    }
    if (-not $WhatIfPreference -and (-not $Password -or $Password.Length -eq 0)) {
        throw 'An initial password is required (supply -Password or enter one at the prompt).'
    }

    # Pass -Server/-Credential only when actually supplied, rather than empty/null values.
    $targetOuArguments = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $targetOuArguments['Server'] = $Server }
    if ($Credential) { $targetOuArguments['Credential'] = $Credential }
    $targetOu = Get-TargetOU $Path @targetOuArguments
    $targetOuDistinguishedName = $targetOu.DistinguishedName

    if (-not $UserPrincipalName) {
        $UserPrincipalName = "$SamAccountName@$((Get-ADDomain @adContext).DNSRoot)"
    }

    # Fail early with a clear message instead of an obscure AD error mid-create.
    $safeSam = ConvertTo-LdapFilterValue $SamAccountName
    $safeUpn = ConvertTo-LdapFilterValue $UserPrincipalName
    $existing = @(Get-ADUser @adContext -LDAPFilter "(|(sAMAccountName=$safeSam)(userPrincipalName=$safeUpn))" -ErrorAction Stop)
    if ($existing.Count -gt 0) {
        throw "A user with SamAccountName '$SamAccountName' or UPN '$UserPrincipalName' already exists ($($existing[0].DistinguishedName))."
    }

    # The expected Enabled state depends on -Disabled; compute once and verify against it.
    $expectedEnabled = -not $Disabled.IsPresent

    $params = @{
        GivenName             = $GivenName
        Surname               = $Surname
        SamAccountName        = $SamAccountName
        UserPrincipalName     = $UserPrincipalName
        Name                  = $displayName
        DisplayName           = $displayName
        Path                  = $targetOuDistinguishedName
        Enabled               = $expectedEnabled
        ChangePasswordAtLogon = (-not $NoChangePasswordAtLogon.IsPresent)
        PassThru              = $true
        ErrorAction           = 'Stop'
    }
    if ($Password) { $params['AccountPassword'] = $Password }

    # Skip empty/whitespace values: AD rejects or ignores them, and verification would
    # then compare $null against '' and report a false failure.
    $verifyAttributes = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'Department', 'Title', 'Description') {
        $value = $PSBoundParameters[$name]
        if ($PSBoundParameters.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($value)) {
            $params[$name] = $value
            $verifyAttributes.Add($name)
        }
    }

    if ($PSCmdlet.ShouldProcess($SamAccountName, 'Create Active Directory user')) {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Started' -Details "Creating user '$SamAccountName' in OU '$targetOuDistinguishedName'."
        $createdUser = New-ADUser @adContext @params

        # Verify by ObjectGUID: -Identity with a SamAccountName that looks like a SID or
        # DN could otherwise resolve a different object.
        $verifiedUser = Get-ADUser @adContext -Identity $createdUser.ObjectGUID -Properties Enabled, UserPrincipalName, Department, Title, Description, DistinguishedName -ErrorAction Stop
        $verificationIssues = [System.Collections.Generic.List[string]]::new()

        if ($verifiedUser.Enabled -ne $expectedEnabled) {
            $verificationIssues.Add("the account Enabled state is '$($verifiedUser.Enabled)' rather than the expected '$expectedEnabled'.")
        }
        if ($verifiedUser.UserPrincipalName -ne $UserPrincipalName) {
            $verificationIssues.Add("the UPN is '$($verifiedUser.UserPrincipalName)' rather than '$UserPrincipalName'.")
        }
        foreach ($name in $verifyAttributes) {
            if ($verifiedUser.$name -ne $params[$name]) {
                $verificationIssues.Add("the $name is '$($verifiedUser.$name)' rather than '$($params[$name])'.")
            }
        }

        if ($verificationIssues.Count -gt 0) {
            throw "Create verification failed for '$SamAccountName': $($verificationIssues -join ' ') The account WAS created ($($verifiedUser.DistinguishedName)) and needs manual review."
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Succeeded' -Details "Created and verified user '$SamAccountName' in OU '$targetOuDistinguishedName'."
        Write-Host "Created $SamAccountName" -ForegroundColor Green
    }
    else {
        $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
        $details = if ($WhatIfPreference) {
            "Preview only: would create user '$SamAccountName' in OU '$targetOuDistinguishedName'."
        }
        else {
            "Creation of user '$SamAccountName' in OU '$targetOuDistinguishedName' was declined."
        }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status $status -Details $details
    }
}
catch {
    $originalError = $_
    try {
        Write-ADAuditRecord -Path $AuditLogPath -Action 'CreateUser' -Target $SamAccountName -TargetType 'User' -Status 'Failed' -Message $originalError.Exception.Message -Details "Failed to create user '$SamAccountName' in OU '$Path'."
    }
    catch {
        # Never let an audit-write failure mask the real error.
        Write-Warning "Could not write the failure audit record: $($_.Exception.Message)"
    }
    throw $originalError
}
finally {
    try {
        Clear-ADToolContext
    }
    catch {
        # A cleanup failure must not replace the original exception.
        Write-Warning "Clear-ADToolContext failed: $($_.Exception.Message)"
    }
}
