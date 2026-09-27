Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Validate-ADProvisioningInput {
    param(
        [string[]]$Departments,
        [string]$OrganizationalUnitName = 'Company',
        [string]$StaffNamesOrganizationalUnitName = 'Staff',
        [string]$NamesPath = '',
        [string]$ReportPath = '',
        [string]$AuditLogPath = '',
        [int]$AccountCount = 20
    )

    if ($null -eq $Departments) { throw 'Departments cannot be null.' }
    if ($Departments.Count -eq 0) { throw 'At least one department is required.' }

    $validated = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($department in $Departments) {
        if ($null -eq $department) { throw 'Department names cannot be null.' }

        $trimmed = $department.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { throw 'Department names cannot be blank or whitespace-only.' }
        if ($trimmed.Length -ne $department.Length) { throw "Department name '$department' contains leading or trailing whitespace." }
        # BUGFIX: original pattern only rejected DN-special characters (,+=<>;"\) but allowed
        # '*', '(', ')' and NUL through untouched, which is exactly what an LDAP filter needs
        # escaped (see Escape-LdapFilterValue below). Reject them here too so department names
        # can never be used to break out of either a DN or an LDAP filter.
        if ($trimmed -match '[,+=<>;"\\*()\x00]') { throw "Department name '$trimmed' contains invalid OU/LDAP characters." }
        if (-not $seen.Add($trimmed)) { throw "Duplicate department name '$trimmed' was provided." }

        $validated.Add($trimmed)
    }

    if ([string]::IsNullOrWhiteSpace($OrganizationalUnitName)) { throw 'OrganizationalUnitName cannot be blank.' }
    if ([string]::IsNullOrWhiteSpace($StaffNamesOrganizationalUnitName)) { throw 'StaffNamesOrganizationalUnitName cannot be blank.' }
    if ($AccountCount -lt 0) { throw 'AccountCount cannot be negative.' }

    if (-not [string]::IsNullOrWhiteSpace($NamesPath) -and -not (Test-Path -LiteralPath $NamesPath -PathType Leaf)) {
        throw "Names file not found: $NamesPath"
    }

    if (-not [string]::IsNullOrWhiteSpace($ReportPath) -and -not (Test-Path -LiteralPath (Split-Path -Parent $ReportPath) -PathType Container)) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $ReportPath) -Force
    }

    # BUGFIX: AuditLogPath's parent directory was never validated/created, unlike ReportPath's.
    # A run pointed at a fresh directory would fail the first time it tried to write the audit
    # log instead of failing fast here or succeeding.
    if (-not [string]::IsNullOrWhiteSpace($AuditLogPath) -and -not (Test-Path -LiteralPath (Split-Path -Parent $AuditLogPath) -PathType Container)) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $AuditLogPath) -Force
    }

    return $validated.ToArray()
}

function Escape-LdapFilterValue {
    # BUGFIX (new helper): New-DepartmentGroups was escaping group names for an LDAP filter
    # using [Regex]::Escape, which escapes regex metacharacters (., $, ^, ?, ...) and does
    # NOT escape the characters that are actually special in an LDAP filter: '\', '*', '(',
    # ')' and NUL. That mismatch is an LDAP filter injection bug. Per RFC 4515, escape those
    # four/five characters as \5C \2A \28 \29 \00.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $escaped = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([char]0, '\00')
    return $escaped
}

function Initialize-ADProvisioning {
    [CmdletBinding()]
    param(
        [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),
        [string]$OrganizationalUnitName = 'Company',
        [string]$StaffNamesOrganizationalUnitName = 'Staff',
        [string]$NamesPath = '',
        [string]$ReportPath = '',
        [string]$AuditLogPath = '',
        [string]$PasswordFile = '',
        [switch]$ExportPasswords,
        [switch]$OverwritePasswordFile,
        [string]$AdministratorUsername = '',
        [switch]$CreateDepartmentAdministrators,
        [switch]$AdministratorsOnly,
        [switch]$EnableAccountsAfterVerification,
        [int]$AccountCount = 20,
        [string]$Server,
        [pscredential]$Credential,
        [string]$UPNSuffix,
        [securestring]$Password,
        [string]$PasswordPattern,
        [string]$AdministratorPasswordPattern,
        [switch]$WhatIf
    )

    $scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $resolvedDepartments = @(Validate-ADProvisioningInput -Departments $Departments -OrganizationalUnitName $OrganizationalUnitName -StaffNamesOrganizationalUnitName $StaffNamesOrganizationalUnitName -NamesPath $NamesPath -ReportPath $ReportPath -AuditLogPath $AuditLogPath -AccountCount $AccountCount)

    if ([string]::IsNullOrWhiteSpace($NamesPath)) {
        $NamesPath = Join-Path $scriptDirectory 'nigerian-names.txt'
    }
    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
    }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $ReportPath = Join-Path $scriptDirectory 'AD-Provisioning-Report.csv'
    }

    # BUGFIX: a live (non-WhatIf) run with no -Password supplied used to silently fall back to
    # a hardcoded, publicly-visible plaintext password ('WhatIf-Preview-Password-Not-Used') for
    # every account it created — despite the name saying it's for preview only. Fail fast
    # instead so real accounts are never created with a known password.
    if (-not $WhatIf -and -not $Password) {
        throw 'A -Password (or a working -PasswordPattern) must be supplied for a live run. Refusing to fall back to a default password.'
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
        throw 'The Active Directory PowerShell module is not available or did not load correctly.'
    }

    $operationsModule = Join-Path $scriptDirectory 'AD-Operations.psm1'
    if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
        throw "Required module not found: $operationsModule"
    }

    Import-Module $operationsModule -Force
    Assert-ADOperationsDependencies
    $resolvedServer = Set-ADToolContext -Server $Server -Credential $Credential
    $script:adContext = @{ Server = $resolvedServer }
    if ($Credential) { $script:adContext.Credential = $Credential }
    $aclDriveName = 'ADProvisioning'
    if (Get-PSDrive -Name $aclDriveName -ErrorAction SilentlyContinue) {
        Remove-PSDrive -Name $aclDriveName -Force -ErrorAction Stop
    }
    $aclDriveParameters = @{
        Name = $aclDriveName
        PSProvider = 'ActiveDirectory'
        Root = '//RootDSE/'
        Server = $resolvedServer
    }
    if ($Credential) { $aclDriveParameters.Credential = $Credential }
    $null = New-PSDrive @aclDriveParameters -ErrorAction Stop

    $domain = Get-ADDomain @script:adContext -ErrorAction Stop
    $forest = Get-ADForest @script:adContext -ErrorAction Stop
    $executionContext = [pscustomobject]@{
        Domain = $domain.DNSRoot
        Forest = $forest.Name
        DC = $resolvedServer
        DomainController = $resolvedServer
        User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ExecutionTime = (Get-Date).ToUniversalTime().ToString('o')
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        OS = [System.Environment]::OSVersion.VersionString
    }
    $state = [pscustomobject]@{
        ScriptDirectory = $scriptDirectory
        Departments = $resolvedDepartments
        OrganizationalUnitName = $OrganizationalUnitName
        StaffNamesOrganizationalUnitName = $StaffNamesOrganizationalUnitName
        NamesPath = $NamesPath
        ReportPath = $ReportPath
        AuditLogPath = $AuditLogPath
        PasswordFile = $PasswordFile
        ExportPasswords = [bool]$ExportPasswords
        OverwritePasswordFile = [bool]$OverwritePasswordFile
        AdministratorUsername = $AdministratorUsername
        CreateDepartmentAdministrators = [bool]($CreateDepartmentAdministrators -or (-not [string]::IsNullOrWhiteSpace($AdministratorUsername)))
        AdministratorsOnly = [bool]$AdministratorsOnly
        EnableAccountsAfterVerification = [bool]$EnableAccountsAfterVerification
        AccountCount = $AccountCount
        Server = $resolvedServer
        Credential = $Credential
        ADContext = $script:adContext
        AclDriveName = $aclDriveName
        ExecutionContext = $executionContext
        UPNSuffix = $UPNSuffix
        DomainRoot = $domain.DistinguishedName
        DomainNetBIOSName = $domain.NetBIOSName
        EffectiveUPNSuffix = if ($UPNSuffix) { $UPNSuffix } else { $domain.DNSRoot }
        Password = $Password
        PasswordPattern = $PasswordPattern
        AdministratorPasswordPattern = $AdministratorPasswordPattern
        WhatIf = [bool]$WhatIf
        DepartmentOUs = @{}
        DepartmentUserOUs = @{}
        DepartmentAdministratorOUs = @{}
        DepartmentUserGroups = @{}
        DepartmentAdministratorGroups = @{}
        DepartmentAttributeAdministratorGroups = @{}
        CreatedAccounts = [System.Collections.Generic.List[psobject]]::new()
        ReportRecords = [System.Collections.Generic.List[psobject]]::new()
        PasswordRecords = [System.Collections.Generic.List[psobject]]::new()
    }

    return $state
}

function Test-ADProvisioningPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    $checks = [System.Collections.Generic.List[psobject]]::new()

    function Add-PreflightCheck {
        param(
            [string]$Name,
            [string]$Status,
            [string]$Details = ''
        )
        $checks.Add([pscustomobject]@{
                Name = $Name
                Status = $Status
                Details = $Details
            })
    }

    if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
        Add-PreflightCheck -Name 'AD module' -Status 'Failed' -Details 'Active Directory module not available.'
    }
    else {
        Add-PreflightCheck -Name 'AD module' -Status 'Passed' -Details 'Active Directory module loaded.'
    }

    try {
        $null = Get-ADDomain @script:adContext -ErrorAction Stop
        Add-PreflightCheck -Name 'Domain connectivity' -Status 'Passed' -Details "Domain root resolved to '$($State.DomainRoot)'."
    }
    catch {
        Add-PreflightCheck -Name 'Domain connectivity' -Status 'Failed' -Details $_.Exception.Message
    }

    if (-not [string]::IsNullOrWhiteSpace($State.NamesPath) -and -not (Test-Path -LiteralPath $State.NamesPath -PathType Leaf)) {
        Add-PreflightCheck -Name 'Names file' -Status 'Failed' -Details "Names file not found: $($State.NamesPath)"
    }
    else {
        Add-PreflightCheck -Name 'Names file' -Status 'Passed' -Details "Names file resolved to '$($State.NamesPath)'."
    }

    foreach ($department in $State.Departments) {
        $departmentName = $department.Trim()
        Add-PreflightCheck -Name "Department name: $departmentName" -Status 'Passed' -Details "Validated department '$departmentName'."
    }

    if ($State.CreateDepartmentAdministrators -and -not [string]::IsNullOrWhiteSpace($State.AdministratorUsername) -and $State.Departments.Count -gt 1 -and -not $State.AdministratorUsername.Contains('{0}')) {
        Add-PreflightCheck -Name 'Administrator username template' -Status 'Failed' -Details "When creating department administrators for multiple departments, -AdministratorUsername must include {0}."
    }
    else {
        Add-PreflightCheck -Name 'Administrator username template' -Status 'Passed' -Details 'Administrator naming pattern is valid for the requested department layout.'
    }

    $summary = [pscustomobject]@{
        Passed = (@($checks | Where-Object { $_.Status -eq 'Passed' }).Count -gt 0) -and (@($checks | Where-Object { $_.Status -eq 'Failed' }).Count -eq 0)
        PassedCount = @($checks | Where-Object { $_.Status -eq 'Passed' }).Count
        NeedsAttentionCount = @($checks | Where-Object { $_.Status -eq 'NeedsAttention' }).Count
        FailedCount = @($checks | Where-Object { $_.Status -eq 'Failed' }).Count
        Checks = $checks.ToArray()
    }

    return $summary
}

function Test-ADProvisioningTargetPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    $userClassGuid = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    $createChildRight = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $writePropertyRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
    $genericWriteRight = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
    $genericAllRight = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $checks = [System.Collections.Generic.List[psobject]]::new()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $identitySids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $null = $identitySids.Add($identity.User.Value)
    foreach ($groupSid in $identity.Groups) {
        $null = $identitySids.Add($groupSid.Value)
    }

    foreach ($department in $State.Departments) {
        $targetOu = $State.DepartmentUserOUs[$department]
        $targetPath = "$($State.AclDriveName):\$targetOu"

        try {
            $acl = Get-Acl -Path $targetPath -ErrorAction Stop
            $matchingRules = @($acl.Access | Where-Object {
                    try {
                        $ruleSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        $identitySids.Contains($ruleSid)
                    }
                    catch {
                        $false
                    }
                })

            $relevantRules = @($matchingRules | Where-Object {
                    $_.ObjectType -eq [Guid]::Empty -or $_.ObjectType -eq $userClassGuid
                })
            $denyRules = @($relevantRules | Where-Object {
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                    (($_.ActiveDirectoryRights -band $createChildRight) -ne 0 -or
                     ($_.ActiveDirectoryRights -band $genericAllRight) -ne 0)
                })
            $allowRules = @($relevantRules | Where-Object {
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
                })
            $hasCreateChild = @($allowRules | Where-Object {
                    ($_.ActiveDirectoryRights -band $createChildRight) -ne 0 -or
                    ($_.ActiveDirectoryRights -band $genericAllRight) -ne 0
                }).Count -gt 0
            $hasAttributeWrite = @($allowRules | Where-Object {
                    ($_.ActiveDirectoryRights -band $writePropertyRight) -ne 0 -or
                    ($_.ActiveDirectoryRights -band $genericWriteRight) -ne 0 -or
                    ($_.ActiveDirectoryRights -band $genericAllRight) -ne 0
                }).Count -gt 0

            if ($denyRules.Count -gt 0) {
                $checks.Add([pscustomobject]@{
                        Name = "Create users in $department"
                        Status = 'Failed'
                        Details = "The current identity is explicitly denied user creation on '$targetOu'."
                    })
            }
            elseif (-not $hasCreateChild -or -not $hasAttributeWrite) {
                $missing = [System.Collections.Generic.List[string]]::new()
                if (-not $hasCreateChild) { $missing.Add('CreateChild for user objects') }
                if (-not $hasAttributeWrite) { $missing.Add('user attribute write access') }
                $checks.Add([pscustomobject]@{
                        Name = "Create users in $department"
                        Status = 'Failed'
                        Details = "The current identity does not have a detectable allow rule for $($missing -join ' and ') on '$targetOu'."
                    })
            }
            else {
                $checks.Add([pscustomobject]@{
                        Name = "Create users in $department"
                        Status = 'Passed'
                        Details = "The current identity has detectable user CreateChild and attribute-write permissions on '$targetOu'."
                    })
            }

            if ($State.CreateDepartmentAdministrators) {
                $writeDaclRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                $hasWriteDacl = @($matchingRules | Where-Object {
                        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                        (($_.ActiveDirectoryRights -band $writeDaclRight) -ne 0 -or
                         ($_.ActiveDirectoryRights -band $genericAllRight) -ne 0)
                    }).Count -gt 0
                $hasDaclDeny = @($matchingRules | Where-Object {
                        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                        (($_.ActiveDirectoryRights -band $writeDaclRight) -ne 0 -or
                         ($_.ActiveDirectoryRights -band $genericAllRight) -ne 0)
                    }).Count -gt 0

                if ($hasDaclDeny -or -not $hasWriteDacl) {
                    $details = if ($hasDaclDeny) {
                        "The current identity is denied permission to modify the ACL on '$targetOu'."
                    }
                    else {
                        "The current identity does not have a detectable allow rule for WriteDacl on '$targetOu'."
                    }
                    $checks.Add([pscustomobject]@{
                            Name = "Grant delegation on $department"
                            Status = 'Failed'
                            Details = $details
                        })
                }
                else {
                    $checks.Add([pscustomobject]@{
                            Name = "Grant delegation on $department"
                            Status = 'Passed'
                            Details = "The current identity has detectable WriteDacl permission on '$targetOu'."
                        })
                }
            }
        }
        catch {
            $checks.Add([pscustomobject]@{
                    Name = "Create users in $department"
                    Status = if ($State.WhatIf) { 'NeedsAttention' } else { 'Failed' }
                    Details = if ($State.WhatIf) {
                        "Could not inspect permissions on planned OU '$targetOu' because it does not exist in preview mode. Live execution will inspect it after OU creation."
                    }
                    else {
                        "Could not inspect permissions on '$targetOu': $($_.Exception.Message)"
                    }
                })
        }
    }

    return [pscustomobject]@{
        Passed = (@($checks | Where-Object Status -eq 'Failed').Count -eq 0)
        PassedCount = @($checks | Where-Object Status -eq 'Passed').Count
        FailedCount = @($checks | Where-Object Status -eq 'Failed').Count
        Checks = $checks.ToArray()
    }
}

function Get-ExactADOrganizationalUnit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ParentDistinguishedName
    )

    $expectedDistinguishedName = "OU=$(ConvertTo-DistinguishedNameValue $Name),$ParentDistinguishedName"
    try {
        $ou = Get-ADOrganizationalUnit @script:adContext -Identity $expectedDistinguishedName -ErrorAction Stop
        if (@($ou).Count -ne 1) {
            throw "The expected OU '$expectedDistinguishedName' was not resolved uniquely."
        }
        return $ou
    }
    catch {
        if ($_.Exception.Message -match 'Cannot find|not found|does not exist') {
            return $null
        }
        throw "Unable to resolve expected OU '$expectedDistinguishedName': $($_.Exception.Message)"
    }
}

function New-VerifiedADOrganizationalUnit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ParentDistinguishedName
    )

    $expectedDistinguishedName = "OU=$(ConvertTo-DistinguishedNameValue $Name),$ParentDistinguishedName"
    $existingOu = Get-ExactADOrganizationalUnit -Name $Name -ParentDistinguishedName $ParentDistinguishedName
    if ($existingOu) {
        return [pscustomobject]@{ DistinguishedName = $existingOu.DistinguishedName; Created = $false; Skipped = $true; Verified = $true }
    }

    if ($State.WhatIf) {
        return [pscustomobject]@{ DistinguishedName = $expectedDistinguishedName; Created = $true; Skipped = $false; Verified = $false }
    }

    $null = New-ADOrganizationalUnit @script:adContext -Name $Name -Path $ParentDistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop
    $verifiedOu = Get-ExactADOrganizationalUnit -Name $Name -ParentDistinguishedName $ParentDistinguishedName
    if (-not $verifiedOu) {
        throw "The OU '$expectedDistinguishedName' was created but could not be retrieved from the pinned domain controller '$($script:adContext.Server)'."
    }

    return [pscustomobject]@{ DistinguishedName = $verifiedOu.DistinguishedName; Created = $true; Skipped = $false; Verified = $true }
}

function New-CompanyOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    return New-VerifiedADOrganizationalUnit -State $State -Name $State.OrganizationalUnitName -ParentDistinguishedName $State.DomainRoot
}

function New-DepartmentOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Department,

        [Parameter(Mandatory)]
        [string]$ParentDistinguishedName
    )

    return New-VerifiedADOrganizationalUnit -State $State -Name $Department -ParentDistinguishedName $ParentDistinguishedName
}

function New-DepartmentGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Department,

        [Parameter(Mandatory)]
        [string]$DepartmentOU
    )

    $userGroupName = "${Department}-Users"
    $adminGroupName = "${Department}-Administrators"
    $attributeAdminGroupName = "${Department}-Attribute-Admins"

    # BUGFIX: Regex::Escape does not escape LDAP filter metacharacters (\, *, (, )), so the
    # original code both under-escaped the filter (real injection risk if a department name
    # ever contained those characters) and over-escaped harmless regex-only characters,
    # potentially breaking valid lookups. Use the dedicated LDAP escaper instead.
    $userGroupFilter = "(cn=$(Escape-LdapFilterValue $userGroupName))"
    $adminGroupFilter = "(cn=$(Escape-LdapFilterValue $adminGroupName))"
    $attributeAdminGroupFilter = "(cn=$(Escape-LdapFilterValue $attributeAdminGroupName))"

    # BUGFIX: in -WhatIf/preview mode $DepartmentOU is a distinguished name that does not exist
    # yet (the OU creation above was itself only previewed). Get-ADGroup -SearchBase against a
    # nonexistent DN throws with -ErrorAction Stop, which used to crash the whole preview run.
    # Treat "search base doesn't exist" the same as "group not found yet" while previewing.
    function Find-ExistingGroup {
        param([string]$Filter)
        try {
            return @(Get-ADGroup @script:adContext -LDAPFilter $Filter -SearchBase $DepartmentOU -SearchScope OneLevel -ErrorAction Stop)
        }
        catch {
            if ($State.WhatIf) { return @() }
            throw
        }
    }

    $userGroup = Find-ExistingGroup -Filter $userGroupFilter
    if ($userGroup.Count -eq 0) {
        if (-not $State.WhatIf) {
            $userGroup = @(New-ADGroup @script:adContext -Name $userGroupName -GroupScope Global -GroupCategory Security -Path $DepartmentOU -PassThru)
        }
    }

    $adminGroup = Find-ExistingGroup -Filter $adminGroupFilter
    if ($adminGroup.Count -eq 0) {
        if (-not $State.WhatIf) {
            $adminGroup = @(New-ADGroup @script:adContext -Name $adminGroupName -GroupScope Global -GroupCategory Security -Path $DepartmentOU -PassThru)
        }
    }

    $attributeAdminGroup = Find-ExistingGroup -Filter $attributeAdminGroupFilter
    if ($attributeAdminGroup.Count -eq 0) {
        if (-not $State.WhatIf) {
            $attributeAdminGroup = @(New-ADGroup @script:adContext -Name $attributeAdminGroupName -GroupScope Global -GroupCategory Security -Path $DepartmentOU -PassThru)
        }
    }

    return [pscustomobject]@{
        UserGroup = if ($userGroup.Count -gt 0) { $userGroup[0] } else { $null }
        AdministratorGroup = if ($adminGroup.Count -gt 0) { $adminGroup[0] } else { $null }
        AttributeAdministratorGroup = if ($attributeAdminGroup.Count -gt 0) { $attributeAdminGroup[0] } else { $null }
    }
}

function New-DepartmentUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Department,

        [Parameter(Mandatory)]
        [string]$TargetOuDistinguishedName,

        [Parameter(Mandatory)]
        [string]$Username,

        [string]$PasswordPattern,

        [string]$PasswordToken = ''
    )

    # BUGFIX: previously fell back to the hardcoded plaintext password
    # 'WhatIf-Preview-Password-Not-Used' for REAL account creation whenever $State.Password was
    # unset — Initialize-ADProvisioning now refuses to build state for a live run without a
    # password, so by the time we get here in live mode $State.Password is guaranteed to be
    # set. WhatIf mode still uses a clearly-labelled dummy value since no account is created.
    $password = if ($State.Password) { $State.Password } else { (ConvertTo-SecureString 'WhatIf-Preview-Password-Not-Used' -AsPlainText -Force) }

    if (-not $State.WhatIf) {
        $createdUser = New-ADUser @script:adContext -SamAccountName $Username -UserPrincipalName "$Username@$($State.EffectiveUPNSuffix)" -AccountPassword $password -GivenName $Department -Surname 'User' -DisplayName "$Department User" -Name $Username -Department $Department -Path $TargetOuDistinguishedName -Enabled (-not $State.EnableAccountsAfterVerification) -PassThru -ErrorAction Stop
        return [pscustomobject]@{ User = $createdUser; Created = $true }
    }

    return [pscustomobject]@{ User = [pscustomobject]@{ SamAccountName = $Username; DistinguishedName = "CN=$Username,$TargetOuDistinguishedName" }; Created = $true }
}

function Enable-VerifiedDepartmentAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [psobject]$Account,

        [Parameter(Mandatory)]
        [string]$Department
    )

    if (-not $State.EnableAccountsAfterVerification) {
        return [pscustomobject]@{ Status = 'NotRequired'; SamAccountName = $Account.SamAccountName }
    }

    if ($State.WhatIf) {
        return [pscustomobject]@{ Status = 'Preview'; SamAccountName = $Account.SamAccountName }
    }

    $verifiedAccount = Get-ADUser @script:adContext -Identity $Account.DistinguishedName -Properties Enabled,Department,UserPrincipalName -ErrorAction Stop
    if (-not $verifiedAccount -or $verifiedAccount.Department -ne $Department) {
        throw "Account '$($Account.SamAccountName)' failed verification and will remain disabled."
    }

    Set-ADUser @script:adContext -Identity $verifiedAccount -Enabled $true -ErrorAction Stop
    $enabledAccount = Get-ADUser @script:adContext -Identity $Account.DistinguishedName -Properties Enabled -ErrorAction Stop
    if (-not $enabledAccount.Enabled) {
        throw "Account '$($Account.SamAccountName)' could not be verified as enabled and may require manual review."
    }

    return [pscustomobject]@{ Status = 'Enabled'; SamAccountName = $Account.SamAccountName }
}

function New-DepartmentAdministrator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Department,

        [Parameter(Mandatory)]
        [string]$TargetOuDistinguishedName,

        [Parameter(Mandatory)]
        [string]$Username,

        [string]$PasswordPattern,

        [string]$PasswordToken = ''
    )

    # BUGFIX: same demo-password fallback issue as New-DepartmentUser; see notes there.
    $password = if ($State.Password) { $State.Password } else { (ConvertTo-SecureString 'WhatIf-Preview-Password-Not-Used' -AsPlainText -Force) }

    if (-not $State.WhatIf) {
        $createdAdmin = New-ADUser @script:adContext -SamAccountName $Username -UserPrincipalName "$Username@$($State.EffectiveUPNSuffix)" -AccountPassword $password -GivenName ($Department.ToUpperInvariant() + 'Admin') -Surname 'Administrator' -DisplayName "$Department Administrator" -Name $Username -Department $Department -Path $TargetOuDistinguishedName -Enabled (-not $State.EnableAccountsAfterVerification) -PassThru -ErrorAction Stop
        return [pscustomobject]@{ User = $createdAdmin; Created = $true }
    }

    return [pscustomobject]@{ User = [pscustomobject]@{ SamAccountName = $Username; DistinguishedName = "CN=$Username,$TargetOuDistinguishedName" }; Created = $true }
}

function Set-DepartmentDelegation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [string]$TargetOuDistinguishedName,

        [string]$DomainNetBIOSName = ''
    )

    $groupIdentityValue = if ($DomainNetBIOSName) { "$DomainNetBIOSName\$GroupName" } else { $GroupName }
    # BUGFIX: an identical NTAccount object used to be built twice under two different variable
    # names ($groupIdentity here, $identity further down) — the first was computed and never
    # used. Build it once and reuse it.
    $groupIdentity = [System.Security.Principal.NTAccount]::new($groupIdentityValue)
    $ouPath = "$($State.AclDriveName):\$TargetOuDistinguishedName"

    $userClassGuid = [System.Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    $managedAccessRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    if ($State.WhatIf) {
        return [pscustomobject]@{ GroupName = $GroupName; TargetOuDistinguishedName = $TargetOuDistinguishedName; Status = 'Preview' }
    }

    $acl = Get-Acl -Path $ouPath
    $groupAllowRules = @(
        $acl.Access | Where-Object {
            $_.IdentityReference.Value -ieq $groupIdentityValue -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
        }
    )

    $alreadyGranted = $groupAllowRules | Where-Object {
        $_.ObjectType -eq $userClassGuid -and
        $_.InheritedObjectType -eq $userClassGuid -and
        $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents -and
        ($_.ActiveDirectoryRights -band $managedAccessRights) -eq $managedAccessRights
    }

    if ($alreadyGranted) {
        return [pscustomobject]@{ GroupName = $GroupName; TargetOuDistinguishedName = $TargetOuDistinguishedName; Status = 'AlreadyPresent' }
    }

    $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($groupIdentity, $managedAccessRights, 'Allow', $userClassGuid, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents, $userClassGuid)
    $acl.AddAccessRule($accessRule)
    Set-Acl -Path $ouPath -AclObject $acl

    return [pscustomobject]@{ GroupName = $GroupName; TargetOuDistinguishedName = $TargetOuDistinguishedName; Status = 'Granted' }
}

function Test-DepartmentProvisioning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [Parameter(Mandatory)]
        [string]$Department,

        [string]$ExpectedUserPrincipalName = ''
    )

    $result = [pscustomobject]@{
        Department = $Department
        Passed = $true
        Messages = [System.Collections.Generic.List[string]]::new()
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedUserPrincipalName)) {
        try {
            $user = Get-ADUser @script:adContext -Identity $ExpectedUserPrincipalName -Properties UserPrincipalName -ErrorAction Stop
            if (-not $user) { $result.Passed = $false; $result.Messages.Add("User '$ExpectedUserPrincipalName' was not found.") }
        }
        catch {
            $result.Passed = $false
            $result.Messages.Add($_.Exception.Message)
        }
    }

    return $result
}

function Export-ProvisioningReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State,

        [string]$OutputPath = ''
    )

    $targetPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) { $State.ReportPath } else { $OutputPath }
    if ($State.WhatIf) {
        return [pscustomobject]@{ OutputPath = $targetPath; Written = $false; Preview = $true }
    }

    $reportDirectory = Split-Path -Parent $targetPath
    if (-not [string]::IsNullOrWhiteSpace($reportDirectory) -and -not (Test-Path -LiteralPath $reportDirectory)) {
        $null = New-Item -ItemType Directory -Path $reportDirectory -Force
    }

    $orderedRecords = foreach ($record in $State.ReportRecords) {
        [pscustomobject]@{
            Domain = $State.ExecutionContext.Domain
            Forest = $State.ExecutionContext.Forest
            DC = $State.ExecutionContext.DC
            DomainController = $State.ExecutionContext.DomainController
            User = $State.ExecutionContext.User
            ExecutionTime = $State.ExecutionContext.ExecutionTime
            PowerShellVersion = $State.ExecutionContext.PowerShellVersion
            OS = $State.ExecutionContext.OS
            Username = if ($record.PSObject.Properties.Name -contains 'Username') { $record.Username } else { '' }
            Department = if ($record.PSObject.Properties.Name -contains 'Department') { $record.Department } else { '' }
            Role = if ($record.PSObject.Properties.Name -contains 'Role') { $record.Role } else { '' }
            OU = if ($record.PSObject.Properties.Name -contains 'OU') { $record.OU } else { '' }
            Status = if ($record.PSObject.Properties.Name -contains 'Status') { $record.Status } else { '' }
            Stage = if ($record.PSObject.Properties.Name -contains 'Stage') { $record.Stage } else { '' }
            CreatedAt = if ($record.PSObject.Properties.Name -contains 'CreatedAt') { $record.CreatedAt } else { '' }
            ErrorCategory = if ($record.PSObject.Properties.Name -contains 'ErrorCategory') { $record.ErrorCategory } else { '' }
            Error = if ($record.PSObject.Properties.Name -contains 'Error') { $record.Error } else { '' }
        }
    }

    if ($orderedRecords.Count -gt 0) {
        $orderedRecords | Export-Csv -LiteralPath $targetPath -NoTypeInformation -Force
    }
    else {
        $header = 'Domain,Forest,DC,DomainController,User,ExecutionTime,PowerShellVersion,OS,Username,Department,Role,OU,Status,Stage,CreatedAt,ErrorCategory,Error'
        $header | Set-Content -LiteralPath $targetPath -Force
    }

    return [pscustomobject]@{ OutputPath = $targetPath; Written = $true; Preview = $false }
}

function Invoke-ProvisioningRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$State
    )

    foreach ($createdAccount in $State.CreatedAccounts) {
        try {
            Remove-ADUser @script:adContext -Identity $createdAccount.DistinguishedName -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to roll back account '$($createdAccount.SamAccountName)': $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{ RolledBack = $true; AccountsRemoved = $State.CreatedAccounts.Count }
}

Export-ModuleMember -Function 'Initialize-ADProvisioning', 'Test-ADProvisioningPreflight', 'Test-ADProvisioningTargetPermissions', 'New-CompanyOU', 'New-DepartmentOU', 'New-DepartmentGroups', 'New-DepartmentUser', 'New-DepartmentAdministrator', 'Enable-VerifiedDepartmentAccount', 'Set-DepartmentDelegation', 'Test-DepartmentProvisioning', 'Export-ProvisioningReport', 'Invoke-ProvisioningRollback'