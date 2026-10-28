<#
.SYNOPSIS
    Creates uniquely named test users and department administrators in Active Directory OUs.

.DESCRIPTION
        Provisions a lab or test environment by creating department-specific OUs, security groups, and
        user accounts. Department administrator accounts and their OUs are enabled by default; pass
        -CreateDepartmentAdministrators:$false to opt out. The script is designed to be
    repeatable and auditable, with explicit safeguards for preview mode, dependency validation,
    audit logging, and controlled cleanup behavior.

    This script intentionally does not add a custom `-DryRun` switch. Preview behavior is handled by
    PowerShell's native `-WhatIf` support through `SupportsShouldProcess`, which keeps the command
    consistent with standard PowerShell semantics and avoids a second, redundant preview mechanism.

    The script now follows an explicit four-phase execution model:
    Phase 1 = Preflight (non-mutating validation and collision checks),
    Phase 2 = Provision (create OUs, groups, users, membership, and delegation),
    Phase 3 = Verify (post-create validation of state and attributes),
    Phase 4 = Report (CSV, JSONL audit, and console summary output).

.EXAMPLE
    .\Cmdlets\mark42.ps1 -AccountCount 100 -WhatIf

.EXAMPLE
    .\Cmdlets\mark42.ps1 -AccountCount 100 -OrganizationalUnitName 'Company'

.EXAMPLE
    .\Cmdlets\mark42.ps1 -AccountCount 100 -EnableAccountsAfterVerification

.PARAMETER AccountCount
    Number of users to create.
    Use 0 to create one account for every valid name in the names file. If the requested count exceeds
    the number of available valid names, the script automatically reduces the effective count and warns.
    Before creating an account, the script checks the target OU for an existing matching person. Matching
    users and department administrators are reported as skipped, making repeated runs idempotent for
    identities created with the same attributes. Genuine SAM-name collisions for different identities
    still receive a numeric suffix.

.PARAMETER PasswordPattern
    Optional deterministic password pattern for standard department users. When supplied, the script
    resolves the pattern against the username or token value and performs a best-effort preflight
    validation against the domain default password policy plus metadata from any fine-grained password
    policies that exist in the domain. This is a convenience check only; the actual Active Directory
    create operation remains the final authority because account-specific policy assignment, password
    history, password age rules, and external password-filtering mechanisms may still affect the
    effective policy for a specific user. Note that Active Directory complexity rules reject passwords
    that contain the account name, so patterns that embed {0} (the username) may be refused at create time.

.PARAMETER AdministratorPasswordPattern
    Optional deterministic password pattern for department administrators. Like -PasswordPattern,
    this is preflight-validated against the domain default password policy plus available fine-grained
    policy metadata, but the final authorization still happens during the AD create call itself.

.PARAMETER RollbackCreatedAccountsOnFailure
    If enabled, the script performs account rollback only. When an account fails verification or group
    membership, only that account is removed and the batch continues with other users and departments.
    Account creation failures are recorded and also remain isolated to that account. This switch does
    not remove OUs, groups, group memberships, or ACL delegation changes. Unexpected run-level failures
    can still abort the run and roll back all remaining accounts created by this invocation.

.PARAMETER RollbackCreatedResourcesOnFailure
    If enabled, an unexpected run-level failure or credential-export failure removes accounts and groups
    created by this invocation, removes the exact delegation ACEs it added, and removes only empty OUs
    carrying this provisioner's generated-object marker. Non-empty or unmarked OUs are reported and
    left in place; OU removal is never recursive. This is intended for the ADAutoX compatibility API.

.PARAMETER PasswordFile
    Destination path for generated account passwords. This parameter must be used with
    -ExportPasswords; credentials are never persisted by default. If export is explicitly enabled
    and this parameter is omitted, the script uses 'user-passwords.clixml' at the repository root.
    The file is written using Export-Clixml and is protected for the current Windows user context.
    It is not a general-purpose encrypted password vault and must be handled as sensitive material.

.PARAMETER ExportPasswords
    Explicitly enables credential export. Use -PasswordFile to select a destination; otherwise the
    script uses 'user-passwords.clixml' at the repository root. Export is supported on Windows only, uses
    a secured staging file, and refuses to replace an existing destination unless
    -OverwritePasswordFile is also supplied.

.PARAMETER OverwritePasswordFile
    Allows an existing password export file to be overwritten. Use this only when you intentionally want
    to replace the prior export file contents.

.PARAMETER EnableAccountsAfterVerification
    Creates user and administrator accounts disabled, verifies their attributes and group membership,
    then enables each account and verifies the enabled state.

.PARAMETER TreatZeroAccountCountAsNone
    Compatibility option for entry points where -AccountCount 0 means create no standard users.

.PARAMETER IncludePasswordInReport
    Opt-in switch that adds a plaintext Password column to the CSV written to -ReportPath, alongside
    Username and Department, for every account this run actually created. Unlike -PasswordFile (which
    is DPAPI-protected to the current Windows user/machine context via Export-Clixml), the provisioning
    report is a plain CSV. When this switch is used, the script restricts the report file's ACLs
    to the current Windows identity BEFORE any password is written to it, but a CSV can still be opened,
    copied, or emailed by anyone who gets a copy of it. Only enable this when you have a specific,
    time-boxed reason to review passwords next to account metadata in one file, and delete or archive
    the report securely once you are done with it.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateRange(0, 1000)]
    [int]$AccountCount = 20,

    [ValidateNotNullOrEmpty()]
    [string]$OrganizationalUnitName = 'Company',

    [ValidateNotNullOrEmpty()]
    [string]$StaffNamesOrganizationalUnitName = 'Staff',

    [ValidateNotNullOrEmpty()]
    [string]$NamesPath = '',

    [ValidateNotNullOrEmpty()]
    [string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),

    [string]$AdministratorUsername = '',

    [switch]$CreateDepartmentAdministrators,

    [switch]$AdministratorsOnly,

    [AllowNull()]
    [string]$PasswordPattern,

    [string]$AdministratorPasswordPattern,

    [string]$PasswordFile,

    [switch]$ExportPasswords,

    [switch]$OverwritePasswordFile,

    [switch]$IncludePasswordInReport,

    [switch]$EnableAccountsAfterVerification,

    [Parameter(DontShow)]
    [switch]$TreatZeroAccountCountAsNone,

    [Parameter(DontShow)]
    [switch]$DisableDepartmentAdministratorsByDefault,

    [string]$ReportPath = '',

    [Alias('RollbackOnFailure', 'RollbackAccountsOnFailure')]
    [switch]$RollbackCreatedAccountsOnFailure,

    [switch]$RollbackCreatedResourcesOnFailure,

    [SecureString]$Password,

    [string]$Server,

    [ValidateNotNullOrEmpty()]
    [string]$UPNSuffix,

    [PSCredential]$Credential,

    [string]$AuditLogPath = '',

    [string]$CorrelationId = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$CorrelationId = if ([string]::IsNullOrWhiteSpace($CorrelationId)) {
    [Guid]::NewGuid().ToString()
}
else {
    $CorrelationId
}
$script:ProvisioningConfirmSpecified = $PSBoundParameters.ContainsKey('Confirm')
$script:ProvisioningConfirmValue = if ($script:ProvisioningConfirmSpecified) {
    [bool]$PSBoundParameters['Confirm']
}
else {
    $false
}

$scriptDirectory = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$provisioningModule = Join-Path $scriptDirectory 'Modules\AD-Provisioning.psm1'
if (-not (Test-Path -LiteralPath $provisioningModule -PathType Leaf)) {
    throw "Required module not found: $provisioningModule"
}
Import-Module $provisioningModule -Force

# Resolve user-supplied paths against the PowerShell location ONCE. [IO.Path]::GetFullPath uses the
# process working directory, which can differ from (Get-Location), so a relative path could be
# existence-checked in one folder and written to another.
function Resolve-ScriptPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

if ([string]::IsNullOrWhiteSpace($PasswordFile)) {
    if ($ExportPasswords) {
        $PasswordFile = Join-Path -Path $scriptDirectory -ChildPath 'user-passwords.clixml'
    }
}

if ([string]::IsNullOrWhiteSpace($NamesPath)) {
    $NamesPath = Join-Path $scriptDirectory 'Data\sample-names.txt'
}
if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $scriptDirectory 'AD-Provisioning-Report.csv'
}
$PasswordFile = Resolve-ScriptPath $PasswordFile
$NamesPath = Resolve-ScriptPath $NamesPath
$AuditLogPath = Resolve-ScriptPath $AuditLogPath
$ReportPath = Resolve-ScriptPath $ReportPath

if (-not $AdministratorsOnly -and -not ($TreatZeroAccountCountAsNone -and $AccountCount -eq 0) -and
    -not (Test-Path -LiteralPath $NamesPath -PathType Leaf)) {
    throw "Names file not found: $NamesPath"
}

if ($Password -and -not [string]::IsNullOrWhiteSpace($PasswordPattern)) {
    Write-Warning '-Password and -PasswordPattern were both supplied; -Password takes precedence for standard users.'
}

$requestedAccountCount = if ($AdministratorsOnly) { 0 } else { $AccountCount }
$passwordRecords = [System.Collections.Generic.List[psobject]]::new()
$reportRecords = [System.Collections.Generic.List[psobject]]::new()
$createdAccounts = [System.Collections.Generic.List[psobject]]::new()
$script:ProvisioningResourceRollbackTriggered = $false

$Departments = @(Test-DepartmentNames -DepartmentNames $Departments)
if ($Departments.Count -eq 0) { throw 'At least one department is required.' }
$createDepartmentAdministrators = if ($PSBoundParameters.ContainsKey('CreateDepartmentAdministrators')) {
    [bool]$CreateDepartmentAdministrators
}
else {
    $true
}
$createDepartmentAdministrators = $createDepartmentAdministrators -or (-not [string]::IsNullOrWhiteSpace($AdministratorUsername))
if ($DisableDepartmentAdministratorsByDefault -and
    -not $PSBoundParameters.ContainsKey('CreateDepartmentAdministrators') -and
    [string]::IsNullOrWhiteSpace($AdministratorUsername)) {
    $createDepartmentAdministrators = $false
}

if ($AdministratorsOnly -and -not $createDepartmentAdministrators) {
    throw '-AdministratorsOnly requires department administrators to be enabled. Remove -CreateDepartmentAdministrators:$false or omit -AdministratorsOnly.'
}

if ($Departments.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($AdministratorUsername) -and -not $AdministratorUsername.Contains('{0}')) {
    throw "When creating department administrators for multiple departments, -AdministratorUsername must include {0} so each department can receive a unique SAM account name. Example: 'deptadmin-{0}'."
}

Import-Module ActiveDirectory -ErrorAction Stop
if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
    throw 'The Active Directory PowerShell module is not available or did not load correctly.'
}

$operationsModule = Join-Path $scriptDirectory 'Modules\AD-Operations.psm1'

if (-not (Test-Path -LiteralPath $operationsModule -PathType Leaf)) {
    throw "Required module not found: $operationsModule"
}

Import-Module $operationsModule -Force
Assert-ADOperationsDependencies
$autoXModule = Join-Path $scriptDirectory 'Modules\ADAutoX.psd1'
if (-not (Test-Path -LiteralPath $autoXModule -PathType Leaf)) {
    throw "Required module not found: $autoXModule"
}
Import-Module $autoXModule -ErrorAction Stop

# Marker written to every OU this script creates so cleanup tooling can recognise generated OUs.
$generatedOUDescription = 'Generated by AD_PS provisioning (test data)'
$auditStarted = $false

try {
$resolvedServer = Set-ADToolContext -Server $Server -Credential $Credential

function Invoke-ADPreflight {
    param(
        [Parameter(Mandatory)]
        [string[]]$DepartmentNames,

        [Parameter(Mandatory)]
        [string]$CompanyOuName,

        [Parameter(Mandatory)]
        [string]$StaffNamesOuName,

        [Parameter(Mandatory)]
        [string]$DomainRoot,

        [Parameter(Mandatory)]
        [string]$DomainNetBIOSName,

        [Parameter()]
        [bool]$CreateDepartmentAdministrators = $false,

        [Parameter()]
        [bool]$AdministratorsOnly = $false,

        [Parameter()]
        [string]$AdministratorUsername = ''
    )

    if (-not (Get-Command Invoke-ADAutoXPreflight -ErrorAction SilentlyContinue)) {
        Import-Module (Join-Path $scriptDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop
    }

    $state = [pscustomobject]@{
        CanonicalProvisioning = $true
        AdministratorsOnly = $AdministratorsOnly
        CreateDepartmentAdministrators = $CreateDepartmentAdministrators
        AdministratorUsername = $AdministratorUsername
        NamesPath = $NamesPath
        AccountCount = $AccountCount
        TreatZeroAccountCountAsNone = $TreatZeroAccountCountAsNone
        ADContext = $adContext
    }
    Invoke-ADAutoXPreflight `
        -CompanyOuName $CompanyOuName `
        -StaffOuName $StaffNamesOuName `
        -Departments $DepartmentNames `
        -DomainDN $DomainRoot `
        -NetBIOSName $DomainNetBIOSName `
        -State $state `
        -ADContext $adContext
}

function Assert-PasswordPatternMeetsDomainPolicy {
    # NOTE: a password pattern is effectively the password for every account that uses it, so this
    # function never echoes the pattern or its resolved sample in errors or warnings.
    param(
        [Parameter()]
        [psobject]$DomainPasswordPolicy,

        [string]$PasswordPatternValue,

        [Parameter(Mandatory)]
        [string]$ParameterName,

        [string]$SampleValue = 'User01',

        [object[]]$FineGrainedPasswordPolicies = @()
    )

    if (-not $DomainPasswordPolicy -or [string]::IsNullOrWhiteSpace($PasswordPatternValue)) {
        return
    }

    $resolvedPatternText = Resolve-PasswordPatternText -Pattern $PasswordPatternValue -Username $SampleValue -Token $SampleValue
    $issues = [System.Collections.Generic.List[string]]::new()

    if ($DomainPasswordPolicy.MinPasswordLength -and $resolvedPatternText.Length -lt [int]$DomainPasswordPolicy.MinPasswordLength) {
        $issues.Add("length $($resolvedPatternText.Length) is shorter than the domain minimum of $($DomainPasswordPolicy.MinPasswordLength)")
    }

    if ($DomainPasswordPolicy.ComplexityEnabled -and -not (Test-PasswordComplexity -PasswordText $resolvedPatternText)) {
        $issues.Add('it does not meet the domain complexity rule (must contain at least three of: uppercase, lowercase, number, special character)')
    }

    if ($issues.Count -gt 0) {
        throw "$ParameterName does not satisfy the current domain password policy for a representative sample account because $($issues -join '; '). Use a pattern that meets the policy, or omit the pattern to let the script generate a strong random password."
    }

    if ($DomainPasswordPolicy.ComplexityEnabled -and $PasswordPatternValue.Contains('{0}')) {
        Write-Warning "$ParameterName embeds the account name ({0}). Active Directory complexity rules reject passwords that contain the account name, so account creation may fail for these users."
    }

    if ($FineGrainedPasswordPolicies.Count -gt 0) {
        $fgppWarnings = [System.Collections.Generic.List[string]]::new()

        foreach ($fineGrainedPolicy in $FineGrainedPasswordPolicies) {
            $fineGrainedIssues = [System.Collections.Generic.List[string]]::new()

            if ($fineGrainedPolicy.MinPasswordLength -and $resolvedPatternText.Length -lt [int]$fineGrainedPolicy.MinPasswordLength) {
                $fineGrainedIssues.Add("length $($resolvedPatternText.Length) is shorter than the fine-grained policy minimum of $($fineGrainedPolicy.MinPasswordLength)")
            }

            if ($fineGrainedPolicy.ComplexityEnabled -and -not (Test-PasswordComplexity -PasswordText $resolvedPatternText)) {
                $fineGrainedIssues.Add('it does not meet the fine-grained policy complexity rule (must contain at least three of: uppercase, lowercase, number, special character)')
            }

            if ($fineGrainedIssues.Count -gt 0) {
                $fgppWarnings.Add("Fine-grained password policy '$($fineGrainedPolicy.Name)' would reject the sample because $($fineGrainedIssues -join '; ')")
            }
        }

        if ($fgppWarnings.Count -gt 0) {
            Write-Warning "$ParameterName satisfies the domain default policy, but a representative sample would not satisfy one or more fine-grained password policies that exist in the domain. This is only a best-effort preflight hint: a specific user may or may not be subject to one of those fine-grained policies, and final validation still happens when Active Directory processes the actual account creation request. $($fgppWarnings -join ' | ')"
        }
    }
}

function Test-PathUnderRoot {
    # Separator-aware containment check ("C:\Windows" must not match "C:\WindowsEvil").
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Root)) { return $false }
    $trimmedRoot = $Root.TrimEnd('\', '/')
    $trimmedPath = $Path.TrimEnd('\', '/')
    if ($trimmedPath.Equals($trimmedRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $trimmedPath.StartsWith($trimmedRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-ProtectedSystemFolders {
    return @(
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles),
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonProgramFiles),
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFilesX86),
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonProgramFilesX86),
        $env:SystemRoot,
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData),
        [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonDocuments)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

function Confirm-PasswordExportPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'A password export file path is required when exporting credentials.'
    }

    $fullPath = Resolve-ScriptPath $Path
    $fileName = [System.IO.Path]::GetFileName($fullPath)

    if ([string]::IsNullOrWhiteSpace($fileName)) {
        throw "Password export path '$Path' does not point to a file. Use a specific file path such as '.\\user-passwords.clixml'."
    }

    if ([System.IO.Path]::GetExtension($fileName) -ne '.clixml') {
        throw "Password export path '$Path' must be a .clixml file intended for credential storage. Avoid exporting sensitive credentials to arbitrary file types."
    }

    if ($fileName -notmatch '(?i)(password|credential|secret)') {
        Write-Warning "Password export file '$fileName' does not look like a dedicated credential-store path. Verify that this is intentional before changing ACLs."
    }

    foreach ($dangerousParent in (Get-ProtectedSystemFolders)) {
        if (Test-PathUnderRoot -Path $fullPath -Root $dangerousParent) {
            throw "Password export path '$Path' points into a protected system location. Use a dedicated credential file under your profile or another explicitly approved admin folder instead."
        }
    }

    $userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
    $currentLocation = (Get-Location).ProviderPath

    if (-not (Test-PathUnderRoot -Path $fullPath -Root $userProfile) -and
        -not (Test-PathUnderRoot -Path $fullPath -Root $currentLocation)) {
        Write-Warning "Password export path '$Path' is outside your profile and current working directory. Confirm that this is an approved credential-storage location before ACL changes are made."
    }
}

function Protect-PasswordExportFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($WhatIfPreference) {
        Write-Host "WhatIf: would restrict ACLs on '$Path' to the current Windows identity only." -ForegroundColor DarkGray
        return
    }

    Confirm-PasswordExportPath -Path $Path

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'DPAPI-protected credential exports require Windows. Refusing to write credential material on this platform.'
    }

    $acl = Get-Acl -LiteralPath $Path
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $currentIdentity -or $null -eq $currentIdentity.User) {
        throw 'Could not determine the current Windows identity to secure the password export file.'
    }

    $currentUser = $currentIdentity.User

    Write-Warning "Restricting ACLs on '$Path' to the current Windows identity only. Confirm that this file is intended for credential storage before proceeding."

    $acl.SetAccessRuleProtection($true, $false)

    foreach ($accessRule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
        $null = $acl.RemoveAccessRule($accessRule)
    }

    $fullControlRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $currentUser,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $acl.AddAccessRule($fullControlRule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Export-PasswordRecordsSecurely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[psobject]]$Records,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [switch]$Overwrite
    )

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'DPAPI-protected credential exports require Windows. Refusing to write credential material on this platform.'
    }

    $fullPath = Resolve-ScriptPath $Path
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
    }

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($fullPath)
    $stagingPath = Join-Path $directory ".$fileName.$([Guid]::NewGuid().ToString('N')).tmp.clixml"
    try {
        $null = New-Item -ItemType File -Path $stagingPath -ErrorAction Stop
        Protect-PasswordExportFile -Path $stagingPath
        $Records | Export-Clixml -LiteralPath $stagingPath -Force -ErrorAction Stop
        Move-ADSecuredFileIntoPlace -StagingPath $stagingPath -DestinationPath $fullPath -Overwrite:$Overwrite
    }
    finally {
        if (Test-Path -LiteralPath $stagingPath -PathType Leaf) {
            try {
                Remove-Item -LiteralPath $stagingPath -Force -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to remove sensitive staging file '$stagingPath': $($_.Exception.Message)"
            }
        }
    }
}

function Confirm-SensitiveReportPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'A report file path is required when including passwords in the provisioning report.'
    }

    $fullPath = Resolve-ScriptPath $Path
    $fileName = [System.IO.Path]::GetFileName($fullPath)

    if ([string]::IsNullOrWhiteSpace($fileName)) {
        throw "Report path '$Path' does not point to a file."
    }

    foreach ($dangerousParent in (Get-ProtectedSystemFolders)) {
        if (Test-PathUnderRoot -Path $fullPath -Root $dangerousParent) {
            throw "Report path '$Path' points into a protected system location, and -IncludePasswordInReport would place plaintext credentials there. Use a dedicated path under your profile or another explicitly approved admin folder instead."
        }
    }

    $userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
    $currentLocation = (Get-Location).ProviderPath

    if (-not (Test-PathUnderRoot -Path $fullPath -Root $userProfile) -and
        -not (Test-PathUnderRoot -Path $fullPath -Root $currentLocation)) {
        Write-Warning "Report path '$Path' is outside your profile and current working directory, and -IncludePasswordInReport will place plaintext credentials there. Confirm that this is an approved, access-controlled location before ACL changes are made."
    }
}

function Protect-SensitiveReportFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($WhatIfPreference) {
        Write-Host "WhatIf: would restrict ACLs on '$Path' to the current Windows identity only because it would contain plaintext passwords." -ForegroundColor DarkGray
        return
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    $acl = Get-Acl -LiteralPath $Path
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $currentIdentity -or $null -eq $currentIdentity.User) {
        # Never write plaintext passwords to a file we could not lock down.
        throw 'Could not determine the current Windows identity to secure the plaintext-password report file.'
    }

    $currentUser = $currentIdentity.User

    Write-Warning "Restricting ACLs on '$Path' to the current Windows identity only because it contains plaintext passwords (-IncludePasswordInReport). This CSV is not encrypted at rest; delete or securely archive it once you are done reviewing credentials."

    $acl.SetAccessRuleProtection($true, $false)

    foreach ($accessRule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
        $null = $acl.RemoveAccessRule($accessRule)
    }

    $fullControlRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $currentUser,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $acl.AddAccessRule($fullControlRule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

$adContext = Get-ADInvocationContext -Server $resolvedServer -Credential $Credential
$domainReachability = Test-ADDomainReachability -Server $resolvedServer -Credential $Credential

if (-not $domainReachability.IsReachable) {
    $message = @(
        'Active Directory is not reachable from this session.',
        'This usually means the machine is not joined to the domain, DNS cannot resolve the domain controller, or the supplied -Server/-Credential is incorrect.',
        'Checklist: join the workstation to the domain; confirm DNS resolves your DC; use -Server "dc01.domain.local" with a valid -Credential; verify the Active Directory RSAT module is installed.',
        'Example: .\Cmdlets\mark42.ps1 -AccountCount 5 -Server "dc01.domain.local" -Credential (Get-Credential)',
        "Original error: $($domainReachability.Error)"
    )
    throw ($message -join ' ')
}

try {
    $null = Get-ADDomain @adContext -ErrorAction Stop
}
catch {
    $message = @(
        'Active Directory is not reachable from this session.',
        'Ensure the machine is joined to the domain or use a reachable domain controller with -Server and a valid -Credential.',
        'Example: .\Cmdlets\mark42.ps1 -AccountCount 5 -Server "dc01.domain.local" -Credential (Get-Credential)',
        "Original error: $($_.Exception.Message)"
    )
    throw ($message -join ' ')
}

$domainPasswordPolicy = $null
$fineGrainedPasswordPolicies = @()
$randomPasswordLength = 32
try {
    $domainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy @adContext -ErrorAction Stop
    if ($domainPasswordPolicy.MinPasswordLength) {
        $randomPasswordLength = [Math]::Min(256, [Math]::Max($randomPasswordLength, [int]$domainPasswordPolicy.MinPasswordLength))
    }
    Write-Verbose "Retrieved domain default password policy: MinPasswordLength=$($domainPasswordPolicy.MinPasswordLength), ComplexityEnabled=$($domainPasswordPolicy.ComplexityEnabled), PasswordHistoryCount=$($domainPasswordPolicy.PasswordHistoryCount), MinPasswordAge=$($domainPasswordPolicy.MinPasswordAge), MaxPasswordAge=$($domainPasswordPolicy.MaxPasswordAge)."
}
catch {
    Write-Warning "Could not retrieve the domain default password policy. Active Directory will enforce its policy at account creation time; the script will not block custom password patterns without a policy lookup. Original error: $($_.Exception.Message)"
}

try {
    $fineGrainedPasswordPolicies = @(Get-ADFineGrainedPasswordPolicy @adContext -Filter '*' -ErrorAction Stop)
}
catch {
    Write-Warning "Could not enumerate fine-grained password policies in the domain. Fine-grained policy assignment is a per-user concern, so the script will rely on AD's actual account creation process for final validation. Original error: $($_.Exception.Message)"
}

if ($fineGrainedPasswordPolicies.Count -gt 0) {
    $fineGrainedSummary = ($fineGrainedPasswordPolicies | ForEach-Object {
        "Name=$($_.Name); MinPasswordLength=$($_.MinPasswordLength); ComplexityEnabled=$($_.ComplexityEnabled); PasswordHistoryCount=$($_.PasswordHistoryCount); MinPasswordAge=$($_.MinPasswordAge); MaxPasswordAge=$($_.MaxPasswordAge)"
    }) -join '; '
    Write-Verbose "Detected $($fineGrainedPasswordPolicies.Count) fine-grained password policy object(s): $fineGrainedSummary"
    Write-Warning "Fine-grained password policies exist in the domain. The script preflights only the domain default policy and the discovered fine-grained policy metadata, but the effective policy for a specific user can still depend on account-specific assignment, password history, password age rules, and any external password-filtering mechanisms. Active Directory account creation remains the final authority."
}

Assert-PasswordPatternMeetsDomainPolicy -DomainPasswordPolicy $domainPasswordPolicy -PasswordPatternValue $PasswordPattern -ParameterName '-PasswordPattern' -SampleValue 'User01' -FineGrainedPasswordPolicies $fineGrainedPasswordPolicies
Assert-PasswordPatternMeetsDomainPolicy -DomainPasswordPolicy $domainPasswordPolicy -PasswordPatternValue $AdministratorPasswordPattern -ParameterName '-AdministratorPasswordPattern' -SampleValue 'DeptAdmin01' -FineGrainedPasswordPolicies $fineGrainedPasswordPolicies

function New-SimulatedOU {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ParentDistinguishedName
    )

    [pscustomobject]@{
        Name = $Name
        DistinguishedName = "OU=$(ConvertTo-DistinguishedNameValue $Name),$ParentDistinguishedName"
        Simulated = $true
    }
}

function New-SimulatedGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ParentDistinguishedName
    )

    [pscustomobject]@{
        Name = $Name
        DistinguishedName = "CN=$(ConvertTo-DistinguishedNameValue $Name),$ParentDistinguishedName"
        Simulated = $true
    }
}

function Test-SimulatedResource {
    param([psobject]$Resource)

    return $null -ne $Resource -and $Resource.PSObject.Properties.Name -contains 'Simulated' -and [bool]$Resource.Simulated
}

function Add-ResourceLedgerEntry {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Name = '',
        [bool]$CreatedByThisRun = $true,
        [string]$SecurityIdentifier = '',
        [string[]]$DelegationRuleTypes = @()
    )

    $objectType = switch ($Type) {
        'OrganizationalUnit' { 'OU' }
        'OU' { 'OU' }
        'Group' { 'Group' }
        'User' { 'User' }
        'Delegation' { 'Delegation' }
        default { throw "Unsupported provisioning ledger resource type '$Type'." }
    }
    $undoData = if ($objectType -eq 'OU') {
        @{ GeneratedDescription = $generatedOUDescription }
    }
    else {
        @{}
    }
    $samAccountName = if ($objectType -eq 'User') { $Name } else { '' }
    Add-ADAutoXLedgerEntry `
        -ObjectType $objectType `
        -DistinguishedName $DistinguishedName `
        -SamAccountName $samAccountName `
        -Name $Name `
        -CreatedByThisRun $CreatedByThisRun `
        -SecurityIdentifier $SecurityIdentifier `
        -DelegationRuleTypes $DelegationRuleTypes `
        -RunId $CorrelationId `
        -UndoData $undoData
}

function Invoke-AccountRollback {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[psobject]]$CreatedAccounts,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$ReportRecords,

        [psobject]$Account
    )

    <#
        This rollback is intentionally scoped to created user accounts.
        The resource ledger tracks which objects were created by this invocation versus which
        objects already existed before the run started, so rollback can safely remove only
        the run-created account resources while leaving pre-existing OUs, groups, and ACL
        delegation changes alone.

        Successful removals are pruned from the in-memory list so a later rollback path cannot
        attempt to delete the same objects again after the first rollback already removed them.
    #>

    if ($CreatedAccounts.Count -eq 0) {
        return
    }

    $rollbackIndexes = if ($Account) {
        $matchingIndexes = [System.Collections.Generic.List[int]]::new()
        for ($candidateIndex = 0; $candidateIndex -lt $CreatedAccounts.Count; $candidateIndex++) {
            if ($CreatedAccounts[$candidateIndex].DistinguishedName -eq $Account.DistinguishedName) {
                $matchingIndexes.Add($candidateIndex)
            }
        }
        $matchingIndexes.ToArray()
    }
    else {
        0..($CreatedAccounts.Count - 1)
    }

    foreach ($index in @($rollbackIndexes | Sort-Object -Descending)) {
        $createdAccount = $CreatedAccounts[$index]
        try {
            Remove-ADObject @adContext -Identity $createdAccount.DistinguishedName -Confirm:$false -ErrorAction Stop
            for ($passwordIndex = $passwordRecords.Count - 1; $passwordIndex -ge 0; $passwordIndex--) {
                if ($passwordRecords[$passwordIndex].Username -ieq $createdAccount.SamAccountName) {
                    $passwordRecords.RemoveAt($passwordIndex)
                }
            }
            if ($ReportRecords) {
                foreach ($reportRecord in @($ReportRecords | Where-Object { $_.Username -ieq $createdAccount.SamAccountName })) {
                    $reportRecord.Status = 'RolledBack'
                    $reportRecord.Stage = 'RollbackCompleted'
                    $reportRecord.ErrorCategory = 'AccountRolledBack'
                    $reportRecord.Error = "Account '$($createdAccount.SamAccountName)' was removed by account rollback after provisioning did not complete successfully."
                    # The account no longer exists, so its plaintext password must not stay in the report.
                    $reportRecord.Password = ''
                }
            }
            $CreatedAccounts.RemoveAt($index)
            Write-Host "Rolled back created account '$($createdAccount.SamAccountName)'." -ForegroundColor Yellow
        }
        catch {
            Write-Warning "Failed to roll back account '$($createdAccount.SamAccountName)': $($_.Exception.Message)"
        }
    }
}

function Invoke-ProvisioningResourceRollback {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$CreatedAccounts,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$ReportRecords
    )

    if ($script:ProvisioningResourceRollbackTriggered) {
        return
    }
    $script:ProvisioningResourceRollbackTriggered = $true

    $rollbackArguments = @{
        AllowedRoot = $domainRoot
        RunId = $CorrelationId
        LogPath = $AuditLogPath
        AllowDestructiveOperation = $true
        Confirm = $script:ProvisioningConfirmValue
        Server = $resolvedServer
        Credential = $Credential
    }
    if ($WhatIfPreference) { $rollbackArguments.WhatIf = $true }
    if ($script:ProvisioningConfirmSpecified) {
        $rollbackArguments.Confirm = $script:ProvisioningConfirmValue
    }
    $rollbackResult = Invoke-ADAutoXLedgerRollback @rollbackArguments

    foreach ($userResult in @($rollbackResult.Results | Where-Object {
        $_.ObjectType -eq 'User' -and $_.Status -eq 'Succeeded'
    })) {
        for ($accountIndex = $CreatedAccounts.Count - 1; $accountIndex -ge 0; $accountIndex--) {
            if ($CreatedAccounts[$accountIndex].DistinguishedName -ceq $userResult.DistinguishedName) {
                $CreatedAccounts.RemoveAt($accountIndex)
            }
        }
        for ($passwordIndex = $passwordRecords.Count - 1; $passwordIndex -ge 0; $passwordIndex--) {
            if ($passwordRecords[$passwordIndex].Username -ieq $userResult.SamAccountName) {
                $passwordRecords.RemoveAt($passwordIndex)
            }
        }
        foreach ($reportRecord in @($ReportRecords | Where-Object {
            $_.Username -ieq $userResult.SamAccountName
        })) {
            $reportRecord.Status = 'RolledBack'
            $reportRecord.Stage = 'RollbackCompleted'
            $reportRecord.ErrorCategory = 'AccountRolledBack'
            $reportRecord.Error = "Account '$($userResult.SamAccountName)' was removed by account rollback after provisioning did not complete successfully."
            $reportRecord.Password = ''
        }
    }
    $rollbackResult
}

function Invoke-ProvisioningFailureRollback {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$CreatedAccounts,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$ReportRecords,

        [Parameter(Mandatory)]
        [ref]$RollbackTriggered,

        [psobject]$Account
    )

    if (-not $RollbackCreatedAccountsOnFailure) {
        return
    }

    if (-not $Account) {
        $RollbackTriggered.Value = $true
    }
    $targetDescription = if ($Account) { "only account '$($Account.SamAccountName)'" } else { 'all accounts created in this invocation' }
    Write-Host "Account rollback is enabled. Removing $targetDescription; OUs, groups, and delegation changes will be left in place." -ForegroundColor Yellow
    Invoke-AccountRollback -CreatedAccounts $CreatedAccounts -ReportRecords $ReportRecords -Account $Account
    Write-ADProvisioningReport -OutputPath $ReportPath -Records $ReportRecords -IncludePasswords:$IncludePasswordInReport
}

function Write-ADProvisioningReport {
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$Records,

        [switch]$IncludePasswords
    )

    if ($WhatIfPreference) {
        Write-Host "WhatIf: would write provisioning report to '$OutputPath'." -ForegroundColor DarkGray
        return
    }

    $reportDirectory = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($reportDirectory) -and -not (Test-Path -LiteralPath $reportDirectory)) {
        New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    }

    # Lock the file down BEFORE any plaintext password is written, not after.
    if ($IncludePasswords) {
        if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
            [System.IO.File]::Create($OutputPath).Dispose()
        }
        Protect-SensitiveReportFile -Path $OutputPath
    }

    $orderedRecords = @(foreach ($record in $Records) {
        $reportRow = [pscustomobject]@{
            Domain = $runExecutionContext.Domain
            Forest = $runExecutionContext.Forest
            DC = $runExecutionContext.DC
            DomainController = $runExecutionContext.DomainController
            User = $runExecutionContext.User
            ExecutionTime = $runExecutionContext.ExecutionTime
            PowerShellVersion = $runExecutionContext.PowerShellVersion
            OS = $runExecutionContext.OS
            Username = $record.Username
            FullName = $record.FullName
            Department = $record.Department
            Role = $record.Role
            OU = $record.OU
            Status = $record.Status
            Stage = if ($record.PSObject.Properties.Name -contains 'Stage') { $record.Stage } else { '' }
            CreatedAt = $record.CreatedAt
            ErrorCategory = if ($record.PSObject.Properties.Name -contains 'ErrorCategory') { $record.ErrorCategory } else { '' }
            Error = if ($record.PSObject.Properties.Name -contains 'Error') { $record.Error } else { '' }
        }

        if ($IncludePasswords) {
            $reportRow | Add-Member -MemberType NoteProperty -Name 'Password' -Value $(if ($record.PSObject.Properties.Name -contains 'Password') { $record.Password } else { '' })
        }

        $reportRow
    })

    # -Encoding UTF8: Windows PowerShell 5.1 defaults to ASCII and would turn accented/tonal
    # characters in names into '?'.
    if ($Records.Count -eq 0) {
        $header = 'Domain,Forest,DC,DomainController,User,ExecutionTime,PowerShellVersion,OS,Username,FullName,Department,Role,OU,Status,Stage,CreatedAt,ErrorCategory,Error'
        if ($IncludePasswords) { $header += ',Password' }
        $header | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -Force
        return
    }

    $orderedRecords | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -Force
}

function Write-ADProvisioningAuditRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [string]$Status,

        [string]$Message = '',

        [string]$Details = '',

        [string]$TargetType = 'Provisioning'
    )

    if ($WhatIfPreference) {
        $previewMessage = if ([string]::IsNullOrWhiteSpace($Message) -and [string]::IsNullOrWhiteSpace($Details)) {
            "WhatIf: would write audit record [$Action] [$Status] [$Target]."
        }
        elseif ([string]::IsNullOrWhiteSpace($Details)) {
            "WhatIf: would write audit record [$Action] [$Status] [$Target] - $Message."
        }
        else {
            "WhatIf: would write audit record [$Action] [$Status] [$Target] - $Details."
        }

        Write-Host $previewMessage -ForegroundColor DarkGray
        return
    }

    $effectiveDetails = if ([string]::IsNullOrWhiteSpace($Details)) { $Message } else { $Details }
    Write-ADAuditRecord -Path $AuditLogPath -Action $Action -Target $Target -TargetType $TargetType -Status $Status -Message $Message -Details $effectiveDetails -Source 'ADAutoX' -CorrelationId $CorrelationId
}

Write-ADProvisioningAuditRecord -Action 'CreateUsers' -Target $OrganizationalUnitName -Status 'Started'
$auditStarted = $true

if ($ExportPasswords -and [string]::IsNullOrWhiteSpace($PasswordFile)) {
    throw 'Use -PasswordFile with -ExportPasswords to write credential material. This file contains sensitive account information.'
}

if (-not $ExportPasswords -and $PasswordFile) {
    throw 'Password export is disabled unless you explicitly provide -ExportPasswords. Remove -PasswordFile or add -ExportPasswords to save credential material.'
}

if (-not $Password -and -not $PasswordPattern -and -not $WhatIfPreference) {
    Write-Host 'No explicit password source was provided. A strong random password will be generated for each account. Use -ExportPasswords with -PasswordFile only when you intentionally want to persist credential material.' -ForegroundColor Yellow
}

if ($PasswordFile) {
    Confirm-PasswordExportPath -Path $PasswordFile
}

if (-not $WhatIfPreference -and $PasswordFile -and (Test-Path -LiteralPath $PasswordFile) -and -not $OverwritePasswordFile) {
    throw "Password file '$PasswordFile' already exists. Use a new path or explicitly specify -OverwritePasswordFile."
}

if ($IncludePasswordInReport) {
    Confirm-SensitiveReportPath -Path $ReportPath
    Write-Warning "-IncludePasswordInReport is enabled. '$ReportPath' will contain plaintext passwords for every account this run creates, alongside Username and Department. This CSV is NOT DPAPI-protected like -PasswordFile; the script restricts its file ACLs to the current Windows identity before writing, but treat the file itself as highly sensitive, limit who can access it, and delete or securely archive it once you're done reviewing credentials."
}

if (-not $AdministratorsOnly) {
    Write-Verbose "Loading source names from '$NamesPath'."
    # -Encoding UTF8 so names with diacritics/tonal marks are not mangled by the ANSI default of Windows PowerShell 5.1.
    $nameRecords = @(foreach ($line in Get-Content -LiteralPath $NamesPath -Encoding UTF8 -ErrorAction Stop) {
        $trimmedLine = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmedLine)) {
            continue
        }

        $nameParts = $trimmedLine -split '\s+', 2
        if ($nameParts.Count -ne 2) {
            Write-Warning "Skipping invalid name entry: '$line'"
            continue
        }

        [pscustomobject]@{
            FirstName = $nameParts[0]
            LastName  = $nameParts[1]
        }
    })

    if ($nameRecords.Count -eq 0) {
        throw "No valid first and last names were found in '$NamesPath'."
    }

    Write-Verbose "Loaded $($nameRecords.Count) valid names from '$NamesPath'."

    if ($AccountCount -eq 0 -and -not $TreatZeroAccountCountAsNone) {
        Write-Verbose "AccountCount is 0, so all $($nameRecords.Count) available valid names will be used."
        $AccountCount = $nameRecords.Count
    }
    if ($AccountCount -gt $nameRecords.Count) {
        Write-Warning "Only $($nameRecords.Count) valid names are available. AccountCount will be reduced from $AccountCount."
        Write-Verbose "Reducing AccountCount from $AccountCount to $($nameRecords.Count) because fewer valid names are available than requested."
        $AccountCount = $nameRecords.Count
    }
}
else {
    $nameRecords = @()
    Write-Verbose "AdministratorsOnly mode is enabled; no source names will be loaded."
}
$usersToCreate = if ($AdministratorsOnly -or ($TreatZeroAccountCountAsNone -and $AccountCount -eq 0)) { 0 } else { $AccountCount }
Write-Verbose "Requested user creation count is $usersToCreate."

$domain = Get-ADDomain @adContext -ErrorAction Stop
$forest = Get-ADForest @adContext -ErrorAction Stop
$runExecutionContext = [pscustomobject]@{
    Domain = $domain.DNSRoot
    Forest = $forest.Name
    DC = $resolvedServer
    DomainController = $resolvedServer
    User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    ExecutionTime = (Get-Date).ToUniversalTime().ToString('o')
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    OS = [System.Environment]::OSVersion.VersionString
}
$domainRoot = $domain.DistinguishedName
$effectiveUPNSuffix = if ($UPNSuffix) { $UPNSuffix } else { $domain.DNSRoot }
$domainNetBIOSName = $domain.NetBIOSName
Write-Verbose "Resolved Active Directory domain root '$domainRoot' and UPN suffix '$effectiveUPNSuffix'."

try {
    $preflightResult = Invoke-ADPreflight -DepartmentNames $Departments -CompanyOuName $OrganizationalUnitName -StaffNamesOuName $StaffNamesOrganizationalUnitName -DomainRoot $domainRoot -DomainNetBIOSName $domainNetBIOSName -CreateDepartmentAdministrators:$createDepartmentAdministrators -AdministratorsOnly:$AdministratorsOnly -AdministratorUsername $AdministratorUsername
}
catch {
    Write-Host '=== Invoke-ADPreflight failed. Full diagnostic stack trace below. ===' -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Write-Host '=== End diagnostic stack trace ===' -ForegroundColor Red
    throw
}

if ($preflightResult.FailedCount -gt 0) {
    $failureMessages = @($preflightResult.Checks | Where-Object { $_.Status -eq 'Failed' } | ForEach-Object { $_.Details })
    throw "Preflight failed: $($failureMessages -join '; ' )"
}

$preflightSummaryLines = @(
    '========================================',
    ' Phase 1 Preflight Summary',
    '========================================',
    '',
    ("Passed          : {0}" -f $preflightResult.PassedCount),
    ("Needs attention : {0}" -f $preflightResult.NeedsAttentionCount),
    ("Failed          : {0}" -f $preflightResult.FailedCount),
    ''
)

foreach ($preflightCheck in $preflightResult.Checks) {
    $preflightSummaryLines += ("[{0}] {1} - {2}" -f $preflightCheck.Status, $preflightCheck.Name, $preflightCheck.Details)
}

if ($preflightSummaryLines.Count -gt 0) {
    Write-Host ($preflightSummaryLines -join [Environment]::NewLine) -ForegroundColor DarkGray
}

$safeOrganizationalUnitName = ConvertTo-LdapFilterValue $OrganizationalUnitName
Write-Verbose "Checking for Company OU '$OrganizationalUnitName' under '$domainRoot'."
Write-Verbose '=== Phase 2: Provision ==='
$organizationalUnit = @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeOrganizationalUnitName)" -SearchBase $domainRoot -SearchScope OneLevel -ErrorAction Stop)
if ($organizationalUnit.Count -gt 1) { throw "More than one OU named '$OrganizationalUnitName' was found below '$domainRoot'. Use a unique name." }

if (-not $organizationalUnit) {
    Write-Verbose "Company OU '$OrganizationalUnitName' was not found, so it will be created under '$domainRoot'."
    if (-not $PSCmdlet.ShouldProcess("OU=$OrganizationalUnitName,$domainRoot", 'Create organizational unit')) {
        if (-not $WhatIfPreference) {
            throw "Organizational unit '$OrganizationalUnitName' was not created because the operation was not approved."
        }
    }

    if ($WhatIfPreference) {
        $organizationalUnit = New-SimulatedOU -Name $OrganizationalUnitName -ParentDistinguishedName $domainRoot
    }
    else {
        $organizationalUnit = New-ADOrganizationalUnit @adContext -Name $OrganizationalUnitName -Path $domainRoot -Description $generatedOUDescription -ProtectedFromAccidentalDeletion $false -PassThru
        Write-Verbose "Created Company OU '$OrganizationalUnitName' at '$($organizationalUnit.DistinguishedName)'."
        Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $organizationalUnit.DistinguishedName -Name $OrganizationalUnitName -CreatedByThisRun $true
        Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $organizationalUnit.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Succeeded' -Details "Created organizational unit '$OrganizationalUnitName' under '$domainRoot'."
    }
}
else {
    Write-Verbose "Company OU '$OrganizationalUnitName' already exists at '$(@($organizationalUnit)[0].DistinguishedName)'."
    Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName (@($organizationalUnit)[0].DistinguishedName) -Name $OrganizationalUnitName -CreatedByThisRun $false
    Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target (@($organizationalUnit)[0].DistinguishedName) -TargetType 'OrganizationalUnit' -Status 'Skipped' -Details "Organizational unit '$OrganizationalUnitName' already existed under '$domainRoot'; no creation was needed."
}
# Normalise to a single object (the lookup returns a one-element array).
$organizationalUnit = @($organizationalUnit)[0]

$safeStaffNamesOrganizationalUnitName = ConvertTo-LdapFilterValue $StaffNamesOrganizationalUnitName
$staffNamesOrganizationalUnit = @(if (Test-SimulatedResource $organizationalUnit) {
    @()
}
else {
    @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeStaffNamesOrganizationalUnitName)" `
        -SearchBase $organizationalUnit.DistinguishedName -SearchScope OneLevel -ErrorAction Stop
    )
})
if ($staffNamesOrganizationalUnit.Count -gt 1) {
    throw "More than one OU named '$StaffNamesOrganizationalUnitName' was found below '$($organizationalUnit.DistinguishedName)'."
}

if (-not $staffNamesOrganizationalUnit) {
    Write-Verbose "Staff names OU '$StaffNamesOrganizationalUnitName' was not found, so it will be created under '$($organizationalUnit.DistinguishedName)'."
    if (-not $PSCmdlet.ShouldProcess("OU=$StaffNamesOrganizationalUnitName,$($organizationalUnit.DistinguishedName)", 'Create staff names organizational unit')) {
        if (-not $WhatIfPreference) {
            throw "Staff names OU '$StaffNamesOrganizationalUnitName' was not created because the operation was not approved."
        }
    }

    if ($WhatIfPreference) {
        $staffNamesOrganizationalUnit = New-SimulatedOU -Name $StaffNamesOrganizationalUnitName -ParentDistinguishedName $organizationalUnit.DistinguishedName
    }
    else {
        $staffNamesOrganizationalUnit = New-ADOrganizationalUnit @adContext -Name $StaffNamesOrganizationalUnitName `
            -Path $organizationalUnit.DistinguishedName -Description $generatedOUDescription -ProtectedFromAccidentalDeletion $false -PassThru
        Write-Verbose "Created staff names OU '$StaffNamesOrganizationalUnitName' at '$($staffNamesOrganizationalUnit.DistinguishedName)'."
        Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $staffNamesOrganizationalUnit.DistinguishedName -Name $StaffNamesOrganizationalUnitName -CreatedByThisRun $true
        Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $staffNamesOrganizationalUnit.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Succeeded' -Details "Created organizational unit '$StaffNamesOrganizationalUnitName' under '$($organizationalUnit.DistinguishedName)'."
    }
}
else {
    $staffNamesOrganizationalUnit = @($staffNamesOrganizationalUnit)[0]
    Write-Verbose "Staff names OU '$StaffNamesOrganizationalUnitName' already exists at '$($staffNamesOrganizationalUnit.DistinguishedName)'."
    Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $staffNamesOrganizationalUnit.DistinguishedName -Name $StaffNamesOrganizationalUnitName -CreatedByThisRun $false
    Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $staffNamesOrganizationalUnit.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Skipped' -Details "Organizational unit '$StaffNamesOrganizationalUnitName' already existed under '$($organizationalUnit.DistinguishedName)'; no creation was needed."
}

function ConvertTo-PlainTextFromSecureString {
    param(
        [Parameter(Mandatory)]
        [SecureString]$SecureString
    )

    $passwordPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
}

function Get-AccountPassword {
    param(
        [string]$Username,
        [SecureString]$PasswordValue,
        [string]$PasswordPatternValue,
        [string]$PasswordToken,
        [switch]$WhatIfMode
    )

    if ($PasswordValue) {
        return $PasswordValue
    }

    if ($PasswordPatternValue) {
        $patternText = Resolve-PasswordPatternText -Pattern $PasswordPatternValue -Username $Username -Token $PasswordToken
        if ([string]::IsNullOrWhiteSpace($patternText)) {
            throw "Password pattern for '$Username' resolved to an empty value. Supply a non-empty pattern or omit -PasswordPattern."
        }

        return (ConvertTo-SecureString $patternText -AsPlainText -Force)
    }

    if ($WhatIfMode) {
        return (ConvertTo-SecureString 'WhatIf-Preview-Password-Not-Used' -AsPlainText -Force)
    }

    $generatedPassword = New-RandomPassword -Length $randomPasswordLength
    return (ConvertTo-SecureString $generatedPassword -AsPlainText -Force)
}

function Test-ADProvisionedUser {
    param(
        [Parameter(Mandatory)]
        [psobject]$CreatedAccount,

        [Parameter(Mandatory)]
        [string]$ExpectedDepartment,

        [Parameter(Mandatory)]
        [string]$ExpectedUserPrincipalName,

        [Parameter(Mandatory)]
        [string]$ExpectedOrganizationalUnit,

        [string]$ExpectedGroupDistinguishedName,

        [switch]$RequireGroupMembership,

        [switch]$RequireEnabled,

        [switch]$RequirePasswordChangeAtLogon
    )

    $verifiedUser = Get-ADUser @adContext -Identity $CreatedAccount.DistinguishedName -Properties DistinguishedName, Department, UserPrincipalName, Enabled, pwdLastSet, MemberOf -ErrorAction Stop

    $issues = [System.Collections.Generic.List[string]]::new()

    if ($verifiedUser.DistinguishedName -ne $CreatedAccount.DistinguishedName) {
        $issues.Add("expected DistinguishedName '$($CreatedAccount.DistinguishedName)' but found '$($verifiedUser.DistinguishedName)'.")
    }

    # The account must sit DIRECTLY in the expected OU. Compare canonical parent DNs rather than doing a
    # text suffix match, which is fooled by escaped commas and differing escape styles.
    $actualParentDistinguishedName = Get-ADDistinguishedNameParent -DistinguishedName $verifiedUser.DistinguishedName
    if ((ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $actualParentDistinguishedName) -ne
        (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $ExpectedOrganizationalUnit)) {
        $issues.Add("expected the user to exist under '$ExpectedOrganizationalUnit' but found '$($verifiedUser.DistinguishedName)'.")
    }

    if ($verifiedUser.Department -ne $ExpectedDepartment) {
        $issues.Add("expected Department '$ExpectedDepartment' but found '$($verifiedUser.Department)'.")
    }

    if ($verifiedUser.UserPrincipalName -ne $ExpectedUserPrincipalName) {
        $issues.Add("expected UPN '$ExpectedUserPrincipalName' but found '$($verifiedUser.UserPrincipalName)'.")
    }

    if ($RequireEnabled -and -not $verifiedUser.Enabled) {
        $issues.Add('expected the account to be enabled.')
    }

    if ($RequirePasswordChangeAtLogon -and $verifiedUser.pwdLastSet -ne 0) {
        $issues.Add('expected ChangePasswordAtLogon to be enabled.')
    }

    if ($RequireGroupMembership) {
        $hasExpectedGroupMembership = $false
        $expectedGroupCanonical = ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $ExpectedGroupDistinguishedName
        foreach ($memberOfEntry in @($verifiedUser.MemberOf)) {
            if ((ConvertTo-ADCanonicalDistinguishedName -DistinguishedName ([string]$memberOfEntry)) -eq $expectedGroupCanonical) {
                $hasExpectedGroupMembership = $true
                break
            }
        }

        if (-not $hasExpectedGroupMembership) {
            $issues.Add("expected group membership in '$ExpectedGroupDistinguishedName'.")
        }
    }

    if ($issues.Count -gt 0) {
        throw "Provisioning verification failed for '$($CreatedAccount.SamAccountName)': $($issues -join ' ' )"
    }

    return $verifiedUser
}

function Enable-VerifiedProvisionedAccount {
    param(
        [Parameter(Mandatory)]
        [psobject]$CreatedAccount,

        [Parameter(Mandatory)]
        [string]$ExpectedDepartment,

        [Parameter(Mandatory)]
        [string]$ExpectedUserPrincipalName,

        [Parameter(Mandatory)]
        [string]$ExpectedOrganizationalUnit
    )

    if (-not $EnableAccountsAfterVerification) {
        return
    }

    $accountBeforeEnable = Get-ADUser @adContext -Identity $CreatedAccount.DistinguishedName -Properties Enabled -ErrorAction Stop
    if ($accountBeforeEnable.Enabled) {
        throw "Account '$($CreatedAccount.SamAccountName)' was expected to remain disabled until verification."
    }

    Enable-ADAccount @adContext -Identity $accountBeforeEnable -Confirm:$false -ErrorAction Stop
    $null = Test-ADProvisionedUser -CreatedAccount $CreatedAccount `
        -ExpectedDepartment $ExpectedDepartment `
        -ExpectedUserPrincipalName $ExpectedUserPrincipalName `
        -ExpectedOrganizationalUnit $ExpectedOrganizationalUnit `
        -RequireEnabled -RequirePasswordChangeAtLogon
    Write-ADProvisioningAuditRecord -Action 'EnableVerifiedAccount' `
        -Target $CreatedAccount.DistinguishedName `
        -TargetType 'User' `
        -Status 'Succeeded' `
        -Details "Enabled '$($CreatedAccount.SamAccountName)' only after provisioning attributes and membership were verified."
}

function Grant-DepartmentUserDelegation {
    param(
        [Parameter(Mandatory)][psobject]$Group,
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$ExpectedGroupParentDistinguishedName,
        [Parameter(Mandatory)][bool]$CreatedByThisRun,
        [Parameter(Mandatory)][string]$TargetOuDistinguishedName,
        [string]$DomainNetBIOSName = ''
    )

    $ouPath = "AD:\$TargetOuDistinguishedName"

    # Scoped OU delegation for the department user-object lifecycle role.
    # This intentionally excludes broad property-write access because attribute updates,
    # password resets, account unlocks, enable/disable operations, and other approved user
    # modifications should be handled explicitly and separately. The delegated group is
    # limited to creating, enumerating, reading, and deleting USER objects within the
    # department's Users OU by targeting the Active Directory User class GUID rather than
    # the empty object GUID that would apply to all child classes.
    $userClassGuid = [System.Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'

    $managedAccessRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    if ($WhatIfPreference) {
        Write-ADProvisioningAuditRecord -Action 'GrantDelegation' -Target $GroupName -TargetType 'Delegation' -Status 'Preview' -Details "WhatIf: would grant scoped user-object lifecycle delegation to '$GroupName' on '$TargetOuDistinguishedName'."
        Write-Host "WhatIf: would grant '$GroupName' scoped user-object lifecycle delegation on '$TargetOuDistinguishedName'." -ForegroundColor Yellow
        return
    }

    if (-not $PSCmdlet.ShouldProcess($TargetOuDistinguishedName, "Grant '$GroupName' OU-scoped user-object lifecycle delegation")) {
        Write-ADProvisioningAuditRecord -Action 'GrantDelegation' -Target $GroupName -TargetType 'Delegation' -Status 'Skipped' -Details "Delegation grant for '$GroupName' on '$TargetOuDistinguishedName' was not executed because ShouldProcess was declined."
        return
    }

    $groupSid = Get-ADValidatedSecurityGroupSid -Group $Group -ExpectedName $GroupName -ExpectedParentDistinguishedName $ExpectedGroupParentDistinguishedName
    $acl = Get-Acl -LiteralPath $ouPath -ErrorAction Stop
    $alreadyGranted = Test-ADUserLifecycleDelegation -AccessRules @($acl.Access) -GroupSid $groupSid
    Assert-ADUserLifecycleDelegationSafe -GroupSid $groupSid -CreatedByThisRun $CreatedByThisRun -ExistingDelegation $alreadyGranted

    if ($alreadyGranted) {
        Add-ResourceLedgerEntry -Type 'Delegation' -DistinguishedName $TargetOuDistinguishedName -Name $GroupName `
            -CreatedByThisRun $false -SecurityIdentifier $groupSid.Value
        Write-ADProvisioningAuditRecord -Action 'GrantDelegation' -Target $GroupName -TargetType 'Delegation' -Status 'Skipped' -Details "Delegation for '$GroupName' on '$TargetOuDistinguishedName' already existed with the scoped descendant User-class ACE; no changes were required."
        return
    }

    $childManagementRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $delegationRuleTypes = [System.Collections.Generic.List[string]]::new()
    $hasExactChildRule = @($acl.Access | Where-Object {
        $ruleSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $ruleSid -eq $groupSid.Value -and
        -not $_.IsInherited -and
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        $_.ActiveDirectoryRights -eq $childManagementRights -and
        $_.ObjectType -eq $userClassGuid -and
        $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None -and
        $_.InheritedObjectType -eq [Guid]::Empty
    }).Count -gt 0
    $hasExactDescendantRule = @($acl.Access | Where-Object {
        $ruleSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $ruleSid -eq $groupSid.Value -and
        -not $_.IsInherited -and
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        $_.ActiveDirectoryRights -eq $managedAccessRights -and
        $_.ObjectType -eq $userClassGuid -and
        $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents -and
        $_.InheritedObjectType -eq $userClassGuid
    }).Count -gt 0

    if (-not $hasExactChildRule) {
        $childManagementRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $groupSid,
            $childManagementRights,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $userClassGuid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
        )
        $acl.AddAccessRule($childManagementRule)
        $delegationRuleTypes.Add('ChildManagement')
    }

    if (-not $hasExactDescendantRule) {
        $descendantAccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $groupSid,
            $managedAccessRights,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $userClassGuid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
            $userClassGuid
        )
        $acl.AddAccessRule($descendantAccessRule)
        $delegationRuleTypes.Add('DescendantUserAccess')
    }

    Add-ResourceLedgerEntry -Type 'Delegation' -DistinguishedName $TargetOuDistinguishedName -Name $GroupName `
        -CreatedByThisRun $true -SecurityIdentifier $groupSid.Value -DelegationRuleTypes $delegationRuleTypes.ToArray()
    Set-Acl -LiteralPath $ouPath -AclObject $acl -ErrorAction Stop

    # Verify the grant landed instead of trusting that Set-Acl did not throw.
    $verifiedAcl = Get-Acl -LiteralPath $ouPath -ErrorAction Stop
    if (-not (Test-ADUserLifecycleDelegation -AccessRules @($verifiedAcl.Access) -GroupSid $groupSid)) {
        throw "Delegation for group '$GroupName' on '$TargetOuDistinguishedName' could not be verified after Set-Acl."
    }

    Write-ADProvisioningAuditRecord -Action 'GrantDelegation' -Target $GroupName -TargetType 'Delegation' -Status 'Succeeded' -Details "Granted scoped user-object lifecycle delegation to '$GroupName' on '$TargetOuDistinguishedName'."
    Write-Host "Delegated scoped user-object lifecycle rights to '$GroupName' on '$TargetOuDistinguishedName' (create/list/read/delete only; explicit attribute/control rights are intentionally excluded)." -ForegroundColor Yellow
}

function Write-DepartmentAttributeDelegationNotice {
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$TargetOuDistinguishedName
    )

    $noticeText = "Reserved attribute-management group '$GroupName' on '$TargetOuDistinguishedName' is intentionally not granted sensitive attribute rights automatically. This group is a placeholder for future explicit, reviewed delegation; do not assume it already has password-reset, enable/disable, unlock, or other privileged attribute-management access."

    if ($WhatIfPreference) {
        Write-Host "WhatIf: would display attribute-admin delegation guidance for '$GroupName' on '$TargetOuDistinguishedName'." -ForegroundColor Yellow
        return
    }

    if (-not $PSCmdlet.ShouldProcess($TargetOuDistinguishedName, "Show attribute-admin delegation guidance for '$GroupName'")) {
        return
    }

    Write-Host $noticeText -ForegroundColor Yellow
}

$departmentOUs = @{}
$departmentUserOUs = @{}
$departmentUserOUSimulated = @{}
$departmentAdministratorOUs = @{}
$departmentAdministratorOUSimulated = @{}
$departmentAdministratorGroups = @{}
$departmentAttributeAdministratorGroups = @{}
$departmentUserGroups = @{}
Write-Verbose "Preparing department-specific OUs, groups, and delegation for $($Departments.Count) departments."
foreach ($department in $Departments) {
    Write-Verbose "Processing department '$department'."
    $departmentOUName = $department
    $safeDepartmentOUName = ConvertTo-LdapFilterValue $departmentOUName

    $departmentOU = @(if (Test-SimulatedResource $staffNamesOrganizationalUnit) {
        @()
    }
    else {
        @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeDepartmentOUName)" `
            -SearchBase $staffNamesOrganizationalUnit.DistinguishedName -SearchScope OneLevel -ErrorAction Stop
        )
    })
    if ($departmentOU.Count -gt 1) { throw "More than one department OU named '$departmentOUName' was found below '$($staffNamesOrganizationalUnit.DistinguishedName)'." }

    if (-not $departmentOU) {
        Write-Verbose "Department OU '$departmentOUName' was not found under '$($staffNamesOrganizationalUnit.DistinguishedName)', so it will be created."
        if (-not $PSCmdlet.ShouldProcess("OU=$departmentOUName,$($staffNamesOrganizationalUnit.DistinguishedName)", 'Create department organizational unit')) {
            if (-not $WhatIfPreference) {
                throw "Department OU '$departmentOUName' was not created because the operation was not approved."
            }
        }

        if ($WhatIfPreference) {
            $departmentOU = New-SimulatedOU -Name $departmentOUName -ParentDistinguishedName $staffNamesOrganizationalUnit.DistinguishedName
        }
        else {
            $departmentOU = New-ADOrganizationalUnit @adContext -Name $departmentOUName `
                -Path $staffNamesOrganizationalUnit.DistinguishedName -Description $generatedOUDescription -ProtectedFromAccidentalDeletion $false -PassThru
            Write-Verbose "Created department OU '$departmentOUName' at '$($departmentOU.DistinguishedName)'."
            Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $departmentOU.DistinguishedName -Name $departmentOUName -CreatedByThisRun $true
            Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $departmentOU.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Succeeded' -Details "Created department organizational unit '$departmentOUName' under '$($staffNamesOrganizationalUnit.DistinguishedName)'."
        }
    }
    else {
        $departmentOU = @($departmentOU)[0]
        Write-Verbose "Department OU '$departmentOUName' already exists at '$($departmentOU.DistinguishedName)'."
        Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $departmentOU.DistinguishedName -Name $departmentOUName -CreatedByThisRun $false
        Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $departmentOU.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Skipped' -Details "Department OU '$departmentOUName' already existed under '$($staffNamesOrganizationalUnit.DistinguishedName)'; no creation was needed."
    }

    $departmentOUs[$department] = $departmentOU.DistinguishedName

    if (-not $AdministratorsOnly) {
        $departmentUsersOUName = 'Users'
        $safeDepartmentUsersOUName = ConvertTo-LdapFilterValue $departmentUsersOUName

        $departmentUsersOU = @(if (Test-SimulatedResource $departmentOU) {
            @()
        }
        else {
            @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeDepartmentUsersOUName)" `
                -SearchBase $departmentOU.DistinguishedName -SearchScope OneLevel -ErrorAction Stop
            )
        })
        if ($departmentUsersOU.Count -gt 1) { throw "More than one user OU named '$departmentUsersOUName' was found below '$($departmentOU.DistinguishedName)'." }

        if (-not $departmentUsersOU) {
            if (-not $PSCmdlet.ShouldProcess("OU=$departmentUsersOUName,$($departmentOU.DistinguishedName)", 'Create department users organizational unit')) {
                if (-not $WhatIfPreference) {
                    throw "User OU '$departmentUsersOUName' was not created because the operation was not approved."
                }
            }

            if ($WhatIfPreference) {
                $departmentUsersOU = New-SimulatedOU -Name $departmentUsersOUName -ParentDistinguishedName $departmentOU.DistinguishedName
            }
            else {
                $departmentUsersOU = New-ADOrganizationalUnit @adContext -Name $departmentUsersOUName `
                    -Path $departmentOU.DistinguishedName -Description $generatedOUDescription -ProtectedFromAccidentalDeletion $false -PassThru
                Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $departmentUsersOU.DistinguishedName -Name $departmentUsersOUName -CreatedByThisRun $true
                Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $departmentUsersOU.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Succeeded' -Details "Created department users OU '$departmentUsersOUName' under '$($departmentOU.DistinguishedName)'."
            }
        }
        else {
            $departmentUsersOU = @($departmentUsersOU)[0]
            Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $departmentUsersOU.DistinguishedName -Name $departmentUsersOUName -CreatedByThisRun $false
            Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $departmentUsersOU.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Skipped' -Details "Department users OU '$departmentUsersOUName' already existed under '$($departmentOU.DistinguishedName)'; no creation was needed."
        }

        $departmentUserOUs[$department] = $departmentUsersOU.DistinguishedName
        $departmentUserOUSimulated[$department] = Test-SimulatedResource $departmentUsersOU
    }

    if ($createDepartmentAdministrators) {
        $departmentAdministratorsOUName = 'Administrators'
        $safeDepartmentAdministratorsOUName = ConvertTo-LdapFilterValue $departmentAdministratorsOUName

        $departmentAdministratorsOU = @(if (Test-SimulatedResource $departmentOU) {
            @()
        }
        else {
            @(Get-ADOrganizationalUnit @adContext -LDAPFilter "(ou=$safeDepartmentAdministratorsOUName)" `
                -SearchBase $departmentOU.DistinguishedName -SearchScope OneLevel -ErrorAction Stop
            )
        })
        if ($departmentAdministratorsOU.Count -gt 1) { throw "More than one administrator OU named '$departmentAdministratorsOUName' was found below '$($departmentOU.DistinguishedName)'." }

        if (-not $departmentAdministratorsOU) {
            if (-not $PSCmdlet.ShouldProcess("OU=$departmentAdministratorsOUName,$($departmentOU.DistinguishedName)", 'Create department administrators organizational unit')) {
                if (-not $WhatIfPreference) {
                    throw "Administrator OU '$departmentAdministratorsOUName' was not created because the operation was not approved."
                }
            }

            if ($WhatIfPreference) {
                $departmentAdministratorsOU = New-SimulatedOU -Name $departmentAdministratorsOUName -ParentDistinguishedName $departmentOU.DistinguishedName
            }
            else {
                $departmentAdministratorsOU = New-ADOrganizationalUnit @adContext -Name $departmentAdministratorsOUName `
                    -Path $departmentOU.DistinguishedName -Description $generatedOUDescription -ProtectedFromAccidentalDeletion $false -PassThru
                Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $departmentAdministratorsOU.DistinguishedName -Name $departmentAdministratorsOUName -CreatedByThisRun $true
                Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $departmentAdministratorsOU.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Succeeded' -Details "Created department administrators OU '$departmentAdministratorsOUName' under '$($departmentOU.DistinguishedName)'."
            }
        }
        else {
            $departmentAdministratorsOU = @($departmentAdministratorsOU)[0]
            Add-ResourceLedgerEntry -Type 'OrganizationalUnit' -DistinguishedName $departmentAdministratorsOU.DistinguishedName -Name $departmentAdministratorsOUName -CreatedByThisRun $false
            Write-ADProvisioningAuditRecord -Action 'CreateOU' -Target $departmentAdministratorsOU.DistinguishedName -TargetType 'OrganizationalUnit' -Status 'Skipped' -Details "Department administrators OU '$departmentAdministratorsOUName' already existed under '$($departmentOU.DistinguishedName)'; no creation was needed."
        }

        $departmentAdministratorOUs[$department] = $departmentAdministratorsOU.DistinguishedName
        $departmentAdministratorOUSimulated[$department] = Test-SimulatedResource $departmentAdministratorsOU

        $departmentAdministratorGroupName = "${department}-Administrators"
        $safeDepartmentAdministratorGroupName = ConvertTo-LdapFilterValue $departmentAdministratorGroupName
        $departmentAdministratorGroupCreatedByThisRun = $false

        $departmentAdministratorGroup = @(if (Test-SimulatedResource $departmentAdministratorsOU) {
            @()
        }
        else {
            @(Get-ADGroup @adContext -LDAPFilter "(cn=$safeDepartmentAdministratorGroupName)" -Properties SID,GroupScope,GroupCategory `
                -SearchBase $departmentAdministratorsOU.DistinguishedName -SearchScope OneLevel -ErrorAction Stop
            )
        })
        if ($departmentAdministratorGroup.Count -gt 1) {
            throw "More than one administrator group named '$departmentAdministratorGroupName' was found below '$($departmentAdministratorsOU.DistinguishedName)'."
        }

        if (-not $departmentAdministratorGroup) {
            if (-not $PSCmdlet.ShouldProcess("$departmentAdministratorGroupName in $($departmentAdministratorsOU.DistinguishedName)", 'Create department administrator security group')) {
                if (-not $WhatIfPreference) {
                    throw "Administrator group '$departmentAdministratorGroupName' was not created because the operation was not approved."
                }
            }

            if ($WhatIfPreference) {
                $departmentAdministratorGroup = New-SimulatedGroup -Name $departmentAdministratorGroupName -ParentDistinguishedName $departmentAdministratorsOU.DistinguishedName
            }
            else {
                $createdAdministratorGroup = New-ADGroup @adContext -Name $departmentAdministratorGroupName `
                    -GroupScope Global -GroupCategory Security -Path $departmentAdministratorsOU.DistinguishedName -PassThru -ErrorAction Stop
                Add-ResourceLedgerEntry -Type 'Group' -DistinguishedName $createdAdministratorGroup.DistinguishedName -Name $departmentAdministratorGroupName -CreatedByThisRun $true
                $departmentAdministratorGroup = Get-ADGroup @adContext -Identity $createdAdministratorGroup.DistinguishedName `
                    -Properties SID,GroupScope,GroupCategory -ErrorAction Stop
                $departmentAdministratorGroupCreatedByThisRun = $true
                Write-ADProvisioningAuditRecord -Action 'CreateGroup' -Target $departmentAdministratorGroup.DistinguishedName -TargetType 'Group' -Status 'Succeeded' -Details "Created department administrator group '$departmentAdministratorGroupName' in '$($departmentAdministratorsOU.DistinguishedName)'."
            }
        }
        else {
            Add-ResourceLedgerEntry -Type 'Group' -DistinguishedName (@($departmentAdministratorGroup)[0].DistinguishedName) -Name $departmentAdministratorGroupName -CreatedByThisRun $false
            Write-ADProvisioningAuditRecord -Action 'CreateGroup' -Target (@($departmentAdministratorGroup)[0].DistinguishedName) -TargetType 'Group' -Status 'Skipped' -Details "Department administrator group '$departmentAdministratorGroupName' already existed in '$($departmentAdministratorsOU.DistinguishedName)'; no creation was needed."
        }

        $departmentAdministratorGroups[$department] = @($departmentAdministratorGroup)[0]

        $departmentAttributeAdministratorGroupName = "${department}-Attribute-Admins"
        $safeDepartmentAttributeAdministratorGroupName = ConvertTo-LdapFilterValue $departmentAttributeAdministratorGroupName

        $departmentAttributeAdministratorGroup = @(if (Test-SimulatedResource $departmentAdministratorsOU) {
            @()
        }
        else {
            @(Get-ADGroup @adContext -LDAPFilter "(cn=$safeDepartmentAttributeAdministratorGroupName)" `
                -SearchBase $departmentAdministratorsOU.DistinguishedName -SearchScope OneLevel -ErrorAction Stop
            )
        })
        if ($departmentAttributeAdministratorGroup.Count -gt 1) {
            throw "More than one attribute-admin group named '$departmentAttributeAdministratorGroupName' was found below '$($departmentAdministratorsOU.DistinguishedName)'."
        }

        if (-not $departmentAttributeAdministratorGroup) {
            if (-not $PSCmdlet.ShouldProcess("$departmentAttributeAdministratorGroupName in $($departmentAdministratorsOU.DistinguishedName)", 'Create department attribute-administrator security group')) {
                if (-not $WhatIfPreference) {
                    throw "Attribute-admin group '$departmentAttributeAdministratorGroupName' was not created because the operation was not approved."
                }
            }

            if ($WhatIfPreference) {
                $departmentAttributeAdministratorGroup = New-SimulatedGroup -Name $departmentAttributeAdministratorGroupName -ParentDistinguishedName $departmentAdministratorsOU.DistinguishedName
            }
            else {
                $departmentAttributeAdministratorGroup = New-ADGroup @adContext -Name $departmentAttributeAdministratorGroupName `
                    -GroupScope Global -GroupCategory Security -Path $departmentAdministratorsOU.DistinguishedName -PassThru
                Add-ResourceLedgerEntry -Type 'Group' -DistinguishedName $departmentAttributeAdministratorGroup.DistinguishedName -Name $departmentAttributeAdministratorGroupName -CreatedByThisRun $true
                Write-ADProvisioningAuditRecord -Action 'CreateGroup' -Target $departmentAttributeAdministratorGroup.DistinguishedName -TargetType 'Group' -Status 'Succeeded' -Details "Created department attribute-administrator group '$departmentAttributeAdministratorGroupName' in '$($departmentAdministratorsOU.DistinguishedName)'."
            }
        }
        else {
            Add-ResourceLedgerEntry -Type 'Group' -DistinguishedName (@($departmentAttributeAdministratorGroup)[0].DistinguishedName) -Name $departmentAttributeAdministratorGroupName -CreatedByThisRun $false
            Write-ADProvisioningAuditRecord -Action 'CreateGroup' -Target (@($departmentAttributeAdministratorGroup)[0].DistinguishedName) -TargetType 'Group' -Status 'Skipped' -Details "Department attribute-administrator group '$departmentAttributeAdministratorGroupName' already existed in '$($departmentAdministratorsOU.DistinguishedName)'; no creation was needed."
        }

        $departmentAttributeAdministratorGroups[$department] = @($departmentAttributeAdministratorGroup)[0]

        if (-not $AdministratorsOnly) {
            Grant-DepartmentUserDelegation -Group $departmentAdministratorGroups[$department] `
                -GroupName $departmentAdministratorGroupName `
                -ExpectedGroupParentDistinguishedName $departmentAdministratorsOU.DistinguishedName `
                -CreatedByThisRun $departmentAdministratorGroupCreatedByThisRun `
                -TargetOuDistinguishedName $departmentUserOUs[$department] -DomainNetBIOSName $domainNetBIOSName
            Write-DepartmentAttributeDelegationNotice -GroupName $departmentAttributeAdministratorGroupName -TargetOuDistinguishedName $departmentUserOUs[$department]
        }
    }

    if (-not $AdministratorsOnly) {
        $departmentUserGroupName = "${department}-Users"
        $safeDepartmentUserGroupName = ConvertTo-LdapFilterValue $departmentUserGroupName

        $departmentUserGroup = @(if (Test-SimulatedResource $departmentUsersOU) {
            @()
        }
        else {
            @(Get-ADGroup @adContext -LDAPFilter "(cn=$safeDepartmentUserGroupName)" `
                -SearchBase $departmentUserOUs[$department] -SearchScope OneLevel -ErrorAction Stop
            )
        })
        if ($departmentUserGroup.Count -gt 1) {
            throw "More than one user group named '$departmentUserGroupName' was found below '$($departmentUserOUs[$department])'."
        }

        if (-not $departmentUserGroup) {
            if (-not $PSCmdlet.ShouldProcess("$departmentUserGroupName in $($departmentUserOUs[$department])", 'Create department users security group')) {
                if (-not $WhatIfPreference) {
                    throw "User group '$departmentUserGroupName' was not created because the operation was not approved."
                }
            }

            if ($WhatIfPreference) {
                $departmentUserGroup = New-SimulatedGroup -Name $departmentUserGroupName -ParentDistinguishedName $departmentUserOUs[$department]
            }
            else {
                $departmentUserGroup = New-ADGroup @adContext -Name $departmentUserGroupName `
                    -GroupScope Global -GroupCategory Security -Path $departmentUserOUs[$department] -PassThru
                Add-ResourceLedgerEntry -Type 'Group' -DistinguishedName $departmentUserGroup.DistinguishedName -Name $departmentUserGroupName -CreatedByThisRun $true
                Write-ADProvisioningAuditRecord -Action 'CreateGroup' -Target $departmentUserGroup.DistinguishedName -TargetType 'Group' -Status 'Succeeded' -Details "Created department user group '$departmentUserGroupName' in '$($departmentUserOUs[$department])'."
            }
        }
        else {
            Add-ResourceLedgerEntry -Type 'Group' -DistinguishedName (@($departmentUserGroup)[0].DistinguishedName) -Name $departmentUserGroupName -CreatedByThisRun $false
            Write-ADProvisioningAuditRecord -Action 'CreateGroup' -Target (@($departmentUserGroup)[0].DistinguishedName) -TargetType 'Group' -Status 'Skipped' -Details "Department user group '$departmentUserGroupName' already existed in '$($departmentUserOUs[$department])'; no creation was needed."
        }

        $departmentUserGroups[$department] = @($departmentUserGroup)[0]
    }
}

function Find-ExistingProvisionedUser {
    param(
        [Parameter(Mandatory)][string]$GivenName,
        [Parameter(Mandatory)][string]$Surname,
        [Parameter(Mandatory)][string]$Department,
        [Parameter(Mandatory)][string]$SearchBase
    )

    $ldapFilter = '(&(objectCategory=person)(objectClass=user)(givenName={0})(sn={1})(department={2}))' -f `
        (ConvertTo-LdapFilterValue -Value $GivenName),
        (ConvertTo-LdapFilterValue -Value $Surname),
        (ConvertTo-LdapFilterValue -Value $Department)

    # Not named $matches: that is a PowerShell automatic variable.
    $foundUsers = @(Get-ADUser @adContext -LDAPFilter $ldapFilter -SearchBase $SearchBase -SearchScope OneLevel -Properties SamAccountName,DistinguishedName,GivenName,Surname,Department -ErrorAction Stop)
    if ($foundUsers.Count -eq 0) {
        return $null
    }

    # Always index a real array: [0] on a single ADUser object is not an element lookup.
    return @($foundUsers | Sort-Object DistinguishedName)[0]
}

function Find-ExistingProvisionedAdministrator {
    param(
        [Parameter(Mandatory)][string]$Department,
        [Parameter(Mandatory)][string]$SearchBase,
        [string]$PreferredUsername = ''
    )

    $departmentFilterValue = ConvertTo-LdapFilterValue -Value $Department
    if (-not [string]::IsNullOrWhiteSpace($PreferredUsername)) {
        $ldapFilter = '(&(objectCategory=person)(objectClass=user)(department={0})(sAMAccountName={1}))' -f $departmentFilterValue, (ConvertTo-LdapFilterValue -Value $PreferredUsername)
    }
    else {
        $ldapFilter = '(&(objectCategory=person)(objectClass=user)(department={0})(|(displayName=*Administrator*)(name=*Administrator*)))' -f $departmentFilterValue
    }
    $foundAdministrators = @(Get-ADUser @adContext -LDAPFilter $ldapFilter -SearchBase $SearchBase -SearchScope OneLevel -Properties SamAccountName,DistinguishedName,GivenName,Surname,Department,DisplayName -ErrorAction Stop)

    if ($foundAdministrators.Count -eq 0) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($PreferredUsername)) {
        $preferredMatches = @($foundAdministrators | Where-Object { $_.SamAccountName -ieq $PreferredUsername })
        if ($preferredMatches.Count -gt 0) { return $preferredMatches[0] }
    }

    return @($foundAdministrators | Sort-Object DistinguishedName)[0]
}

$usedSamAccountNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# Preload domain-wide SAM account names so generated names avoid collisions with
# existing AD objects outside the managed Company subtree, including users,
# groups, contacts, computers, and other security principals that may already
# hold a sAMAccountName.
$existingSamAccountNames = @(
    Get-ADObject @adContext -LDAPFilter '(sAMAccountName=*)' -SearchBase $domainRoot -SearchScope Subtree -Properties SamAccountName -ErrorAction Stop |
        Where-Object { $_.SamAccountName } |
        ForEach-Object { $_.SamAccountName }
)
foreach ($existingSamAccountName in $existingSamAccountNames) {
    if (-not [string]::IsNullOrWhiteSpace($existingSamAccountName)) {
        [void]$usedSamAccountNames.Add($existingSamAccountName)
    }
}

$resolvedDepartmentAdministratorSamAccountNames = [ordered]@{}
$preferredDepartmentAdministratorSamAccountNames = [ordered]@{}
# Only reserve administrator names when administrators will actually be created.
if ($createDepartmentAdministrators) {
    foreach ($department in $Departments) {
        $adminUsernameTemplate = if ($AdministratorUsername) {
            if ($AdministratorUsername.Contains('{0}')) {
                $AdministratorUsername -f $department
            }
            else {
                $AdministratorUsername
            }
        }
        else {
            "$($department.ToLowerInvariant()).admin"
        }

        $preferredAdminUsername = Get-UniqueSamAccountName -BaseName $adminUsernameTemplate -UsedNames ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase))
        $adminUsername = Get-UniqueSamAccountName -BaseName $adminUsernameTemplate -UsedNames $usedSamAccountNames
        $preferredDepartmentAdministratorSamAccountNames[$department] = $preferredAdminUsername
        $resolvedDepartmentAdministratorSamAccountNames[$department] = $adminUsername
    }

    $adminNameSummary = ($resolvedDepartmentAdministratorSamAccountNames.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
    Write-Verbose "Preflight department administrator SAM account names: $adminNameSummary"
}

$createdCount = 0
$failedCount = 0
$partialCount = 0
$skippedCount = 0
$createdAdminCount = 0
$departmentTotals = @{}
foreach ($department in $Departments) {
    $departmentTotals[$department] = 0
}
$startTime = Get-Date
$rollbackTriggered = $false

try {
    if ($createDepartmentAdministrators) {
    foreach ($department in $Departments) {
        Write-Verbose "Preparing department administrator for '$department'."
        $adminUsername = $resolvedDepartmentAdministratorSamAccountNames[$department]
        $existingAdministrator = if ($departmentAdministratorOUSimulated[$department]) {
            $null
        }
        else {
            Find-ExistingProvisionedAdministrator -Department $department -SearchBase $departmentAdministratorOUs[$department] -PreferredUsername $preferredDepartmentAdministratorSamAccountNames[$department]
        }
        if (-not $existingAdministrator -and -not $departmentAdministratorOUSimulated[$department] -and $adminUsername -ine $preferredDepartmentAdministratorSamAccountNames[$department]) {
            $existingAdministrator = Find-ExistingProvisionedAdministrator -Department $department -SearchBase $departmentAdministratorOUs[$department] -PreferredUsername $adminUsername
        }
        if ($existingAdministrator) {
            $skippedCount++
            $reportRecords.Add([pscustomobject]@{
                    Username = $existingAdministrator.SamAccountName
                    FullName = "$department Administrator"
                    Department = $department
                    Role = 'Administrator'
                    OU = $departmentAdministratorOUs[$department]
                    Status = 'Skipped'
                    Stage = 'ExistingUserDetected'
                    CreatedAt = Get-Date
                    ErrorCategory = ''
                    Error = "Existing administrator '$($existingAdministrator.SamAccountName)' was detected; no duplicate account was created."
                    Password = ''
                })
            Write-Verbose "Skipping department administrator for '$department': existing account '$($existingAdministrator.SamAccountName)' already exists."
            continue
        }

        $adminPassword = if ($AdministratorPasswordPattern) {
            Get-AccountPassword -Username $adminUsername -PasswordValue $Password -PasswordPatternValue $AdministratorPasswordPattern -WhatIfMode:$WhatIfPreference
        }
        else {
            Get-AccountPassword -Username $adminUsername -PasswordValue $Password -PasswordPatternValue $null -WhatIfMode:$WhatIfPreference
        }

        $adminHadPartialFailure = $false
        $createdAccountRecord = $null
        $createdAdminAccount = $null
        $adminPlainTextPasswordForReport = ''
        try {
            Write-Verbose "Creating department administrator '$adminUsername' in '$($departmentAdministratorOUs[$department])'."
            if ($PSCmdlet.ShouldProcess($adminUsername, 'Create department administrator user')) {
                $createdAdminAccount = New-ADUser @adContext -SamAccountName $adminUsername `
                           -UserPrincipalName "$adminUsername@$effectiveUPNSuffix" `
                           -AccountPassword $adminPassword `
                           -GivenName ($department.ToUpperInvariant() + 'Admin') `
                           -Surname 'Administrator' `
                           -DisplayName "$department Administrator" `
                           -Name $adminUsername `
                           -Department $department `
                           -CannotChangePassword:$false `
                           -PasswordNeverExpires:$false `
                           -ChangePasswordAtLogon:$true `
                           -Path $departmentAdministratorOUs[$department] `
                           -Enabled (-not $EnableAccountsAfterVerification) `
                           -PassThru `
                           -ErrorAction Stop

                if ($createdAdminAccount) {
                $createdAccountRecord = [pscustomobject]@{
                    SamAccountName = $adminUsername
                    DistinguishedName = $createdAdminAccount.DistinguishedName
                }
                $createdAccounts.Add($createdAccountRecord)
                Add-ResourceLedgerEntry -Type 'User' -DistinguishedName $createdAdminAccount.DistinguishedName -Name $adminUsername -CreatedByThisRun $true

                if ($adminPassword) {
                    $adminPasswordExportValue = ConvertFrom-SecureString -SecureString $adminPassword
                    if ($IncludePasswordInReport) {
                        $adminPlainTextPasswordForReport = ConvertTo-PlainTextFromSecureString -SecureString $adminPassword
                    }
                    $adminPassword = $null

                    if ($PasswordFile) {
                        $passwordRecords.Add([pscustomobject]@{ Username=$adminUsername; Password=$adminPasswordExportValue; Department=$department; Role='Administrator'; CreatedAt=Get-Date })
                    }
                }
                }

                $reportRecord = [pscustomobject]@{
                    Username = $adminUsername
                    FullName = "$department Administrator"
                    Department = $department
                    Role = 'Administrator'
                    OU = $departmentAdministratorOUs[$department]
                    Status = 'Partial'
                    Stage = 'UserCreated'
                    CreatedAt = Get-Date
                    ErrorCategory = ''
                    Error = ''
                    Password = $adminPlainTextPasswordForReport
                }
                $reportRecords.Add($reportRecord)
                $adminPlainTextPasswordForReport = $null

                try {
                    $verifiedAdminAccount = Test-ADProvisionedUser -CreatedAccount $createdAdminAccount -ExpectedDepartment $department -ExpectedUserPrincipalName "$adminUsername@$effectiveUPNSuffix" -ExpectedOrganizationalUnit $departmentAdministratorOUs[$department] -RequireEnabled:(-not $EnableAccountsAfterVerification) -RequirePasswordChangeAtLogon
                    $reportRecord.Stage = 'UserVerified'
                    Write-ADProvisioningAuditRecord -Action 'VerifyUser' -Target $verifiedAdminAccount.DistinguishedName -TargetType 'User' -Status 'Succeeded' -Details "Verified department administrator '$adminUsername' exists in '$($departmentAdministratorOUs[$department])' with the expected UPN and department configuration."
                }
                catch {
                    $adminHadPartialFailure = $true
                    $partialCount++
                    $reportRecord.Stage = 'UserCreated'
                    $reportRecord.Status = 'Partial'
                    $reportRecord.ErrorCategory = 'UserVerificationFailed'
                    $reportRecord.Error = $_.Exception.Message

                    Write-ADProvisioningAuditRecord -Action 'VerifyUser' -Target $createdAdminAccount.DistinguishedName -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to verify department administrator '$adminUsername' in '$($departmentAdministratorOUs[$department])'."
                    Write-Warning "Failed to verify department administrator '$adminUsername' after creation [UserVerificationFailed]: $($_.Exception.Message)"

                    if ($RollbackCreatedAccountsOnFailure) {
                        Invoke-ProvisioningFailureRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords -RollbackTriggered ([ref]$rollbackTriggered) -Account $createdAccountRecord
                    }
                    throw
                }

                try {
                    Write-Verbose "Adding department administrator '$adminUsername' to group '$($departmentAdministratorGroups[$department].DistinguishedName)'."
                    Add-ADGroupMember @adContext -Identity $departmentAdministratorGroups[$department].DistinguishedName -Members $adminUsername -ErrorAction Stop
                    Write-ADProvisioningAuditRecord -Action 'AddGroupMember' -Target "$($createdAdminAccount.DistinguishedName) -> $($departmentAdministratorGroups[$department].DistinguishedName)" -TargetType 'GroupMembership' -Status 'Succeeded' -Details "Added administrator '$adminUsername' to department group '$($departmentAdministratorGroups[$department].Name)'."
                    $reportRecord.Stage = 'GroupMembershipAdded'

                    $verifiedAdminAccount = Test-ADProvisionedUser -CreatedAccount $createdAdminAccount -ExpectedDepartment $department -ExpectedUserPrincipalName "$adminUsername@$effectiveUPNSuffix" -ExpectedOrganizationalUnit $departmentAdministratorOUs[$department] -ExpectedGroupDistinguishedName $departmentAdministratorGroups[$department].DistinguishedName -RequireGroupMembership -RequireEnabled:(-not $EnableAccountsAfterVerification) -RequirePasswordChangeAtLogon
                    Enable-VerifiedProvisionedAccount -CreatedAccount $createdAdminAccount `
                        -ExpectedDepartment $department `
                        -ExpectedUserPrincipalName "$adminUsername@$effectiveUPNSuffix" `
                        -ExpectedOrganizationalUnit $departmentAdministratorOUs[$department]
                    $reportRecord.Stage = 'Completed'
                    $reportRecord.Status = 'Succeeded'
                    $createdAdminCount++
                    Write-ADProvisioningAuditRecord -Action 'VerifyGroupMembership' -Target "$($verifiedAdminAccount.DistinguishedName) -> $($departmentAdministratorGroups[$department].DistinguishedName)" -TargetType 'GroupMembership' -Status 'Succeeded' -Details "Verified administrator '$adminUsername' is present in department group '$($departmentAdministratorGroups[$department].Name)'."
                    Write-Host "Created department administrator: $adminUsername | UPN: $adminUsername@$effectiveUPNSuffix | Department: $department | Group: $($departmentAdministratorGroups[$department].Name)" -ForegroundColor Yellow
                }
                catch {
                    $adminHadPartialFailure = $true
                    $partialCount++
                    $reportRecord.Stage = 'GroupMembershipFailed'
                    $reportRecord.Status = 'Partial'
                    $reportRecord.ErrorCategory = 'GroupMembershipFailed'
                    $reportRecord.Error = $_.Exception.Message

                    Write-ADProvisioningAuditRecord -Action 'AddGroupMember' -Target "$($createdAdminAccount.DistinguishedName) -> $($departmentAdministratorGroups[$department].DistinguishedName)" -TargetType 'GroupMembership' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to add administrator '$adminUsername' to department group '$($departmentAdministratorGroups[$department].Name)'."
                    Write-Warning "Failed to add administrator '$adminUsername' to department group '$($departmentAdministratorGroups[$department].Name)' [GroupMembershipFailed]: $($_.Exception.Message)"

                    if ($RollbackCreatedAccountsOnFailure) {
                        Invoke-ProvisioningFailureRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords -RollbackTriggered ([ref]$rollbackTriggered) -Account $createdAccountRecord
                    }
                    throw
                }
            }
            else {
                $skippedCount++
                $reportRecords.Add([pscustomobject]@{
                        Username = $adminUsername
                        FullName = "$department Administrator"
                        Department = $department
                        Role = 'Administrator'
                        OU = $departmentAdministratorOUs[$department]
                        Status = 'Preview'
                        Stage = 'Preview'
                        CreatedAt = Get-Date
                        ErrorCategory = ''
                        Error = 'WhatIf preview: account creation, verification, and group membership were not executed.'
                        Password = ''
                    })
                Write-ADProvisioningAuditRecord -Action 'CreateUser' -Target $adminUsername -TargetType 'User' -Status 'Preview' -Details "WhatIf: would create department administrator '$adminUsername' in '$($departmentAdministratorOUs[$department])' and add it to '$($departmentAdministratorGroups[$department].Name)'."
            }
        }
        catch {
            if ($adminHadPartialFailure) {
                Write-Verbose "Preserving post-creation partial failure for '$adminUsername'; this is not counted as a user-creation failure."
                continue
            }

            $failedCount++
            $errorCategory = Get-ADFailureCategory -ErrorRecord $_
            $errorDetails = Get-ADCreateFailureDetails -Username $adminUsername -ErrorCategory $errorCategory -OriginalMessage $_.Exception.Message
            Write-ADProvisioningAuditRecord -Action 'CreateUser' -Target $adminUsername -TargetType 'User' -Status 'Failed' -Message $errorDetails -Details "Failed to create department administrator '$adminUsername' in '$($departmentAdministratorOUs[$department])'."
            $reportRecords.Add([pscustomobject]@{
                Username = $adminUsername
                FullName = "$department Administrator"
                Department = $department
                Role = 'Administrator'
                OU = $departmentAdministratorOUs[$department]
                Status = 'Failed'
                Stage = 'UserCreationFailed'
                CreatedAt = Get-Date
                ErrorCategory = $errorCategory
                Error = $errorDetails
                Password = ''
            })
            Write-Warning "Failed to create department administrator '$adminUsername' [$errorCategory]: $errorDetails"

            continue
        }
    }
}

for ($count = 1; $count -le $usersToCreate; $count++) {
    $name = $nameRecords[$count - 1]
    $firstName = $name.FirstName
    $lastName = $name.LastName
    $fullName = "$firstName $lastName"
    $department = $Departments[($count - 1) % $Departments.Count]
    if ([string]::IsNullOrWhiteSpace($firstName) -or [string]::IsNullOrWhiteSpace($lastName)) {
        Write-Warning "Skipping name with no usable username characters: '$firstName $lastName'"
        $skippedCount++
        continue
    }

    $existingUser = if ($departmentUserOUSimulated[$department]) {
        $null
    }
    else {
        Find-ExistingProvisionedUser -GivenName $firstName -Surname $lastName -Department $department -SearchBase $departmentUserOUs[$department]
    }
    if ($existingUser) {
        $skippedCount++
        $reportRecords.Add([pscustomobject]@{
                Username = $existingUser.SamAccountName
                FullName = $fullName
                Department = $department
                Role = 'User'
                OU = $departmentUserOUs[$department]
                Status = 'Skipped'
                Stage = 'ExistingUserDetected'
                CreatedAt = Get-Date
                ErrorCategory = ''
                Error = "Existing user '$($existingUser.SamAccountName)' matched '$fullName'; no duplicate account was created."
                Password = ''
            })
        Write-Verbose "Skipping '$fullName': existing user '$($existingUser.SamAccountName)' already exists in '$($departmentUserOUs[$department])'."
        continue
    }

    # A name with no Latin letters (for example only digits or non-Latin script) cannot yield a SAM name.
    # Skip that one entry instead of letting the exception abort the whole run mid-way.
    try {
        $username = Get-UniqueSamAccountName -BaseName "$firstName.$lastName" -UsedNames $usedSamAccountNames
    }
    catch {
        $skippedCount++
        $nameError = $_.Exception.Message
        $reportRecords.Add([pscustomobject]@{
                Username = ''
                FullName = $fullName
                Department = $department
                Role = 'User'
                OU = $departmentUserOUs[$department]
                Status = 'Skipped'
                Stage = 'InvalidName'
                CreatedAt = Get-Date
                ErrorCategory = 'InvalidName'
                Error = $nameError
                Password = ''
            })
        Write-Warning "Skipping '$fullName': $nameError"
        continue
    }

    $accountPassword = Get-AccountPassword -Username $username -PasswordValue $Password -PasswordPatternValue $PasswordPattern -PasswordToken $count -WhatIfMode:$WhatIfPreference
    Write-Progress -Activity 'Creating Active Directory users' -Status $username -PercentComplete (($count / $usersToCreate) * 100)
    Write-Verbose "Creating user #$count/$usersToCreate for '$fullName' ($username) in department '$department'."

    $userHadPartialFailure = $false
    $createdAccountRecord = $null
    $createdAccount = $null
    $userPlainTextPasswordForReport = ''
    try {
        if ($PSCmdlet.ShouldProcess($username, 'Create Active Directory user')) {
            $createdAccount = New-ADUser @adContext -SamAccountName $username `
                       -UserPrincipalName "$username@$effectiveUPNSuffix" `
                       -AccountPassword $accountPassword `
                       -GivenName $firstName `
                       -Surname $lastName `
                       -DisplayName $fullName `
                       -Name $username `
                       -Department $department `
                       -CannotChangePassword:$false `
                       -PasswordNeverExpires:$false `
                       -ChangePasswordAtLogon:$true `
                       -Path $departmentUserOUs[$department] `
                       -Enabled (-not $EnableAccountsAfterVerification) `
                       -PassThru `
                       -ErrorAction Stop
            if ($createdAccount) {
                $createdAccountRecord = [pscustomobject]@{
                    SamAccountName = $username
                    DistinguishedName = $createdAccount.DistinguishedName
                }
                $createdAccounts.Add($createdAccountRecord)
                Add-ResourceLedgerEntry -Type 'User' -DistinguishedName $createdAccount.DistinguishedName -Name $username -CreatedByThisRun $true

                if ($accountPassword) {
                    $accountPasswordExportValue = ConvertFrom-SecureString -SecureString $accountPassword
                    if ($IncludePasswordInReport) {
                        $userPlainTextPasswordForReport = ConvertTo-PlainTextFromSecureString -SecureString $accountPassword
                    }
                    $accountPassword = $null

                    if ($PasswordFile) {
                        $passwordRecords.Add([pscustomobject]@{ Username=$username; Password=$accountPasswordExportValue; Department=$department; Role='User'; CreatedAt=Get-Date })
                    }
                }

                Write-ADProvisioningAuditRecord -Action 'CreateUser' -Target $createdAccount.DistinguishedName -TargetType 'User' -Status 'Succeeded' -Details "Created user '$username' in '$($departmentUserOUs[$department])'."
            }
            $reportRecord = [pscustomobject]@{
                Username = $username
                FullName = $fullName
                Department = $department
                Role = 'User'
                OU = $departmentUserOUs[$department]
                Status = 'Partial'
                Stage = 'UserCreated'
                CreatedAt = Get-Date
                ErrorCategory = ''
                Error = ''
                Password = $userPlainTextPasswordForReport
            }
            $userPlainTextPasswordForReport = $null
            $reportRecords.Add($reportRecord)

            try {
                $verifiedAccount = Test-ADProvisionedUser -CreatedAccount $createdAccount -ExpectedDepartment $department -ExpectedUserPrincipalName "$username@$effectiveUPNSuffix" -ExpectedOrganizationalUnit $departmentUserOUs[$department] -RequireEnabled:(-not $EnableAccountsAfterVerification) -RequirePasswordChangeAtLogon
                $reportRecord.Stage = 'UserVerified'
                Write-ADProvisioningAuditRecord -Action 'VerifyUser' -Target $verifiedAccount.DistinguishedName -TargetType 'User' -Status 'Succeeded' -Details "Verified user '$username' exists in '$($departmentUserOUs[$department])' with the expected UPN and department configuration."
            }
            catch {
                $userHadPartialFailure = $true
                $partialCount++
                $reportRecord.Stage = 'UserCreated'
                $reportRecord.Status = 'Partial'
                $reportRecord.ErrorCategory = 'UserVerificationFailed'
                $reportRecord.Error = $_.Exception.Message

                Write-ADProvisioningAuditRecord -Action 'VerifyUser' -Target $createdAccount.DistinguishedName -TargetType 'User' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to verify user '$username' in '$($departmentUserOUs[$department])'."
                Write-Warning "Failed to verify user '$username' after creation [UserVerificationFailed]: $($_.Exception.Message)"

                if ($RollbackCreatedAccountsOnFailure) {
                    Invoke-ProvisioningFailureRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords -RollbackTriggered ([ref]$rollbackTriggered) -Account $createdAccountRecord
                }
                throw
            }

            try {
                Write-Verbose "Adding user '$username' to department group '$($departmentUserGroups[$department].DistinguishedName)'."
                Add-ADGroupMember @adContext -Identity $departmentUserGroups[$department].DistinguishedName -Members $username -ErrorAction Stop
                Write-ADProvisioningAuditRecord -Action 'AddGroupMember' -Target "$($createdAccount.DistinguishedName) -> $($departmentUserGroups[$department].DistinguishedName)" -TargetType 'GroupMembership' -Status 'Succeeded' -Details "Added user '$username' to department group '$($departmentUserGroups[$department].Name)'."
                $reportRecord.Stage = 'GroupMembershipAdded'

                $verifiedAccount = Test-ADProvisionedUser -CreatedAccount $createdAccount -ExpectedDepartment $department -ExpectedUserPrincipalName "$username@$effectiveUPNSuffix" -ExpectedOrganizationalUnit $departmentUserOUs[$department] -ExpectedGroupDistinguishedName $departmentUserGroups[$department].DistinguishedName -RequireGroupMembership -RequireEnabled:(-not $EnableAccountsAfterVerification) -RequirePasswordChangeAtLogon
                Enable-VerifiedProvisionedAccount -CreatedAccount $createdAccount `
                    -ExpectedDepartment $department `
                    -ExpectedUserPrincipalName "$username@$effectiveUPNSuffix" `
                    -ExpectedOrganizationalUnit $departmentUserOUs[$department]
                $reportRecord.Stage = 'Completed'
                $reportRecord.Status = 'Succeeded'
                $createdCount++
                $departmentTotals[$department]++
                Write-ADProvisioningAuditRecord -Action 'VerifyGroupMembership' -Target "$($verifiedAccount.DistinguishedName) -> $($departmentUserGroups[$department].DistinguishedName)" -TargetType 'GroupMembership' -Status 'Succeeded' -Details "Verified user '$username' is present in department group '$($departmentUserGroups[$department].Name)'."
                Write-Host "Created #${count}: $fullName | Logon: $username | UPN: $username@$effectiveUPNSuffix | Department: $department" -ForegroundColor Cyan
            }
            catch {
                $userHadPartialFailure = $true
                $partialCount++
                $reportRecord.Stage = 'GroupMembershipFailed'
                $reportRecord.Status = 'Partial'
                $reportRecord.ErrorCategory = 'GroupMembershipFailed'
                $reportRecord.Error = $_.Exception.Message

                Write-ADProvisioningAuditRecord -Action 'AddGroupMember' -Target "$($createdAccount.DistinguishedName) -> $($departmentUserGroups[$department].DistinguishedName)" -TargetType 'GroupMembership' -Status 'Failed' -Message $_.Exception.Message -Details "Failed to add user '$username' to department group '$($departmentUserGroups[$department].Name)'."
                Write-Warning "Failed to add '$username' to department group '$($departmentUserGroups[$department].Name)' [GroupMembershipFailed]: $($_.Exception.Message)"

                if ($RollbackCreatedAccountsOnFailure) {
                    Invoke-ProvisioningFailureRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords -RollbackTriggered ([ref]$rollbackTriggered) -Account $createdAccountRecord
                }
                throw
            }
        }
        else {
            $skippedCount++
            $reportRecords.Add([pscustomobject]@{
                    Username = $username
                    FullName = $fullName
                    Department = $department
                    Role = 'User'
                    OU = $departmentUserOUs[$department]
                    Status = 'Preview'
                    Stage = 'Preview'
                    CreatedAt = Get-Date
                    ErrorCategory = ''
                    Error = 'WhatIf preview: account creation, verification, and group membership were not executed.'
                    Password = ''
                })
            Write-ADProvisioningAuditRecord -Action 'CreateUser' -Target $username -TargetType 'User' -Status 'Preview' -Details "WhatIf: would create user '$username' in '$($departmentUserOUs[$department])' and add it to '$($departmentUserGroups[$department].Name)'."
        }
    }
    catch {
        if ($userHadPartialFailure) {
            Write-Verbose "Preserving post-creation partial failure for '$username'; this is not counted as a user-creation failure."
            continue
        }

        $failedCount++
        $errorCategory = Get-ADFailureCategory -ErrorRecord $_
        $errorDetails = Get-ADCreateFailureDetails -Username $username -ErrorCategory $errorCategory -OriginalMessage $_.Exception.Message
        Write-ADProvisioningAuditRecord -Action 'CreateUser' -Target $username -TargetType 'User' -Status 'Failed' -Message $errorDetails -Details "Failed to create user '$username' in '$($departmentUserOUs[$department])'."
        $reportRecords.Add([pscustomobject]@{
            Username = $username
            FullName = $fullName
            Department = $department
            Role = 'User'
            OU = $departmentUserOUs[$department]
            Status = 'Failed'
            Stage = 'UserCreationFailed'
            CreatedAt = Get-Date
            ErrorCategory = $errorCategory
            Error = $errorDetails
            Password = ''
        })
        Write-Warning "Failed to create '$username' [$errorCategory]: $errorDetails"

        continue
    }

    }
}
catch {
    if ($RollbackCreatedResourcesOnFailure) {
        Write-Host 'Full rollback is enabled. Removing run-created accounts, groups, exact delegation rules, and only empty marked OUs.' -ForegroundColor Yellow
        Invoke-ProvisioningResourceRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords
    }
    elseif ($RollbackCreatedAccountsOnFailure -and -not $rollbackTriggered) {
        Write-Host 'Account rollback is enabled. Removing only the user accounts created during this invocation; OUs, groups, and delegation changes are intentionally left in place.' -ForegroundColor Yellow
        Invoke-AccountRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords
    }
    elseif (-not $RollbackCreatedAccountsOnFailure) {
        Write-Host 'Account rollback is not enabled. Created user accounts will not be removed automatically, and OUs, groups, and delegation changes are left in place.' -ForegroundColor DarkGray
    }
    Write-ADProvisioningReport -OutputPath $ReportPath -Records $reportRecords -IncludePasswords:$IncludePasswordInReport
    throw
}

if ($RollbackCreatedResourcesOnFailure -and
    -not $script:ProvisioningResourceRollbackTriggered -and
    ($failedCount -gt 0 -or $partialCount -gt 0)) {
    Write-Host 'Provisioning reported failed or partial accounts. Full rollback is enabled; removing run-created resources.' -ForegroundColor Yellow
    Invoke-ProvisioningResourceRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords
    $remainingAccountNames = @($createdAccounts | ForEach-Object { $_.SamAccountName })
    $createdCount = @($reportRecords | Where-Object {
        $_.Role -eq 'User' -and $_.Username -in $remainingAccountNames
    }).Count
    $createdAdminCount = @($reportRecords | Where-Object {
        $_.Role -eq 'Administrator' -and $_.Username -in $remainingAccountNames
    }).Count
    foreach ($department in $Departments) {
        $departmentTotals[$department] = @($reportRecords | Where-Object {
            $_.Role -eq 'User' -and $_.Department -eq $department -and $_.Username -in $remainingAccountNames
        }).Count
    }
}

Write-Progress -Activity 'Creating Active Directory users' -Completed
if (-not $WhatIfPreference -and $ExportPasswords -and $PasswordFile -and $passwordRecords.Count -gt 0) {
    try {
        Write-Warning "Credential export requested. '$PasswordFile' contains DPAPI-protected credential material for the accounts created in this run. This is scoped to the current Windows user/machine context and is not a general-purpose encrypted password vault. Protect the file and limit access to authorized administrators only."
        Export-PasswordRecordsSecurely -Records $passwordRecords -Path $PasswordFile -Overwrite:$OverwritePasswordFile
        Write-Host "DPAPI-protected credential material saved to: $PasswordFile (intended for the same Windows user/machine context)." -ForegroundColor Yellow
    }
    catch {
        $exportError = $_
        Write-Warning "Credential export failed: $($exportError.Exception.Message)"
        if ($RollbackCreatedResourcesOnFailure) {
            Write-Host 'Full rollback is enabled. Removing run-created resources after credential export failed.' -ForegroundColor Yellow
            Invoke-ProvisioningResourceRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords
        }
        elseif ($RollbackCreatedAccountsOnFailure) {
            Write-Host 'Account rollback is enabled. Removing accounts because credential export did not complete.' -ForegroundColor Yellow
            Invoke-AccountRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords
        }
        else {
            Write-Host 'Account rollback is not enabled. Created accounts were retained after credential export failed.' -ForegroundColor DarkGray
        }
        Write-ADProvisioningReport -OutputPath $ReportPath -Records $reportRecords -IncludePasswords:$IncludePasswordInReport
        throw $exportError
    }
}

$totalCreated = $createdCount + $createdAdminCount
$auditStatus = if ($WhatIfPreference) {
    'Preview'
}
elseif ($failedCount -gt 0 -or $partialCount -gt 0) {
    'CompletedWithErrors'
}
elseif ($totalCreated -eq 0) {
    'Skipped'
}
else {
    'Succeeded'
}
Write-ADProvisioningAuditRecord -Action 'CreateUsers' -Target $OrganizationalUnitName -Status $auditStatus -Message "Created $createdCount user accounts and $createdAdminCount administrator accounts; failed $failedCount; partial $partialCount; skipped $skippedCount; requested $requestedAccountCount."
$auditStarted = $false

$executionTime = [DateTime]::Now - $startTime
$summaryLines = @(
    '========================================',
    ' Active Directory Provisioning Summary',
    '========================================',
    '',
    ("Requested users : {0}" -f $requestedAccountCount),
    ("Created         : {0}" -f $createdCount),
    ("Failed          : {0}" -f $failedCount),
    ("Partial         : {0}" -f $partialCount),
    ("Skipped         : {0}" -f $skippedCount),
    ("Created admins  : {0}" -f $createdAdminCount),
    '',
    ($Departments | ForEach-Object {
        "{0,-15} : {1}" -f $_, $departmentTotals[$_]
    }),
    '',
    ("Execution time  : {0:hh\:mm\:ss}" -f $executionTime),
    ("Total accounts  : {0}" -f $totalCreated),
    ("User/Admin split: {0}/{1}" -f $createdCount, $createdAdminCount),
    '',
    ($statusText = if ($WhatIfPreference) {
        'Status          : PREVIEW ONLY'
    }
    elseif ($failedCount -gt 0 -or $partialCount -gt 0) {
        'Status          : COMPLETED WITH ERRORS'
    }
    elseif ($totalCreated -eq 0) {
        'Status          : SKIPPED'
    }
    else {
        'Status          : SUCCESS'
    }),
    '========================================'
)

Write-Host ($summaryLines -join [Environment]::NewLine) -ForegroundColor Green
Write-ADProvisioningReport -OutputPath $ReportPath -Records $reportRecords -IncludePasswords:$IncludePasswordInReport
Write-Host "Completed. Created: $createdCount; Failed: $failedCount; Skipped: $skippedCount; Requested: $requestedAccountCount; Available names used: $AccountCount; Departments: $($Departments -join ', ')" -ForegroundColor Green
}
catch {
    # Any run-level failure after the 'Started' audit record must leave a terminal record.
    $runFailure = $_
    if ($RollbackCreatedResourcesOnFailure -and -not $script:ProvisioningResourceRollbackTriggered) {
        Write-Host 'Full rollback is enabled. Removing run-created accounts, groups, exact delegation rules, and only empty marked OUs.' -ForegroundColor Yellow
        try {
            Invoke-ProvisioningResourceRollback -CreatedAccounts $createdAccounts -ReportRecords $reportRecords
        }
        catch {
            Write-Warning "Full provisioning rollback encountered an unexpected error: $($_.Exception.Message)"
        }
    }
    if ($auditStarted) {
        try {
            Write-ADProvisioningAuditRecord -Action 'CreateUsers' -Target $OrganizationalUnitName -Status 'Failed' -Message $runFailure.Exception.Message
        }
        catch {
            Write-Warning "Could not write the failure audit record: $($_.Exception.Message)"
        }
    }
    throw $runFailure
}
finally {
    Clear-ADToolContext
}
