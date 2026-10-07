Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'AD-Operations.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repoRoot 'AD-Provisioning.psm1') -Force -ErrorAction Stop

$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Condition) {
        $script:Passed++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][string]$Name
    )

    $threw = $false
    try {
        & $ScriptBlock
    }
    catch {
        $threw = $true
    }
    Assert-True -Condition $threw -Name $Name
}

Write-Host 'Running AD_PS offline regression checks (no AD connection or writes).' -ForegroundColor Cyan

$serverDefaultKey = '*-AD*:Server'
$credentialDefaultKey = '*-AD*:Credential'
$hadServerDefault = $global:PSDefaultParameterValues.ContainsKey($serverDefaultKey)
$hadCredentialDefault = $global:PSDefaultParameterValues.ContainsKey($credentialDefaultKey)
$originalServerDefault = if ($hadServerDefault) { $global:PSDefaultParameterValues[$serverDefaultKey] } else { $null }
$originalCredentialDefault = if ($hadCredentialDefault) { $global:PSDefaultParameterValues[$credentialDefaultKey] } else { $null }
try {
    $global:PSDefaultParameterValues[$serverDefaultKey] = 'operator-configured-server'
    $global:PSDefaultParameterValues[$credentialDefaultKey] = 'operator-configured-credential'
    Clear-ADToolContext
    Assert-True ($global:PSDefaultParameterValues[$serverDefaultKey] -ceq 'operator-configured-server' -and
        $global:PSDefaultParameterValues[$credentialDefaultKey] -ceq 'operator-configured-credential') `
        'Context cleanup leaves operator AD defaults untouched when no tool context is active'
}
finally {
    if ($hadServerDefault) { $global:PSDefaultParameterValues[$serverDefaultKey] = $originalServerDefault }
    else { [void]$global:PSDefaultParameterValues.Remove($serverDefaultKey) }
    if ($hadCredentialDefault) { $global:PSDefaultParameterValues[$credentialDefaultKey] = $originalCredentialDefault }
    else { [void]$global:PSDefaultParameterValues.Remove($credentialDefaultKey) }
}

Assert-True ((ConvertTo-LdapFilterValue 'x*(y)\z') -ceq 'x\2a\28y\29\5cz') 'LDAP filter special characters are escaped'
Assert-True ((ConvertTo-DistinguishedNameValue ' Smith, Jr ') -ceq '\20Smith\2c Jr\20') 'DN values escape boundary spaces and commas'
Assert-True ((Get-ADDistinguishedNameParent 'CN=User,OU=Users,DC=example,DC=com') -ceq 'OU=Users,DC=example,DC=com') `
    'DN parent extraction returns the immediate parent'
Assert-True ((Get-ADDistinguishedNameParent 'CN=O\,Brien,OU=Users,DC=example,DC=com') -ceq 'OU=Users,DC=example,DC=com') `
    'DN parent extraction respects escaped commas'
Assert-Throws { Get-ADDistinguishedNameParent 'OU=Users' } 'DN parent extraction rejects a DN without a parent'

$notFoundError = [System.Management.Automation.ErrorRecord]::new(
    [System.Exception]::new('Identity does not exist.'),
    'ADIdentityNotFound,Microsoft.ActiveDirectory.Management.Commands.GetADUser',
    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
    $null
)
$connectivityError = [System.Management.Automation.ErrorRecord]::new(
    [System.Exception]::new('Identity not found because the server is unreachable.'),
    'ServerUnavailable,Microsoft.ActiveDirectory.Management.Commands.GetADUser',
    [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
    $null
)
Assert-True (Test-ADIdentityNotFoundError -ErrorRecord $notFoundError) 'AD identity-not-found classification recognizes its error ID'
Assert-True (-not (Test-ADIdentityNotFoundError -ErrorRecord $connectivityError)) 'AD identity-not-found classification does not infer from message text'

$inactiveCutoff = [datetime]::new(2026, 7, 9)
$oldNeverLoggedOnIsInactive = Test-ADAccountInactive -User ([pscustomobject]@{
    LastLogonDate = $null
    WhenCreated = [datetime]::new(2026, 1, 1)
}) -Cutoff $inactiveCutoff
Assert-True $oldNeverLoggedOnIsInactive 'Never-logged-on accounts older than the cutoff are inactive'
$newNeverLoggedOnIsInactive = Test-ADAccountInactive -User ([pscustomobject]@{
    LastLogonDate = $null
    WhenCreated = [datetime]::new(2026, 9, 1)
}) -Cutoff $inactiveCutoff
Assert-True (-not $newNeverLoggedOnIsInactive) 'Never-logged-on accounts created after the cutoff are not inactive'
$oldLastLogonIsInactive = Test-ADAccountInactive -User ([pscustomobject]@{
    LastLogonDate = [datetime]::new(2026, 1, 1)
    WhenCreated = [datetime]::new(2025, 1, 1)
}) -Cutoff $inactiveCutoff
Assert-True $oldLastLogonIsInactive 'Accounts with an old last logon are inactive'
$recentLastLogonIsInactive = Test-ADAccountInactive -User ([pscustomobject]@{
    LastLogonDate = [datetime]::new(2026, 8, 1)
    WhenCreated = [datetime]::new(2025, 1, 1)
}) -Cutoff $inactiveCutoff
Assert-True (-not $recentLastLogonIsInactive) 'Accounts with a recent last logon are not inactive'

$fixedTerminationDate = [datetime]::new(2026, 10, 7)
$terminationDescription = New-ADTerminationDescription -ExistingDescription 'Existing employee note' -Reason 'Role ended' -TerminationDate $fixedTerminationDate
Assert-True ($terminationDescription -ceq 'Existing employee note | TERMINATED on 2026-10-07 - Reason: Role ended') 'Termination note preserves existing description'
$repeatTerminationDescription = New-ADTerminationDescription -ExistingDescription $terminationDescription -Reason 'Role ended' -TerminationDate $fixedTerminationDate
Assert-True ($repeatTerminationDescription -ceq $terminationDescription) 'Repeated termination on the same date does not duplicate its note'
Assert-Throws {
    New-ADTerminationDescription -ExistingDescription ('x' * 1000) -Reason 'Role ended' -TerminationDate $fixedTerminationDate
} 'Termination note refuses to exceed the AD description limit'

$fileTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "AD-PS-OfflineTest-$([Guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $fileTestRoot -ErrorAction Stop
try {
    $stagingPath = Join-Path $fileTestRoot 'staged.tmp'
    $destinationPath = Join-Path $fileTestRoot 'credentials.clixml'
    Set-Content -LiteralPath $stagingPath -Value 'new-content' -NoNewline
    Move-ADSecuredFileIntoPlace -StagingPath $stagingPath -DestinationPath $destinationPath
    Assert-True ((Get-Content -LiteralPath $destinationPath -Raw) -ceq 'new-content' -and
        -not (Test-Path -LiteralPath $stagingPath)) 'Secure file publish moves a staged file into an absent destination'

    $stagingPath = Join-Path $fileTestRoot 'staged-overwrite.tmp'
    Set-Content -LiteralPath $stagingPath -Value 'replacement' -NoNewline
    Assert-Throws {
        Move-ADSecuredFileIntoPlace -StagingPath $stagingPath -DestinationPath $destinationPath
    } 'Secure file publish refuses implicit overwrite'
    Assert-True ((Get-Content -LiteralPath $destinationPath -Raw) -ceq 'new-content') 'Refused overwrite preserves the existing destination'

    Move-ADSecuredFileIntoPlace -StagingPath $stagingPath -DestinationPath $destinationPath -Overwrite
    Assert-True ((Get-Content -LiteralPath $destinationPath -Raw) -ceq 'replacement' -and
        -not (Test-Path -LiteralPath $stagingPath)) 'Explicit overwrite atomically replaces the destination'

    $otherDirectory = Join-Path $fileTestRoot 'other'
    $null = New-Item -ItemType Directory -Path $otherDirectory -ErrorAction Stop
    $crossDirectoryStagingPath = Join-Path $otherDirectory 'staged.tmp'
    Set-Content -LiteralPath $crossDirectoryStagingPath -Value 'content' -NoNewline
    Assert-Throws {
        Move-ADSecuredFileIntoPlace -StagingPath $crossDirectoryStagingPath -DestinationPath $destinationPath -Overwrite
    } 'Secure file publish rejects cross-directory moves'
}
finally {
    Remove-Item -LiteralPath $fileTestRoot -Recurse -Force -ErrorAction Stop
}

$credentialExportScripts = @('mark42.ps1')
$allExportsOptIn = $true
$allExportsUseSecurePublisher = $true
foreach ($scriptName in $credentialExportScripts) {
    $scriptPath = Join-Path $repoRoot $scriptName
    $scriptTokens = $null
    $scriptParseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$scriptTokens, [ref]$scriptParseErrors)

    $implicitPasswordExportAssignments = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq 'ExportPasswords' -and
        $node.Right.Extent.Text -eq '$true'
    }, $true))
    if ($implicitPasswordExportAssignments.Count -gt 0) { $allExportsOptIn = $false }

    $scriptCommands = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true))
    $usesSecurePasswordPublisher = @($scriptCommands | Where-Object { $_.GetCommandName() -eq 'Export-PasswordRecordsSecurely' }).Count -gt 0
    $directPasswordFileExport = @($scriptCommands | Where-Object {
        $_.GetCommandName() -eq 'Export-Clixml' -and $_.Extent.Text -match '(?i)-LiteralPath\s+\$PasswordFile'
    }).Count -gt 0
    if (-not $usesSecurePasswordPublisher -or $directPasswordFileExport) {
        $allExportsUseSecurePublisher = $false
    }
}
Assert-True $allExportsOptIn 'Provisioning scripts do not silently enable password export'
Assert-True $allExportsUseSecurePublisher 'Credential exports use a restricted staging file rather than writing directly to their destinations'

$expectedCompatibilityParameters = @(
    'AccountCount',
    'OrganizationalUnitName',
    'StaffNamesOrganizationalUnitName',
    'NamesPath',
    'Departments',
    'AdministratorUsername',
    'CreateDepartmentAdministrators',
    'AdministratorsOnly',
    'PasswordPattern',
    'AdministratorPasswordPattern',
    'PasswordFile',
    'ExportPasswords',
    'OverwritePasswordFile',
    'ReportPath',
    'RollbackCreatedAccountsOnFailure',
    'Password',
    'Server',
    'UPNSuffix',
    'Credential',
    'AuditLogPath'
)
$compatibilityEntrypointsForwardToCanonical = $true
foreach ($scriptName in @('ActiveDirectory-Provisioner.ps1', 'Generate-ADUsers.ps1')) {
    $scriptPath = Join-Path $repoRoot $scriptName
    $scriptTokens = $null
    $scriptParseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$scriptTokens, [ref]$scriptParseErrors)
    $entrypointParameters = @($scriptAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    foreach ($parameterName in $expectedCompatibilityParameters) {
        if ($parameterName -notin $entrypointParameters) { $compatibilityEntrypointsForwardToCanonical = $false }
    }

    $entrypointFunctions = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true))
    $canonicalDispatch = $scriptAst.Extent.Text.Contains('& $canonicalScriptPath @forwardArguments')
    if ($entrypointFunctions.Count -gt 0 -or -not $canonicalDispatch) {
        $compatibilityEntrypointsForwardToCanonical = $false
    }
}
Assert-True $compatibilityEntrypointsForwardToCanonical 'Provisioning compatibility entry points forward to mark42 and preserve shared CLI parameters'

$generateEntrySource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Generate-ADUsers.ps1'))
$generatePreservesLegacyDefaults = $generateEntrySource.Contains("`$forwardArguments['DisableDepartmentAdministratorsByDefault'] = `$true") -and
    $generateEntrySource.Contains("`$forwardArguments['TreatZeroAccountCountAsNone'] = `$true")
Assert-True $generatePreservesLegacyDefaults 'Generate-ADUsers preserves its legacy zero-count and administrator defaults'

$generateAstTokens = $null
$generateAstErrors = $null
$generateAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'Generate-ADUsers.ps1'),
    [ref]$generateAstTokens,
    [ref]$generateAstErrors
)
$generateHasSafeEnableSwitch = @($generateAst.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -eq 'EnableAccountsAfterVerification'
}).Count -eq 1
Assert-True $generateHasSafeEnableSwitch 'Generate-ADUsers retains the disabled-create/verify/enable option'

$mark42Path = Join-Path $repoRoot 'mark42.ps1'
$mark42Tokens = $null
$mark42ParseErrors = $null
$mark42Ast = [System.Management.Automation.Language.Parser]::ParseFile($mark42Path, [ref]$mark42Tokens, [ref]$mark42ParseErrors)
$safeEnableFunction = @($mark42Ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Enable-VerifiedProvisionedAccount'
}, $true)) | Select-Object -First 1
$safeEnableSource = if ($safeEnableFunction) { $safeEnableFunction.Extent.Text } else { '' }
$safeEnableWorkflowIsVerified = $safeEnableSource -match 'Enable-ADAccount' -and
    $safeEnableSource -match 'Test-ADProvisionedUser' -and
    $safeEnableSource -match 'RequireEnabled'
Assert-True $safeEnableWorkflowIsVerified 'Canonical provisioner enables accounts only through the verification helper'

$mark42NewUserCommands = @($mark42Ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'New-ADUser'
}, $true))
$disabledCreatePaths = @($mark42NewUserCommands | Where-Object {
    $_.Extent.Text -match '(?s)-Enabled\s+\(-not\s+\$EnableAccountsAfterVerification\)'
}).Count
Assert-True ($disabledCreatePaths -ge 2) 'Canonical provisioner can create both standard and administrator accounts disabled'

$plainTextConversionHelper = @($mark42Ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'ConvertTo-PlainTextFromSecureString'
}, $true)) | Select-Object -First 1
$plainTextConversionSource = if ($plainTextConversionHelper) { $plainTextConversionHelper.Extent.Text } else { '' }
Assert-True ($plainTextConversionSource -match '(?s)PtrToStringBSTR.*finally\s*\{.*ZeroFreeBSTR') `
    'SecureString plaintext conversion clears its unmanaged BSTR in a finally block'

$scriptsWithContextLeaks = [System.Collections.Generic.List[string]]::new()
foreach ($scriptFile in Get-ChildItem -LiteralPath $repoRoot -File -Filter '*.ps1') {
    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$tokens, [ref]$parseErrors)
    $contextInvocations = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Set-ADToolContext'
    }, $true))
    if ($contextInvocations.Count -eq 0) { continue }

    $cleanupFound = $false
    $tryStatements = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally
    }, $true))
    foreach ($tryStatement in $tryStatements) {
        $cleanupCommands = @($tryStatement.Finally.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -in @('Clear-ADToolContext', 'Clear-ADProvisioningContext')
        }, $true))
        if ($cleanupCommands.Count -gt 0) {
            $cleanupFound = $true
            break
        }
    }
    if (-not $cleanupFound) { $scriptsWithContextLeaks.Add($scriptFile.Name) }
}
if ($scriptsWithContextLeaks.Count -gt 0) {
    Write-Host "  Scripts missing AD context cleanup: $($scriptsWithContextLeaks -join ', ')" -ForegroundColor Yellow
}
Assert-True ($scriptsWithContextLeaks.Count -eq 0) 'Every script that establishes AD context clears it in a finally block'

$passwordsValid = $true
for ($attempt = 0; $attempt -lt 100; $attempt++) {
    $password = New-RandomPassword -Length 24
    if ($password.Length -ne 24 -or -not (Test-PasswordComplexity -PasswordText $password)) {
        $passwordsValid = $false
        break
    }
}
Assert-True $passwordsValid 'Cryptographic password generation returns requested length and complexity'

$patternResolved = Resolve-PasswordPatternText -Pattern 'Start-{0}-{1}!' -Username 'qa.user' -Token '42'
Assert-True ($patternResolved -ceq 'Start-qa.user-42!') 'Password pattern placeholders resolve as documented'
Assert-Throws { Resolve-PasswordPatternText -Pattern 'Pass-{9}' -Username 'qa.user' } 'Unsupported password placeholders are rejected'
$patternState = [pscustomobject]@{
    Password = $null
    PasswordPattern = $null
    WhatIf = $false
}
$securePatternPassword = & (Get-Module AD-Provisioning) {
    param($state)
    Get-ADProvisioningPassword -State $state -Username 'qa.user' -PasswordPattern 'Start-{0}-42!'
} $patternState
Assert-True ($securePatternPassword -is [System.Security.SecureString]) 'Resolved account passwords are converted to SecureString before use'

$usedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$firstName = Get-UniqueSamAccountName -BaseName "Ren$([char]0x00E9).Example" -UsedNames $usedNames
$secondName = Get-UniqueSamAccountName -BaseName 'Rene.Example' -UsedNames $usedNames
Assert-True ($firstName -eq 'rene.example' -and $secondName -eq 'rene.example2') 'SAM names normalize diacritics and avoid in-run collisions'

$validDepartments = Test-DepartmentNames -DepartmentNames @('Finance', 'IT')
Assert-True ($validDepartments.Count -eq 2) 'Valid department names are retained'
Assert-Throws { Test-DepartmentNames -DepartmentNames @('Finance,Inc', 'IT') } 'Invalid department names are rejected'

$expectedParent = 'OU=Administrators,DC=example,DC=com'
$groupSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1000')
$group = [pscustomobject]@{
    Name = 'Finance-Administrators'
    DistinguishedName = "CN=Finance-Administrators,$expectedParent"
    GroupCategory = 'Security'
    GroupScope = 'Global'
    SID = $groupSid
}
$validatedSid = Get-ADValidatedSecurityGroupSid -Group $group -ExpectedName 'Finance-Administrators' -ExpectedParentDistinguishedName $expectedParent
Assert-True ($validatedSid -eq $groupSid) 'Administrator groups must match expected name, OU, scope, category, and SID'
$badGroup = $group | Select-Object *
$badGroup.GroupCategory = 'Distribution'
Assert-Throws { Get-ADValidatedSecurityGroupSid -Group $badGroup -ExpectedName 'Finance-Administrators' -ExpectedParentDistinguishedName $expectedParent } 'Distribution groups are rejected for delegated administrator roles'

$userClassGuid = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$delegationRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$validAce = [pscustomobject]@{
    IdentityReference = $groupSid
    AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    ObjectType = $userClassGuid
    InheritedObjectType = $userClassGuid
    InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    ActiveDirectoryRights = $delegationRights
}
Assert-True (Test-ADUserLifecycleDelegation -AccessRules @($validAce) -GroupSid $groupSid) 'Delegation ACL recognition is SID-based and validates exact scope'

$otherSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
$otherAce = $validAce | Select-Object *
$otherAce.IdentityReference = $otherSid
Assert-True (-not (Test-ADUserLifecycleDelegation -AccessRules @($otherAce) -GroupSid $groupSid)) 'A name collision or unrelated SID does not satisfy delegation checks'
Assert-Throws { Assert-ADUserLifecycleDelegationSafe -GroupSid $groupSid -CreatedByThisRun $false -ExistingDelegation $false } 'New delegation is refused for an unapproved pre-existing group'
Assert-ADUserLifecycleDelegationSafe -GroupSid $groupSid -CreatedByThisRun $true -ExistingDelegation $false
Assert-True $true 'Delegation can be granted to a validated group created in this run'

Write-Host "`nOffline tests: $script:Passed passed, $script:Failed failed." -ForegroundColor Cyan
if ($script:Failed -gt 0) { exit 1 }
exit 0
