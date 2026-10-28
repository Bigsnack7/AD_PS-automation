Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'Modules\AD-Operations.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repoRoot 'Modules\AD-Provisioning.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repoRoot 'Modules\ADAutoX.psd1') -Force -ErrorAction Stop

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

Write-Host 'Running AD_PS offline regression checks (no AD connection or Active Directory changes).' -ForegroundColor Cyan

$rootPowerShellScripts = @(Get-ChildItem -LiteralPath $repoRoot -Filter '*.ps1' -File | Select-Object -ExpandProperty Name)
$organizedPathsExist = (Test-Path -LiteralPath (Join-Path $repoRoot 'Modules\ADAutoX.psd1') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $repoRoot 'Cmdlets\mark42.ps1') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $repoRoot 'Tests\validate_repo.ps1') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $repoRoot 'Cmdlets\Script_Find_Locked-Out_Users.ps1') -PathType Leaf) -and
    $rootPowerShellScripts.Count -eq 0
Assert-True $organizedPathsExist 'PowerShell implementations are organized under Cmdlets, Modules, and Tests'
$lockedUsersEntryPoint = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\Script_Find_Locked-Out_Users.ps1'))
Assert-True ($lockedUsersEntryPoint.Contains("Import-Module (Join-Path (Split-Path -Parent `$PSScriptRoot) 'Modules\ADAutoX.psd1')") -and
    $lockedUsersEntryPoint.Contains('Get-ADAutoXLockedOutUsers @arguments')) `
    'Locked-account entry point calls the exported module implementation'

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
$preflightChecks = [System.Collections.Generic.List[psobject]]::new()
Add-ADPreflightCheck -Checks $preflightChecks -Name 'Offline check' -Status 'Passed' -Details 'Shared helper'
Assert-True ($preflightChecks.Count -eq 1 -and $preflightChecks[0].Name -ceq 'Offline check' -and
    $preflightChecks[0].Status -ceq 'Passed' -and $preflightChecks[0].Details -ceq 'Shared helper') `
    'Shared preflight helper creates the expected check record'

$preflightProvisioningSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\AD-Provisioning.psm1'))
$preflightTokens = $null
$preflightParseErrors = $null
$preflightProvisioningAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $preflightProvisioningSource, [ref]$preflightTokens, [ref]$preflightParseErrors
)
$preflightShimAst = $preflightProvisioningAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Test-ADProvisioningPreflight'
}, $true)
$preflightShimCommands = if ($preflightShimAst) {
    @($preflightShimAst.Body.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() })
}
else { @() }
Assert-True (@($preflightParseErrors).Count -eq 0 -and @($preflightShimCommands).Count -eq 1 -and
    [string]$preflightShimCommands -ceq 'Invoke-ADAutoXPreflight') `
    'Test-ADProvisioningPreflight contains only the compatibility call, not a second preflight implementation'

$preflightModuleSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\ADAutoX.psm1'))
$preflightModuleTokens = $null
$preflightModuleParseErrors = $null
$preflightModuleAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $preflightModuleSource, [ref]$preflightModuleTokens, [ref]$preflightModuleParseErrors
)
$preflightFunctionAst = $preflightModuleAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-ADAutoXPreflight'
}, $true)
$preflightFunctionSource = if ($preflightFunctionAst) { $preflightFunctionAst.Extent.Text } else { '' }
$preflightHasLiveChecks = @('Get-ADDomain', 'Get-ADOrganizationalUnit', 'Get-ADGroup', 'Get-Acl') |
    Where-Object { $preflightFunctionSource.Contains($_) }
Assert-True (@($preflightModuleParseErrors).Count -eq 0 -and @($preflightHasLiveChecks).Count -eq 4) `
    'Unified preflight contains the real AD domain, OU, group, and ACL checks'

$mark42Source = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\mark42.ps1'))
$mark42Tokens = $null
$mark42ParseErrors = $null
$mark42Ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $mark42Source, [ref]$mark42Tokens, [ref]$mark42ParseErrors
)
$mark42PreflightAst = $mark42Ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-ADPreflight'
}, $true)
$mark42PreflightSource = if ($mark42PreflightAst) { $mark42PreflightAst.Extent.Text } else { '' }
Assert-True (@($mark42ParseErrors).Count -eq 0 -and
    $mark42PreflightSource.Contains('CanonicalProvisioning = $true') -and
    $mark42PreflightSource.Contains('Invoke-ADAutoXPreflight') -and
    -not $mark42PreflightSource.Contains('Get-ADOrganizationalUnit') -and
    -not $mark42PreflightSource.Contains('Get-ADGroup') -and
    -not $mark42PreflightSource.Contains('Get-Acl')) `
    'mark42 preflight forwards to the single shared implementation without duplicate AD checks'
Assert-True ((Get-ADDistinguishedNameDepth -DistinguishedName 'CN=O\,Brien,OU=Users,DC=example,DC=com') -eq 4) `
    'Shared DN-depth helper counts escaped commas correctly'
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

$credentialExportScripts = @('Cmdlets\mark42.ps1')
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
$compatibilityEntrypointsResolveCanonicalScript = $true
foreach ($scriptName in @('ActiveDirectory-Provisioner.ps1', 'Generate-ADUsers.ps1')) {
    $scriptPath = Join-Path $repoRoot "Cmdlets\$scriptName"
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
    $usesLiteralPathLookup = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Get-Command' -and
        $node.Extent.Text -match '(?i)-LiteralPath'
    }, $true)).Count -gt 0
    $usesNamePathLookup = @($scriptAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Get-Command' -and
        $node.Extent.Text -match '(?i)-Name\s+\$canonicalScriptPath'
    }, $true)).Count -gt 0
    if ($usesLiteralPathLookup -or -not $usesNamePathLookup) {
        $compatibilityEntrypointsResolveCanonicalScript = $false
    }
    if ($entrypointFunctions.Count -gt 0 -or -not $canonicalDispatch) {
        $compatibilityEntrypointsForwardToCanonical = $false
    }
}
Assert-True $compatibilityEntrypointsForwardToCanonical 'Provisioning compatibility entry points forward to mark42 and preserve shared CLI parameters'
Assert-True $compatibilityEntrypointsResolveCanonicalScript 'Compatibility entry points resolve mark42 by its supported Get-Command -Name parameter'

$cleanupEntryPath = Join-Path $repoRoot 'Cmdlets\Remove-Test-Users.ps1'
$cleanupTokens = $null
$cleanupParseErrors = $null
$cleanupAst = [System.Management.Automation.Language.Parser]::ParseFile($cleanupEntryPath, [ref]$cleanupTokens, [ref]$cleanupParseErrors)
$cleanupParameters = @($cleanupAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$cleanupSource = $cleanupAst.Extent.Text
$cleanupForwardsSafetyParameters = 'ExpectedDistinguishedName' -in $cleanupParameters -and
    'Force' -in $cleanupParameters -and
    $cleanupSource -match "'ExpectedDistinguishedName','Force'"
Assert-True $cleanupForwardsSafetyParameters 'Cleanup wrapper exposes and forwards required DN confirmation and force parameters'

$resetCleanupSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\2_RESET_TEST_USERS.ps1'))
$resetRestoresAccidentalDeletionProtection = $resetCleanupSource.Contains('clearedProtectionDistinguishedNames') -and
    $resetCleanupSource.Contains('Set-ADObject @adContext -Identity $distinguishedName -ProtectedFromAccidentalDeletion $true')
Assert-True $resetRestoresAccidentalDeletionProtection 'Cleanup restores accidental-deletion protection when a protected OU remains'

$securityReportSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\Script_AD_Security_Report.ps1'))
$securityReportModuleSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\ADAutoX.psm1'))
$securityReportUsesModuleScan = $securityReportSource.Contains('Get-ADAutoXSecurityScan @scanParameters') -and
    $securityReportModuleSource.Contains('ConvertTo-LdapFilterValue')
Assert-True $securityReportUsesModuleScan 'Security report wrapper delegates to the module scan with shared LDAP escaping'

$auditReportRoot = Join-Path ([System.IO.Path]::GetTempPath()) "AD-PS-AuditReportTest-$([Guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $auditReportRoot -ErrorAction Stop
try {
    $auditLogPath = Join-Path $auditReportRoot 'audit.jsonl'
    $auditOutputPath = Join-Path $auditReportRoot 'nested\summary.json'
    Set-Content -LiteralPath $auditLogPath -Value '{"Timestamp":"2026-10-27T12:00:00.0000000Z","Action":"Test","Target":"jdoe","Status":"Succeeded"}' -Encoding UTF8
    & (Join-Path $repoRoot 'Cmdlets\Script_AD_Audit_Report.ps1') -AuditLogPath $auditLogPath -AsJson -OutputPath $auditOutputPath | Out-Null
    Assert-True ((Test-Path -LiteralPath $auditOutputPath -PathType Leaf) -and
        (Get-Content -LiteralPath $auditOutputPath -Raw -Encoding UTF8 | ConvertFrom-Json).TotalRecords -eq 1) `
        'Audit report creates missing output directories for JSON exports'
}
finally {
    Remove-Item -LiteralPath $auditReportRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$unifiedManifest = Test-ModuleManifest (Join-Path $repoRoot 'Modules\ADAutoX.psd1') -ErrorAction Stop
$unifiedCommands = @(Get-Command -Module ADAutoX -CommandType Function | ForEach-Object Name)
$missingUnifiedFunctions = @($unifiedManifest.ExportedFunctions.Keys | Where-Object { $_ -notin $unifiedCommands })
$hasTerminationCompatibilityAlias = $unifiedManifest.ExportedAliases.ContainsKey('Terminate-ADAutoXUser') -and
    (Get-Command Terminate-ADAutoXUser -ErrorAction SilentlyContinue).CommandType -eq 'Alias'
Assert-True ($missingUnifiedFunctions.Count -eq 0 -and $hasTerminationCompatibilityAlias) `
    'Unified ADAutoX manifest exports its functions and preserves the termination compatibility alias'
$ledgerUserIdentity = [Guid]::NewGuid().ToString()
$lifecycleUndoData = @{
    UserIdentity = $ledgerUserIdentity
    SamAccountName = 'offline-user'
    UserDistinguishedName = 'CN=offline-user,OU=Users,OU=Company,DC=example,DC=com'
    ExpectedEnabled = $false
    RestoreEnabled = $true
}
Add-ADAutoXLedgerEntry -ObjectType Lifecycle -Action RestoreEnabled -UndoData $lifecycleUndoData
$laterUndoData = @{
    UserIdentity = $ledgerUserIdentity
    SamAccountName = 'offline-user'
    UserDistinguishedName = 'CN=offline-user,OU=Users,OU=Company,DC=example,DC=com'
    ExpectedDescription = 'Updated'
    RestoreDescription = 'Original'
}
Add-ADAutoXLedgerEntry -ObjectType Lifecycle -Action RestoreDescription -UndoData $laterUndoData
$lifecycleLedgerEntries = @(Get-ADAutoXLedger | Where-Object ObjectType -eq 'Lifecycle')
Assert-True ($lifecycleLedgerEntries.Count -eq 2 -and $lifecycleLedgerEntries[0].Action -ceq 'RestoreEnabled' -and
    $lifecycleLedgerEntries[0].UndoData.UserIdentity -ceq $ledgerUserIdentity -and
    -not $lifecycleLedgerEntries[0].CreatedByThisRun -and
    $lifecycleLedgerEntries[1].Sequence -gt $lifecycleLedgerEntries[0].Sequence) `
    'Lifecycle changes can be stored in the shared rollback ledger as reversible undo entries'
Initialize-ADAutoXLedger

$contractRunId = [Guid]::NewGuid().ToString()
$contractEntries = @(
    Add-ADAutoXLedgerEntry -ObjectType OU -DistinguishedName 'OU=Offline,DC=example,DC=com' `
        -Name 'Offline' -UndoData @{ GeneratedDescription = 'Generated by test' } -RunId $contractRunId
    Add-ADAutoXLedgerEntry -ObjectType Group -DistinguishedName 'CN=Offline,OU=Offline,DC=example,DC=com' `
        -Name 'Offline' -RunId $contractRunId
    Add-ADAutoXLedgerEntry -ObjectType User -DistinguishedName 'CN=offline,OU=Offline,DC=example,DC=com' `
        -SamAccountName 'offline' -Name 'offline' -RunId $contractRunId
    Add-ADAutoXLedgerEntry -ObjectType Delegation -DistinguishedName 'OU=Offline,DC=example,DC=com' `
        -Name 'Offline' -SecurityIdentifier 'S-1-5-21-111-222-333-444' `
        -DelegationRuleTypes @('ChildManagement') -RunId $contractRunId
)
$expectedLedgerProperties = @(
    'ObjectType', 'DistinguishedName', 'SamAccountName', 'Name', 'CreatedByThisRun',
    'Action', 'UndoData', 'SecurityIdentifier', 'DelegationRuleTypes', 'RunId',
    'Sequence', 'Timestamp'
)
$ledgerSchemaConsistent = $contractEntries.Count -eq 4 -and @($contractEntries | Where-Object {
    $entry = $_
    @($expectedLedgerProperties | Where-Object { $_ -notin $entry.PSObject.Properties.Name }).Count -gt 0
}).Count -eq 0 -and
    @($contractEntries | Select-Object -ExpandProperty ObjectType -Unique).Count -eq 4
Assert-True $ledgerSchemaConsistent `
    'Shared ledger writer emits one consistent, run-scoped schema for OU, group, user, and delegation entries'
Initialize-ADAutoXLedger

$shouldProcessFunctionContracts = @(
    @{ Path = (Join-Path $repoRoot 'Modules\AD-Provisioning.psm1'); Name = 'Set-DepartmentDelegation' }
    @{ Path = (Join-Path $repoRoot 'Modules\AD-Provisioning.psm1'); Name = 'Invoke-ProvisioningRollback' }
    @{ Path = (Join-Path $repoRoot 'Modules\ADAutoX.psm1'); Name = 'Invoke-ADAutoXLifecycleUndo' }
    @{ Path = (Join-Path $repoRoot 'Modules\ADAutoX.psm1'); Name = 'Invoke-ADAutoXLedgerRollback' }
)
$shouldProcessContractsValid = $true
foreach ($contract in $shouldProcessFunctionContracts) {
    $tokens = $null
    $parseErrors = $null
    $moduleAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $contract.Path,
        [ref]$tokens,
        [ref]$parseErrors
    )
    $functionAst = $moduleAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $contract.Name
    }, $true)
    if ($parseErrors.Count -gt 0 -or -not $functionAst -or
        -not $functionAst.Extent.Text.Contains('[CmdletBinding(SupportsShouldProcess') -or
        -not $functionAst.Extent.Text.Contains('$PSCmdlet.ShouldProcess')) {
        $shouldProcessContractsValid = $false
        break
    }
}
$mark42SourceForShouldProcess = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\mark42.ps1'))
$resetSourceForShouldProcess = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\Reset-ADAutoXEnvironment.ps1'))
$unifiedRollbackSourceForShouldProcess = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\ADAutoX.psm1'))
$shouldProcessContractsValid = $shouldProcessContractsValid -and
    $mark42SourceForShouldProcess.Contains('$WhatIfPreference') -and
    $mark42SourceForShouldProcess.Contains('$PSBoundParameters[''Confirm'']') -and
    $resetSourceForShouldProcess.Contains('$WhatIfPreference') -and
    $resetSourceForShouldProcess.Contains('$PSBoundParameters[''Confirm'']') -and
    $unifiedRollbackSourceForShouldProcess.Contains('WhatIf = [bool]$WhatIfPreference') -and
    $unifiedRollbackSourceForShouldProcess.Contains('$undoParameters.Confirm = $PSBoundParameters[''Confirm'']')
Assert-True $shouldProcessContractsValid `
    'Rollback and delegation expose ShouldProcess and preserve WhatIf/Confirm through callers'

$resetEnvironmentPath = Join-Path $repoRoot 'Cmdlets\Reset-ADAutoXEnvironment.ps1'
$resetEnvironmentSource = [System.IO.File]::ReadAllText($resetEnvironmentPath)
$resetCleanupTarget = Join-Path (Split-Path -Parent $resetEnvironmentPath) 'Remove-Test-Users.ps1'
Assert-True ($resetEnvironmentSource.Contains("Join-Path `$PSScriptRoot 'Remove-Test-Users.ps1'") -and
    (Test-Path -LiteralPath $resetCleanupTarget -PathType Leaf)) `
    'Environment reset resolves its cleanup implementation from the Cmdlets folder'
$resetEnvironmentAstTokens = $null
$resetEnvironmentAstErrors = $null
$resetEnvironmentAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $resetEnvironmentPath,
    [ref]$resetEnvironmentAstTokens,
    [ref]$resetEnvironmentAstErrors
)
$resetSupportsLedgerRollback = @($resetEnvironmentAst.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -eq 'RollbackLedger'
}).Count -eq 1 -and $resetEnvironmentSource.Contains('Invoke-ADAutoXLedgerRollback') -and
    $resetEnvironmentSource.Contains('ExpectedDistinguishedName')
Assert-True $resetSupportsLedgerRollback 'Environment reset exposes scoped rollback of lifecycle ledger entries'

$lifecycleWrappersPreserveModuleState = $true
$ledgerLifecycleEntryPaths = @(
    Get-ChildItem -LiteralPath $repoRoot -Filter 'Script_*.ps1' -File
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'Cmdlets') -Filter '*.ps1' -File
)
foreach ($entryPath in $ledgerLifecycleEntryPaths) {
    $scriptText = [System.IO.File]::ReadAllText($entryPath.FullName)
    if ($scriptText -match "Import-Module.*ADAutoX\.psd1.*-Force") {
        $lifecycleWrappersPreserveModuleState = $false
        break
    }
}
if ($lifecycleWrappersPreserveModuleState -and $resetEnvironmentSource -match "Import-Module.*ADAutoX\.psd1.*-Force") {
    $lifecycleWrappersPreserveModuleState = $false
}
Assert-True $lifecycleWrappersPreserveModuleState 'Lifecycle entry points preserve the session-scoped rollback ledger'
$unifiedProvisionFunction = Get-Command Invoke-ADAutoXProvision -Module ADAutoX -ErrorAction SilentlyContinue
$unifiedProvisionSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\ADAutoX.psm1'))
$provisioningScriptTokens = $null
$provisioningScriptErrors = $null
$provisioningScriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'Cmdlets\mark42.ps1'),
    [ref]$provisioningScriptTokens,
    [ref]$provisioningScriptErrors
)
$provisionEntrypointUsesCanonicalEngine = $null -ne $unifiedProvisionFunction -and
    $unifiedProvisionSource.Contains('$scriptDirectory = $repositoryRoot') -and
    $unifiedProvisionSource.Contains("Join-Path `$scriptDirectory 'Cmdlets\mark42.ps1'") -and
    $unifiedProvisionSource.Contains("Join-Path `$scriptDirectory 'Data\sample-names.txt'") -and
    $unifiedProvisionSource.Contains('RollbackCreatedResourcesOnFailure = $RollbackOnFailure') -and
    $unifiedProvisionSource.Contains('$arguments.CorrelationId = New-ADAutoXCorrelationId')
Assert-True $provisionEntrypointUsesCanonicalEngine `
    'ADAutoX provisioning delegates to the canonical engine with sample data, rollback, and correlation wiring'
$resourceRollback = $provisioningScriptAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-ProvisioningResourceRollback' }, $true)
$resourceRollbackSource = if ($resourceRollback) { $resourceRollback.Extent.Text } else { '' }
$resourceRollbackModuleSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\ADAutoX.psm1'))
$resourceRollbackIsCentralized = $resourceRollbackSource.Contains('Invoke-ADAutoXLedgerRollback') -and
    $resourceRollbackSource.Contains('RunId = $CorrelationId') -and
    $resourceRollbackModuleSource.Contains("'ChildManagement'") -and
    $resourceRollbackModuleSource.Contains("'DescendantUserAccess'") -and
    $resourceRollbackModuleSource.Contains('DelegationRuleTypes') -and
    $resourceRollbackModuleSource.Contains('Get-ADGroupMember @adContext -Identity $item.DistinguishedName') -and
    $resourceRollbackModuleSource.Contains('$item.UndoData.GeneratedDescription') -and
    $resourceRollbackModuleSource.Contains('-SearchScope OneLevel -ResultSetSize 1') -and
    $resourceRollbackModuleSource.Contains('ProtectedFromAccidentalDeletion $true') -and
    $resourceRollbackModuleSource.Contains('-Confirm:$false -ErrorAction Stop') -and
    -not $resourceRollbackSource.Contains('Get-Acl') -and
    -not $resourceRollbackSource.Contains('Remove-ADOrganizationalUnit')
Assert-True $resourceRollbackIsCentralized `
    'Provisioning delegates resource rollback to the shared ledger while retaining group, delegation, and OU safeguards'
$runLevelCatch = $provisioningScriptAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.CatchClauseAst] -and
    $node.Extent.Text.Contains('# Any run-level failure after the')
}, $true)
$runLevelCatchSource = if ($runLevelCatch) { $runLevelCatch.Extent.Text } else { '' }
Assert-True ($runLevelCatchSource.Contains('$RollbackCreatedResourcesOnFailure') -and
    $runLevelCatchSource.Contains('Invoke-ProvisioningResourceRollback')) `
    'Full resource rollback is also invoked for setup, OU, group, and delegation failures'
$failedBatchRollbackIndex = $provisioningScriptAst.Extent.Text.IndexOf(
    'if ($RollbackCreatedResourcesOnFailure -and',
    [System.StringComparison]::Ordinal
)
$finalSummaryIndex = $provisioningScriptAst.Extent.Text.IndexOf('$totalCreated = $createdCount + $createdAdminCount', [System.StringComparison]::Ordinal)
$failedBatchRollbackSource = if ($failedBatchRollbackIndex -ge 0 -and $finalSummaryIndex -gt $failedBatchRollbackIndex) {
    $provisioningScriptAst.Extent.Text.Substring($failedBatchRollbackIndex, $finalSummaryIndex - $failedBatchRollbackIndex)
}
else { '' }
Assert-True ($failedBatchRollbackSource.Contains('$failedCount -gt 0 -or $partialCount -gt 0') -and
    $failedBatchRollbackSource.Contains('Invoke-ProvisioningResourceRollback') -and
    $failedBatchRollbackSource.Contains('$remainingAccountNames') -and
    $failedBatchRollbackSource.Contains('$createdCount = @($reportRecords')) `
    'Full rollback cleans run-created resources after account-level failures and recalculates remaining-account counts'
$adminGroupCreation = $provisioningScriptAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Extent.Text.Contains('$createdAdministratorGroup = New-ADGroup')
}, $true)
$adminGroupCreationSource = if ($adminGroupCreation) { $adminGroupCreation.Extent.Text } else { '' }
$adminGroupLedgerIndex = $adminGroupCreationSource.IndexOf('Add-ResourceLedgerEntry -Type ''Group'' -DistinguishedName $createdAdministratorGroup.DistinguishedName', [System.StringComparison]::Ordinal)
$adminGroupLookupIndex = $adminGroupCreationSource.IndexOf('Get-ADGroup @adContext -Identity $createdAdministratorGroup.DistinguishedName', [System.StringComparison]::Ordinal)
Assert-True ($adminGroupLedgerIndex -ge 0 -and $adminGroupLookupIndex -gt $adminGroupLedgerIndex) `
    'New department administrator groups enter the rollback ledger before follow-up directory reads'
$ledgerAdapter = $provisioningScriptAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Add-ResourceLedgerEntry'
}, $true)
$ledgerAdapterSource = if ($ledgerAdapter) { $ledgerAdapter.Extent.Text } else { '' }
Assert-True ($ledgerAdapterSource.Contains('Add-ADAutoXLedgerEntry') -and
    $ledgerAdapterSource.Contains("'OrganizationalUnit' { 'OU' }") -and
    $ledgerAdapterSource.Contains('-RunId $CorrelationId') -and
    $ledgerAdapterSource.Contains('GeneratedDescription = $generatedOUDescription')) `
    'Provisioning resource ledger compatibility adapter delegates all entries to the shared writer and preserves rollback metadata'
$delegationGrant = $provisioningScriptAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Grant-DepartmentUserDelegation' }, $true)
$delegationGrantSource = if ($delegationGrant) { $delegationGrant.Extent.Text } else { '' }
$childRuleLedgerIndex = $delegationGrantSource.IndexOf('Add-ResourceLedgerEntry -Type ''Delegation'' -DistinguishedName $TargetOuDistinguishedName -Name $GroupName `', [System.StringComparison]::Ordinal)
$applyDelegationAclIndex = $delegationGrantSource.IndexOf('Set-Acl -LiteralPath $ouPath -AclObject $acl', [System.StringComparison]::Ordinal)
$delegationRollbackTracksOnlyAddedRules = $delegationGrantSource.Contains('$hasExactChildRule') -and
    $delegationGrantSource.Contains('$hasExactDescendantRule') -and
    $delegationGrantSource.Contains('$delegationRuleTypes.ToArray()') -and
    $childRuleLedgerIndex -ge 0 -and
    $applyDelegationAclIndex -ge 0 -and
    $childRuleLedgerIndex -lt $applyDelegationAclIndex
Assert-True $delegationRollbackTracksOnlyAddedRules `
    'Delegation rollback records exact ACEs introduced by this run before applying ACL changes'
$sampleNames = @(Get-Content -LiteralPath (Join-Path $repoRoot 'Data\sample-names.txt') -ErrorAction Stop)
$uniqueSampleNames = @($sampleNames | Sort-Object -Unique)
Assert-True ($sampleNames.Count -eq 112 -and $uniqueSampleNames.Count -eq 112 -and
    $sampleNames -contains 'Chukwuemeka Iroha' -and $sampleNames -contains 'Kofi Mensah' -and
    $sampleNames -contains "David O'Connor" -and $sampleNames -contains 'Anna-Marie Van Der Berg') `
    'Shared provisioning name data merges Nigerian and sample-only names without duplicates'
Assert-True ((Get-ADSanitizedUserPrincipalName -SamAccountName 'jdoe' -UPNSuffix '@example.com') -ceq 'jdoe@example.com') `
    'UPN sanitizer normalizes a leading at-sign on the DNS suffix'
Assert-Throws { Get-ADSanitizedUserPrincipalName -SamAccountName 'jdoe' -UPNSuffix 'invalid/suffix' } `
    'UPN sanitizer rejects non-DNS suffix characters'

$previousCorrelationId = Get-ADAutoXCorrelationId
$newCorrelationId = New-ADAutoXCorrelationId
Assert-True ($newCorrelationId -match '^[0-9a-fA-F-]{36}$' -and
    (Get-ADAutoXCorrelationId) -ceq $newCorrelationId -and $newCorrelationId -cne $previousCorrelationId) `
    'Correlation ID generator updates the ID used by ADAutoX audit records'

$autoXAuditRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ADAutoX-AuditTest-$([Guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $autoXAuditRoot -ErrorAction Stop
try {
    $correlatedLogPath = Join-Path $autoXAuditRoot 'correlated.jsonl'
    Write-ADAutoXLogRecord -LogPath $correlatedLogPath -Action 'OfflineTest' -Target 'fixture' -Status 'Succeeded'
    $correlatedRecord = Get-Content -LiteralPath $correlatedLogPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($correlatedRecord.CorrelationId -ceq $newCorrelationId -and $correlatedRecord.Source -ceq 'ADAutoX') `
        'ADAudit logging includes the active correlation ID and source'

    $autoXAuditPath = Join-Path $autoXAuditRoot 'audit.jsonl'
    Set-Content -LiteralPath $autoXAuditPath -Value @(
        '{"Target":"jdoe","Operator":"offline-operator","Action":"ResetPassword","Status":"Succeeded"}'
        '{"Action":"Other","Status":"Failed"}'
        'null'
    ) -Encoding UTF8
    $autoXAuditRecords = @(Get-ADAutoXAuditReport -LogPath $autoXAuditPath -Identity 'jdoe' -Action 'ResetPassword')
    Assert-True ($autoXAuditRecords.Count -eq 1 -and $autoXAuditRecords[0].Target -ceq 'jdoe') `
        'Unified audit report filters partial JSONL records without missing-property errors'
    $operatorFilteredAuditRecords = @(Get-ADAutoXAuditReport -LogPath $autoXAuditPath -Identity 'offline-operator')
    Assert-True ($operatorFilteredAuditRecords.Count -eq 1 -and $operatorFilteredAuditRecords[0].Operator -ceq 'offline-operator') `
        'Unified audit report identity search includes operator fields'

    $malformedAuditPath = Join-Path $autoXAuditRoot 'malformed.jsonl'
    Set-Content -LiteralPath $malformedAuditPath -Value '{malformed' -Encoding UTF8
    Assert-Throws {
        Get-ADAutoXAuditReport -LogPath $malformedAuditPath -ErrorOnMalformedEntries
    } 'Unified audit report can reject malformed JSON for strict legacy callers'

    $credentialExportPath = Join-Path $autoXAuditRoot 'credentials.clixml'
    Export-ADAutoXCredentials -CredentialMap @{ 'offline-user' = 'Offline-Test-Secret!42' } -OutputPath $credentialExportPath
    $exportAcl = Get-Acl -LiteralPath $credentialExportPath -ErrorAction Stop
    $exportRules = @($exportAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $restoredCredentials = @(Import-Clixml -LiteralPath $credentialExportPath -ErrorAction Stop)
    Assert-True ($exportAcl.AreAccessRulesProtected -and $exportRules.Count -eq 1 -and
        $exportRules[0].IdentityReference.Value -ceq $currentSid -and $restoredCredentials.Count -eq 1 -and
        $restoredCredentials[0].UserName -ceq 'offline-user') `
        'Credential export is DPAPI-readable by its creator and restricted to that Windows identity'
}
finally {
    Remove-Item -LiteralPath $autoXAuditRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$lifecycleModuleSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Modules\ADAutoX.Lifecycle.psm1'))
$terminationSupportsTarget = $lifecycleModuleSource -match '(?s)''Terminate''\s*\{.*?Get-TargetOU\s+-Path\s+\$TargetPath'
$confirmForwardingIsConditional = $lifecycleModuleSource.Contains('if ($ConfirmBound) { $Arguments.Confirm = $Confirm }')
Assert-True ($terminationSupportsTarget -and $confirmForwardingIsConditional) `
    'Lifecycle module resolves termination OUs and forwards confirmation only when explicitly bound'
$reversibleLifecycleActionsAreTracked = $lifecycleModuleSource.Contains("-Action RestoreEnabled") -and
    $lifecycleModuleSource.Contains("-Action MoveUser") -and
    $lifecycleModuleSource.Contains("-Action GroupMembership") -and
    $lifecycleModuleSource.Contains("-Action RestoreDescription") -and
    $lifecycleModuleSource.Contains("-Action RestoreAttributes")
Assert-True $reversibleLifecycleActionsAreTracked `
    'Reversible lifecycle changes record inverse state for enablement, moves, membership, descriptions, and attributes'

$lifecycleTokens = $null
$lifecycleParseErrors = $null
$lifecycleAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'Modules\ADAutoX.Lifecycle.psm1'),
    [ref]$lifecycleTokens,
    [ref]$lifecycleParseErrors
)
$protectedHelperAst = $lifecycleAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Test-ADAutoXProtectedAccount'
}, $true)
$protectedHelperSource = if ($protectedHelperAst) { $protectedHelperAst.Extent.Text } else { '' }
$protectedConditions = @(
    'AdminCount'
    'IsCriticalSystemObject'
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Backup Operators'
    'Administrator'
    'Guest'
    'krbtgt'
    'WindowsIdentity]::GetCurrent'
    'ProtectedFromAccidentalDeletion'
)
$protectedConditionsPresent = @($protectedConditions | Where-Object {
    $protectedHelperSource.Contains($_)
}).Count -eq $protectedConditions.Count
$deletionProtectionIsScoped = $protectedHelperSource -match '(?s)if \(\$Action -in @\(''Terminate'', ''Delete''\)\).*?ProtectedFromAccidentalDeletion'
Assert-True (@($lifecycleParseErrors).Count -eq 0 -and $protectedConditionsPresent -and $deletionProtectionIsScoped) `
    'Protected-account implementation contains all configured checks and scopes deletion protection to delete/terminate'

$dispatcherAst = $lifecycleAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-ADAutoXUserLifecycle'
}, $true)
$dispatcherSource = if ($dispatcherAst) { $dispatcherAst.Extent.Text } else { '' }
$dispatcherGuardIndex = $dispatcherSource.IndexOf('Test-ADAutoXProtectedAccount', [System.StringComparison]::Ordinal)
$mutationCommandNames = @('Disable-ADAccount', 'Set-ADAccountPassword', 'Move-ADObject', 'Remove-ADUser', 'Add-ADGroupMember', 'Remove-ADGroupMember')
$mutationCommands = @($dispatcherAst.Body.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -in $mutationCommandNames
}, $true))
$guardPrecedesMutations = $dispatcherGuardIndex -ge 0 -and $mutationCommands.Count -gt 0 -and
    @($mutationCommands | Where-Object { $_.Extent.StartOffset -le ($dispatcherAst.Extent.StartOffset + $dispatcherGuardIndex) }).Count -eq 0
$dispatcherAuditsGuard = $dispatcherSource.Contains('Blocked protected-account action') -and
    $dispatcherSource.Contains('Refusing action') -and
    $dispatcherSource.Contains('WARNING: -AllowProtectedAccount bypassed') -and
    $dispatcherSource.Contains('[switch]$AllowProtectedAccount')
Assert-True ($guardPrecedesMutations -and $dispatcherAuditsGuard) `
    'Lifecycle dispatcher checks protected accounts before mutations, audits refusal, and warns on explicit bypass'

$inactiveDisableAst = $lifecycleAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Disable-ADAutoXInactiveUsers'
}, $true)
$inactiveDisableSource = if ($inactiveDisableAst) { $inactiveDisableAst.Extent.Text } else { '' }
$inactiveDisableGuarded = $inactiveDisableSource.Contains('Test-ADAutoXProtectedAccount') -and
    $inactiveDisableSource.Contains('AllowProtectedAccount') -and
    $inactiveDisableSource.Contains('Blocked protected-account action')
Assert-True $inactiveDisableGuarded `
    'Inactive-account disabling uses the protected-account guard and explicit bypass'

$manageUserSource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\Manage-ADAutoXUser.ps1'))
$manageUserAlias = Get-Command Manage-ADAutoXUser -ErrorAction SilentlyContinue
$manageUserExposesPhase1Actions = $manageUserSource.Contains("[ValidateSet('Disable', 'Enable', 'Unlock', 'Move', 'RemoveFromGroup', 'ResetPassword', 'Terminate')]") -and
    $manageUserSource.Contains("if (`$PSBoundParameters.ContainsKey('Group')) { `$arguments.Group = `$Group }") -and
    $manageUserSource.Contains('Invoke-ADAutoXUserAction @arguments') -and
    $null -ne $manageUserAlias -and
    $manageUserAlias.CommandType -eq 'Alias' -and
    $manageUserAlias.Definition -eq 'Invoke-ADAutoXUserAction'
Assert-True $manageUserExposesPhase1Actions `
    'User manager calls the approved action function and preserves its compatibility alias'

$legacyLifecycleNames = @(
    'Script_Disable_Inactive_Users.ps1','Script_Disable_User.ps1','Script_Enable_User.ps1',
    'Script_Find_Locked-Out_Users.ps1','Script_Move_User.ps1','Script_Add_User_to_Group.ps1','Script_Remove_User_from_Group.ps1',
    'Script_Reset_User_Passwords.ps1','Script_Terminate_User.ps1','Script_Unlock_User_Account.ps1'
)
$legacyWrappersUseUnifiedModule = $true
foreach ($scriptName in $legacyLifecycleNames) {
    $scriptText = [System.IO.File]::ReadAllText((Join-Path $repoRoot "Cmdlets\$scriptName"))
    if (-not $scriptText.Contains('ADAutoX.psd1')) {
        $legacyWrappersUseUnifiedModule = $false
        break
    }
}
Assert-True $legacyWrappersUseUnifiedModule 'Lifecycle scripts delegate to the unified ADAutoX module'

$generateEntrySource = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Cmdlets\Generate-ADUsers.ps1'))
$generatePreservesLegacyDefaults = $generateEntrySource.Contains("`$forwardArguments['DisableDepartmentAdministratorsByDefault'] = `$true") -and
    $generateEntrySource.Contains("`$forwardArguments['TreatZeroAccountCountAsNone'] = `$true")
Assert-True $generatePreservesLegacyDefaults 'Generate-ADUsers preserves its legacy zero-count and administrator defaults'

$generateAstTokens = $null
$generateAstErrors = $null
$generateAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'Cmdlets\Generate-ADUsers.ps1'),
    [ref]$generateAstTokens,
    [ref]$generateAstErrors
)
$generateHasSafeEnableSwitch = @($generateAst.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -eq 'EnableAccountsAfterVerification'
}).Count -eq 1
Assert-True $generateHasSafeEnableSwitch 'Generate-ADUsers retains the disabled-create/verify/enable option'

$mark42Path = Join-Path $repoRoot 'Cmdlets\mark42.ps1'
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
$childManagementRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
$childManagementAce = [pscustomobject]@{
    IdentityReference = $groupSid
    AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    ObjectType = $userClassGuid
    InheritedObjectType = [Guid]::Empty
    InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    ActiveDirectoryRights = $childManagementRights
}
Assert-True (-not (Test-ADUserLifecycleDelegation -AccessRules @($validAce) -GroupSid $groupSid)) `
    'Descendant-only delegation does not claim user creation and deletion rights on the target OU'
Assert-True (Test-ADUserLifecycleDelegation -AccessRules @($validAce, $childManagementAce) -GroupSid $groupSid) `
    'Delegation ACL recognition requires exact OU and user-descendant scopes for the validated SID'

$otherSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
$otherAce = $validAce | Select-Object *
$otherAce.IdentityReference = $otherSid
$otherChildManagementAce = $childManagementAce | Select-Object *
$otherChildManagementAce.IdentityReference = $otherSid
Assert-True (-not (Test-ADUserLifecycleDelegation -AccessRules @($otherAce, $otherChildManagementAce) -GroupSid $groupSid)) `
    'A name collision or unrelated SID does not satisfy delegation checks'

$delegationGrantPathsAddOuScopedChildRights = $true
foreach ($grantPath in @(
    @{ Path = (Join-Path $repoRoot 'Modules\AD-Provisioning.psm1'); Function = 'Set-DepartmentDelegation' },
    @{ Path = (Join-Path $repoRoot 'Cmdlets\mark42.ps1'); Function = 'Grant-DepartmentUserDelegation' }
)) {
    $grantTokens = $null
    $grantParseErrors = $null
    $grantAst = [System.Management.Automation.Language.Parser]::ParseFile($grantPath.Path, [ref]$grantTokens, [ref]$grantParseErrors)
    $grantFunction = @($grantAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $grantPath.Function
    }, $true)) | Select-Object -First 1
    $grantSource = if ($grantFunction) { $grantFunction.Extent.Text } else { '' }
    if (-not $grantSource.Contains('$childManagementRule') -or
        -not $grantSource.Contains('[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None') -or
        -not $grantSource.Contains('$acl.AddAccessRule($childManagementRule)')) {
        $delegationGrantPathsAddOuScopedChildRights = $false
    }
}
Assert-True $delegationGrantPathsAddOuScopedChildRights 'Both delegation paths grant Create/Delete Child on the target OU itself'

Assert-Throws { Assert-ADUserLifecycleDelegationSafe -GroupSid $groupSid -CreatedByThisRun $false -ExistingDelegation $false } 'New delegation is refused for an unapproved pre-existing group'
Assert-ADUserLifecycleDelegationSafe -GroupSid $groupSid -CreatedByThisRun $true -ExistingDelegation $false
Assert-True $true 'Delegation can be granted to a validated group created in this run'

Write-Host "`nOffline tests: $script:Passed passed, $script:Failed failed." -ForegroundColor Cyan
if ($script:Failed -gt 0) { exit 1 }
exit 0
