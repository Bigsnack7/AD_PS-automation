Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = $PSScriptRoot
$repositoryRoot = Split-Path -Parent $moduleRoot
$modulePaths = @(
    (Join-Path $moduleRoot 'AD-Operations.psm1'),
    (Join-Path $moduleRoot 'AD-Provisioning.psm1'),
    (Join-Path $moduleRoot 'ADAutoX.Lifecycle.psm1')
)

foreach ($modulePath in $modulePaths) {
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw "Required ADAutoX module component not found: $modulePath"
    }
    Import-Module $modulePath -ErrorAction Stop
}

function ConvertTo-ADLdapFilter {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    ConvertTo-LdapFilterValue -Value $Value
}

function ConvertTo-ADDistinguishedNameValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    ConvertTo-DistinguishedNameValue -Value $Value
}

function Get-ADSanitizedSamAccountName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [System.Collections.Generic.HashSet[string]]$UsedNames
    )
    Get-UniqueSamAccountName -BaseName $BaseName -UsedNames $UsedNames
}

function Get-ADSanitizedUserPrincipalName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SamAccountName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UPNSuffix
    )
    $cleanSuffix = $UPNSuffix.Trim().TrimStart('@')
    if ($cleanSuffix -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$') {
        throw "UPN suffix '$UPNSuffix' is invalid. Supply a bare DNS-style suffix such as 'example.com'."
    }
    "$SamAccountName@$cleanSuffix"
}

function New-ADAutoXRandomPassword {
    [CmdletBinding()]
    param([ValidateRange(12, 256)][int]$Length = 24)
    New-RandomPassword -Length $Length
}

function Test-ADAutoXPasswordComplexity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PasswordText)
    Test-PasswordComplexity -PasswordText $PasswordText
}

function Get-ADAutoXSecurityScan {
    [CmdletBinding()]
    param(
        [string]$SearchBase,
        [ValidateRange(1,3650)][int]$InactiveDays = 90,
        [string]$Server,
        [PSCredential]$Credential
    )

    Import-ADTools
    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        $query = @{}
        if ($SearchBase) { $query.SearchBase = $SearchBase; $query.SearchScope = 'Subtree' }
        $lockedUsers = @(Get-ADUser @adContext @query -Filter 'LockedOut -eq $true' -Properties LockedOut, AccountExpirationDate, LastLogonDate, Department -ErrorAction Stop)
        $neverExpires = @(Get-ADUser @adContext @query -Filter 'PasswordNeverExpires -eq $true' -Properties PasswordNeverExpires, Enabled, Department -ErrorAction Stop)
        $threshold = (Get-Date).AddDays(-$InactiveDays)
        $inactiveUsers = @(Get-ADUser @adContext @query -Filter 'Enabled -eq $true' -Properties LastLogonDate, WhenCreated, Department -ErrorAction Stop |
            Where-Object { Test-ADAccountInactive -User $_ -Cutoff $threshold })
        [pscustomobject]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            LockedOutAccountsCount = $lockedUsers.Count
            PasswordNeverExpiresCount = $neverExpires.Count
            InactiveAccountsCount = $inactiveUsers.Count
            LockedUsers = $lockedUsers
            NeverExpiresUsers = $neverExpires
            InactiveUsers = $inactiveUsers
        }
    }
    finally { Clear-ADToolContext }
}

function Invoke-ADAutoXProvision {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [ValidateRange(0, 1000)][int]$AccountCount = 20,
        [Alias('OrganizationalUnitName')][ValidateNotNullOrEmpty()][string]$CompanyOuName = 'Company',
        [Alias('StaffNamesOrganizationalUnitName')][ValidateNotNullOrEmpty()][string]$StaffOuName = 'Staff',
        [string]$NamesPath = '',
        [ValidateNotNullOrEmpty()][string[]]$Departments = @('IT', 'HR', 'Finance', 'Sales'),
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

    $scriptDirectory = $repositoryRoot
    $canonicalScript = Join-Path $scriptDirectory 'Cmdlets\mark42.ps1'
    if (-not (Test-Path -LiteralPath $canonicalScript -PathType Leaf)) {
        throw "Canonical provisioning implementation not found: $canonicalScript"
    }

    if ([string]::IsNullOrWhiteSpace($NamesPath)) {
        $NamesPath = Join-Path $scriptDirectory 'Data\sample-names.txt'
    }
    if ($ExportPasswords -and [string]::IsNullOrWhiteSpace($PasswordFile)) {
        $PasswordFile = Join-Path $scriptDirectory 'user-passwords.clixml'
    }
    if ($IncludePasswordInReport -and [string]::IsNullOrWhiteSpace($ReportPath)) {
        $ReportPath = Join-Path $scriptDirectory 'ADAutoX-Provisioning-Report.csv'
    }
    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path $scriptDirectory 'AD-Operations.jsonl'
    }

    $arguments = @{
        AccountCount = $AccountCount
        OrganizationalUnitName = $CompanyOuName
        StaffNamesOrganizationalUnitName = $StaffOuName
        NamesPath = $NamesPath
        Departments = $Departments
        CreateDepartmentAdministrators = $CreateDepartmentAdministrators
    }
    $optionalArguments = @{
        AdministratorsOnly = $AdministratorsOnly
        AdministratorUsername = $AdministratorUsername
        PasswordPattern = $PasswordPattern
        AdministratorPasswordPattern = $AdministratorPasswordPattern
        Password = $Password
        EnableAccountsAfterVerification = $EnableAccountsAfterVerification
        RollbackCreatedResourcesOnFailure = $RollbackOnFailure
        IncludePasswordInReport = $IncludePasswordInReport
        PasswordFile = $PasswordFile
        ExportPasswords = $ExportPasswords
        OverwritePasswordFile = $OverwritePasswordFile
        ReportPath = $ReportPath
        AuditLogPath = $AuditLogPath
        Server = $Server
        UPNSuffix = $UPNSuffix
        Credential = $Credential
    }
    foreach ($entry in $optionalArguments.GetEnumerator()) {
        $hasValue = if ($entry.Value -is [string]) {
            -not [string]::IsNullOrWhiteSpace($entry.Value)
        }
        else {
            [bool]$entry.Value
        }
        if ($hasValue) {
            $arguments[$entry.Key] = $entry.Value
        }
    }

    if ($WhatIfPreference) { $arguments.WhatIf = $true }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
    $arguments.CorrelationId = New-ADAutoXCorrelationId
    & $canonicalScript @arguments
}

$script:ADAutoXLedger = [System.Collections.Generic.List[psobject]]::new()
$script:ADAutoXLedgerSequence = 0

function Test-ADAutoXDomainReachability {
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)

    $result = Test-ADDomainReachability -Server $Server -Credential $Credential
    [pscustomobject]@{
        IsReachable = $result.IsReachable
        DomainName = $result.Domain
        Forest = $result.Forest
        DomainDN = $result.DomainDN
        NetBIOSName = $result.NetBIOSName
        Server = $result.Server
        Error = $result.Error
    }
}

function Initialize-ADAutoXContext {
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)

    Import-ADTools
    $null = Set-ADToolContext -Server $Server -Credential $Credential
    try {
        $context = Get-ADToolContextParameters
        $domain = Get-ADDomain @context -ErrorAction Stop
        [pscustomobject]@{
            Server = $context.Server
            DomainName = $domain.DNSRoot
            Forest = $domain.Forest
            DomainDN = $domain.DistinguishedName
            NetBIOSName = $domain.NetBIOSName
            UPNSuffixes = $domain.UPNSuffixes
        }
    }
    catch {
        Clear-ADToolContext
        throw
    }
}

function Clear-ADAutoXContext {
    [CmdletBinding()]
    param()
    Clear-ADToolContext
}

function Write-ADAutoXConsole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Verbose', 'Phase')][string]$Level = 'Info'
    )
    $time = (Get-Date).ToString('HH:mm:ss')
    switch ($Level) {
        'Success' { Write-Host "[$time] [+] $Message" -ForegroundColor Green }
        'Warning' { Write-Host "[$time] [!] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$time] [-] $Message" -ForegroundColor Red }
        'Phase' { Write-Host "`n[$time] === $Message ===" -ForegroundColor Cyan }
        'Verbose' { Write-Verbose "[$time] [*] $Message" }
        default { Write-Host "[$time] [*] $Message" -ForegroundColor Gray }
    }
}

function Initialize-ADAutoXLedger {
    [CmdletBinding()]
    param()
    $script:ADAutoXLedger.Clear()
    $script:ADAutoXLedgerSequence = 0
}

function Get-ADAutoXLedger {
    [CmdletBinding()]
    param()
    $script:ADAutoXLedger.ToArray()
}

function Add-ADAutoXLedgerEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('OU', 'Group', 'User', 'Lifecycle')][string]$ObjectType,
        [string]$DistinguishedName,
        [string]$SamAccountName,
        [ValidateSet('RestoreEnabled', 'MoveUser', 'GroupMembership', 'RestoreDescription', 'RestoreAttributes')]
        [string]$Action,
        [hashtable]$UndoData,
        [bool]$CreatedByThisRun = $true
    )
    if ($ObjectType -eq 'Lifecycle') {
        if (-not $Action -or -not $UndoData -or -not $UndoData.UserIdentity) {
            throw 'Lifecycle ledger entries require an undo action and a user object identity.'
        }
        if (-not $DistinguishedName) { $DistinguishedName = [string]$UndoData.UserDistinguishedName }
        if (-not $SamAccountName) { $SamAccountName = [string]$UndoData.SamAccountName }
        $CreatedByThisRun = $false
    }
    elseif ([string]::IsNullOrWhiteSpace($DistinguishedName) -or [string]::IsNullOrWhiteSpace($SamAccountName)) {
        throw 'Created-resource ledger entries require a distinguished name and SAM account name.'
    }
    $script:ADAutoXLedgerSequence++
    $script:ADAutoXLedger.Add([pscustomobject]@{
        ObjectType = $ObjectType
        DistinguishedName = $DistinguishedName
        SamAccountName = $SamAccountName
        CreatedByThisRun = $CreatedByThisRun
        Action = $Action
        UndoData = $UndoData
        Sequence = $script:ADAutoXLedgerSequence
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    })
}

function Invoke-ADAutoXLifecycleUndo {
    param(
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][hashtable]$ADContext,
        [Parameter(Mandatory)][string]$AllowedRoot
    )

    $undo = $Entry.UndoData
    $user = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Enabled,Description,Department,Company,DistinguishedName -ErrorAction Stop
    Assert-ADTargetWithinRoot -Target $user.DistinguishedName -AllowedRoot $AllowedRoot
    $userParent = Get-ADDistinguishedNameParent -DistinguishedName $user.DistinguishedName

    switch ($Entry.Action) {
        'RestoreEnabled' {
            if ([bool]$user.Enabled -ne [bool]$undo.ExpectedEnabled) {
                throw "Account enabled state changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to overwrite the newer state."
            }
            if ([bool]$undo.RestoreEnabled) {
                Enable-ADAccount @ADContext -Identity $user -Confirm:$false -ErrorAction Stop
            }
            else {
                Disable-ADAccount @ADContext -Identity $user -Confirm:$false -ErrorAction Stop
            }
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Enabled -ErrorAction Stop
            if ([bool]$verified.Enabled -ne [bool]$undo.RestoreEnabled) {
                throw "Account enabled-state rollback verification failed for '$($user.SamAccountName)'."
            }
        }
        'MoveUser' {
            if ((ConvertTo-ADCanonicalDistinguishedName $userParent) -ne
                (ConvertTo-ADCanonicalDistinguishedName ([string]$undo.ExpectedParent))) {
                throw "Account location changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to move it."
            }
            Assert-ADTargetWithinRoot -Target ([string]$undo.RestoreParent) -AllowedRoot $AllowedRoot
            Move-ADObject @ADContext -Identity $user -TargetPath ([string]$undo.RestoreParent) -Confirm:$false -ErrorAction Stop
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties DistinguishedName -ErrorAction Stop
            $verifiedParent = Get-ADDistinguishedNameParent -DistinguishedName $verified.DistinguishedName
            if ((ConvertTo-ADCanonicalDistinguishedName $verifiedParent) -ne
                (ConvertTo-ADCanonicalDistinguishedName ([string]$undo.RestoreParent))) {
                throw "Account move rollback verification failed for '$($user.SamAccountName)'."
            }
        }
        'GroupMembership' {
            $group = Get-ADGroup @ADContext -Identity ([Guid]$undo.GroupIdentity) -ErrorAction Stop
            $isMember = @((Get-ADGroupMember @ADContext -Identity $group -ErrorAction Stop) |
                Where-Object { $_.SID -eq $user.SID }).Count -gt 0
            if ($isMember -ne [bool]$undo.ExpectedMembership) {
                throw "Group membership changed since the ledger entry was recorded for '$($user.SamAccountName)' and '$($group.Name)'; refusing to overwrite the newer state."
            }
            if ([bool]$undo.RestoreMembership) {
                Add-ADGroupMember @ADContext -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
            }
            else {
                Remove-ADGroupMember @ADContext -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
            }
            $isMemberAfter = @((Get-ADGroupMember @ADContext -Identity $group -ErrorAction Stop) |
                Where-Object { $_.SID -eq $user.SID }).Count -gt 0
            if ($isMemberAfter -ne [bool]$undo.RestoreMembership) {
                throw "Group membership rollback verification failed for '$($user.SamAccountName)' and '$($group.Name)'."
            }
        }
        'RestoreDescription' {
            if ([string]$user.Description -cne [string]$undo.ExpectedDescription) {
                throw "Account description changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to overwrite the newer value."
            }
            if ([string]::IsNullOrEmpty([string]$undo.RestoreDescription)) {
                Set-ADUser @ADContext -Identity $user -Clear Description -Confirm:$false -ErrorAction Stop
            }
            else {
                Set-ADUser @ADContext -Identity $user -Description ([string]$undo.RestoreDescription) -Confirm:$false -ErrorAction Stop
            }
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Description -ErrorAction Stop
            if ([string]$verified.Description -cne [string]$undo.RestoreDescription) {
                throw "Account description rollback verification failed for '$($user.SamAccountName)'."
            }
        }
        'RestoreAttributes' {
            foreach ($attribute in @('Department', 'Company')) {
                if ([string]$user.$attribute -cne [string]$undo.ExpectedAttributes[$attribute]) {
                    throw "Account $attribute changed since the ledger entry was recorded for '$($user.SamAccountName)'; refusing to overwrite the newer value."
                }
            }
            $setAttributes = @{}
            $clearAttributes = [System.Collections.Generic.List[string]]::new()
            foreach ($attribute in @('Department', 'Company')) {
                $previousValue = [string]$undo.RestoreAttributes[$attribute]
                if ([string]::IsNullOrEmpty($previousValue)) {
                    $clearAttributes.Add($attribute)
                }
                else {
                    $setAttributes[$attribute] = $previousValue
                }
            }
            $setParameters = @{ Identity = $user; Confirm = $false; ErrorAction = 'Stop' }
            foreach ($attribute in $setAttributes.Keys) { $setParameters[$attribute] = $setAttributes[$attribute] }
            if ($clearAttributes.Count -gt 0) { $setParameters.Clear = $clearAttributes.ToArray() }
            Set-ADUser @ADContext @setParameters
            $verified = Get-ADUser @ADContext -Identity ([Guid]$undo.UserIdentity) -Properties Department,Company -ErrorAction Stop
            foreach ($attribute in @('Department', 'Company')) {
                if ([string]$verified.$attribute -cne [string]$undo.RestoreAttributes[$attribute]) {
                    throw "Account $attribute rollback verification failed for '$($user.SamAccountName)'."
                }
            }
        }
        default { throw "Unsupported lifecycle undo action '$($Entry.Action)'." }
    }
}

function Invoke-ADAutoXLedgerRollback {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$LogPath = '',
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$AllowedRoot,
        [switch]$AllowDestructiveOperation,
        [string]$Server,
        [PSCredential]$Credential
    )

    if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
        throw 'Live rollback requires -AllowDestructiveOperation. Preview with -WhatIf first.'
    }
    $lifecycleItems = @($script:ADAutoXLedger |
        Where-Object ObjectType -eq 'Lifecycle' |
        Sort-Object Sequence -Descending)
    $items = @($lifecycleItems + @($script:ADAutoXLedger | Where-Object {
        $_.ObjectType -ne 'Lifecycle' -and $_.CreatedByThisRun
    }))
    if ($items.Count -eq 0) {
        return [pscustomobject]@{ RolledBack = $false; RestoredCount = 0; RemovedCount = 0; FailedCount = 0; Results = @() }
    }

    Import-ADTools
    $results = [System.Collections.Generic.List[object]]::new()
    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        foreach ($item in $lifecycleItems) {
            $mutationCompleted = $false
            $target = if ($item.DistinguishedName) { $item.DistinguishedName } else { $item.SamAccountName }
            try {
                $operation = "Restore lifecycle change '$($item.Action)'"
                if (-not $PSCmdlet.ShouldProcess($target, $operation)) {
                    $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
                    $results.Add([pscustomobject]@{ ObjectType = 'Lifecycle'; Action = $item.Action; Identity = $item.SamAccountName; Status = $status })
                    continue
                }
                Invoke-ADAutoXLifecycleUndo -Entry $item -ADContext $adContext -AllowedRoot $AllowedRoot
                $mutationCompleted = $true
                $null = $script:ADAutoXLedger.Remove($item)
                $results.Add([pscustomobject]@{ ObjectType = 'Lifecycle'; Action = $item.Action; Identity = $item.SamAccountName; Status = 'Succeeded' })
                if ($LogPath) {
                    Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.Action)" -Target $target -Status 'Succeeded'
                }
            }
            catch {
                $status = if ($mutationCompleted) { 'CompletedWithErrors' } else { 'Failed' }
                $message = $_.Exception.Message
                if ($LogPath) {
                    try {
                        Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.Action)" -Target $target -Status $status -Message $message
                    }
                    catch {
                        $message += " Audit logging also failed: $($_.Exception.Message)"
                    }
                }
                $results.Add([pscustomobject]@{ ObjectType = 'Lifecycle'; Action = $item.Action; Identity = $item.SamAccountName; Status = $status; Error = $message })
            }
        }
        $orderedItems = @(
            @($items | Where-Object ObjectType -eq 'User')
            @($items | Where-Object ObjectType -eq 'Group')
            @($items | Where-Object ObjectType -eq 'OU' | Sort-Object {
                - (Get-ADDistinguishedNameDepth -DistinguishedName $_.DistinguishedName)
            })
        )
        $allowedRootCanonical = ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $AllowedRoot
        foreach ($item in $orderedItems) {
            $mutationCompleted = $false
            try {
                Assert-ADTargetWithinRoot -Target $item.DistinguishedName -AllowedRoot $AllowedRoot
                if ($item.ObjectType -eq 'OU' -and
                    (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $item.DistinguishedName) -eq $allowedRootCanonical) {
                    throw "Rollback refuses to remove the approved scope root '$AllowedRoot'."
                }
                $operation = "Remove created $($item.ObjectType) during rollback"
                if (-not $PSCmdlet.ShouldProcess($item.DistinguishedName, $operation)) {
                    $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
                    $results.Add([pscustomobject]@{ ObjectType = $item.ObjectType; Identity = $item.SamAccountName; Status = $status })
                    continue
                }

                switch ($item.ObjectType) {
                    'User' { Remove-ADUser @adContext -Identity $item.DistinguishedName -Confirm:$false -ErrorAction Stop }
                    'Group' { Remove-ADGroup @adContext -Identity $item.DistinguishedName -Confirm:$false -ErrorAction Stop }
                    'OU' {
                        $organizationalUnit = Get-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
                        $wasProtected = [bool]$organizationalUnit.ProtectedFromAccidentalDeletion
                        if ($wasProtected) {
                            Set-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                        }
                        try {
                            Remove-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -Confirm:$false -ErrorAction Stop
                        }
                        catch {
                            if ($wasProtected) {
                                try { Set-ADOrganizationalUnit @adContext -Identity $item.DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop }
                                catch { Write-Warning "Could not restore accidental-deletion protection on '$($item.DistinguishedName)': $($_.Exception.Message)" }
                            }
                            throw
                        }
                    }
                }
                $mutationCompleted = $true
                $null = $script:ADAutoXLedger.Remove($item)
                $results.Add([pscustomobject]@{ ObjectType = $item.ObjectType; Identity = $item.SamAccountName; Status = 'Succeeded' })
                if ($LogPath) {
                    Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.ObjectType)" -Target $item.DistinguishedName -Status 'Succeeded'
                }
            }
            catch {
                $status = if ($mutationCompleted) { 'CompletedWithErrors' } else { 'Failed' }
                $message = $_.Exception.Message
                if ($LogPath) {
                    try {
                        Write-ADAutoXLogRecord -LogPath $LogPath -Action "Rollback$($item.ObjectType)" -Target $item.DistinguishedName -Status $status -Message $message
                    }
                    catch {
                        $message += " Audit logging also failed: $($_.Exception.Message)"
                    }
                }
                $results.Add([pscustomobject]@{ ObjectType = $item.ObjectType; Identity = $item.SamAccountName; Status = $status; Error = $message })
            }
        }
    }
    finally { Clear-ADToolContext }

    $failedCount = @($results | Where-Object Status -in @('Failed', 'CompletedWithErrors')).Count
    [pscustomobject]@{
        RolledBack = $failedCount -eq 0 -and @($results | Where-Object Status -eq 'Succeeded').Count -gt 0
        RestoredCount = @($results | Where-Object {
            $_.ObjectType -eq 'Lifecycle' -and $_.Status -in @('Succeeded', 'CompletedWithErrors')
        }).Count
        RemovedCount = @($results | Where-Object {
            $_.ObjectType -ne 'Lifecycle' -and $_.Status -in @('Succeeded', 'CompletedWithErrors')
        }).Count
        FailedCount = $failedCount
        Results = $results.ToArray()
    }
}

function Invoke-ADAutoXPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CompanyOuName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$StaffOuName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Departments,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DomainDN,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$NetBIOSName
    )

    Write-ADAutoXConsole -Message 'Phase 1: Preflight Validation (Non-mutating)' -Level Phase
    $checks = [System.Collections.Generic.List[object]]::new()

    if (-not (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue)) {
        Write-ADAutoXConsole -Message '[Offline/Preview] Active Directory module is unavailable. Simulating preflight checks.' -Level Warning
        $checks.Add([pscustomobject]@{ Name = 'Company OU'; Status = 'NeedsAttention'; Details = "Root OU '$CompanyOuName' will be created during provisioning." })
        $checks.Add([pscustomobject]@{ Name = 'Staff OU'; Status = 'NeedsAttention'; Details = "Staff OU '$StaffOuName' will be created during provisioning." })
        foreach ($department in $Departments) {
            $checks.Add([pscustomobject]@{ Name = "Department Structure: $department"; Status = 'Passed'; Details = "Validated target scope for $department." })
        }
        $summary = [pscustomobject]@{
            PassedCount = @($checks | Where-Object Status -eq 'Passed').Count
            NeedsAttentionCount = @($checks | Where-Object Status -eq 'NeedsAttention').Count
            Checks = $checks.ToArray()
        }
        Write-ADAutoXConsole -Message "Preflight completed: $($summary.PassedCount) passed, $($summary.NeedsAttentionCount) pending creation." -Level Info
        return $summary
    }

    $companyFilterValue = ConvertTo-LdapFilterValue -Value $CompanyOuName
    $companyOUs = @(Get-ADOrganizationalUnit -LDAPFilter "(ou=$companyFilterValue)" -SearchBase $DomainDN -SearchScope OneLevel -ErrorAction Stop)
    $companyExists = $companyOUs.Count -eq 1
    $checks.Add([pscustomobject]@{
        Name = 'Company OU'
        Status = if ($companyExists) { 'Passed' } else { 'NeedsAttention' }
        Details = if ($companyExists) { "Root OU '$CompanyOuName' exists." } else { "Root OU '$CompanyOuName' will be created." }
    })

    $staffExists = $false
    if ($companyExists) {
        $staffFilterValue = ConvertTo-LdapFilterValue -Value $StaffOuName
        $staffOUs = @(Get-ADOrganizationalUnit -LDAPFilter "(ou=$staffFilterValue)" -SearchBase $companyOUs[0].DistinguishedName -SearchScope OneLevel -ErrorAction Stop)
        $staffExists = $staffOUs.Count -eq 1
    }
    $checks.Add([pscustomobject]@{
        Name = 'Staff OU'
        Status = if ($staffExists) { 'Passed' } else { 'NeedsAttention' }
        Details = if ($staffExists) { "Staff OU '$StaffOuName' exists." } else { "Staff OU '$StaffOuName' will be created." }
    })
    foreach ($department in $Departments) {
        $checks.Add([pscustomobject]@{ Name = "Department Structure: $department"; Status = 'Passed'; Details = "Validated target scope for $department." })
    }
    $summary = [pscustomobject]@{
        PassedCount = @($checks | Where-Object Status -eq 'Passed').Count
        NeedsAttentionCount = 0
        Checks = $checks.ToArray()
    }
    $summary.NeedsAttentionCount = @($checks | Where-Object Status -eq 'NeedsAttention').Count
    Write-ADAutoXConsole -Message "Preflight completed: $($summary.PassedCount) passed, $($summary.NeedsAttentionCount) pending creation." -Level Info
    $summary
}

$publicFunctions = @(
    'Import-ADTools', 'Test-ADDomainReachability', 'Assert-ADOperationsDependencies',
    'Set-ADToolContext', 'Get-ADToolContextParameters', 'Clear-ADToolContext',
    'Move-ADSecuredFileIntoPlace', 'ConvertTo-LdapFilterValue', 'ConvertTo-DistinguishedNameValue',
    'Split-ADDistinguishedName', 'Get-ADDistinguishedNameDepth', 'ConvertTo-ADCanonicalDistinguishedName',
    'Get-ADDistinguishedNameParent', 'Test-ADIdentityNotFoundError', 'Test-ADAccountInactive',
    'New-ADTerminationDescription', 'Get-ADValidatedSecurityGroupSid', 'Test-ADUserLifecycleDelegation',
    'Assert-ADUserLifecycleDelegationSafe', 'Assert-CsvColumns', 'ConvertTo-CsvBoolean',
    'Resolve-ADIdentitySafe', 'Test-ADUserExists', 'Get-TargetOU', 'Write-ADAuditRecord',
    'Assert-ADTargetWithinRoot', 'Export-ADResults',
    'Test-DepartmentNames', 'Get-ADInvocationContext', 'New-RandomPassword',
    'Test-PasswordComplexity', 'Resolve-PasswordPatternText', 'Get-UniqueSamAccountName',
    'Get-ADFailureCategory', 'Get-ADCreateFailureDetails', 'Initialize-ADProvisioning',
    'Clear-ADProvisioningContext', 'Test-ADProvisioningPreflight', 'Test-ADProvisioningTargetPermissions',
    'New-CompanyOU', 'New-DepartmentOU', 'New-DepartmentGroups', 'New-DepartmentUser',
    'New-DepartmentAdministrator', 'Enable-VerifiedDepartmentAccount', 'Set-DepartmentDelegation',
    'Test-DepartmentProvisioning', 'Export-ProvisioningReport', 'Invoke-ProvisioningRollback',
    'Invoke-ADAutoXUserLifecycle', 'Enable-ADAutoXUser', 'Disable-ADAutoXUser',
    'Unlock-ADAutoXUser', 'Reset-ADAutoXUserPassword', 'Move-ADAutoXUser',
    'Stop-ADAutoXUser', 'Remove-ADAutoXUser', 'Set-ADAutoXUserGroupMembership',
    'Disable-ADAutoXInactiveUsers', 'Get-ADAutoXLockedOutUsers', 'Update-ADAutoXUserDepartments',
    'ConvertTo-ADLdapFilter', 'ConvertTo-ADDistinguishedNameValue',
    'Get-ADSanitizedSamAccountName', 'Get-ADSanitizedUserPrincipalName', 'New-ADAutoXRandomPassword',
    'Test-ADAutoXPasswordComplexity', 'Get-ADAutoXSecurityScan', 'Invoke-ADAutoXProvision',
    'Protect-ADAutoXFileAcl', 'Export-ADAutoXCredentials', 'Get-ADAutoXAuditReport',
    'New-ADAutoXCorrelationId', 'Get-ADAutoXCorrelationId', 'Write-ADAutoXLogRecord',
    'Test-ADAutoXDomainReachability', 'Initialize-ADAutoXContext', 'Clear-ADAutoXContext',
    'Write-ADAutoXConsole', 'Initialize-ADAutoXLedger', 'Get-ADAutoXLedger',
    'Add-ADAutoXLedgerEntry', 'Invoke-ADAutoXLedgerRollback', 'Invoke-ADAutoXPreflight'
)

Export-ModuleMember -Function $publicFunctions -Alias Terminate-ADAutoXUser
