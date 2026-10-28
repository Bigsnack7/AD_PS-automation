Set-StrictMode -Version Latest

# Stack of saved PSDefaultParameterValues snapshots, one per successful Set-ADToolContext call.
# Clear-ADToolContext pops exactly one snapshot, so nested contexts restore the OUTER context
# (not the operator's original defaults) and an unmatched Clear is a harmless no-op.
$script:ADToolContextStack = [System.Collections.Generic.Stack[object]]::new()
$script:CreatedADToolDrive = $false

function Import-ADTools {
    Import-Module ActiveDirectory -ErrorAction Stop
    if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
        throw 'The Active Directory PowerShell module is not available.'
    }
}

function Test-ADDomainReachability {
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $context = @{}
    if ($Server) { $context.Server = $Server }
    if ($Credential) { $context.Credential = $Credential }

    try {
        $domain = Get-ADDomain @context -ErrorAction Stop
        return [pscustomobject]@{
            IsReachable = $true
            Domain = $domain.DNSRoot
            Forest = $domain.Forest
            DomainDN = $domain.DistinguishedName
            NetBIOSName = $domain.NetBIOSName
            Server = $Server
            Error = ''
        }
    }
    catch {
        return [pscustomobject]@{
            IsReachable = $false
            Domain = $null
            Forest = $null
            DomainDN = $null
            NetBIOSName = $null
            Error = $_.Exception.Message
            Server = $Server
        }
    }
}

function Assert-ADOperationsDependencies {
    $requiredFunctions = @(
        'Import-ADTools',
        'Set-ADToolContext',
        'Get-ADToolContextParameters',
        'Clear-ADToolContext',
        'Get-ADDistinguishedNameDepth',
        'Add-ADPreflightCheck',
        'Move-ADSecuredFileIntoPlace',
        'Get-ADDistinguishedNameParent',
        'Split-ADDistinguishedName',
        'ConvertTo-ADCanonicalDistinguishedName',
        'Test-ADIdentityNotFoundError',
        'Test-ADAccountInactive',
        'New-ADTerminationDescription',
        'ConvertTo-DistinguishedNameValue',
        'ConvertTo-LdapFilterValue',
        'Get-ADValidatedSecurityGroupSid',
        'Test-ADUserLifecycleDelegation',
        'Assert-ADUserLifecycleDelegationSafe',
        'Assert-ADTargetWithinRoot',
        'Write-ADAuditRecord'
    )

    $missingFunctions = @(
        $requiredFunctions | Where-Object {
            -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
        }
    )

    if ($missingFunctions.Count -gt 0) {
        throw "AD-Operations module was loaded but is missing required functions: $($missingFunctions -join ', ')"
    }
}

function Get-ADToolDefaultSnapshot {
    $defaults = $global:PSDefaultParameterValues
    $hasServer = $defaults.ContainsKey('*-AD*:Server')
    $hasCredential = $defaults.ContainsKey('*-AD*:Credential')
    return [pscustomobject]@{
        HasServer = $hasServer
        Server = if ($hasServer) { $defaults['*-AD*:Server'] } else { $null }
        HasCredential = $hasCredential
        Credential = if ($hasCredential) { $defaults['*-AD*:Credential'] } else { $null }
    }
}

function Restore-ADToolDefaultSnapshot {
    param([Parameter(Mandatory)][psobject]$Snapshot)

    [void]$global:PSDefaultParameterValues.Remove('*-AD*:Server')
    [void]$global:PSDefaultParameterValues.Remove('*-AD*:Credential')
    if ($Snapshot.HasServer) { $global:PSDefaultParameterValues['*-AD*:Server'] = $Snapshot.Server }
    if ($Snapshot.HasCredential) { $global:PSDefaultParameterValues['*-AD*:Credential'] = $Snapshot.Credential }
}

function Set-ADToolContext {
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $isOutermost = ($script:ADToolContextStack.Count -eq 0)
    $existingADDrive = Get-PSDrive -Name AD -ErrorAction SilentlyContinue
    if ($isOutermost -and $existingADDrive -and -not $script:CreatedADToolDrive) {
        throw "A pre-existing AD: drive was found. Its target server cannot be verified safely; remove it or use a clean PowerShell session before starting AD automation."
    }

    $snapshot = Get-ADToolDefaultSnapshot

    # Preserve whatever an already-active (outer) context has set unless this call
    # explicitly overrides it.
    $effectiveCredential = if ($Credential) { $Credential } else { $snapshot.Credential }
    $createdDriveHere = $false

    try {
        [void]$global:PSDefaultParameterValues.Remove('*-AD*:Server')
        [void]$global:PSDefaultParameterValues.Remove('*-AD*:Credential')
        $credentialContext = @{}
        if ($effectiveCredential) {
            $global:PSDefaultParameterValues['*-AD*:Credential'] = $effectiveCredential
            $credentialContext.Credential = $effectiveCredential
        }

        $resolvedServer = if (-not [string]::IsNullOrWhiteSpace($Server)) { $Server } else { [string]$snapshot.Server }
        if ([string]::IsNullOrWhiteSpace($resolvedServer)) {
            $resolvedController = Get-ADDomainController @credentialContext -Discover -Writable -ErrorAction Stop
            $resolvedServer = [string]$resolvedController.HostName
        }

        $global:PSDefaultParameterValues['*-AD*:Server'] = $resolvedServer
        if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
            $adDriveParameters = @{
                Name = 'AD'
                PSProvider = 'ActiveDirectory'
                Root = '//RootDSE/'
                Server = $resolvedServer
                Scope = 'Global'
            }
            if ($effectiveCredential) { $adDriveParameters.Credential = $effectiveCredential }
            $null = New-PSDrive @adDriveParameters -ErrorAction Stop
            $script:CreatedADToolDrive = $true
            $createdDriveHere = $true
        }

        # Only a fully successful call is recorded, so a failed call can never be "cleared".
        $script:ADToolContextStack.Push($snapshot)
        return $resolvedServer
    }
    catch {
        $setFailure = $_
        if ($createdDriveHere) {
            Remove-PSDrive -Name AD -Scope Global -Force -ErrorAction SilentlyContinue
            $script:CreatedADToolDrive = $false
        }
        # Put the outer context back exactly as it was before this failed call.
        Restore-ADToolDefaultSnapshot -Snapshot $snapshot
        throw $setFailure
    }
}

function Get-ADToolContextParameters {
    $context = @{}
    if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Server')) {
        $context.Server = $global:PSDefaultParameterValues['*-AD*:Server']
    }
    if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Credential')) {
        $context.Credential = $global:PSDefaultParameterValues['*-AD*:Credential']
    }
    return $context
}

function Clear-ADToolContext {
    if ($script:ADToolContextStack.Count -eq 0) {
        # Nothing active: leave operator-configured defaults alone. Only clean up a drive we created.
        if ($script:CreatedADToolDrive) {
            if (Get-PSDrive -Name AD -ErrorAction SilentlyContinue) {
                Remove-PSDrive -Name AD -Scope Global -Force -ErrorAction SilentlyContinue
            }
            $script:CreatedADToolDrive = $false
        }
        return
    }

    $snapshot = $script:ADToolContextStack.Pop()

    if ($script:ADToolContextStack.Count -eq 0) {
        if ($script:CreatedADToolDrive -and (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
            Remove-PSDrive -Name AD -Scope Global -Force -ErrorAction SilentlyContinue
        }
        $script:CreatedADToolDrive = $false
    }

    Restore-ADToolDefaultSnapshot -Snapshot $snapshot
}

function Move-ADSecuredFileIntoPlace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$StagingPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationPath,

        [switch]$Overwrite
    )

    $fullStagingPath = [System.IO.Path]::GetFullPath($StagingPath)
    $fullDestinationPath = [System.IO.Path]::GetFullPath($DestinationPath)
    if ($fullStagingPath.Equals($fullDestinationPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Staging and destination paths must be different.'
    }
    if (-not (Test-Path -LiteralPath $fullStagingPath -PathType Leaf)) {
        throw "Staging file '$fullStagingPath' does not exist."
    }

    $stagingDirectory = [System.IO.Path]::GetDirectoryName($fullStagingPath)
    $destinationDirectory = [System.IO.Path]::GetDirectoryName($fullDestinationPath)
    if (-not $stagingDirectory.Equals($destinationDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Staging and destination files must be in the same directory for a safe atomic move.'
    }

    $destinationExists = Test-Path -LiteralPath $fullDestinationPath -PathType Leaf
    if (-not $destinationExists) {
        try {
            [System.IO.File]::Move($fullStagingPath, $fullDestinationPath)
            return
        }
        catch [System.IO.IOException] {
            if (-not (Test-Path -LiteralPath $fullDestinationPath -PathType Leaf)) {
                throw
            }
            if (-not $Overwrite) {
                throw "Destination file '$fullDestinationPath' was created concurrently; refusing to overwrite it."
            }
        }
    }
    elseif (-not $Overwrite) {
        throw "Destination file '$fullDestinationPath' already exists. Specify -Overwrite to replace it."
    }

    $stagingAcl = Get-Acl -LiteralPath $fullStagingPath -ErrorAction Stop
    $destinationAcl = Get-Acl -LiteralPath $fullDestinationPath -ErrorAction Stop
    $backupPath = "$fullDestinationPath.$([Guid]::NewGuid().ToString('N')).bak"
    $replacementCompleted = $false
    try {
        Set-Acl -LiteralPath $fullDestinationPath -AclObject $stagingAcl -ErrorAction Stop
        [System.IO.File]::Replace($fullStagingPath, $fullDestinationPath, $backupPath)
        $replacementCompleted = $true
    }
    catch {
        $replacementError = $_
        if (-not $replacementCompleted -and (Test-Path -LiteralPath $fullDestinationPath -PathType Leaf)) {
            try {
                Set-Acl -LiteralPath $fullDestinationPath -AclObject $destinationAcl -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to restore the original ACL on '$fullDestinationPath' after secure replacement failed: $($_.Exception.Message)"
            }
        }
        throw $replacementError
    }
    finally {
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            try {
                Remove-Item -LiteralPath $backupPath -Force -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to remove secured replacement backup '$backupPath': $($_.Exception.Message)"
            }
        }
    }
}

function New-ADTerminationDescription {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$ExistingDescription,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason,

        [datetime]$TerminationDate = [datetime]::Now
    )

    # Control characters (CR/LF/tab...) would break the single-line description and could be used
    # to forge extra "TERMINATED" entries, so collapse them to a single space.
    $cleanReason = ($Reason -replace '[\x00-\x1F\x7F]+', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($cleanReason)) {
        throw 'Termination reason cannot be blank.'
    }

    $terminationNote = "TERMINATED on $($TerminationDate.ToString('yyyy-MM-dd')) - Reason: $cleanReason"
    $existingValue = if ($null -eq $ExistingDescription) { '' } else { $ExistingDescription }

    if ($existingValue.IndexOf($terminationNote, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        return $existingValue
    }

    $separator = if ([string]::IsNullOrWhiteSpace($existingValue)) { '' } else { ' | ' }
    $updatedDescription = "$existingValue$separator$terminationNote"
    if ($updatedDescription.Length -gt 1024) {
        throw "Termination note would exceed the Active Directory description limit of 1024 characters; no description change was made."
    }

    return $updatedDescription
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $builder = [Text.StringBuilder]::new()
    foreach ($character in $Value.ToCharArray()) {
        switch ([int][char]$character) {
            0 { [void]$builder.Append('\00') }
            40 { [void]$builder.Append('\28') }
            41 { [void]$builder.Append('\29') }
            42 { [void]$builder.Append('\2a') }
            92 { [void]$builder.Append('\5c') }
            default { [void]$builder.Append($character) }
        }
    }
    $builder.ToString()
}

function ConvertTo-DistinguishedNameValue {
    param([Parameter(Mandatory)][string]$Value)
    $escaped = $Value -replace '\\', '\5c' -replace ([char]0), '\00' -replace ',', '\2c' -replace '\+', '\2b' -replace '"', '\22' -replace '<', '\3c' -replace '>', '\3e' -replace ';', '\3b' -replace '=', '\3d'
    if ($escaped.StartsWith(' ')) { $escaped = '\20' + $escaped.Substring(1) }
    elseif ($escaped.StartsWith('#')) { $escaped = '\23' + $escaped.Substring(1) }
    if ($escaped.EndsWith(' ')) { $escaped = $escaped.Substring(0, $escaped.Length - 1) + '\20' }
    $escaped
}

function Split-ADDistinguishedName {
    # Splits a DN into its RDNs on UNESCAPED commas only.
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DistinguishedName)

    $parts = [System.Collections.Generic.List[string]]::new()
    $builder = [System.Text.StringBuilder]::new()
    $escaped = $false
    foreach ($character in $DistinguishedName.ToCharArray()) {
        if ($escaped) {
            [void]$builder.Append($character)
            $escaped = $false
            continue
        }
        if ($character -eq '\') {
            [void]$builder.Append($character)
            $escaped = $true
            continue
        }
        if ($character -eq ',') {
            $parts.Add($builder.ToString())
            [void]$builder.Clear()
            continue
        }
        [void]$builder.Append($character)
    }
    $parts.Add($builder.ToString())
    return $parts.ToArray()
}

function Get-ADDistinguishedNameDepth {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DistinguishedName)
    return @(Split-ADDistinguishedName -DistinguishedName $DistinguishedName).Count
}

function Add-ADPreflightCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[psobject]]$Checks,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Status,
        [string]$Details = ''
    )

    $Checks.Add([pscustomobject]@{
        Name = $Name
        Status = $Status
        Details = $Details
    })
}

function ConvertTo-ADCanonicalDistinguishedName {
    # Normalizes escaping so "\," "\2c" and "\2C" compare equal, and lower-cases the result.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$DistinguishedName)

    $hexDigits = '0123456789abcdefABCDEF'
    $builder = [System.Text.StringBuilder]::new()
    $index = 0
    while ($index -lt $DistinguishedName.Length) {
        $character = $DistinguishedName[$index]
        if ($character -eq '\' -and ($index + 1) -lt $DistinguishedName.Length) {
            $next = $DistinguishedName[$index + 1]
            if (($index + 2) -lt $DistinguishedName.Length -and
                $hexDigits.IndexOf($next) -ge 0 -and
                $hexDigits.IndexOf($DistinguishedName[$index + 2]) -ge 0) {
                [void]$builder.Append('\').Append($DistinguishedName.Substring($index + 1, 2).ToLowerInvariant())
                $index += 3
            }
            else {
                [void]$builder.Append('\').Append(([int][char]$next).ToString('x2'))
                $index += 2
            }
        }
        else {
            [void]$builder.Append($character)
            $index++
        }
    }
    return $builder.ToString().ToLowerInvariant()
}

function Get-ADDistinguishedNameParent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName
    )

    $leadingRdn = [regex]::Match($DistinguishedName, '^(?:[^,\\]|\\.)*,')
    if (-not $leadingRdn.Success -or $leadingRdn.Length -ge $DistinguishedName.Length) {
        throw "Distinguished name '$DistinguishedName' does not contain a parent component."
    }

    return $DistinguishedName.Substring($leadingRdn.Length)
}

function Test-ADIdentityNotFoundError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.GetType().FullName -eq 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException') {
            return $true
        }
        $exception = $exception.InnerException
    }

    return ([string]$ErrorRecord.FullyQualifiedErrorId -match '(^|[,:])(ADIdentityNotFound|Microsoft\.ActiveDirectory\.Management\.ADIdentityNotFoundException)(,|$)')
}

function Test-ADAccountInactive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$User,

        [Parameter(Mandatory)]
        [datetime]$Cutoff
    )

    # Property lookups go through PSObject so an ADUser fetched without -Properties LastLogonDate
    # does not throw under StrictMode. Note LastLogonDate is the replicated lastLogonTimestamp,
    # which can lag real logons by ~14 days; do not use a cutoff shorter than that.
    $lastLogonProperty = $User.PSObject.Properties['LastLogonDate']
    $lastLogon = if ($null -ne $lastLogonProperty) { $lastLogonProperty.Value } else { $null }
    if ($lastLogon) {
        return ([datetime]$lastLogon -lt $Cutoff)
    }

    $createdProperty = $User.PSObject.Properties['WhenCreated']
    $whenCreated = if ($null -ne $createdProperty) { $createdProperty.Value } else { $null }
    if (-not $whenCreated) {
        return $false
    }

    return ([datetime]$whenCreated -lt $Cutoff)
}

function Get-ADValidatedSecurityGroupSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Group,

        [Parameter(Mandatory)]
        [string]$ExpectedName,

        [Parameter(Mandatory)]
        [string]$ExpectedParentDistinguishedName
    )

    $expectedDistinguishedName = "CN=$(ConvertTo-DistinguishedNameValue -Value $ExpectedName),$ExpectedParentDistinguishedName"
    # Compare canonical forms so equivalent escapings ("\," vs "\2c") are not false mismatches.
    if ([string]$Group.Name -ine $ExpectedName -or
        (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName ([string]$Group.DistinguishedName)) -ne
        (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $expectedDistinguishedName)) {
        throw "Administrator group '$ExpectedName' was not resolved at its expected distinguished name '$expectedDistinguishedName'."
    }
    if ([string]$Group.GroupCategory -ine 'Security') {
        throw "Administrator group '$ExpectedName' must be a Security group."
    }
    if ([string]$Group.GroupScope -ine 'Global') {
        throw "Administrator group '$ExpectedName' must have Global scope."
    }

    $sidValue = $Group.SID
    if ($sidValue -is [System.Security.Principal.SecurityIdentifier]) {
        return $sidValue
    }
    if ([string]::IsNullOrWhiteSpace([string]$sidValue)) {
        throw "Administrator group '$ExpectedName' has no SID; refusing delegation."
    }

    try {
        return [System.Security.Principal.SecurityIdentifier]::new([string]$sidValue)
    }
    catch {
        throw "Administrator group '$ExpectedName' has an invalid SID; refusing delegation. $($_.Exception.Message)"
    }
}

function Test-ADUserLifecycleDelegation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AccessRules,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$GroupSid
    )

    $userClassGuid = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    $requiredChildRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $requiredDescendantRights =
        [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListObject -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    $hasChildManagementRights = $false
    $hasUserDescendantRights = $false
    foreach ($rule in $AccessRules) {
        try {
            $ruleSid = if ($rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                $rule.IdentityReference
            }
            else {
                $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            }
            if ($ruleSid -eq $GroupSid) {
                if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                    continue
                }

                if ($rule.ObjectType -eq $userClassGuid -and
                    $rule.InheritedObjectType -eq [Guid]::Empty -and
                    $rule.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None -and
                    (($rule.ActiveDirectoryRights -band $requiredChildRights) -eq $requiredChildRights)) {
                    $hasChildManagementRights = $true
                }

                if ($rule.ObjectType -eq $userClassGuid -and
                    $rule.InheritedObjectType -eq $userClassGuid -and
                    $rule.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents -and
                    (($rule.ActiveDirectoryRights -band $requiredDescendantRights) -eq $requiredDescendantRights)) {
                    $hasUserDescendantRights = $true
                }
            }
        }
        catch {
            continue
        }
    }

    return ($hasChildManagementRights -and $hasUserDescendantRights)
}

function Assert-ADUserLifecycleDelegationSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$GroupSid,

        [Parameter(Mandatory)]
        [bool]$CreatedByThisRun,

        [Parameter(Mandatory)]
        [bool]$ExistingDelegation
    )

    if (-not $CreatedByThisRun -and -not $ExistingDelegation) {
        throw "Refusing to grant user-lifecycle delegation to pre-existing group SID '$($GroupSid.Value)'. Review the group and have an authorized administrator approve its delegation separately."
    }
}

function Assert-CsvColumns {
    param(
        [Parameter(Mandatory)][object]$Row,
        [Parameter(Mandatory)][string[]]$RequiredColumns
    )
    foreach ($column in $RequiredColumns) {
        if (-not ($Row.PSObject.Properties.Name -contains $column)) {
            throw "CSV is missing required column '$column'. Required columns: $($RequiredColumns -join ', ')"
        }
    }
}

function ConvertTo-CsvBoolean {
    param([AllowNull()][string]$Value, [bool]$Default = $false)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    switch ($Value.Trim().ToLowerInvariant()) {
        'true' { return $true }
        'yes' { return $true }
        '1' { return $true }
        'false' { return $false }
        'no' { return $false }
        '0' { return $false }
        default { throw "Invalid Boolean value '$Value'. Use True, False, Yes, No, 1, or 0." }
    }
}

function Resolve-ADIdentitySafe {
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    $context = @{}
    if ($Server) { $context.Server = $Server }
    if ($Credential) { $context.Credential = $Credential }
    try { Get-ADUser @context -Identity $Identity -Properties SamAccountName,UserPrincipalName,Name,DistinguishedName,Enabled -ErrorAction Stop }
    catch {
        $message = $_.Exception.Message
        if (Test-ADIdentityNotFoundError -ErrorRecord $_) {
            throw "User '$Identity' was not found. $message"
        }
        throw "Unable to resolve user '$Identity'. $message"
    }
}

function Test-ADUserExists {
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    $context = @{}
    if ($Server) { $context.Server = $Server }
    if ($Credential) { $context.Credential = $Credential }
    try {
        Get-ADUser @context -Identity $Identity -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        if (Test-ADIdentityNotFoundError -ErrorRecord $_) { return $false }
        throw "Unable to check whether user '$Identity' exists. $($_.Exception.Message)"
    }
}

function Get-TargetOU {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    $context = @{}
    if ($Server) { $context.Server = $Server }
    if ($Credential) { $context.Credential = $Credential }
    try {
        $ou = Get-ADOrganizationalUnit @context -Identity $Path -ErrorAction Stop
        if (@($ou).Count -ne 1) { throw "The target OU '$Path' is ambiguous." }
        $ou
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match 'ambiguous') { throw $message }
        throw "Unable to resolve organizational unit '$Path'. $message"
    }
}

function Write-ADAuditRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [ValidateSet('Started','Succeeded','Failed','Skipped','Preview','CompletedWithErrors')]
        [string]$Status = 'Succeeded',
        [string]$Message = '',
        [string]$Actor,
        [string]$TargetType = 'Unknown',
        [string]$Details = '',
        [string]$Source = '',
        [string]$CorrelationId = ''
    )

    # Resolve against the PowerShell location (not the process working directory) so the directory
    # we create is the same one Add-Content writes to.
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $directory = Split-Path -Parent $resolvedPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    # When -Credential is in use, AD changes are made by that account, not by the logged-on user.
    $adIdentity = ''
    if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Credential')) {
        $adCredential = $global:PSDefaultParameterValues['*-AD*:Credential']
        if ($adCredential -is [System.Management.Automation.PSCredential]) { $adIdentity = $adCredential.UserName }
    }
    $defaultActor = if ($adIdentity) { $adIdentity } else { $currentIdentity.Name }
    $resolvedActor = if (-not [string]::IsNullOrWhiteSpace($Actor)) { $Actor } else { $defaultActor }

    $record = [ordered]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Actor = $resolvedActor
        Operator = $currentIdentity.Name
        Computer = $env:COMPUTERNAME
        Action = $Action
        Target = $Target
        TargetType = $TargetType
        Status = $Status
        Message = $Message
        Details = if ([string]::IsNullOrWhiteSpace($Details)) { $Message } else { $Details }
        Source = $Source
        CorrelationId = $CorrelationId
    }
    ($record | ConvertTo-Json -Compress) | Add-Content -LiteralPath $resolvedPath -Encoding UTF8
}

function Assert-ADTargetWithinRoot {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Target,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$AllowedRoot
    )

    # Compare RDN-by-RDN on UNESCAPED commas. A plain EndsWith(",root") check is bypassable by an
    # object whose NAME contains the root text (e.g. CN=x\,OU=Company,DC=example,DC=com).
    $targetParts = @(Split-ADDistinguishedName -DistinguishedName $Target.Trim() |
        ForEach-Object { (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $_).Trim() })
    $rootParts = @(Split-ADDistinguishedName -DistinguishedName $AllowedRoot.Trim() |
        ForEach-Object { (ConvertTo-ADCanonicalDistinguishedName -DistinguishedName $_).Trim() })

    $isWithinRoot = $rootParts.Count -gt 0 -and $targetParts.Count -ge $rootParts.Count
    if ($isWithinRoot) {
        $offset = $targetParts.Count - $rootParts.Count
        for ($index = 0; $index -lt $rootParts.Count; $index++) {
            if ($targetParts[$offset + $index] -ne $rootParts[$index]) {
                $isWithinRoot = $false
                break
            }
        }
    }

    if (-not $isWithinRoot) {
        throw "Target '$Target' is outside the approved root '$AllowedRoot'."
    }
}

function Export-ADResults {
    # SupportsShouldProcess so callers can pass -WhatIf. Module functions do not inherit the caller's
    # $WhatIfPreference, so checking that variable here never worked.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results,
        [Parameter(Mandatory)][string]$Path
    )

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    if ($Results.Count -eq 0) {
        Write-Warning "No results to export to '$resolvedPath'."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($resolvedPath, "Export $($Results.Count) result(s) to CSV")) {
        return
    }

    $parent = Split-Path -Parent $resolvedPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $Results | Export-Csv -LiteralPath $resolvedPath -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "Results exported to $resolvedPath" -ForegroundColor Green
}

Export-ModuleMember -Function Import-ADTools,Test-ADDomainReachability,Assert-ADOperationsDependencies,Set-ADToolContext,Get-ADToolContextParameters,Clear-ADToolContext,Move-ADSecuredFileIntoPlace,ConvertTo-LdapFilterValue,ConvertTo-DistinguishedNameValue,Split-ADDistinguishedName,Get-ADDistinguishedNameDepth,Add-ADPreflightCheck,ConvertTo-ADCanonicalDistinguishedName,Get-ADDistinguishedNameParent,Test-ADIdentityNotFoundError,Test-ADAccountInactive,New-ADTerminationDescription,Get-ADValidatedSecurityGroupSid,Test-ADUserLifecycleDelegation,Assert-ADUserLifecycleDelegationSafe,Assert-CsvColumns,ConvertTo-CsvBoolean,Resolve-ADIdentitySafe,Test-ADUserExists,Get-TargetOU,Write-ADAuditRecord,Assert-ADTargetWithinRoot,Export-ADResults
