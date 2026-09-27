Set-StrictMode -Version Latest

$script:SavedADToolDefaults = $null
$script:ADToolContextDepth = 0
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
            Server = $Server
        }
    }
    catch {
        return [pscustomobject]@{
            IsReachable = $false
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
        'ConvertTo-DistinguishedNameValue',
        'ConvertTo-LdapFilterValue',
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

function Set-ADToolContext {
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    if ($script:ADToolContextDepth -eq 0) {
        $script:SavedADToolDefaults = @{
            HasServer = $global:PSDefaultParameterValues.ContainsKey('*-AD*:Server')
            Server = if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Server')) { $global:PSDefaultParameterValues['*-AD*:Server'] } else { $null }
            HasCredential = $global:PSDefaultParameterValues.ContainsKey('*-AD*:Credential')
            Credential = if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Credential')) { $global:PSDefaultParameterValues['*-AD*:Credential'] } else { $null }
        }
    }

    # Preserve whatever an already-active (outer) context has set unless this call
    # explicitly overrides it. Without this, a nested Set-ADToolContext call that
    # omits -Credential/-Server would silently clobber the outer context's values.
    $existingCredential = if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Credential')) { $global:PSDefaultParameterValues['*-AD*:Credential'] } else { $null }
    $existingServer = if ($global:PSDefaultParameterValues.ContainsKey('*-AD*:Server')) { $global:PSDefaultParameterValues['*-AD*:Server'] } else { $null }
    $effectiveCredential = if ($Credential) { $Credential } else { $existingCredential }

    [void]$global:PSDefaultParameterValues.Remove('*-AD*:Server')
    [void]$global:PSDefaultParameterValues.Remove('*-AD*:Credential')
    $credentialContext = @{}
    if ($effectiveCredential) {
        $global:PSDefaultParameterValues['*-AD*:Credential'] = $effectiveCredential
        $credentialContext.Credential = $effectiveCredential
    }

    $resolvedServer = if (-not [string]::IsNullOrWhiteSpace($Server)) { $Server } else { $existingServer }
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
        }
        if ($effectiveCredential) { $adDriveParameters.Credential = $effectiveCredential }
        $null = New-PSDrive @adDriveParameters -ErrorAction Stop
        $script:CreatedADToolDrive = $true
    }

    $script:ADToolContextDepth++
    return $resolvedServer
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
    if ($script:ADToolContextDepth -gt 0) {
        $script:ADToolContextDepth--
    }

    if ($script:ADToolContextDepth -gt 0) {
        # Still inside an outer Set-ADToolContext call - leave the context in place
        # until the matching outer Clear-ADToolContext call is made.
        return
    }

    if ($script:CreatedADToolDrive -and (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        Remove-PSDrive -Name AD -Force -ErrorAction SilentlyContinue
    }

    [void]$global:PSDefaultParameterValues.Remove('*-AD*:Server')
    [void]$global:PSDefaultParameterValues.Remove('*-AD*:Credential')

    if ($script:SavedADToolDefaults) {
        if ($script:SavedADToolDefaults.HasServer) {
            $global:PSDefaultParameterValues['*-AD*:Server'] = $script:SavedADToolDefaults.Server
        }
        if ($script:SavedADToolDefaults.HasCredential) {
            $global:PSDefaultParameterValues['*-AD*:Credential'] = $script:SavedADToolDefaults.Credential
        }
    }

    $script:SavedADToolDefaults = $null
    $script:CreatedADToolDrive = $false
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory)][string]$Value)
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
        if ($message -match 'Cannot find|not found|does not exist') {
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
        if ($_.Exception.Message -match 'Cannot find|not found|does not exist') { return $false }
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

    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $resolvedActor = if (-not [string]::IsNullOrWhiteSpace($Actor)) { $Actor } else { $currentIdentity.Name }

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
    ($record | ConvertTo-Json -Compress) | Add-Content -LiteralPath $Path -Encoding UTF8
}

function Assert-ADTargetWithinRoot {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $targetDn = $Target.Trim()
    $rootDn = $AllowedRoot.Trim()
    if (-not $targetDn.Equals($rootDn, [StringComparison]::OrdinalIgnoreCase) -and
        -not $targetDn.EndsWith(",${rootDn}", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Target '$Target' is outside the approved root '$AllowedRoot'."
    }
}
function Export-ADResults {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results, [Parameter(Mandatory)][string]$Path)

    if ($WhatIfPreference) {
        Write-Host "WhatIf: would export $($Results.Count) results to '$Path'." -ForegroundColor DarkGray
        return
    }

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if ($Results.Count -eq 0) {
        Write-Warning "No results to export to '$Path'."
        return
    }
    $Results | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "Results exported to $Path" -ForegroundColor Green
}
Export-ModuleMember -Function Import-ADTools,Test-ADDomainReachability,Assert-ADOperationsDependencies,Set-ADToolContext,Get-ADToolContextParameters,Clear-ADToolContext,ConvertTo-LdapFilterValue,ConvertTo-DistinguishedNameValue,Assert-CsvColumns,ConvertTo-CsvBoolean,Resolve-ADIdentitySafe,Test-ADUserExists,Get-TargetOU,Write-ADAuditRecord,Assert-ADTargetWithinRoot,Export-ADResults