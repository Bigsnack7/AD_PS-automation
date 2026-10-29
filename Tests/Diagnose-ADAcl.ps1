[CmdletBinding()]
param(
    [string]$Server = '',
    [string]$DistinguishedName = 'OU=Users,OU=IT,OU=Staff,OU=Company,DC=hexwatch,DC=lab',
    [System.Management.Automation.PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '..\Modules\AD-Operations.psm1') -Force -ErrorAction Stop

$adDrive = Get-PSDrive -Name AD -ErrorAction SilentlyContinue
if ($adDrive) {
    Write-Output "AD drive Root: $($adDrive.Root)"
    $driveServer = if ($adDrive.PSObject.Properties['Server']) { [string]$adDrive.Server } else { '' }
    Write-Output "AD drive Server: $driveServer"
    Write-Output "AD drive Provider: $($adDrive.Provider.Name)"
}
else {
    Write-Output 'AD drive: not present'
}

if ([string]::IsNullOrWhiteSpace($Server)) {
    $Server = if ($adDrive -and -not [string]::IsNullOrWhiteSpace($driveServer)) {
        $driveServer
    }
    else {
        $discoveryParameters = @{ Discover = $true; Writable = $true; ErrorAction = 'Stop' }
        if ($Credential) { $discoveryParameters.Credential = $Credential }
        [string](Get-ADDomainController @discoveryParameters).HostName
    }
}
Write-Output "Pinned diagnostic server: $Server"
Write-Output "Distinguished name: $DistinguishedName"

$providerPath = "AD:\$DistinguishedName"
try {
    $pathExists = Test-Path -LiteralPath $providerPath -ErrorAction Stop
    Write-Output "Test-Path '$providerPath': $pathExists"
}
catch {
    Write-Output "Test-Path '$providerPath': error: $($_.Exception.Message)"
}

$lookupParameters = @{ Identity = $DistinguishedName; Server = $Server; ErrorAction = 'Stop' }
if ($Credential) { $lookupParameters.Credential = $Credential }
try {
    $foundOu = Get-ADOrganizationalUnit @lookupParameters
    Write-Output "Get-ADOrganizationalUnit found OU: $([bool]$foundOu)"
}
catch {
    if (Test-ADIdentityNotFoundError -ErrorRecord $_) {
        Write-Output 'Get-ADOrganizationalUnit found OU: False (not found)'
    }
    else {
        Write-Output "Get-ADOrganizationalUnit found OU: error: $($_.Exception.Message)"
    }
}

$aclContext = @{ Server = $Server }
if ($Credential) { $aclContext.Credential = $Credential }
try {
    $acl = Invoke-ADObjectAcl -Action Read -DistinguishedName $DistinguishedName -ADContext $aclContext
    Write-Output "ADSI ObjectSecurity readable: True (ACE count: $($acl.Access.Count))"
}
catch {
    Write-Output "ADSI ObjectSecurity readable: False (error: $($_.Exception.Message))"
}
