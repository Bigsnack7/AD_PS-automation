[CmdletBinding()]
param(
    [string]$SearchBase,
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [string]$Server,
    [PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootDirectory = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $rootDirectory 'Modules\ADAutoX.psd1') -ErrorAction Stop
Get-ADAutoXSecurityScan @PSBoundParameters
