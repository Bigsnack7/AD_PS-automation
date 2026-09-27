<#
.SYNOPSIS
    Disables a specific Active Directory user account.

.DESCRIPTION
    Compatibility entry point for the shared disable workflow. The implementation lives in
    Script_Disable_Inactive_Users.ps1, which also supports bulk inactive-account processing.
    This is a destructive change and should be previewed with -WhatIf before an approval is granted.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
    [switch]$AllowDestructiveOperation,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AuditLogPath = ''
)

if ([string]::IsNullOrWhiteSpace($Identity)) {
    throw 'Identity cannot be blank.'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$targetScript = Join-Path $scriptDirectory 'Script_Disable_Inactive_Users.ps1'
if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) {
    throw "Required disable workflow not found: $targetScript"
}

# Only forward parameters the caller actually supplied, so this wrapper's own
# defaults (e.g. blank AuditLogPath, null Server/Credential) don't silently
# override whatever default-handling the target script implements.
$arguments = @{
    Identity = $Identity
}
foreach ($name in 'AllowDestructiveOperation','Server','Credential','AuditLogPath') {
    if ($PSBoundParameters.ContainsKey($name)) {
        $arguments[$name] = $PSBoundParameters[$name]
    }
}

$commonArguments = @{}
if ($WhatIfPreference) { $commonArguments.WhatIf = $true }
# Forward the actual bound value, not a hardcoded $true — ContainsKey only
# tells you -Confirm was passed, not whether it was -Confirm or -Confirm:$false.
# Hardcoding $true here would force a prompt even when the caller explicitly
# passed -Confirm:$false to suppress one.
if ($PSBoundParameters.ContainsKey('Confirm')) { $commonArguments.Confirm = $PSBoundParameters['Confirm'] }

& $targetScript @arguments @commonArguments