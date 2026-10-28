Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$operationsPath = Join-Path $PSScriptRoot 'AD-Operations.psm1'
Import-Module $operationsPath -ErrorAction Stop

function Add-ADAutoXLifecycleUndoEntry {
    param(
        [Parameter(Mandatory)][ValidateSet('RestoreEnabled', 'MoveUser', 'GroupMembership', 'RestoreDescription', 'RestoreAttributes')][string]$Action,
        [Parameter(Mandatory)][psobject]$User,
        [Parameter(Mandatory)][hashtable]$UndoData
    )

    $UndoData.UserIdentity = [string]$User.ObjectGUID
    $UndoData.SamAccountName = [string]$User.SamAccountName
    $UndoData.UserDistinguishedName = [string]$User.DistinguishedName
    Add-ADAutoXLedgerEntry -ObjectType Lifecycle -Action $Action -UndoData $UndoData
}

function Test-ADAutoXProtectedAccount {
    param(
        [Parameter(Mandatory)][psobject]$User,
        [Parameter(Mandatory)][hashtable]$ADContext,
        [Parameter(Mandatory)][ValidateSet('Disable', 'Terminate', 'Delete', 'ResetPassword', 'Move', 'AddToGroup', 'RemoveFromGroup')][string]$Action,
        [ref]$Reason
    )

    $account = Get-ADUser @ADContext -Identity $User.DistinguishedName `
        -Properties AdminCount,IsCriticalSystemObject,SID,SamAccountName -ErrorAction Stop
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ([int]$account.AdminCount -eq 1) {
        $reasons.Add('AdminCount is 1')
    }

    $protectedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators'
    )
    $accountGroups = @(Get-ADPrincipalGroupMembership @ADContext -Identity $account -ErrorAction Stop)
    foreach ($group in $accountGroups) {
        if ($group.Name -in $protectedGroups) {
            $reasons.Add("member of protected group '$($group.Name)'")
        }
    }

    if ($account.IsCriticalSystemObject) {
        $reasons.Add('IsCriticalSystemObject is true')
    }

    if ($account.SamAccountName -in @('Administrator', 'Guest', 'krbtgt')) {
        $reasons.Add("built-in account '$($account.SamAccountName)'")
    }

    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($currentUserSid -and $account.SID -and
        [string]$currentUserSid -eq [string]$account.SID) {
        $reasons.Add('account is running this script')
    }

    if ($Action -in @('Terminate', 'Delete')) {
        $protectedObject = Get-ADObject @ADContext -Identity $account.DistinguishedName `
            -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
        if ($protectedObject.ProtectedFromAccidentalDeletion) {
            $reasons.Add('ProtectedFromAccidentalDeletion is true')
        }
    }

    if ($Reason) {
        $Reason.Value = $reasons -join '; '
    }
    return ($reasons.Count -gt 0)
}

function Invoke-ADAutoXUserLifecycle {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable', 'Unlock', 'ResetPassword', 'Move', 'Terminate', 'Delete', 'AddToGroup', 'RemoveFromGroup')]
        [string]$Action,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        [string]$TargetPath,
        [string]$Group,
        [string]$Reason = 'Terminated',
        [SecureString]$NewPassword,
        [switch]$MustChangeAtLogon,
        [switch]$AllowDestructiveOperation,
        [switch]$AllowProtectedAccount,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AD-Operations.jsonl'
    }
    $correlationId = New-ADAutoXCorrelationId

    $destructiveActions = @('Disable', 'Terminate', 'Delete', 'RemoveFromGroup')
    if (-not $WhatIfPreference -and $Action -in $destructiveActions -and -not $AllowDestructiveOperation) {
        throw "Action '$Action' requires -AllowDestructiveOperation. Preview with -WhatIf first."
    }
    if ($Action -eq 'Move' -and [string]::IsNullOrWhiteSpace($TargetPath)) {
        throw 'Move action requires -TargetPath.'
    }
    if ($Action -in @('AddToGroup', 'RemoveFromGroup') -and [string]::IsNullOrWhiteSpace($Group)) {
        throw "Action '$Action' requires -Group."
    }
    if ($Action -eq 'Terminate' -and [string]::IsNullOrWhiteSpace($Reason)) {
        throw 'Termination reason cannot be blank.'
    }

    Import-ADTools
    $target = $Identity
    $user = $null
    $mutationAttempted = $false
    $actionName = switch ($Action) {
        'Enable' { 'EnableUser' }
        'Disable' { 'DisableUser' }
        'Unlock' { 'UnlockUser' }
        'ResetPassword' { 'ResetPassword' }
        'Move' { 'MoveUser' }
        'Terminate' { 'TerminateUser' }
        'Delete' { 'DeleteUser' }
        'AddToGroup' { 'AddGroupMember' }
        'RemoveFromGroup' { 'RemoveGroupMember' }
    }
    $targetType = if ($Action -in @('AddToGroup', 'RemoveFromGroup')) { 'GroupMembership' } else { 'User' }

    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        $user = Resolve-ADIdentitySafe -Identity $Identity @adContext
        $target = $user.DistinguishedName

        if ($Action -in @('Disable', 'Terminate', 'Delete', 'ResetPassword', 'Move', 'AddToGroup', 'RemoveFromGroup')) {
            $protectionReason = ''
            $isProtectedAccount = Test-ADAutoXProtectedAccount -User $user -ADContext $adContext `
                -Action $Action -Reason ([ref]$protectionReason)
            if ($isProtectedAccount) {
                if (-not $AllowProtectedAccount) {
                    $message = "Refusing action '$Action' on protected account '$($user.SamAccountName)': $protectionReason. Use -AllowProtectedAccount only when this change is explicitly approved."
                    Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType `
                        -Status 'Failed' -Message $message -Details "Blocked protected-account action. $protectionReason" `
                        -Source 'ADAutoX' -CorrelationId $correlationId
                    throw $message
                }

                $warning = "WARNING: -AllowProtectedAccount bypassed the protected-account guard for '$($user.SamAccountName)' during '$Action'. Reasons: $protectionReason"
                Write-Warning $warning
                Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType `
                    -Status 'Started' -Message $warning -Details $warning `
                    -Source 'ADAutoX' -CorrelationId $correlationId
            }
        }

        $targetOU = $null
        $groupObject = $null
        $currentParent = $null
        $isMember = $false

        switch ($Action) {
            'Move' {
                $targetOU = Get-TargetOU -Path $TargetPath @adContext
                $target = "$($user.DistinguishedName) -> $($targetOU.DistinguishedName)"
                $currentParent = Get-ADDistinguishedNameParent -DistinguishedName $user.DistinguishedName
                if ((ConvertTo-ADCanonicalDistinguishedName $currentParent) -eq
                    (ConvertTo-ADCanonicalDistinguishedName $targetOU.DistinguishedName)) {
                    Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType -Status 'Skipped' -Details "User '$($user.SamAccountName)' is already in the target OU." -Source 'ADAutoX' -CorrelationId $correlationId
                    return [pscustomobject]@{ Action = $Action; Identity = $user.SamAccountName; Status = 'Skipped'; Target = $target }
                }
            }
            { $_ -in @('AddToGroup', 'RemoveFromGroup') } {
                $groupObject = Get-ADGroup @adContext -Identity $Group -ErrorAction Stop
                $target = "$($user.DistinguishedName) -> $($groupObject.DistinguishedName)"
                $isMember = @((Get-ADGroupMember @adContext -Identity $groupObject -ErrorAction Stop) |
                    Where-Object { $_.SID -eq $user.SID }).Count -gt 0
                if (($Action -eq 'AddToGroup' -and $isMember) -or
                    ($Action -eq 'RemoveFromGroup' -and -not $isMember)) {
                    $membershipStatus = if ($Action -eq 'AddToGroup') { 'already a member' } else { 'not a member' }
                    Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType -Status 'Skipped' -Details "User '$($user.SamAccountName)' is $membershipStatus of group '$($groupObject.Name)'." -Source 'ADAutoX' -CorrelationId $correlationId
                    return [pscustomobject]@{ Action = $Action; Identity = $user.SamAccountName; Status = 'Skipped'; Target = $target }
                }
            }
            'Terminate' {
                if ($TargetPath) {
                    $targetOU = Get-TargetOU -Path $TargetPath @adContext
                    $target = "$($user.DistinguishedName) -> $($targetOU.DistinguishedName)"
                }
                $currentUser = Get-ADUser @adContext -Identity $user -Properties Enabled,Description -ErrorAction Stop
                $terminationDescription = New-ADTerminationDescription -ExistingDescription $currentUser.Description -Reason $Reason
                $currentParent = Get-ADDistinguishedNameParent -DistinguishedName $user.DistinguishedName
            }
            'ResetPassword' {
                if (-not $PSBoundParameters.ContainsKey('NewPassword') -and -not $WhatIfPreference) {
                    $NewPassword = Read-Host 'New password' -AsSecureString
                }
                if (-not $WhatIfPreference -and ($null -eq $NewPassword -or $NewPassword.Length -eq 0)) {
                    throw 'A non-empty password is required.'
                }
            }
        }

        $description = switch ($Action) {
            'Enable' { 'Enable Active Directory account' }
            'Disable' { 'Disable Active Directory account' }
            'Unlock' { 'Unlock Active Directory account' }
            'ResetPassword' { 'Reset Active Directory account password' }
            'Move' { "Move Active Directory account to '$($targetOU.DistinguishedName)'" }
            'Terminate' { 'Terminate Active Directory account' }
            'Delete' { 'Delete Active Directory account' }
            'AddToGroup' { "Add user to group '$($groupObject.Name)'" }
            'RemoveFromGroup' { "Remove user from group '$($groupObject.Name)'" }
        }

        if (-not $PSCmdlet.ShouldProcess($target, $description)) {
            $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
            Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType -Status $status -Details "$status only: action '$Action' was not executed for '$($user.SamAccountName)'." -Source 'ADAutoX' -CorrelationId $correlationId
            return [pscustomobject]@{ Action = $Action; Identity = $user.SamAccountName; Status = $status; Target = $target }
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType -Status 'Started' -Details "$Action requested for '$($user.SamAccountName)'." -Source 'ADAutoX' -CorrelationId $correlationId
        $mutationAttempted = $true
        switch ($Action) {
            'Enable' {
                if (-not $user.Enabled) {
                    Enable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop
                    Add-ADAutoXLifecycleUndoEntry -Action RestoreEnabled -User $user -UndoData @{
                        ExpectedEnabled = $true
                        RestoreEnabled = $false
                    }
                }
            }
            'Disable' {
                if ($user.Enabled) {
                    Disable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop
                    Add-ADAutoXLifecycleUndoEntry -Action RestoreEnabled -User $user -UndoData @{
                        ExpectedEnabled = $false
                        RestoreEnabled = $true
                    }
                }
            }
            'Unlock' { Unlock-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop }
            'ResetPassword' {
                Set-ADAccountPassword @adContext -Identity $user -Reset -NewPassword $NewPassword -Confirm:$false -ErrorAction Stop
                if ($MustChangeAtLogon) { Set-ADUser @adContext -Identity $user -ChangePasswordAtLogon $true -Confirm:$false -ErrorAction Stop }
            }
            'Move' {
                Move-ADObject @adContext -Identity $user -TargetPath $targetOU.DistinguishedName -Confirm:$false -ErrorAction Stop
                Add-ADAutoXLifecycleUndoEntry -Action MoveUser -User $user -UndoData @{
                    ExpectedParent = $targetOU.DistinguishedName
                    RestoreParent = $currentParent
                }
            }
            'Terminate' {
                if ($currentUser.Enabled) {
                    Disable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop
                    Add-ADAutoXLifecycleUndoEntry -Action RestoreEnabled -User $user -UndoData @{
                        ExpectedEnabled = $false
                        RestoreEnabled = $true
                    }
                }
                if ($targetOU -and (ConvertTo-ADCanonicalDistinguishedName $currentParent) -ne
                    (ConvertTo-ADCanonicalDistinguishedName $targetOU.DistinguishedName)) {
                    Move-ADObject @adContext -Identity $user -TargetPath $targetOU.DistinguishedName -Confirm:$false -ErrorAction Stop
                    Add-ADAutoXLifecycleUndoEntry -Action MoveUser -User $user -UndoData @{
                        ExpectedParent = $targetOU.DistinguishedName
                        RestoreParent = $currentParent
                    }
                }
                if ([string]$currentUser.Description -cne [string]$terminationDescription) {
                    Set-ADUser @adContext -Identity $user -Description $terminationDescription -Confirm:$false -ErrorAction Stop
                    Add-ADAutoXLifecycleUndoEntry -Action RestoreDescription -User $user -UndoData @{
                        ExpectedDescription = $terminationDescription
                        RestoreDescription = [string]$currentUser.Description
                    }
                }
            }
            'Delete' { Remove-ADUser @adContext -Identity $user -Confirm:$false -ErrorAction Stop }
            'AddToGroup' {
                Add-ADGroupMember @adContext -Identity $groupObject -Members $user -Confirm:$false -ErrorAction Stop
                Add-ADAutoXLifecycleUndoEntry -Action GroupMembership -User $user -UndoData @{
                    GroupIdentity = [string]$groupObject.ObjectGUID
                    GroupName = $groupObject.Name
                    ExpectedMembership = $true
                    RestoreMembership = $false
                }
            }
            'RemoveFromGroup' {
                Remove-ADGroupMember @adContext -Identity $groupObject -Members $user -Confirm:$false -ErrorAction Stop
                Add-ADAutoXLifecycleUndoEntry -Action GroupMembership -User $user -UndoData @{
                    GroupIdentity = [string]$groupObject.ObjectGUID
                    GroupName = $groupObject.Name
                    ExpectedMembership = $false
                    RestoreMembership = $true
                }
            }
        }

        if ($Action -ne 'Delete') {
            $properties = switch ($Action) {
                'Enable' { @('Enabled') }
                'Disable' { @('Enabled') }
                'Unlock' { @('LockedOut') }
                'ResetPassword' { @('pwdLastSet') }
                'Move' { @('DistinguishedName') }
                'Terminate' { @('Enabled', 'DistinguishedName', 'Description') }
                default { @() }
            }
            if ($Action -in @('AddToGroup', 'RemoveFromGroup')) {
                $membersAfter = @(Get-ADGroupMember @adContext -Identity $groupObject -ErrorAction Stop)
                $isMemberAfter = @($membersAfter | Where-Object { $_.SID -eq $user.SID }).Count -gt 0
                if (($Action -eq 'AddToGroup' -and -not $isMemberAfter) -or
                    ($Action -eq 'RemoveFromGroup' -and $isMemberAfter)) {
                    throw "Group membership verification failed for '$($user.SamAccountName)' and '$($groupObject.Name)'."
                }
            }
            elseif ($properties.Count -gt 0) {
                $verifiedUser = Get-ADUser @adContext -Identity $user.SamAccountName -Properties $properties -ErrorAction Stop
                switch ($Action) {
                    'Enable' { if (-not $verifiedUser.Enabled) { throw 'Enable verification failed: account remains disabled.' } }
                    'Disable' { if ($verifiedUser.Enabled) { throw 'Disable verification failed: account remains enabled.' } }
                    'Unlock' { if ($verifiedUser.LockedOut) { throw 'Unlock verification failed: account remains locked.' } }
                    'ResetPassword' {
                        if ($MustChangeAtLogon -and $verifiedUser.pwdLastSet -ne 0) { throw 'Password verification failed: must-change-at-logon is not enabled.' }
                        if (-not $MustChangeAtLogon -and $verifiedUser.pwdLastSet -eq 0) { throw 'Password verification failed: account remains in must-change-at-logon state.' }
                    }
                    'Move' {
                        $actualParent = Get-ADDistinguishedNameParent -DistinguishedName $verifiedUser.DistinguishedName
                        if ((ConvertTo-ADCanonicalDistinguishedName $actualParent) -ne
                            (ConvertTo-ADCanonicalDistinguishedName $targetOU.DistinguishedName)) {
                            throw "Move verification failed: account remains outside '$($targetOU.DistinguishedName)'."
                        }
                    }
                    'Terminate' {
                        if ($verifiedUser.Enabled -or $verifiedUser.Description -ne $terminationDescription) {
                            throw 'Termination verification failed: the account state or description did not match the requested result.'
                        }
                        if ($targetOU) {
                            $actualParent = Get-ADDistinguishedNameParent -DistinguishedName $verifiedUser.DistinguishedName
                            if ((ConvertTo-ADCanonicalDistinguishedName $actualParent) -ne
                                (ConvertTo-ADCanonicalDistinguishedName $targetOU.DistinguishedName)) {
                                throw "Termination verification failed: account is not in '$($targetOU.DistinguishedName)'."
                            }
                        }
                    }
                }
            }
        }

        Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType -Status 'Succeeded' -Details "$Action completed and was verified for '$($user.SamAccountName)'." -Source 'ADAutoX' -CorrelationId $correlationId
        [pscustomobject]@{ Action = $Action; Identity = $user.SamAccountName; Status = 'Succeeded'; Target = $target }
    }
    catch {
        $failureStatus = if ($mutationAttempted) { 'CompletedWithErrors' } else { 'Failed' }
        try {
            Write-ADAuditRecord -Path $AuditLogPath -Action $actionName -Target $target -TargetType $targetType -Status $failureStatus -Message $_.Exception.Message -Details "$Action failed for '$Identity'." -Source 'ADAutoX' -CorrelationId $correlationId
        }
        catch {
            Write-Warning "Failed to write lifecycle audit record: $($_.Exception.Message)"
        }
        throw
    }
    finally {
        Clear-ADToolContext
    }
}

function Invoke-ADAutoXLifecycleAction {
    param(
        [Parameter(Mandatory)][hashtable]$Arguments,
        [bool]$WhatIf,
        [bool]$Confirm,
        [bool]$ConfirmBound
    )
    if ($WhatIf) { $Arguments.WhatIf = $true }
    if ($ConfirmBound) { $Arguments.Confirm = $Confirm }
    Invoke-ADAutoXUserLifecycle @Arguments
}

function Invoke-ADAutoXUserAction {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable', 'Unlock', 'ResetPassword', 'Move', 'Terminate', 'Delete', 'AddToGroup', 'RemoveFromGroup')]
        [string]$Action,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity,
        [string]$TargetPath,
        [string]$Group,
        [string]$Reason = 'Terminated',
        [SecureString]$NewPassword,
        [switch]$MustChangeAtLogon,
        [switch]$AllowDestructiveOperation,
        [switch]$AllowProtectedAccount,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )

    Invoke-ADAutoXUserLifecycle @PSBoundParameters
}

function Enable-ADAutoXUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory)][string]$Identity, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $arguments = @{ Action = 'Enable'; Identity = $Identity; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Disable-ADAutoXUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Identity, [switch]$AllowDestructiveOperation, [switch]$AllowProtectedAccount, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $arguments = @{ Action = 'Disable'; Identity = $Identity; AllowDestructiveOperation = $AllowDestructiveOperation; AllowProtectedAccount = $AllowProtectedAccount; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Unlock-ADAutoXUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory)][string]$Identity, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $arguments = @{ Action = 'Unlock'; Identity = $Identity; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Reset-ADAutoXUserPassword {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Identity, [SecureString]$NewPassword, [switch]$MustChangeAtLogon, [switch]$AllowProtectedAccount, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $parameters = @{
        Action = 'ResetPassword'
        Identity = $Identity
        MustChangeAtLogon = $MustChangeAtLogon
        AllowProtectedAccount = $AllowProtectedAccount
        Server = $Server
        Credential = $Credential
        AuditLogPath = $AuditLogPath
    }
    if ($PSBoundParameters.ContainsKey('NewPassword')) { $parameters.NewPassword = $NewPassword }
    Invoke-ADAutoXLifecycleAction -Arguments $parameters -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Move-ADAutoXUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory)][string]$Identity, [Parameter(Mandatory)][string]$TargetPath, [switch]$AllowProtectedAccount, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $arguments = @{ Action = 'Move'; Identity = $Identity; TargetPath = $TargetPath; AllowProtectedAccount = $AllowProtectedAccount; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Stop-ADAutoXUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Identity, [string]$TargetPath, [ValidateNotNullOrEmpty()][string]$Reason = 'Terminated', [switch]$AllowDestructiveOperation, [switch]$AllowProtectedAccount, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $arguments = @{ Action = 'Terminate'; Identity = $Identity; TargetPath = $TargetPath; Reason = $Reason; AllowDestructiveOperation = $AllowDestructiveOperation; AllowProtectedAccount = $AllowProtectedAccount; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Remove-ADAutoXUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Identity, [switch]$AllowDestructiveOperation, [switch]$AllowProtectedAccount, [string]$Server, [PSCredential]$Credential, [string]$AuditLogPath = '')
    $arguments = @{ Action = 'Delete'; Identity = $Identity; AllowDestructiveOperation = $AllowDestructiveOperation; AllowProtectedAccount = $AllowProtectedAccount; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Set-ADAutoXUserGroupMembership {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateSet('Add', 'Remove')][string]$Operation,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Group,
        [switch]$AllowDestructiveOperation,
        [switch]$AllowProtectedAccount,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )
    $action = if ($Operation -eq 'Add') { 'AddToGroup' } else { 'RemoveFromGroup' }
    $arguments = @{ Action = $action; Identity = $Identity; Group = $Group; AllowDestructiveOperation = $AllowDestructiveOperation; AllowProtectedAccount = $AllowProtectedAccount; Server = $Server; Credential = $Credential; AuditLogPath = $AuditLogPath }
    Invoke-ADAutoXLifecycleAction -Arguments $arguments -WhatIf $WhatIfPreference -Confirm ([bool]$PSBoundParameters['Confirm']) -ConfirmBound ($PSBoundParameters.ContainsKey('Confirm'))
}

function Disable-ADAutoXInactiveUsers {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateRange(1, 3650)][int]$InactiveDays = 90,
        [string]$SearchBase,
        [switch]$AllowDomainWide,
        [switch]$IncludeNeverLoggedOn,
        [switch]$AllowDestructiveOperation,
        [switch]$AllowProtectedAccount,
        [string]$CsvPath,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )

    if (-not $WhatIfPreference -and -not $AllowDestructiveOperation) {
        throw 'Refusing to disable accounts without -AllowDestructiveOperation. Preview with -WhatIf first.'
    }
    if (-not $SearchBase -and -not $AllowDomainWide) {
        throw 'SearchBase is required. Use -AllowDomainWide only after approving a domain-wide operation.'
    }
    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AD-Operations.jsonl'
    }
    $correlationId = New-ADAutoXCorrelationId

    Import-ADTools
    $auditTarget = if ($SearchBase) { $SearchBase } else { 'Domain' }
    $results = [System.Collections.Generic.List[object]]::new()
    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        $cutoff = (Get-Date).AddDays(-$InactiveDays)
        $query = @{
            Filter = 'Enabled -eq $true'
            Properties = 'LastLogonDate', 'WhenCreated', 'Department', 'DistinguishedName', 'adminCount', 'ServicePrincipalName'
        }
        if ($SearchBase) { $query.SearchBase = $SearchBase; $query.SearchScope = 'Subtree' }
        $users = @(Get-ADUser @adContext @query -ErrorAction Stop)

        foreach ($user in $users) {
            $lastLogon = $user.LastLogonDate
            $oldEnough = if ($lastLogon) { $lastLogon -lt $cutoff } elseif ($IncludeNeverLoggedOn) { $user.WhenCreated -lt $cutoff } else { $false }
            if (-not $oldEnough) { continue }
            if ($user.ServicePrincipalName) {
                $results.Add([pscustomobject]@{ Identity = $user.SamAccountName; Status = 'Skipped'; Reason = 'Service account.' })
                continue
            }

            $protectionReason = ''
            if (Test-ADAutoXProtectedAccount -User $user -ADContext $adContext -Action Disable -Reason ([ref]$protectionReason)) {
                if (-not $AllowProtectedAccount) {
                    $message = "Refusing to disable protected account '$($user.SamAccountName)': $protectionReason. Use -AllowProtectedAccount only when this change is explicitly approved."
                    Write-ADAuditRecord -Path $AuditLogPath -Action 'DisableUser' -Target $user.DistinguishedName `
                        -TargetType 'User' -Status 'Failed' -Message $message -Details "Blocked protected-account action. $protectionReason" `
                        -Source 'ADAutoX' -CorrelationId $correlationId
                    throw $message
                }

                $warning = "WARNING: -AllowProtectedAccount bypassed the protected-account guard for '$($user.SamAccountName)' during inactive-account disable. Reasons: $protectionReason"
                Write-Warning $warning
                Write-ADAuditRecord -Path $AuditLogPath -Action 'DisableUser' -Target $user.DistinguishedName `
                    -TargetType 'User' -Status 'Started' -Message $warning -Details $warning `
                    -Source 'ADAutoX' -CorrelationId $correlationId
            }

            if ($PSCmdlet.ShouldProcess($user.SamAccountName, 'Disable inactive Active Directory account')) {
                Disable-ADAccount @adContext -Identity $user -Confirm:$false -ErrorAction Stop
                Add-ADAutoXLifecycleUndoEntry -Action RestoreEnabled -User $user -UndoData @{
                    ExpectedEnabled = $false
                    RestoreEnabled = $true
                }
                $verified = Get-ADUser @adContext -Identity $user -Properties Enabled -ErrorAction Stop
                if ($verified.Enabled) { throw "Disable verification failed for '$($user.SamAccountName)'." }
                $results.Add([pscustomobject]@{ Identity = $user.SamAccountName; Status = 'Disabled'; Reason = '' })
            }
            else {
                $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
                $results.Add([pscustomobject]@{ Identity = $user.SamAccountName; Status = $status; Reason = '' })
            }
        }

        if ($CsvPath) { Export-ADResults -Results $results.ToArray() -Path $CsvPath }
        $status = if ($WhatIfPreference) { 'Preview' } elseif (@($results | Where-Object Status -eq 'Disabled').Count) { 'Succeeded' } else { 'Skipped' }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'DisableInactiveUsers' -Target $auditTarget -Status $status -Message "Disabled $(@($results | Where-Object Status -eq 'Disabled').Count); skipped $(@($results | Where-Object Status -eq 'Skipped').Count)." -Source 'ADAutoX' -CorrelationId $correlationId
        return $results.ToArray()
    }
    catch {
        try { Write-ADAuditRecord -Path $AuditLogPath -Action 'DisableInactiveUsers' -Target $auditTarget -Status 'Failed' -Message $_.Exception.Message -Source 'ADAutoX' -CorrelationId $correlationId }
        catch { Write-Warning "Failed to write inactive-account audit record: $($_.Exception.Message)" }
        throw
    }
    finally { Clear-ADToolContext }
}

function Get-ADAutoXLockedOutUsers {
    [CmdletBinding()]
    param(
        [string]$SearchBase,
        [string]$CsvPath,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AD-Operations.jsonl'
    }
    $correlationId = New-ADAutoXCorrelationId
    Import-ADTools
    $target = if ($SearchBase) { $SearchBase } else { 'Domain' }
    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        $query = @{ Filter = 'LockedOut -eq $true'; Properties = 'LastLogonDate', 'Department', 'EmailAddress', 'DistinguishedName' }
        if ($SearchBase) { $query.SearchBase = $SearchBase; $query.SearchScope = 'Subtree' }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'FindLockedAccounts' -Target $target -Status 'Started' -Source 'ADAutoX' -CorrelationId $correlationId
        $locked = @(Get-ADUser @adContext @query -ErrorAction Stop |
            Select-Object Name, SamAccountName, UserPrincipalName, LastLogonDate, Department, EmailAddress, DistinguishedName)
        if ($CsvPath) { Export-ADResults -Results $locked -Path $CsvPath }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'FindLockedAccounts' -Target $target -Status 'Succeeded' -Message "Found $($locked.Count) locked accounts." -Source 'ADAutoX' -CorrelationId $correlationId
        return $locked
    }
    catch {
        try { Write-ADAuditRecord -Path $AuditLogPath -Action 'FindLockedAccounts' -Target $target -Status 'Failed' -Message $_.Exception.Message -Source 'ADAutoX' -CorrelationId $correlationId }
        catch { Write-Warning "Failed to write locked-account audit record: $($_.Exception.Message)" }
        throw
    }
    finally { Clear-ADToolContext }
}

function Update-ADAutoXUserDepartments {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SearchBase,
        [ValidateNotNullOrEmpty()][string]$CompanyName = 'Company',
        [string]$Server,
        [PSCredential]$Credential,
        [string]$AuditLogPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
        $AuditLogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AD-Operations.jsonl'
    }
    $correlationId = New-ADAutoXCorrelationId
    Import-ADTools
    $updated = [System.Collections.Generic.List[object]]::new()
    try {
        $null = Set-ADToolContext -Server $Server -Credential $Credential
        $adContext = Get-ADToolContextParameters
        $users = @(Get-ADUser @adContext -Filter * -SearchBase $SearchBase -SearchScope Subtree -Properties DistinguishedName, Department, Company -ErrorAction Stop)
        foreach ($user in $users) {
            $rdns = @(Split-ADDistinguishedName -DistinguishedName $user.DistinguishedName)
            if ($rdns.Count -lt 4 -or $rdns[1] -notmatch '^(?i)OU=Users$' -or $rdns[2] -notmatch '^(?i)OU=') {
                $updated.Add([pscustomobject]@{ Identity = $user.SamAccountName; Status = 'Skipped'; Department = $null })
                continue
            }
            $department = $rdns[2].Substring(3)
            if ($PSCmdlet.ShouldProcess($user.DistinguishedName, "Set Department='$department', Company='$CompanyName'")) {
                $previousDepartment = [string]$user.Department
                $previousCompany = [string]$user.Company
                Set-ADUser @adContext -Identity $user -Department $department -Company $CompanyName -Confirm:$false -ErrorAction Stop
                Add-ADAutoXLifecycleUndoEntry -Action RestoreAttributes -User $user -UndoData @{
                    ExpectedAttributes = @{ Department = $department; Company = $CompanyName }
                    RestoreAttributes = @{ Department = $previousDepartment; Company = $previousCompany }
                }
                $verified = Get-ADUser @adContext -Identity $user -Properties Department, Company -ErrorAction Stop
                if ($verified.Department -ne $department -or $verified.Company -ne $CompanyName) {
                    throw "Department update verification failed for '$($user.SamAccountName)'."
                }
                $updated.Add([pscustomobject]@{ Identity = $user.SamAccountName; Status = 'Succeeded'; Department = $department })
            }
            else {
                $status = if ($WhatIfPreference) { 'Preview' } else { 'Skipped' }
                $updated.Add([pscustomobject]@{ Identity = $user.SamAccountName; Status = $status; Department = $department })
            }
        }
        $status = if ($WhatIfPreference) { 'Preview' } elseif (@($updated | Where-Object Status -eq 'Succeeded').Count -gt 0) { 'Succeeded' } else { 'Skipped' }
        Write-ADAuditRecord -Path $AuditLogPath -Action 'UpdateUserDepartments' -Target $SearchBase -Status $status -Message "Updated $(@($updated | Where-Object Status -eq 'Succeeded').Count); skipped $(@($updated | Where-Object Status -eq 'Skipped').Count)." -Source 'ADAutoX' -CorrelationId $correlationId
        return $updated.ToArray()
    }
    catch {
        $failureStatus = if (@($updated | Where-Object Status -eq 'Succeeded').Count -gt 0) { 'CompletedWithErrors' } else { 'Failed' }
        try { Write-ADAuditRecord -Path $AuditLogPath -Action 'UpdateUserDepartments' -Target $SearchBase -Status $failureStatus -Message $_.Exception.Message -Source 'ADAutoX' -CorrelationId $correlationId }
        catch { Write-Warning "Failed to write department-update audit record: $($_.Exception.Message)" }
        throw
    }
    finally { Clear-ADToolContext }
}

function Protect-ADAutoXFileAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'Credential-file ACL protection requires Windows.'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Cannot secure missing credential file '$Path'."
    }

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $currentIdentity -or $null -eq $currentIdentity.User) {
        throw 'Could not determine the current Windows identity to secure the credential file.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $acl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
        $null = $acl.RemoveAccessRule($rule)
    }
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentIdentity.User,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $fullPath -AclObject $acl -ErrorAction Stop
    $verifiedAcl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
    $verifiedRules = @($verifiedAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if (-not $verifiedAcl.AreAccessRulesProtected -or $verifiedRules.Count -ne 1 -or
        $verifiedRules[0].IdentityReference.Value -ne $currentIdentity.User.Value -or
        $verifiedRules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $verifiedRules[0].FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) {
        throw "Could not verify an exclusive current-user ACL on credential file '$fullPath'."
    }
}

function Export-ADAutoXCredentials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$CredentialMap,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [switch]$Overwrite
    )

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'DPAPI-protected credential exports require Windows.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
    }
    if ((Test-Path -LiteralPath $fullPath) -and -not $Overwrite) {
        throw "Credential export file '$fullPath' already exists. Specify -Overwrite to replace it."
    }

    $stageName = ".$([System.IO.Path]::GetFileNameWithoutExtension($fullPath)).$([Guid]::NewGuid().ToString('N')).tmp.clixml"
    $stagingPath = Join-Path $directory $stageName
    try {
        $null = New-Item -ItemType File -Path $stagingPath -ErrorAction Stop
        Protect-ADAutoXFileAcl -Path $stagingPath
        $credentials = [System.Collections.Generic.List[PSCredential]]::new()
        foreach ($username in $CredentialMap.Keys) {
            $password = $CredentialMap[$username]
            if ($password -isnot [string] -or [string]::IsNullOrEmpty($password)) {
                throw "Credential entry '$username' does not contain a non-empty password string."
            }
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            $credentials.Add([PSCredential]::new([string]$username, $securePassword))
        }
        $credentials | Export-Clixml -LiteralPath $stagingPath -Force -ErrorAction Stop
        Move-ADSecuredFileIntoPlace -StagingPath $stagingPath -DestinationPath $fullPath -Overwrite:$Overwrite
    }
    finally {
        if (Test-Path -LiteralPath $stagingPath -PathType Leaf) {
            try { Remove-Item -LiteralPath $stagingPath -Force -ErrorAction Stop }
            catch { Write-Warning "Failed to remove sensitive staging file '$stagingPath': $($_.Exception.Message)" }
        }
    }
}

function Get-ADAutoXAuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LogPath,
        [string]$Identity,
        [string]$Action,
        [string]$Status,
        [string]$Actor,
        [string]$OutputPath,
        [switch]$Summary,
        [switch]$AsJson,
        [switch]$ErrorOnMalformedEntries
    )

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw "Audit log '$resolvedPath' was not found."
    }

    $records = [System.Collections.Generic.List[object]]::new()
    $invalidLineNumbers = [System.Collections.Generic.List[int]]::new()
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $resolvedPath -Encoding UTF8 -ErrorAction Stop) {
        $lineNumber++
        $trimmedLine = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }
        try {
            $record = $trimmedLine | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $record) {
                if (-not $ErrorOnMalformedEntries) { $invalidLineNumbers.Add($lineNumber) }
                continue
            }
            $records.Add($record)
        }
        catch {
            if ($ErrorOnMalformedEntries) {
                throw "Invalid JSON in audit log '$resolvedPath' on line ${lineNumber}: $($_.Exception.Message)"
            }
            $invalidLineNumbers.Add($lineNumber)
        }
    }
    if ($invalidLineNumbers.Count -gt 0) {
        Write-Warning "Ignored malformed JSONL audit entries at line(s): $($invalidLineNumbers -join ', ')."
    }

    $identityFields = @('Actor', 'Operator', 'Target', 'TargetType', 'Action', 'Message', 'Details', 'Source', 'CorrelationId')
    $filtered = @($records | Where-Object {
        $actionProperty = $_.PSObject.Properties['Action']
        $statusProperty = $_.PSObject.Properties['Status']
        $actorProperty = $_.PSObject.Properties['Actor']
        $actionValue = if ($actionProperty) { [string]$actionProperty.Value } else { '' }
        $statusValue = if ($statusProperty) { [string]$statusProperty.Value } else { '' }
        $actorValue = if ($actorProperty) { [string]$actorProperty.Value } else { '' }
        $identityMatch = [string]::IsNullOrWhiteSpace($Identity)
        if (-not $identityMatch) {
            foreach ($fieldName in $identityFields) {
                $field = $_.PSObject.Properties[$fieldName]
                if ($field -and [string]$field.Value -and
                    ([string]$field.Value).IndexOf($Identity, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $identityMatch = $true
                    break
                }
            }
        }
        $actionMatch = [string]::IsNullOrWhiteSpace($Action) -or $actionValue -ieq $Action
        $statusMatch = [string]::IsNullOrWhiteSpace($Status) -or $statusValue -ieq $Status
        $actorMatch = [string]::IsNullOrWhiteSpace($Actor) -or
            $actorValue.IndexOf($Actor, [StringComparison]::OrdinalIgnoreCase) -ge 0
        $identityMatch -and $actionMatch -and $statusMatch -and $actorMatch
    })

    if ($Summary) {
        $normalizedRecords = @(
            foreach ($record in $filtered) {
                $normalized = [ordered]@{}
                foreach ($fieldName in @(
                    'Timestamp', 'Actor', 'Operator', 'Computer', 'Action', 'Target',
                    'TargetType', 'Status', 'Message', 'Details', 'Source', 'CorrelationId'
                )) {
                    $property = $record.PSObject.Properties[$fieldName]
                    $normalized[$fieldName] = if ($null -eq $property -or $null -eq $property.Value) {
                        ''
                    }
                    else {
                        [string]$property.Value
                    }
                }
                [pscustomobject]$normalized
            }
        )
        $summaryResult = [pscustomobject]@{
            AuditLogPath = $resolvedPath
            TotalRecords = $normalizedRecords.Count
            UniqueActors = @($normalizedRecords | Select-Object -ExpandProperty Actor -Unique).Count
            UniqueTargets = @($normalizedRecords | Select-Object -ExpandProperty Target -Unique).Count
            FirstTimestamp = ''
            LastTimestamp = ''
            StatusCounts = @()
            ActionCounts = @()
            FailedRecords = @()
        }

        if ($normalizedRecords.Count -gt 0) {
            $timestampValues = @($normalizedRecords |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.Timestamp) } |
                Select-Object -ExpandProperty Timestamp)
            if ($timestampValues.Count -gt 0) {
                $sortedTimestamps = @($timestampValues | Sort-Object)
                $summaryResult.FirstTimestamp = $sortedTimestamps[0]
                $summaryResult.LastTimestamp = $sortedTimestamps[-1]
            }

            $summaryResult.StatusCounts = @(
                foreach ($statusName in @('Started', 'Succeeded', 'Failed', 'Skipped', 'Preview', 'CompletedWithErrors')) {
                    $count = @($normalizedRecords | Where-Object { $_.Status -ieq $statusName }).Count
                    if ($count -gt 0) {
                        [pscustomobject]@{ Status = $statusName; Count = $count }
                    }
                }
            )
            $summaryResult.ActionCounts = @(
                $normalizedRecords |
                    Group-Object -Property Action |
                    Sort-Object -Property Count -Descending |
                    Select-Object @{Name = 'Action'; Expression = { $_.Name } }, Count
            )
            $summaryResult.FailedRecords = @(
                $normalizedRecords |
                    Where-Object { $_.Status -ieq 'Failed' } |
                    Select-Object Timestamp, Actor, Action, Target, Message, Details
            )
        }

        if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
            $resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
            if ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetFileName($resolvedOutputPath))) {
                throw "Output path '$OutputPath' must identify a file."
            }
            $outputDirectory = Split-Path -Parent $resolvedOutputPath
            if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $outputDirectory -Force -ErrorAction Stop
            }
            if ($AsJson) {
                $summaryResult | ConvertTo-Json -Depth 8 |
                    Set-Content -LiteralPath $resolvedOutputPath -Encoding UTF8 -ErrorAction Stop
            }
            else {
                $normalizedRecords |
                    Select-Object Timestamp, Actor, Operator, Computer, Action, Target, TargetType, Status, Message, Details, Source, CorrelationId |
                    Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Force -Encoding UTF8 -ErrorAction Stop
            }
        }
        return $summaryResult
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        if ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetFileName($resolvedOutputPath))) {
            throw "Output path '$OutputPath' must identify a file."
        }
        $outputDirectory = Split-Path -Parent $resolvedOutputPath
        if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $outputDirectory -Force -ErrorAction Stop
        }
        $filtered | Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
    }
    return $filtered
}

$script:ADAutoXCorrelationId = [Guid]::NewGuid().ToString()
function New-ADAutoXCorrelationId {
    [CmdletBinding()]
    param()
    $script:ADAutoXCorrelationId = [Guid]::NewGuid().ToString()
    return $script:ADAutoXCorrelationId
}

function Get-ADAutoXCorrelationId {
    [CmdletBinding()]
    param()
    return $script:ADAutoXCorrelationId
}

function Write-ADAutoXLogRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [ValidateSet('Started', 'Succeeded', 'Failed', 'Skipped', 'Preview', 'CompletedWithErrors')][string]$Status = 'Succeeded',
        [string]$Message = '',
        [string]$TargetType = 'User',
        [string]$Details = '',
        [string]$Source = 'ADAutoX',
        [string]$CorrelationId = ''
    )
    $effectiveCorrelationId = if ($CorrelationId) { $CorrelationId } else { $script:ADAutoXCorrelationId }
    Write-ADAuditRecord -Path $LogPath -Action $Action -Target $Target -Status $Status -Message $Message -TargetType $TargetType -Details $Details -Source $Source -CorrelationId $effectiveCorrelationId
}

Set-Alias -Name Terminate-ADAutoXUser -Value Stop-ADAutoXUser
Set-Alias -Name Manage-ADAutoXUser -Value Invoke-ADAutoXUserAction
Export-ModuleMember -Function Invoke-ADAutoXUserLifecycle, Invoke-ADAutoXUserAction, Enable-ADAutoXUser, Disable-ADAutoXUser, Unlock-ADAutoXUser, Reset-ADAutoXUserPassword, Move-ADAutoXUser, Stop-ADAutoXUser, Remove-ADAutoXUser, Set-ADAutoXUserGroupMembership, Disable-ADAutoXInactiveUsers, Get-ADAutoXLockedOutUsers, Update-ADAutoXUserDepartments, Protect-ADAutoXFileAcl, Export-ADAutoXCredentials, Get-ADAutoXAuditReport, New-ADAutoXCorrelationId, Get-ADAutoXCorrelationId, Write-ADAutoXLogRecord -Alias Terminate-ADAutoXUser, Manage-ADAutoXUser
