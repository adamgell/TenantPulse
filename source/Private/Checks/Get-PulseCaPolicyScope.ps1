<#
    Private Conditional Access scope classifiers shared by the controls that claim
    tenant-wide user or resource coverage.

    A policy is all-resource only when conditions.applications is present, explicitly
    includes Graph's `All` sentinel, and carries no resource exclusions, user-action
    targeting, or application filter. A valid narrower include/exclude/filter shape is
    known `Narrow`; a missing or unrecognized shape is `Incomplete`. Consumers must never
    promote either state to tenant-wide coverage.

    All-user coverage permits only explicit, operator-declared excludeUsers exceptions.
    Group and role exclusions are known narrowing because this contract does not infer
    that every member is an approved exception. The caller supplies the accepted principal
    identifiers after removing malformed declarations.

    Admin-role coverage follows the same conservative direct-user exception boundary.
    Canonical explicit excludeUsers entries remain complete only when the caller supplies
    them as accepted break-glass/service-account identifiers. Any other direct-user
    exclusion, any group exclusion, or a guest/external carve-out is incomplete because
    policy shape alone cannot prove which privileged principals were removed.
#>

function Get-PulseCaApplicationScope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $PolicyView
    )

    $incomplete = {
        param(
            [string] $ReasonCode,
            [bool] $CouldBeAllResources = $true,
            [int] $IncludedApplicationCount = 0,
            [int] $ExcludedApplicationCount = 0,
            [int] $IncludedUserActionCount = 0,
            [bool] $HasApplicationFilter = $false,
            [int] $IncludedAuthenticationContextCount = 0
        )
        [pscustomobject][ordered]@{
            State                    = 'Incomplete'
            Complete                 = $false
            ReasonCode               = $ReasonCode
            CouldBeAllResources      = $CouldBeAllResources
            IncludedApplicationCount = $IncludedApplicationCount
            ExcludedApplicationCount = $ExcludedApplicationCount
            IncludedUserActionCount  = $IncludedUserActionCount
            HasApplicationFilter     = $HasApplicationFilter
            IncludedAuthenticationContextCount = $IncludedAuthenticationContextCount
        }
    }

    if ($null -eq $PolicyView) { return & $incomplete 'missing-policy-view' }
    $conditions = Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'conditions'
    $apps = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'apps'
    if ($null -eq $apps) { return & $incomplete 'missing-applications-view' }

    $present = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'present'
    if ($present -isnot [bool] -or -not $present) { return & $incomplete 'missing-applications' }

    # Do not cast the accessor call inline. The accessor deliberately returns an empty
    # string[] behind a unary comma so it survives PowerShell's pipeline unrolling. An
    # inline @(<command>) then treats that protected empty array as one pipeline object,
    # and a [string[]] cast turns it into one empty string. Start with a real empty array
    # and assign only when the returned collection has values instead.
    [string[]] $included = @()
    [string[]] $excluded = @()
    [string[]] $userActions = @()
    [string[]] $authenticationContexts = @()
    $rawIncluded = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeApplications'
    $rawExcluded = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'excludeApplications'
    $rawUserActions = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeUserActions'
    $rawAuthenticationContexts = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'includeAuthenticationContextClassReferences'
    if ($null -ne $rawIncluded -and @($rawIncluded).Count -gt 0) { $included = [string[]] @($rawIncluded) }
    if ($null -ne $rawExcluded -and @($rawExcluded).Count -gt 0) { $excluded = [string[]] @($rawExcluded) }
    if ($null -ne $rawUserActions -and @($rawUserActions).Count -gt 0) { $userActions = [string[]] @($rawUserActions) }
    if ($null -ne $rawAuthenticationContexts -and @($rawAuthenticationContexts).Count -gt 0) { $authenticationContexts = [string[]] @($rawAuthenticationContexts) }

    $allEntries = @($included | Where-Object { [string]::Equals($_, 'All', [System.StringComparison]::OrdinalIgnoreCase) })
    $hasKnownSpecificInclude = $allEntries.Count -eq 0 -and
        @($included | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0
    $hasKnownExclusion = @($excluded | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0
    $hasKnownUserAction = @($userActions | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0
    $hasKnownAuthenticationContext = @($authenticationContexts | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0
    $couldBeAllResources = -not ($hasKnownSpecificInclude -or $hasKnownExclusion -or $hasKnownUserAction -or $hasKnownAuthenticationContext)

    $filter = Get-PulseSettingsCatalogValueProperty -Node $apps -PropertyName 'applicationFilter'
    $hasFilter = $null -ne $filter
    foreach ($value in @($included) + @($excluded) + @($userActions) + @($authenticationContexts)) {
        if ([string]::IsNullOrWhiteSpace([string] $value)) {
            return & $incomplete 'blank-application-scope-value' $couldBeAllResources $included.Count $excluded.Count $userActions.Count $hasFilter $authenticationContexts.Count
        }
    }

    if (@($authenticationContexts | Where-Object { $_ -notmatch '^c(?:[1-9]|1[0-9]|2[0-5])$' }).Count -gt 0) {
        return & $incomplete 'invalid-authentication-context-reference' $false $included.Count $excluded.Count $userActions.Count $hasFilter $authenticationContexts.Count
    }

    if ($hasFilter) {
        $mode = [string] (Get-PulseSettingsCatalogValueProperty -Node $filter -PropertyName 'mode')
        $rule = [string] (Get-PulseSettingsCatalogValueProperty -Node $filter -PropertyName 'rule')
        if ($mode -notin @('include', 'exclude') -or [string]::IsNullOrWhiteSpace($rule)) {
            return & $incomplete 'invalid-application-filter' $couldBeAllResources $included.Count $excluded.Count $userActions.Count $true $authenticationContexts.Count
        }
        $couldBeAllResources = $false
    }

    if ($allEntries.Count -gt 0 -and $included.Count -ne 1) {
        return & $incomplete 'contradictory-all-application-scope' $couldBeAllResources $included.Count $excluded.Count $userActions.Count $hasFilter $authenticationContexts.Count
    }

    $common = [ordered]@{
        Complete                 = $true
        ReasonCode               = $null
        CouldBeAllResources      = $couldBeAllResources
        IncludedApplicationCount = $included.Count
        ExcludedApplicationCount = $excluded.Count
        IncludedUserActionCount  = $userActions.Count
        HasApplicationFilter     = $hasFilter
        IncludedAuthenticationContextCount = $authenticationContexts.Count
    }

    if ($allEntries.Count -eq 1 -and $excluded.Count -eq 0 -and $userActions.Count -eq 0 -and
        $authenticationContexts.Count -eq 0 -and -not $hasFilter) {
        return [pscustomobject]([ordered]@{ State = 'AllResources' } + $common)
    }

    if ($included.Count -gt 0 -or $excluded.Count -gt 0 -or $userActions.Count -gt 0 -or
        $authenticationContexts.Count -gt 0 -or $hasFilter) {
        return [pscustomobject]([ordered]@{ State = 'Narrow' } + $common)
    }

    return & $incomplete 'empty-application-scope' $couldBeAllResources $included.Count $excluded.Count $userActions.Count $hasFilter $authenticationContexts.Count
}

function Get-PulseCaAllUsersScope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $PolicyView,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $AcceptedExcludedIdentifiers = @()
    )

    $newResult = {
        param(
            [string] $State,
            [bool] $Complete,
            [AllowNull()][string] $ReasonCode,
            [int] $AcceptedExcludedUserCount = 0,
            [int] $UnacceptedExcludedUserCount = 0,
            [int] $ExcludedGroupCount = 0,
            [int] $ExcludedRoleCount = 0,
            [bool] $HasExcludedGuestsOrExternalUsers = $false,
            [bool] $CouldBeAllUsers = $true
        )
        [pscustomobject][ordered]@{
            State                       = $State
            Complete                    = $Complete
            ReasonCode                  = $ReasonCode
            CouldBeAllUsers             = $CouldBeAllUsers
            AcceptedExcludedUserCount   = $AcceptedExcludedUserCount
            UnacceptedExcludedUserCount = $UnacceptedExcludedUserCount
            ExcludedGroupCount          = $ExcludedGroupCount
            ExcludedRoleCount           = $ExcludedRoleCount
            HasExcludedGuestsOrExternalUsers = $HasExcludedGuestsOrExternalUsers
        }
    }
    if ($null -eq $PolicyView) {
        return & $newResult 'Incomplete' $false 'missing-policy-view'
    }

    $conditions = Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'conditions'
    $users = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'users'
    if ($null -eq $users -or (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'present') -isnot [bool] -or
        -not [bool] (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'present')) {
        return & $newResult 'Incomplete' $false 'missing-users'
    }

    [string[]] $includeUsers = @()
    [string[]] $includeGroups = @()
    [string[]] $includeRoles = @()
    [string[]] $excludeUsers = @()
    [string[]] $excludeGroups = @()
    [string[]] $excludeRoles = @()
    $rawIncludeUsers = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeUsers'
    $rawIncludeGroups = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeGroups'
    $rawIncludeRoles = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'includeRoles'
    $rawExcludeUsers = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeUsers'
    $rawExcludeGroups = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeGroups'
    $rawExcludeRoles = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'excludeRoles'
    if ($null -ne $rawIncludeUsers -and @($rawIncludeUsers).Count -gt 0) { $includeUsers = [string[]] @($rawIncludeUsers) }
    if ($null -ne $rawIncludeGroups -and @($rawIncludeGroups).Count -gt 0) { $includeGroups = [string[]] @($rawIncludeGroups) }
    if ($null -ne $rawIncludeRoles -and @($rawIncludeRoles).Count -gt 0) { $includeRoles = [string[]] @($rawIncludeRoles) }
    if ($null -ne $rawExcludeUsers -and @($rawExcludeUsers).Count -gt 0) { $excludeUsers = [string[]] @($rawExcludeUsers) }
    if ($null -ne $rawExcludeGroups -and @($rawExcludeGroups).Count -gt 0) { $excludeGroups = [string[]] @($rawExcludeGroups) }
    if ($null -ne $rawExcludeRoles -and @($rawExcludeRoles).Count -gt 0) { $excludeRoles = [string[]] @($rawExcludeRoles) }
    $hasIncludeGuestsOrExternalUsers = [bool] (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'hasIncludeGuestsOrExternalUsers')
    $hasExcludeGuestsOrExternalUsers = [bool] (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'hasExcludeGuestsOrExternalUsers')

    $includeAll = @($includeUsers | Where-Object { [string]::Equals($_, 'All', [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    $accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($identifier in @($AcceptedExcludedIdentifiers)) {
        if (-not [string]::IsNullOrWhiteSpace($identifier)) { [void] $accepted.Add($identifier) }
    }
    $knownIncludedUsers = @($includeUsers | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    $knownIncludedGroups = @($includeGroups | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    $knownIncludedRoles = @($includeRoles | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    $knownUnacceptedExcludedUsers = @($excludeUsers | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string] $_) -and -not $accepted.Contains([string] $_)
    })
    $knownExcludedGroups = @($excludeGroups | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    $knownExcludedRoles = @($excludeRoles | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
    $hasKnownNarrowInclude = -not $includeAll -and
        ($knownIncludedUsers.Count -gt 0 -or $knownIncludedGroups.Count -gt 0 -or
            $knownIncludedRoles.Count -gt 0 -or $hasIncludeGuestsOrExternalUsers)
    $couldBeAllUsers = -not ($hasKnownNarrowInclude -or $knownUnacceptedExcludedUsers.Count -gt 0 -or
        $knownExcludedGroups.Count -gt 0 -or $knownExcludedRoles.Count -gt 0 -or $hasExcludeGuestsOrExternalUsers)

    foreach ($value in @($includeUsers) + @($includeGroups) + @($includeRoles) + @($excludeUsers) + @($excludeGroups) + @($excludeRoles)) {
        if ([string]::IsNullOrWhiteSpace([string] $value)) {
            return & $newResult 'Incomplete' $false 'blank-user-scope-value' 0 0 0 0 $hasExcludeGuestsOrExternalUsers $couldBeAllUsers
        }
    }

    if ($includeAll -and $includeUsers.Count -ne 1) {
        return & $newResult 'Incomplete' $false 'contradictory-all-user-scope' 0 0 0 0 $hasExcludeGuestsOrExternalUsers $couldBeAllUsers
    }
    if (-not $includeAll) {
        if ($includeUsers.Count -eq 0 -and $includeGroups.Count -eq 0 -and $includeRoles.Count -eq 0 -and -not $hasIncludeGuestsOrExternalUsers) {
            $acceptedExcludedUserCount = @($excludeUsers | Where-Object { $accepted.Contains($_) }).Count
            return & $newResult 'Incomplete' $false 'empty-user-scope' $acceptedExcludedUserCount $knownUnacceptedExcludedUsers.Count $excludeGroups.Count $excludeRoles.Count $hasExcludeGuestsOrExternalUsers $couldBeAllUsers
        }
        return & $newResult 'Narrow' $true 'not-all-users' 0 0 0 0 $hasExcludeGuestsOrExternalUsers $false
    }

    $unacceptedCount = @($excludeUsers | Where-Object { -not $accepted.Contains($_) }).Count
    if ($unacceptedCount -eq 0 -and $excludeGroups.Count -eq 0 -and $excludeRoles.Count -eq 0 -and -not $hasExcludeGuestsOrExternalUsers) {
        return & $newResult 'AllIntendedUsers' $true $null ($excludeUsers.Count - $unacceptedCount) $unacceptedCount $excludeGroups.Count $excludeRoles.Count $false
    }
    return & $newResult 'Narrow' $true $null ($excludeUsers.Count - $unacceptedCount) $unacceptedCount $excludeGroups.Count $excludeRoles.Count $hasExcludeGuestsOrExternalUsers $false
}

function Get-PulseCaAdminRoleScope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $PolicyView,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $RequiredRoleIds,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $AcceptedExcludedIdentifiers = @()
    )

    $allRequired = [string[]] @($RequiredRoleIds)
    $newResult = {
        param(
            [string] $State,
            [AllowNull()][string] $ReasonCode,
            [string[]] $PossibleRoleIds,
            [int] $AcceptedExcludedUserCount = 0,
            [int] $UnacceptedExcludedUserCount = 0,
            [int] $ExcludedGroupCount = 0,
            [bool] $HasExcludedGuestsOrExternalUsers = $false
        )
        [pscustomobject][ordered]@{
            State                            = $State
            Complete                         = ($State -ne 'Incomplete')
            ReasonCode                       = $ReasonCode
            PossibleRoleIds                  = [string[]] @($PossibleRoleIds)
            AcceptedExcludedUserCount        = $AcceptedExcludedUserCount
            UnacceptedExcludedUserCount      = $UnacceptedExcludedUserCount
            ExcludedGroupCount               = $ExcludedGroupCount
            HasExcludedGuestsOrExternalUsers = $HasExcludedGuestsOrExternalUsers
        }
    }

    if ($null -eq $PolicyView) {
        return & $newResult 'Incomplete' 'missing-policy-view' $allRequired
    }
    $conditions = Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'conditions'
    $users = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'users'
    if ($null -eq $users -or -not [bool] (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'present')) {
        return & $newResult 'Incomplete' 'missing-users' $allRequired
    }

    [string[]] $includeUsers = @()
    [string[]] $includeGroups = @()
    [string[]] $includeRoles = @()
    [string[]] $excludeUsers = @()
    [string[]] $excludeGroups = @()
    [string[]] $excludeRoles = @()
    foreach ($mapping in @(
        @{ Variable = 'includeUsers'; Property = 'includeUsers' }
        @{ Variable = 'includeGroups'; Property = 'includeGroups' }
        @{ Variable = 'includeRoles'; Property = 'includeRoles' }
        @{ Variable = 'excludeUsers'; Property = 'excludeUsers' }
        @{ Variable = 'excludeGroups'; Property = 'excludeGroups' }
        @{ Variable = 'excludeRoles'; Property = 'excludeRoles' }
    )) {
        $raw = Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName $mapping.Property
        if ($null -ne $raw -and @($raw).Count -gt 0) {
            Set-Variable -Name $mapping.Variable -Value ([string[]] @($raw))
        }
    }

    $incompleteReason = $null
    if (@($includeUsers + $includeGroups + $includeRoles + $excludeUsers + $excludeGroups + $excludeRoles | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
        $incompleteReason = 'blank-user-role-scope-value'
    }
    $includeAllCount = @($includeUsers | Where-Object { [string]::Equals($_, 'All', [System.StringComparison]::OrdinalIgnoreCase) }).Count
    if ($includeAllCount -gt 0 -and ($includeUsers.Count -ne 1 -or $includeRoles.Count -gt 0)) {
        $incompleteReason = 'contradictory-all-role-scope'
    }

    $accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($identifier in @($AcceptedExcludedIdentifiers)) {
        $parsedIdentifier = [guid]::Empty
        if ([guid]::TryParseExact([string] $identifier, 'D', [ref] $parsedIdentifier) -and
            [string]::Equals($parsedIdentifier.ToString('D'), [string] $identifier, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void] $accepted.Add([string] $identifier)
        }
    }

    $acceptedExcludedUserCount = 0
    $unacceptedExcludedUserCount = 0
    foreach ($identifier in $excludeUsers) {
        if ($accepted.Contains($identifier)) {
            $acceptedExcludedUserCount++
        } else {
            $unacceptedExcludedUserCount++
            if ($null -eq $incompleteReason) { $incompleteReason = 'unaccepted-excluded-user-id' }
        }
    }

    $hasExcludedGuestsOrExternalUsers = [bool] (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'hasExcludeGuestsOrExternalUsers')
    if ($excludeGroups.Count -gt 0 -and $null -eq $incompleteReason) {
        $incompleteReason = 'excluded-group-membership-unresolved'
    }
    if ($hasExcludedGuestsOrExternalUsers -and $null -eq $incompleteReason) {
        $incompleteReason = 'excluded-guests-or-external-users'
    }

    $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($roleId in $excludeRoles) {
        $parsedRoleId = [guid]::Empty
        if (-not [guid]::TryParseExact($roleId, 'D', [ref] $parsedRoleId) -or
            -not [string]::Equals($parsedRoleId.ToString('D'), $roleId, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($null -eq $incompleteReason) { $incompleteReason = 'invalid-excluded-role-id' }
            continue
        }
        [void] $excluded.Add($roleId)
    }

    $possible = [System.Collections.Generic.List[string]]::new()
    if ($includeAllCount -eq 1) {
        foreach ($requiredRoleId in $allRequired) {
            if (-not $excluded.Contains($requiredRoleId)) { $possible.Add($requiredRoleId) }
        }
    } elseif ($includeRoles.Count -gt 0) {
        foreach ($roleId in $includeRoles) {
            $parsedRoleId = [guid]::Empty
            if (-not [guid]::TryParseExact($roleId, 'D', [ref] $parsedRoleId) -or
                -not [string]::Equals($parsedRoleId.ToString('D'), $roleId, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($null -eq $incompleteReason) { $incompleteReason = 'invalid-included-role-id' }
                continue
            }
            if ($allRequired -contains $roleId -and -not $excluded.Contains($roleId) -and -not $possible.Contains($roleId)) {
                $possible.Add($roleId)
            }
        }
    } elseif ($includeUsers.Count -eq 0 -and $includeGroups.Count -eq 0 -and
        -not [bool] (Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName 'hasIncludeGuestsOrExternalUsers')) {
        $possibleWithKnownExclusions = @($allRequired | Where-Object { -not $excluded.Contains($_) })
        return & $newResult 'Incomplete' 'empty-user-role-scope' $possibleWithKnownExclusions $acceptedExcludedUserCount $unacceptedExcludedUserCount $excludeGroups.Count $hasExcludedGuestsOrExternalUsers
    }

    if ($null -ne $incompleteReason) {
        return & $newResult 'Incomplete' $incompleteReason ([string[]] @($possible)) $acceptedExcludedUserCount $unacceptedExcludedUserCount $excludeGroups.Count $hasExcludedGuestsOrExternalUsers
    }
    if ($possible.Count -eq 0) {
        return & $newResult 'NotTargeted' 'no-required-admin-role-target' @() $acceptedExcludedUserCount $unacceptedExcludedUserCount $excludeGroups.Count $hasExcludedGuestsOrExternalUsers
    }
    return & $newResult 'Targeted' $null ([string[]] @($possible)) $acceptedExcludedUserCount $unacceptedExcludedUserCount $excludeGroups.Count $hasExcludedGuestsOrExternalUsers
}
