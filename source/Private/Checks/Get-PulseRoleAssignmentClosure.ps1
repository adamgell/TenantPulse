<#
    Private: unify privileged-role and PIM assignment closure.

    Consumes directoryRoleAssignments (active), directoryRoleDefinitions (isPrivileged),
    roleAssignmentScheduleInstances (permanent vs activated), roleEligibilityScheduleInstances
    (eligible), and optional groupMembers/groupClosure. Direct, group-based, and transitive
    members are folded into unique principal sets. Caps on group closure are visible;
    Incomplete is true when membership cannot be proven complete. A caller must never Pass
    a count or zero-permanent assertion when Incomplete is true.

    Eligibility is consumed when present. Missing eligibility does not suppress
    permanent-active evaluation; EligibilityAvailable is false instead. License-aware
    callers still use Data.Gates = EntraP2 for TP.ENT.0022.
#>

function Get-PulseRoleAssignmentClosure {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $empty = [string[]] @()
    $privilegedRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $privilegedRoleNames = [ordered]@{}
    $roleDefinitions = @()
    if ($Datasets -and $Datasets.ContainsKey('directoryRoleDefinitions') -and $null -ne $Datasets.directoryRoleDefinitions) {
        $roleDefinitions = @($Datasets.directoryRoleDefinitions)
    }

    foreach ($roleDefinition in $roleDefinitions) {
        $isPrivileged = Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'isPrivileged'
        if ($null -eq $isPrivileged -or -not [bool] $isPrivileged) { continue }
        $roleDefId = [string] (Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'id')
        if ([string]::IsNullOrWhiteSpace($roleDefId)) { continue }
        [void] $privilegedRoleIds.Add($roleDefId)
        $displayName = [string] (Get-PulseSettingsCatalogValueProperty -Node $roleDefinition -PropertyName 'displayName')
        $privilegedRoleNames[$roleDefId] = $displayName
    }

    $groupMap = ConvertTo-PulseGroupMemberMap -GroupMembers $(
        if ($Datasets -and $Datasets.ContainsKey('groupMembers')) { $Datasets.groupMembers } else { $null }
    )
    $incomplete = $groupMap.Present -and -not $groupMap.Complete
    $closureState = @{ Incomplete = $incomplete }

    function Expand-PulseRolePrincipal {
        param([string] $PrincipalId)

        $ids = [System.Collections.Generic.List[string]]::new()
        if ([string]::IsNullOrWhiteSpace($PrincipalId)) {
            return $ids
        }
        $mapped = $null
        if ($groupMap.Present) {
            foreach ($key in @($groupMap.Map.Keys)) {
                if ([string]::Equals([string] $key, $PrincipalId, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $mapped = @($groupMap.Map[$key])
                    break
                }
            }
        }
        if ($null -ne $mapped) {
            foreach ($memberId in $mapped) {
                if ($memberId) { $ids.Add([string] $memberId) | Out-Null }
            }
            if ($groupMap.TruncatedGroupIds -contains $PrincipalId) {
                $closureState.Incomplete = $true
            }
            return $ids
        }
        $ids.Add($PrincipalId) | Out-Null
        return $ids
    }



    $directActive = [System.Collections.Generic.List[object]]::new()
    $effectiveActive = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $directActiveRows = @()
    if ($Datasets -and $Datasets.ContainsKey('directoryRoleAssignments') -and $null -ne $Datasets.directoryRoleAssignments) {
        $directActiveRows = @($Datasets.directoryRoleAssignments)
    }
    foreach ($assignment in $directActiveRows) {
        $roleDefinitionId = [string] (Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'roleDefinitionId')
        if (-not $privilegedRoleIds.Contains($roleDefinitionId)) { continue }
        $principalId = [string] (Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'principalId')
        $directActive.Add($assignment) | Out-Null
        foreach ($expanded in @(Expand-PulseRolePrincipal -PrincipalId $principalId)) {
            if ($expanded) { [void] $effectiveActive.Add("$expanded`t$roleDefinitionId") }
        }
    }

    $permanentActive = [System.Collections.Generic.List[object]]::new()
    $permanentEffective = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $scheduleRows = @()
    $scheduleAvailable = $false
    if ($Datasets -and $Datasets.ContainsKey('roleAssignmentScheduleInstances') -and $null -ne $Datasets.roleAssignmentScheduleInstances) {
        $scheduleAvailable = $true
        $scheduleRows = @($Datasets.roleAssignmentScheduleInstances)
    }
    foreach ($instance in $scheduleRows) {
        $assignmentType = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'assignmentType')
        $endDateTime = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'endDateTime')
        $roleDefinitionId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'roleDefinitionId')
        if (-not $privilegedRoleIds.Contains($roleDefinitionId)) { continue }
        if (-not [string]::Equals($assignmentType, 'Assigned', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not [string]::IsNullOrWhiteSpace($endDateTime)) { continue }
        $permanentActive.Add($instance) | Out-Null
        $principalId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'principalId')
        foreach ($expanded in @(Expand-PulseRolePrincipal -PrincipalId $principalId)) {
            if ($expanded) { [void] $permanentEffective.Add("$expanded`t$roleDefinitionId") }
        }
    }

    $eligible = [System.Collections.Generic.List[object]]::new()
    $eligibleEffective = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $eligibilityAvailable = $false
    $eligibilityRows = @()
    if ($Datasets -and $Datasets.ContainsKey('roleEligibilityScheduleInstances') -and $null -ne $Datasets.roleEligibilityScheduleInstances) {
        $eligibilityAvailable = $true
        $eligibilityRows = @($Datasets.roleEligibilityScheduleInstances)
    }
    foreach ($instance in $eligibilityRows) {
        $roleDefinitionId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'roleDefinitionId')
        if (-not $privilegedRoleIds.Contains($roleDefinitionId)) { continue }
        $eligible.Add($instance) | Out-Null
        $principalId = [string] (Get-PulseSettingsCatalogValueProperty -Node $instance -PropertyName 'principalId')
        foreach ($expanded in @(Expand-PulseRolePrincipal -PrincipalId $principalId)) {
            if ($expanded) { [void] $eligibleEffective.Add("$expanded`t$roleDefinitionId") }
        }
    }

    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $exemptPrincipals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in (@($exclusionContext.ServiceAccounts) + @($exclusionContext.BreakGlassAccounts))) {
        if ($id) { [void] $exemptPrincipals.Add([string] $id) }
    }

    $permanentOffending = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $permanentExempt = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pairKey in $permanentEffective) {
        $principalId = ([string] $pairKey).Split("`t", 2)[0]
        if ($exemptPrincipals.Contains($principalId)) {
            [void] $permanentExempt.Add($principalId)
        } else {
            [void] $permanentOffending.Add($principalId)
        }
    }

    $activePrincipals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pairKey in $effectiveActive) {
        $principalId = ([string] $pairKey).Split("`t", 2)[0]
        if ($principalId) { [void] $activePrincipals.Add($principalId) }
    }
    $eligiblePrincipals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pairKey in $eligibleEffective) {
        $principalId = ([string] $pairKey).Split("`t", 2)[0]
        if ($principalId) { [void] $eligiblePrincipals.Add($principalId) }
    }

    $incomplete = [bool] $closureState.Incomplete
    $effectiveActiveIds = ConvertTo-PulseOrdinalStringArray -Values $activePrincipals
    $eligibleIds = ConvertTo-PulseOrdinalStringArray -Values $eligiblePrincipals
    $permanentOffendingIds = ConvertTo-PulseOrdinalStringArray -Values $permanentOffending
    $permanentExemptIds = ConvertTo-PulseOrdinalStringArray -Values $permanentExempt

    return [pscustomobject][ordered]@{
        PrivilegedRoleIds              = ConvertTo-PulseOrdinalStringArray -Values $privilegedRoleIds
        PrivilegedRoleCount            = $privilegedRoleIds.Count
        DirectActiveCount              = $directActive.Count
        UniqueEffectiveActiveCount     = $effectiveActive.Count
        UniqueEffectiveActivePrincipals = $effectiveActiveIds
        UniqueEffectiveEligibleCount   = $eligibleEffective.Count
        UniqueEffectiveEligiblePrincipals = $eligibleIds
        PermanentActiveCount           = $permanentActive.Count
        PermanentOffendingPrincipals   = $permanentOffendingIds
        PermanentExemptPrincipals      = $permanentExemptIds
        EligibilityAvailable           = $eligibilityAvailable
        ScheduleAvailable              = $scheduleAvailable
        GroupMembersPresent            = $groupMap.Present
        Incomplete                     = $incomplete
        Sampled                        = [bool] $groupMap.Sampled
        Caps                           = $groupMap.Caps
        DirectActiveAssignments        = @($directActive)
        PermanentActiveInstances       = @($permanentActive)
        EligibleInstances              = @($eligible)
        RoleDisplayNames               = $privilegedRoleNames
    }
}
