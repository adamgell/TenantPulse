<#
    Private: classify one Intune policy's assignment array into a fail-closed intent.

    Existence of a policy is not coverage. This helper is the one place include, exclude-only,
    filter, typed target, malformed target, authoritative empty, and unknown membership are
    named so checks cannot independently drift.

    State:
        Unknown      - assignments were not collected (null). Cannot prove targeting.
        Empty        - authoritative empty array. Targets nobody.
        ExcludeOnly  - only exclusionGroup / intent=exclude targets. Targets nobody.
        Include      - at least one include target (all users/devices, include group, ConfigMgr).
        Malformed    - a target is missing @odata.type, uses an unknown type, or a group
                       target has no groupId. Cannot prove targeting.

    IsAssigned is true only for Include. Empty, ExcludeOnly, Unknown, and Malformed never
    count as assigned. HasFilter is additive disclosure; a filter does not by itself assign.
#>

function Get-PulseAssignmentODataType {
    param($Node)

    $raw = Get-PulseSettingsCatalogValueProperty -Node $Node -PropertyName '@odata.type'
    if ([string]::IsNullOrWhiteSpace([string] $raw)) {
        $raw = Get-PulseSettingsCatalogValueProperty -Node $Node -PropertyName 'odata.type'
    }
    if ([string]::IsNullOrWhiteSpace([string] $raw)) {
        return $null
    }

    $text = ([string] $raw).Trim()
    if ($text.StartsWith('#', [System.StringComparison]::Ordinal)) {
        $text = $text.Substring(1)
    }
    if ($text.StartsWith('microsoft.graph.', [System.StringComparison]::OrdinalIgnoreCase)) {
        $text = $text.Substring('microsoft.graph.'.Length)
    }
    return $text
}

function ConvertTo-PulseAssignmentIntent {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        $Assignments
    )

    $emptyTargets = [string[]] @()
    $result = [pscustomobject][ordered]@{
        State            = 'Unknown'
        IsAssigned       = $false
        HasFilter        = $false
        Complete         = $false
        IncludeKinds     = $emptyTargets
        ExcludeGroupIds  = $emptyTargets
        IncludeGroupIds  = $emptyTargets
        FilterIds        = $emptyTargets
        MalformedReasons = $emptyTargets
    }

    if ($null -eq $Assignments) {
        return $result
    }

    $items = @($Assignments)
    if ($items.Count -eq 0) {
        $result.State = 'Empty'
        $result.Complete = $true
        return $result
    }

    $includeKinds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $includeGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $excludeGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $filterIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $malformedReasons = [System.Collections.Generic.List[string]]::new()
    $hasInclude = $false
    $hasExclude = $false
    $hasMalformed = $false

    foreach ($assignment in $items) {
        if ($null -eq $assignment) {
            $hasMalformed = $true
            $malformedReasons.Add('null-assignment') | Out-Null
            continue
        }

        $intent = [string] (Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'intent')
        $target = Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'target'
        if ($null -eq $target) {
            $target = $assignment
        }

        $typeName = Get-PulseAssignmentODataType -Node $target
        $groupId = [string] (Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName 'groupId')
        $filterId = [string] (Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName 'deviceAndAppManagementAssignmentFilterId')
        $filterType = [string] (Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName 'deviceAndAppManagementAssignmentFilterType')
        if (-not [string]::IsNullOrWhiteSpace($filterId)) {
            $result.HasFilter = $true
            [void] $filterIds.Add($filterId)
        }
        if (-not [string]::IsNullOrWhiteSpace($filterType) -and
            -not [string]::Equals($filterType, 'none', [System.StringComparison]::OrdinalIgnoreCase)) {
            $result.HasFilter = $true
        }

        $isExcludeIntent = [string]::Equals($intent, 'exclude', [System.StringComparison]::OrdinalIgnoreCase)
        $kind = $null
        if ([string]::IsNullOrWhiteSpace($typeName)) {
            $hasMalformed = $true
            $malformedReasons.Add('missing-target-type') | Out-Null
        } elseif ([string]::Equals($typeName, 'groupAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)) {
            $kind = 'Group'
        } elseif ([string]::Equals($typeName, 'exclusionGroupAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)) {
            $kind = 'ExclusionGroup'
        } elseif ([string]::Equals($typeName, 'allLicensedUsersAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)) {
            $kind = 'AllUsers'
        } elseif ([string]::Equals($typeName, 'allDevicesAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)) {
            $kind = 'AllDevices'
        } elseif ([string]::Equals($typeName, 'configurationManagerCollectionAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)) {
            $kind = 'ConfigMgr'
        } else {
            $hasMalformed = $true
            $malformedReasons.Add("unknown-target-type:$typeName") | Out-Null
        }

        if ($kind -eq 'Group' -or $kind -eq 'ExclusionGroup') {
            if ([string]::IsNullOrWhiteSpace($groupId)) {
                $hasMalformed = $true
                $malformedReasons.Add('missing-group-id') | Out-Null
                continue
            }
        }

        if ($isExcludeIntent -or $kind -eq 'ExclusionGroup') {
            $hasExclude = $true
            if (-not [string]::IsNullOrWhiteSpace($groupId)) {
                [void] $excludeGroupIds.Add($groupId)
            }
            continue
        }

        if ($null -eq $kind) {
            continue
        }

        $hasInclude = $true
        [void] $includeKinds.Add($kind)
        if ($kind -eq 'Group' -and -not [string]::IsNullOrWhiteSpace($groupId)) {
            [void] $includeGroupIds.Add($groupId)
        }
    }

    $result.IncludeKinds = ConvertTo-PulseOrdinalStringArray -Values $includeKinds
    $result.IncludeGroupIds = ConvertTo-PulseOrdinalStringArray -Values $includeGroupIds
    $result.ExcludeGroupIds = ConvertTo-PulseOrdinalStringArray -Values $excludeGroupIds
    $result.FilterIds = ConvertTo-PulseOrdinalStringArray -Values $filterIds
    $result.MalformedReasons = ConvertTo-PulseOrdinalStringArray -Values $malformedReasons

    if ($hasMalformed) {
        $result.State = 'Malformed'
        $result.Complete = $false
        $result.IsAssigned = $false
        return $result
    }

    if ($hasInclude) {
        $result.State = 'Include'
        $result.IsAssigned = $true
        $result.Complete = $true
        return $result
    }

    if ($hasExclude) {
        $result.State = 'ExcludeOnly'
        $result.IsAssigned = $false
        $result.Complete = $true
        return $result
    }

    $result.State = 'Empty'
    $result.Complete = $true
    return $result
}

function Test-PulseCompositeRowIsAssigned {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Row
    )

    if ($null -eq $Row) { return $false }
    $intentText = [string] (Get-PulseSettingsCatalogValueProperty -Node $Row -PropertyName 'assignmentIntent')
    if (-not [string]::IsNullOrWhiteSpace($intentText)) {
        return [string]::Equals($intentText, 'Include', [System.StringComparison]::OrdinalIgnoreCase)
    }
    $intent = ConvertTo-PulseAssignmentIntent -Assignments (Get-PulseSettingsCatalogValueProperty -Node $Row -PropertyName 'assignments')
    return [bool] $intent.IsAssigned
}
