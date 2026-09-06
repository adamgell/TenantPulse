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

    Branding-profile and enrollment-configuration assignment responses use the documented
    scopeTagGroupAssignmentTarget shape. Only targetType=user/device with a nonblank
    entraObjectId is an authoritative include; missing, none, and future/unknown target
    types remain Malformed so an unfamiliar service shape cannot become coverage.

    IsAssigned is true only for Include. Empty, ExcludeOnly, Unknown, and Malformed never
    count as assigned. HasFilter is additive disclosure; a filter does not by itself assign.
    Every proof-relevant discriminator, intent, identity, and filter field must be a native
    string when present; implicit PowerShell coercion of arrays or scalars is never evidence.
    A present intent outside include/exclude is Malformed rather than a future value being
    treated as an include.
#>

function Get-PulseAssignmentStringField {
    param(
        $Node,
        [string] $PropertyName
    )

    $isPresent = if ($null -eq $Node) {
        $false
    } elseif ($Node -is [System.Collections.IDictionary]) {
        $Node.Contains($PropertyName)
    } else {
        $null -ne $Node.PSObject.Properties[$PropertyName]
    }
    $rawValue = Get-PulseSettingsCatalogValueProperty -Node $Node -PropertyName $PropertyName
    return [pscustomobject]@{
        IsPresent = $isPresent
        IsValid   = $null -eq $rawValue -or $rawValue -is [string]
        Value     = if ($rawValue -is [string]) { $rawValue } else { $null }
    }
}

function Get-PulseAssignmentODataType {
    param($Node)

    $field = Get-PulseAssignmentStringField -Node $Node -PropertyName '@odata.type'
    if (-not $field.IsValid) {
        return $null
    }
    if (-not $field.IsPresent) {
        $field = Get-PulseAssignmentStringField -Node $Node -PropertyName 'odata.type'
    }
    if (-not $field.IsPresent -or -not $field.IsValid) {
        return $null
    }
    if ([string]::IsNullOrWhiteSpace($field.Value)) {
        return $null
    }

    $text = $field.Value.Trim()
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

        # Reset all per-row values so one malformed item cannot inherit a prior target's
        # shape while PowerShell reuses variables in this function scope.
        $typeName = $null
        $groupId = $null
        $filterId = $null
        $filterType = $null
        $scopeTagTargetType = $null
        $entraObjectId = $null

        # Every proof-relevant text field must remain a native string. PowerShell turns a
        # one-element array into that element when cast to [string], which can otherwise
        # transform malformed persisted evidence into a valid include assignment.
        $intentField = Get-PulseAssignmentStringField -Node $assignment -PropertyName 'intent'
        $normalizedTargetTypeField = Get-PulseAssignmentStringField -Node $assignment -PropertyName 'targetType'
        if (-not $intentField.IsValid -or -not $normalizedTargetTypeField.IsValid) {
            $hasMalformed = $true
            $malformedReasons.Add('non-string-assignment-field') | Out-Null
            continue
        }
        if ($normalizedTargetTypeField.IsPresent -and
            [string]::IsNullOrWhiteSpace($normalizedTargetTypeField.Value)) {
            $hasMalformed = $true
            $malformedReasons.Add('missing-target-type') | Out-Null
            continue
        }
        if ($intentField.IsPresent -and
            ($null -eq $intentField.Value -or [string]::IsNullOrWhiteSpace($intentField.Value) -or
                (-not [string]::Equals($intentField.Value, 'include', [System.StringComparison]::OrdinalIgnoreCase) -and
                    -not [string]::Equals($intentField.Value, 'exclude', [System.StringComparison]::OrdinalIgnoreCase)))) {
            $hasMalformed = $true
            $malformedReasons.Add('unsupported-assignment-intent') | Out-Null
            continue
        }

        # Extract intent - both shapes carry it at the top level.
        $intent = $intentField.Value
        $normalizedTargetType = $normalizedTargetTypeField.Value
        if (-not [string]::IsNullOrWhiteSpace($normalizedTargetType)) {
            switch ($normalizedTargetType) {
                'group'                    { $typeName = 'groupAssignmentTarget' }
                'exclusionGroup'           { $typeName = 'exclusionGroupAssignmentTarget' }
                'allLicensedUsers'         { $typeName = 'allLicensedUsersAssignmentTarget' }
                'allDevices'               { $typeName = 'allDevicesAssignmentTarget' }
                default                    { $typeName = $null }
            }
            $groupIdField = Get-PulseAssignmentStringField -Node $assignment -PropertyName 'groupId'
            $filterIdField = Get-PulseAssignmentStringField -Node $assignment -PropertyName 'filterId'
            $filterTypeField = Get-PulseAssignmentStringField -Node $assignment -PropertyName 'filterType'
            if (-not $groupIdField.IsValid -or -not $filterIdField.IsValid -or -not $filterTypeField.IsValid) {
                $hasMalformed = $true
                $malformedReasons.Add('non-string-assignment-field') | Out-Null
                continue
            }
            $groupId = $groupIdField.Value
            $filterId = $filterIdField.Value
            $filterType = $filterTypeField.Value
        } else {
            $targetIsPresent = if ($assignment -is [System.Collections.IDictionary]) {
                $assignment.Contains('target')
            } else {
                $null -ne $assignment.PSObject.Properties['target']
            }
            $target = Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'target'
            if ($null -eq $target) {
                if ($targetIsPresent) {
                    $hasMalformed = $true
                    $malformedReasons.Add('missing-target') | Out-Null
                    continue
                }
                $target = $assignment
            }
            $typeName = Get-PulseAssignmentODataType -Node $target
            $groupIdField = Get-PulseAssignmentStringField -Node $target -PropertyName 'groupId'
            $filterIdField = Get-PulseAssignmentStringField -Node $target -PropertyName 'deviceAndAppManagementAssignmentFilterId'
            $filterTypeField = Get-PulseAssignmentStringField -Node $target -PropertyName 'deviceAndAppManagementAssignmentFilterType'
            $scopeTagTargetTypeField = Get-PulseAssignmentStringField -Node $target -PropertyName 'targetType'
            $entraObjectIdField = Get-PulseAssignmentStringField -Node $target -PropertyName 'entraObjectId'
            if (-not $groupIdField.IsValid -or -not $filterIdField.IsValid -or
                -not $filterTypeField.IsValid -or -not $scopeTagTargetTypeField.IsValid -or
                -not $entraObjectIdField.IsValid) {
                $hasMalformed = $true
                $malformedReasons.Add('non-string-assignment-field') | Out-Null
                continue
            }
            $groupId = $groupIdField.Value
            $filterId = $filterIdField.Value
            $filterType = $filterTypeField.Value
            $scopeTagTargetType = $scopeTagTargetTypeField.Value
            $entraObjectId = $entraObjectIdField.Value
        }

        # Keep filter semantics aligned with the normalized expansion schemas. The only
        # valid unfiltered forms are both values null/omitted or exact lowercase `none`
        # with a null id. Exact lowercase include/exclude require a native nonblank id.
        # Any other pairing is malformed evidence and must not mutate the result summary.
        $filterShapeValid = if ($null -eq $filterType) {
            $null -eq $filterId
        } elseif ([string]::Equals($filterType, 'none', [System.StringComparison]::Ordinal)) {
            $null -eq $filterId
        } elseif ([string]::Equals($filterType, 'include', [System.StringComparison]::Ordinal) -or
            [string]::Equals($filterType, 'exclude', [System.StringComparison]::Ordinal)) {
            -not [string]::IsNullOrWhiteSpace($filterId)
        } else {
            $false
        }
        if (-not $filterShapeValid) {
            $hasMalformed = $true
            $malformedReasons.Add('invalid-assignment-filter-shape') | Out-Null
            continue
        }

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
        } elseif ([string]::Equals($typeName, 'scopeTagGroupAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)) {
            if ([string]::IsNullOrWhiteSpace($scopeTagTargetType)) {
                $hasMalformed = $true
                $malformedReasons.Add('missing-scope-tag-target-type') | Out-Null
            } elseif ($scopeTagTargetType -notin @('user', 'device')) {
                $hasMalformed = $true
                $malformedReasons.Add("unsupported-scope-tag-target-type:$scopeTagTargetType") | Out-Null
            } elseif ([string]::IsNullOrWhiteSpace($entraObjectId)) {
                $hasMalformed = $true
                $malformedReasons.Add('missing-entra-object-id') | Out-Null
            } else {
                # The service names this a group assignment target; targetType identifies
                # whether the referenced Entra group targets users or devices.
                $kind = 'Group'
                $groupId = $entraObjectId
            }
        } else {
            $hasMalformed = $true
            $malformedReasons.Add("unknown-target-type:$typeName") | Out-Null
        }

        if (($kind -eq 'AllUsers' -or $kind -eq 'AllDevices') -and $null -ne $groupId) {
            $hasMalformed = $true
            $malformedReasons.Add('unexpected-group-id') | Out-Null
            continue
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
    $intentField = Get-PulseAssignmentStringField -Node $Row -PropertyName 'assignmentIntent'
    if ($intentField.IsPresent) {
        if (-not $intentField.IsValid -or $null -eq $intentField.Value) {
            return $false
        }
        return [string]::Equals($intentField.Value, 'Include', [System.StringComparison]::OrdinalIgnoreCase)
    }
    $intent = ConvertTo-PulseAssignmentIntent -Assignments (Get-PulseSettingsCatalogValueProperty -Node $Row -PropertyName 'assignments')
    return [bool] $intent.IsAssigned
}
