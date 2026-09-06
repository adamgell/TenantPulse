<#
    Private: normalize -Datasets.groupMembers into a groupId -> memberIds map.

    Two input shapes are accepted so collection rows and the older dictionary fixture
    used by Get-PulseCaExclusionContext both resolve the same way:

        1. IDictionary keyed by group id, values are member id arrays. Treated as complete
           unless the dictionary carries a Truncated/$true or Complete/$false entry.
        2. Array of closure rows from Invoke-PulseGroupClosurePlan (groupId, memberIds,
           truncated, complete, sampled). All five producer fields are required; a malformed,
           truncated, sampled, or incomplete row never counts as complete.

    Caps remain visible on the returned object. Callers must not Pass when Complete is false.
#>

function ConvertTo-PulseGroupMemberMap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        $GroupMembers
    )

    $empty = [string[]] @()
    $map = [ordered]@{}
    $groupKeysById = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $truncatedGroupIds = [System.Collections.Generic.List[string]]::new()
    $present = $false
    $complete = $true
    $sampled = $false
    $caps = $null

    function Get-GroupMemberDictionaryEntry {
        param(
            [Parameter(Mandatory)] [System.Collections.IDictionary] $Dictionary,
            [Parameter(Mandatory)] [string] $KeyName
        )

        foreach ($candidateKey in @($Dictionary.Keys)) {
            if ($candidateKey -is [string] -and
                [string]::Equals($candidateKey, $KeyName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $value = $Dictionary[$candidateKey]
                return [pscustomobject]@{
                    Present = $true
                    Key     = $candidateKey
                    Value   = $value
                }
            }
        }

        return [pscustomobject]@{ Present = $false; Key = $null; Value = $null }
    }

    function Get-GroupMemberRowPropertyState {
        param(
            $Node,
            [Parameter(Mandatory)] [string] $PropertyName
        )

        if ($Node -is [System.Collections.IDictionary]) {
            return Get-GroupMemberDictionaryEntry -Dictionary $Node -KeyName $PropertyName
        }

        $property = $Node.PSObject.Properties[$PropertyName]
        $value = $null
        if ($null -ne $property) { $value = $property.Value }
        return [pscustomobject]@{
            Present = $null -ne $property
            Value   = $value
        }
    }

    function ConvertTo-NativeGroupMemberIds {
        param(
            [Parameter()]
            [AllowNull()]
            [AllowEmptyCollection()]
            $Values
        )

        $valid = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $validShape = $true
        foreach ($value in @($Values)) {
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
                $validShape = $false
                continue
            }
            $valid.Add($value) | Out-Null
        }
        $normalized = ConvertTo-PulseOrdinalStringArray -Values $valid
        return [pscustomobject]@{
            Complete = $validShape
            Values   = $normalized
        }
    }

    if ($null -eq $GroupMembers) {
        return [pscustomobject][ordered]@{
            Present           = $false
            Complete          = $false
            Sampled           = $false
            Map               = $map
            TruncatedGroupIds = $empty
            Caps              = $null
        }
    }

    $present = $true

    $isCompatibilityDictionary = $false
    if ($GroupMembers -is [System.Collections.IDictionary]) {
        $groupIdEntry = Get-GroupMemberDictionaryEntry -Dictionary $GroupMembers -KeyName 'groupId'
        $isCompatibilityDictionary = -not $groupIdEntry.Present
    }

    if ($isCompatibilityDictionary) {
        foreach ($key in @($GroupMembers.Keys)) {
            if ($key -isnot [string]) {
                $complete = $false
                continue
            }
            $keyText = $key
            if ([string]::IsNullOrWhiteSpace($keyText)) {
                $complete = $false
                continue
            }
            if ($keyText -in @('Truncated', 'Complete', 'Sampled', 'Caps')) { continue }
            $memberValues = $GroupMembers[$key]
            if ($null -eq $memberValues) { $complete = $false }
            $memberResult = ConvertTo-NativeGroupMemberIds -Values $memberValues
            if (-not $memberResult.Complete) { $complete = $false }
            $memberIds = [string[]] @($memberResult.Values)

            $mapKey = $keyText
            if ($groupKeysById.ContainsKey($keyText)) {
                $complete = $false
                $mapKey = $groupKeysById[$keyText]
                $mergedResult = ConvertTo-NativeGroupMemberIds -Values @($map[$mapKey] + $memberIds)
                $memberIds = [string[]] @($mergedResult.Values)
            } else {
                $groupKeysById.Add($keyText, $keyText)
            }
            $map[$mapKey] = $memberIds
        }

        $truncatedEntry = Get-GroupMemberDictionaryEntry -Dictionary $GroupMembers -KeyName 'Truncated'
        if ($truncatedEntry.Present) {
            $truncatedValue = $truncatedEntry.Value
            if ($truncatedValue -isnot [bool]) {
                $complete = $false
            } elseif ($truncatedValue) {
                $complete = $false
                $sampled = $true
            }
        }
        $completeEntry = Get-GroupMemberDictionaryEntry -Dictionary $GroupMembers -KeyName 'Complete'
        if ($completeEntry.Present) {
            $completeValue = $completeEntry.Value
            if ($completeValue -isnot [bool] -or -not $completeValue) {
                $complete = $false
            }
        }
        $sampledEntry = Get-GroupMemberDictionaryEntry -Dictionary $GroupMembers -KeyName 'Sampled'
        if ($sampledEntry.Present) {
            $sampledValue = $sampledEntry.Value
            if ($sampledValue -isnot [bool]) {
                $complete = $false
            } elseif ($sampledValue) {
                $sampled = $true
                $complete = $false
            }
        }
        $capsEntry = Get-GroupMemberDictionaryEntry -Dictionary $GroupMembers -KeyName 'Caps'
        if ($capsEntry.Present) {
            $caps = $capsEntry.Value
        }

        return [pscustomobject][ordered]@{
            Present           = $true
            Complete          = $complete
            Sampled           = $sampled
            Map               = $map
            TruncatedGroupIds = $empty
            Caps              = $caps
        }
    }

    foreach ($row in @($GroupMembers)) {
        if ($null -eq $row) {
            $complete = $false
            continue
        }
        $groupIdState = Get-GroupMemberRowPropertyState -Node $row -PropertyName 'groupId'
        $groupId = $groupIdState.Value
        if (-not $groupIdState.Present -or $groupId -isnot [string] -or [string]::IsNullOrWhiteSpace($groupId)) {
            $complete = $false
            continue
        }

        $memberState = Get-GroupMemberRowPropertyState -Node $row -PropertyName 'memberIds'
        $memberValues = $memberState.Value
        if (-not $memberState.Present -or $null -eq $memberValues) {
            $complete = $false
        }
        $memberResult = ConvertTo-NativeGroupMemberIds -Values $memberValues
        if (-not $memberResult.Complete) { $complete = $false }
        $memberIds = [string[]] @($memberResult.Values)
        $mapKey = $groupId
        if ($groupKeysById.ContainsKey($groupId)) {
            $complete = $false
            $mapKey = $groupKeysById[$groupId]
            $mergedMemberIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($memberId in @($map[$mapKey]) + @($memberIds)) {
                if (-not [string]::IsNullOrWhiteSpace([string] $memberId)) {
                    $mergedMemberIds.Add([string] $memberId) | Out-Null
                }
            }
            $memberIds = ConvertTo-PulseOrdinalStringArray -Values $mergedMemberIds
        } else {
            $groupKeysById.Add($groupId, $groupId)
        }
        $map[$mapKey] = $memberIds

        $truncatedState = Get-GroupMemberRowPropertyState -Node $row -PropertyName 'truncated'
        $completeState = Get-GroupMemberRowPropertyState -Node $row -PropertyName 'complete'
        $sampledState = Get-GroupMemberRowPropertyState -Node $row -PropertyName 'sampled'
        $rowTruncated = $truncatedState.Value
        $rowComplete = $completeState.Value
        $rowSampled = $sampledState.Value
        $rowMetadataInvalid =
            (-not $truncatedState.Present -or $rowTruncated -isnot [bool]) -or
            (-not $completeState.Present -or $rowComplete -isnot [bool]) -or
            (-not $sampledState.Present -or $rowSampled -isnot [bool])
        if ($rowMetadataInvalid -or ($rowComplete -is [bool] -and -not $rowComplete)) {
            $complete = $false
        }
        if (($rowTruncated -is [bool] -and $rowTruncated) -or
            ($rowSampled -is [bool] -and $rowSampled)) {
            $complete = $false
            $truncatedGroupIds.Add($groupId) | Out-Null
            $sampled = $true
        }

        $rowCaps = Get-PulseSettingsCatalogValueProperty -Node $row -PropertyName 'caps'
        if ($null -ne $rowCaps -and $null -eq $caps) {
            $caps = $rowCaps
        }
    }

    $truncatedIds = ConvertTo-PulseOrdinalStringArray -Values $truncatedGroupIds
    return [pscustomobject][ordered]@{
        Present           = $present
        Complete          = $complete
        Sampled           = $sampled
        Map               = $map
        TruncatedGroupIds = $truncatedIds
        Caps              = $caps
    }
}
