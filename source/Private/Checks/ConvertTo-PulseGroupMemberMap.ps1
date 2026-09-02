<#
    Private: normalize -Datasets.groupMembers into a groupId -> memberIds map.

    Two input shapes are accepted so collection rows and the older dictionary fixture
    used by Get-PulseCaExclusionContext both resolve the same way:

        1. IDictionary keyed by group id, values are member id arrays. Treated as complete
           unless the dictionary carries a Truncated/$true or Complete/$false entry.
        2. Array of closure rows from Invoke-PulseGroupClosurePlan (groupId, memberIds,
           truncated, complete). A truncated or incomplete row never counts as complete.

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
    $truncatedGroupIds = [System.Collections.Generic.List[string]]::new()
    $present = $false
    $complete = $true
    $sampled = $false
    $caps = $null

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

    if ($GroupMembers -is [System.Collections.IDictionary] -and
        -not ($GroupMembers.PSObject.Properties['groupId']) -and
        -not ($GroupMembers.Contains('groupId'))) {
        foreach ($key in @($GroupMembers.Keys)) {
            $keyText = [string] $key
            if ([string]::IsNullOrWhiteSpace($keyText)) { continue }
            if ($keyText -in @('Truncated', 'Complete', 'Sampled', 'Caps')) { continue }
            $memberIds = ConvertTo-PulseOrdinalStringArray -Values @($GroupMembers[$key] | Where-Object { $_ })
            $map[$keyText] = $memberIds
        }

        if ($GroupMembers.Contains('Truncated') -and [bool] $GroupMembers['Truncated']) {
            $complete = $false
            $sampled = $true
        }
        if ($GroupMembers.Contains('Complete') -and -not [bool] $GroupMembers['Complete']) {
            $complete = $false
        }
        if ($GroupMembers.Contains('Sampled') -and [bool] $GroupMembers['Sampled']) {
            $sampled = $true
            $complete = $false
        }
        if ($GroupMembers.Contains('Caps')) {
            $caps = $GroupMembers['Caps']
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
        if ($null -eq $row) { continue }
        $groupId = [string] (Get-PulseSettingsCatalogValueProperty -Node $row -PropertyName 'groupId')
        if ([string]::IsNullOrWhiteSpace($groupId)) { continue }

        $memberValues = Get-PulseSettingsCatalogValueProperty -Node $row -PropertyName 'memberIds'
        $memberIds = ConvertTo-PulseOrdinalStringArray -Values @($memberValues | Where-Object { $_ })
        $map[$groupId] = $memberIds

        $rowTruncated = Get-PulseSettingsCatalogValueProperty -Node $row -PropertyName 'truncated'
        $rowComplete = Get-PulseSettingsCatalogValueProperty -Node $row -PropertyName 'complete'
        $rowSampled = Get-PulseSettingsCatalogValueProperty -Node $row -PropertyName 'sampled'
        if (($null -ne $rowTruncated -and [bool] $rowTruncated) -or
            ($null -ne $rowSampled -and [bool] $rowSampled) -or
            ($null -ne $rowComplete -and -not [bool] $rowComplete)) {
            $complete = $false
            $truncatedGroupIds.Add($groupId) | Out-Null
            if ($null -ne $rowSampled -and [bool] $rowSampled) { $sampled = $true }
            if ($null -ne $rowTruncated -and [bool] $rowTruncated) { $sampled = $true }
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
