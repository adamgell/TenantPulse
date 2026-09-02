<#
    Private: bounded, cycle-safe group membership closure over GraphKit GroupMember.List.

    This is a TenantPulse-owned composite. GraphKit remains one operation at a time:
    GroupMember.List (v1.0, /groups/{id}/members). Optional seed discovery uses
    ConditionalAccessPolicy.List and DirectoryRoleAssignment.List, both public GraphKit
    0.3.0 primitives. There is no generic Walk and no parallel fan-out.

    Caps are always visible on the outcome Detail and on each row. Hitting a depth, group,
    member, or page cap produces Partial (or Failed when no usable row remains) and can
    never be Collected. Checks must fail closed on Sampled/truncated closure.
#>

function Get-PulseGroupClosureManifestInteger {
    param(
        $ManifestEntry,
        [string] $Name,
        [int] $Default
    )

    if ($null -eq $ManifestEntry) { return $Default }
    $value = Get-PulseSettingsCatalogValueProperty -Node $ManifestEntry -PropertyName $Name
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string] $value)) { return $Default }
    try {
        $parsed = [int] $value
        if ($parsed -lt 1) { return $Default }
        return $parsed
    } catch {
        return $Default
    }
}

function Test-PulseGroupClosureMemberIsGroup {
    param($Member)

    $typeName = Get-PulseAssignmentODataType -Node $Member
    if ([string]::IsNullOrWhiteSpace([string] $typeName)) {
        return $null
    }
    if ([string]::Equals($typeName, 'group', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $false
}

function ConvertTo-PulseGroupClosureEnvelope {
    param($Result)

    if ($null -eq $Result) {
        return [pscustomobject][ordered]@{
            Outcome   = 'Succeeded'
            Certainty = 'Known'
            Truncated = $false
            Data      = @()
        }
    }

    $outcome = Get-PulseSettingsCatalogValueProperty -Node $Result -PropertyName 'Outcome'
    $data = Get-PulseSettingsCatalogValueProperty -Node $Result -PropertyName 'Data'
    $truncated = Get-PulseSettingsCatalogValueProperty -Node $Result -PropertyName 'Truncated'
    if (-not [string]::IsNullOrWhiteSpace([string] $outcome) -and $null -ne $data) {
        return [pscustomobject][ordered]@{
            Outcome   = [string] $outcome
            Certainty = [string] (Get-PulseSettingsCatalogValueProperty -Node $Result -PropertyName 'Certainty')
            Truncated = [bool] $truncated
            Data      = @($data)
        }
    }

    return [pscustomobject][ordered]@{
        Outcome   = 'Succeeded'
        Certainty = 'Known'
        Truncated = $false
        Data      = @($Result)
    }
}

function Invoke-PulseGroupClosurePlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [pscustomobject] $ManifestEntry,

        [Parameter(Mandatory)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $TenantPseudonym,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState = $null
    )

    if ($null -eq $NetworkAbortState) {
        $NetworkAbortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
    }

    $null = $ProfileId
    $null = $TenantPseudonym

    $maxDepth = Get-PulseGroupClosureManifestInteger -ManifestEntry $ManifestEntry -Name 'MaxDepth' -Default 8
    $maxGroups = Get-PulseGroupClosureManifestInteger -ManifestEntry $ManifestEntry -Name 'MaxGroups' -Default 256
    $maxMembersPerGroup = Get-PulseGroupClosureManifestInteger -ManifestEntry $ManifestEntry -Name 'MaxMembersPerGroup' -Default 2000
    $maxTotalMembers = Get-PulseGroupClosureManifestInteger -ManifestEntry $ManifestEntry -Name 'MaxTotalMembers' -Default 20000
    $memberPageCap = Get-PulseGroupClosureManifestInteger -ManifestEntry $ManifestEntry -Name 'MemberPageCap' -Default 20

    $caps = [ordered]@{
        MaxDepth           = $maxDepth
        MaxGroups          = $maxGroups
        MaxMembersPerGroup = $maxMembersPerGroup
        MaxTotalMembers    = $maxTotalMembers
        MemberPageCap      = $memberPageCap
    }

    $descriptorSpecs = @(
        @{ Type = 'GroupMember'; Operation = 'List'; ApiVersion = 'v1.0' }
    )
    $discoverFromCa = $true
    $discoverFromRoles = $true
    $seedGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $manifestSeeds = Get-PulseSettingsCatalogValueProperty -Node $ManifestEntry -PropertyName 'SeedGroupIds'
    if ($null -ne $manifestSeeds) {
        foreach ($seed in @($manifestSeeds)) {
            if (-not [string]::IsNullOrWhiteSpace([string] $seed)) {
                [void] $seedGroupIds.Add([string] $seed)
            }
        }
        $discoverFromCa = $false
        $discoverFromRoles = $false
    }

    if ($discoverFromCa) {
        $descriptorSpecs += @{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' }
    }
    if ($discoverFromRoles) {
        $descriptorSpecs += @{ Type = 'DirectoryRoleAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }
    }

    foreach ($spec in $descriptorSpecs) {
        Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation -ApiVersion $spec.ApiVersion
    }

    $operations = [System.Collections.Generic.List[string]]::new()
    $operations.Add('GroupMember.List') | Out-Null
    $apiVersion = 'v1.0'

    function New-GroupClosureFailureOutcome {
        param(
            [Parameter(Mandatory)] [string] $Operation,
            [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
        )

        $failure = Resolve-PulseGraphFailure -ErrorRecord $ErrorRecord
        if ($failure.AbortCollection) {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'auth-failure: collection aborted'
        }

        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
            -Detail @{ operation = $Operation; caps = $caps } -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations @($operations)
    }

    if ($discoverFromCa) {
        $operations.Add('ConditionalAccessPolicy.List') | Out-Null
        try {
            $policies = @(Get-GraphObject -Context $Context -Type 'ConditionalAccessPolicy' -Operation 'List' -ErrorAction Stop)
            foreach ($policy in $policies) {
                $conditions = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'conditions'
                $users = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'users'
                foreach ($propertyName in @('includeGroups', 'excludeGroups')) {
                    foreach ($groupId in @(Get-PulseSettingsCatalogValueProperty -Node $users -PropertyName $propertyName)) {
                        if (-not [string]::IsNullOrWhiteSpace([string] $groupId)) {
                            [void] $seedGroupIds.Add([string] $groupId)
                        }
                    }
                }
            }
        } catch {
            return New-GroupClosureFailureOutcome -Operation 'ConditionalAccessPolicy.List' -ErrorRecord $_
        }
    }

    $rolePrincipalIds = [System.Collections.Generic.List[string]]::new()
    if ($discoverFromRoles) {
        $operations.Add('DirectoryRoleAssignment.List') | Out-Null
        try {
            $assignments = @(Get-GraphObject -Context $Context -Type 'DirectoryRoleAssignment' -Operation 'List' -ErrorAction Stop)
            $seenPrincipals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($assignment in $assignments) {
                $principalId = [string] (Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'principalId')
                if ([string]::IsNullOrWhiteSpace($principalId)) { continue }
                if ($seenPrincipals.Add($principalId)) {
                    $rolePrincipalIds.Add($principalId) | Out-Null
                }
            }
        } catch {
            return New-GroupClosureFailureOutcome -Operation 'DirectoryRoleAssignment.List' -ErrorRecord $_
        }
    }

    $gaps = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $depthByGroup = @{}
    $parentByGroup = @{}
    $leafMembersByGroup = @{}
    $nestedGroupsByGroup = @{}
    $truncatedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $cycleGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unknownTypeGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $totalLeafMembers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sampled = $false
    $groupCapHit = $false
    $totalMemberCapHit = $false
    $walkState = @{
        Sampled           = $false
        GroupCapHit       = $false
        TotalMemberCapHit = $false
    }

    function Enqueue-PulseClosureGroup {
        param([string] $GroupId, [int] $Depth, [string] $ParentId)

        if ([string]::IsNullOrWhiteSpace($GroupId)) { return }
        if ($visited.Contains($GroupId)) {
            if (-not [string]::IsNullOrWhiteSpace($ParentId)) {
                [void] $cycleGroups.Add($ParentId)
                [void] $cycleGroups.Add($GroupId)
            }
            return
        }
        if ($walkState.GroupCapHit -or $visited.Count -ge $maxGroups) {
            $walkState.GroupCapHit = $true
            $walkState.Sampled = $true
            return
        }
        if ($Depth -gt $maxDepth) {
            $walkState.Sampled = $true
            if (-not [string]::IsNullOrWhiteSpace($ParentId)) {
                [void] $truncatedGroups.Add($ParentId)
            }
            $gaps.Add((New-PulseCollectionGap -Scope "group:$GroupId" -FailureClass 'Indeterminate' `
                    -ReasonCode 'depth-cap' -Detail @{ groupId = $GroupId; depth = $Depth; caps = [hashtable] $caps } `
                    -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
            return
        }

        [void] $visited.Add($GroupId)
        $depthByGroup[$GroupId] = $Depth
        $parentByGroup[$GroupId] = $ParentId
        $leafMembersByGroup[$GroupId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $nestedGroupsByGroup[$GroupId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $queue.Enqueue($GroupId)
    }

    $sortedSeeds = ConvertTo-PulseOrdinalStringArray -Values $seedGroupIds
    foreach ($seed in $sortedSeeds) {
        Enqueue-PulseClosureGroup -GroupId $seed -Depth 1 -ParentId $null
    }

    foreach ($principalId in $rolePrincipalIds) {
        if ($visited.Contains($principalId)) { continue }
        try {
            $probe = Get-GraphObject -Context $Context -Type 'GroupMember' -Operation 'List' `
                -Parameters @{ id = $principalId } -PassThruResult -PageCap $memberPageCap -ErrorAction Stop
            $envelope = ConvertTo-PulseGroupClosureEnvelope -Result $probe
            if ([string] $envelope.Outcome -ne 'Succeeded') {
                continue
            }
            Enqueue-PulseClosureGroup -GroupId $principalId -Depth 1 -ParentId $null
            # Re-process this group's members below via the queue. Stash the envelope so the
            # walk does not call GroupMember.List twice for a role-seeded group.
            $depthByGroup["__probe__$principalId"] = $envelope
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            if ($failure.AbortCollection) {
                $NetworkAbortState.AuthenticationAborted = $true
                $NetworkAbortState.Reason = 'auth-failure: collection aborted'
                return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
                    -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
                    -Detail @{ operation = 'GroupMember.List'; caps = $caps } -Provider 'GraphKit' `
                    -ApiVersion $apiVersion -Operations @($operations)
            }
            # 400/404: this principal is not a group. Direct assignments stay direct.
        }
    }

    $probeCache = @{}
    foreach ($key in @($depthByGroup.Keys)) {
        if ($key.StartsWith('__probe__', [System.StringComparison]::Ordinal)) {
            $probeCache[$key.Substring('__probe__'.Length)] = $depthByGroup[$key]
            $depthByGroup.Remove($key)
        }
    }

    while ($queue.Count -gt 0) {
        $groupId = [string] $queue.Dequeue()
        $depth = [int] $depthByGroup[$groupId]
        $envelope = $null
        if ($probeCache.ContainsKey($groupId)) {
            $envelope = $probeCache[$groupId]
        } else {
            try {
                $raw = Get-GraphObject -Context $Context -Type 'GroupMember' -Operation 'List' `
                    -Parameters @{ id = $groupId } -PassThruResult -PageCap $memberPageCap -ErrorAction Stop
                $envelope = ConvertTo-PulseGroupClosureEnvelope -Result $raw
            } catch {
                $failure = Resolve-PulseGraphFailure -ErrorRecord $_
                if ($failure.AbortCollection) {
                    $NetworkAbortState.AuthenticationAborted = $true
                    $NetworkAbortState.Reason = 'auth-failure: collection aborted'
                    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
                        -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
                        -Detail @{ operation = 'GroupMember.List'; groupId = $groupId; caps = $caps } `
                        -Provider 'GraphKit' -ApiVersion $apiVersion -Operations @($operations)
                }
                [void] $truncatedGroups.Add($groupId)
                $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass $failure.FailureClass `
                        -ReasonCode $failure.ReasonCode -Detail @{ groupId = $groupId } `
                        -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
                continue
            }
        }

        if ([string] $envelope.Outcome -ne 'Succeeded') {
            [void] $truncatedGroups.Add($groupId)
            $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'ProviderFailed' `
                    -ReasonCode 'provider-failed' -Detail @{ groupId = $groupId; outcome = [string] $envelope.Outcome } `
                    -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
            continue
        }

        if ([bool] $envelope.Truncated -or [string]::Equals([string] $envelope.Certainty, 'Indeterminate', [System.StringComparison]::OrdinalIgnoreCase)) {
            $walkState.Sampled = $true
            [void] $truncatedGroups.Add($groupId)
            $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'Indeterminate' `
                    -ReasonCode 'page-cap' -Detail @{ groupId = $groupId; caps = [hashtable] $caps } `
                    -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
        }

        $memberCountForGroup = 0
        foreach ($member in @($envelope.Data)) {
            if ($null -eq $member) { continue }
            $memberId = [string] (Get-PulseSettingsCatalogValueProperty -Node $member -PropertyName 'id')
            if ([string]::IsNullOrWhiteSpace($memberId)) { continue }

            $isGroup = Test-PulseGroupClosureMemberIsGroup -Member $member
            if ($null -eq $isGroup) {
                [void] $unknownTypeGroups.Add($groupId)
                [void] $truncatedGroups.Add($groupId)
                $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'InvalidProviderData' `
                        -ReasonCode 'unknown-member-type' -Detail @{ groupId = $groupId; memberId = $memberId } `
                        -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
                continue
            }

            if ($isGroup) {
                [void] $nestedGroupsByGroup[$groupId].Add($memberId)
                Enqueue-PulseClosureGroup -GroupId $memberId -Depth ($depth + 1) -ParentId $groupId
                continue
            }

            $memberCountForGroup++
            if ($memberCountForGroup -gt $maxMembersPerGroup) {
                $walkState.Sampled = $true
                [void] $truncatedGroups.Add($groupId)
                $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'Indeterminate' `
                        -ReasonCode 'member-cap' -Detail @{ groupId = $groupId; caps = [hashtable] $caps } `
                        -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
                break
            }
            if ($totalLeafMembers.Count -ge $maxTotalMembers -and -not $totalLeafMembers.Contains($memberId)) {
                $walkState.TotalMemberCapHit = $true
                $walkState.Sampled = $true
                [void] $truncatedGroups.Add($groupId)
                $gaps.Add((New-PulseCollectionGap -Scope "group:$groupId" -FailureClass 'Indeterminate' `
                        -ReasonCode 'total-member-cap' -Detail @{ groupId = $groupId; caps = [hashtable] $caps } `
                        -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
                break
            }

            [void] $leafMembersByGroup[$groupId].Add($memberId)
            [void] $totalLeafMembers.Add($memberId)
        }
    }

    if ($walkState.GroupCapHit) {
        $gaps.Add((New-PulseCollectionGap -Scope 'closure' -FailureClass 'Indeterminate' `
                -ReasonCode 'group-cap' -Detail @{ caps = [hashtable] $caps; groupsVisited = $visited.Count } `
                -Operation 'GroupMember.List' -ApiVersion 'v1.0')) | Out-Null
    }

    # Fold nested-group leaves into each ancestor so a seed group's memberIds are the
    # transitive closure, not only direct members. Cycles are already closed by visited.
    $orderedGroupIds = ConvertTo-PulseOrdinalStringArray -Values $visited
    $changed = $true
    $foldGuard = 0
    while ($changed -and $foldGuard -le $maxGroups) {
        $changed = $false
        $foldGuard++
        foreach ($groupId in $orderedGroupIds) {
            foreach ($nestedId in @($nestedGroupsByGroup[$groupId])) {
                if (-not $leafMembersByGroup.ContainsKey($nestedId)) { continue }
                foreach ($leafId in @($leafMembersByGroup[$nestedId])) {
                    if ($leafMembersByGroup[$groupId].Add($leafId)) {
                        $changed = $true
                        [void] $totalLeafMembers.Add($leafId)
                    }
                }
                if ($truncatedGroups.Contains($nestedId)) {
                    [void] $truncatedGroups.Add($groupId)
                }
            }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($groupId in $orderedGroupIds) {
        $memberIds = ConvertTo-PulseOrdinalStringArray -Values $leafMembersByGroup[$groupId]
        $nestedIds = ConvertTo-PulseOrdinalStringArray -Values $nestedGroupsByGroup[$groupId]
        $isTruncated = $truncatedGroups.Contains($groupId)
        $cycleClosed = $cycleGroups.Contains($groupId)
        $rows.Add([pscustomobject][ordered]@{
                groupId        = $groupId
                memberIds      = $memberIds
                nestedGroupIds = $nestedIds
                depth          = [int] $depthByGroup[$groupId]
                memberCount    = $memberIds.Count
                truncated      = $isTruncated
                complete       = -not $isTruncated
                cycleClosed    = $cycleClosed
                sampled        = $isTruncated -or $walkState.Sampled
                caps           = [hashtable] $caps
            }) | Out-Null
    }

    $rowArray = $rows.ToArray()
    $gapArray = $gaps.ToArray()
    $detail = [hashtable] @{
        caps           = [hashtable] $caps
        sampled        = [bool] $walkState.Sampled
        groupsVisited  = $visited.Count
        uniqueMembers  = $totalLeafMembers.Count
        truncatedCount = $truncatedGroups.Count
        cycleCount     = $cycleGroups.Count
    }

    if ($gapArray.Count -eq 0 -and -not $walkState.Sampled) {
        $reasonCode = if ($rowArray.Count -eq 0) { 'no-seed-groups' } else { 'collected' }
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rowArray -Gaps @() `
            -ReasonCode $reasonCode -Detail $detail -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations @($operations)
    }

    if ($rowArray.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rowArray -Gaps $gapArray `
            -ReasonCode 'sampled-or-incomplete' -Detail $detail -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations @($operations)
    }

    $topFailureClass = [string] $gapArray[0].FailureClass
    $topReasonCode = [string] $gapArray[0].ReasonCode
    foreach ($gap in $gapArray) {
        if ($gap.FailureClass -eq 'AuthenticationFailed') {
            $topFailureClass = 'AuthenticationFailed'
            $topReasonCode = [string] $gap.ReasonCode
            break
        }
    }
    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass $topFailureClass -ReasonCode $topReasonCode -Detail $detail `
        -Provider 'GraphKit' -ApiVersion $apiVersion -Operations @($operations)
}
