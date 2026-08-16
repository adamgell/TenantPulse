<#
    Private: per-policy fan-out driver for ONE typed-policy family ('compliance' or
    'deviceConfiguration') - Task 2.3's sibling of Invoke-PulseSettingsCatalogExpansion
    (T2.2), reusing that task's fragment/merge/publish/gap SHAPE (deterministic ordinal
    merge, structured gap reasons, crash-consistent publish via the shared
    Publish-PulseExpansionRows helper) rather than copying its Settings Catalog-specific
    walk mechanics, which do not apply here (see ConvertTo-PulseTypedPolicyRows.ps1's own
    docstring for why these two families need a flat property-map walk, not a
    definitionId-tree one).

    -Policies is the ALREADY-COLLECTED `deviceCompliancePolicies`/`deviceConfigurations`
    dataset (read back from the snapshot store by the caller, Invoke-PulseTypedPolicyExpansionPipeline)
    - unlike T2.2's `configurationPolicies`, this task's own datasets are collected by the
    ordinary check-driven Invoke-PulseCollection flow already; this function's only NEW
    Graph traffic is the per-policy ASSIGNMENT fetch (DeviceCompliancePolicyAssignment.List
    / DeviceConfigurationAssignment.List - both ALREADY RELEASED in GraphKit 0.1.1, so
    unlike T2.2's settingsCatalog rows, assignments here are NOT deferred).

    ASSIGNMENTS ARE MANDATORY, NOT BEST-EFFORT (per this task's spec - "wire real assignment
    fan-out... with Assert-PulseReadOnlyDescriptor at call sites"): a policy whose own
    assignment fetch fails gaps the WHOLE policy (category:AssignmentFetchFailed, zero
    rows) rather than emitting setting rows with assignments:null - a row this task's own
    frozen schema describes as carrying real assignment data must never silently degrade to
    the T2.2 G-gate's "assignments deferred" shape; a failure here is a genuine per-policy
    Graph error, classified and gapped like any other fetch failure, never smoothed over.

    UNMAPPED TYPE (per this task's spec): a policy whose `@odata.type` (EXACT,
    case-insensitive match against -TypeMap's own keys - never suffix/contains, T2.2's hard
    lesson) has no entry in -TypeMap is gapped with the reason
    'collected, not setting-expanded: no property map for <type>' - the exact wording the
    spec names - and contributes zero rows. This is checked BEFORE the assignment fetch (no
    point fetching assignments for a policy this run cannot setting-expand at all) - saves
    a Graph round-trip and keeps the gap category unambiguous (a policy is never double-
    gapped for both UnmappedType and AssignmentFetchFailed).

    SEQUENTIAL BY DESIGN (unlike T2.2's -MaxParallel worker pool): compliance/legacy
    configuration policy counts are typically an order of magnitude smaller than Settings
    Catalog policy counts (T2.0's own spike measured 781 Settings Catalog policies on
    Ivy24; deviceCompliancePolicies/deviceConfigurations are usually tens, not hundreds) -
    a bounded worker pool's added complexity is not worth taking on for this task. Revisit
    if T2.7's live gate measures otherwise.

    STRUCTURED GAP REASONS ONLY (T2.2's P0-3 lesson, carried forward): every -Gap this
    driver records is a small, closed {category[:reason]} token - never a raw caught
    exception's .Message text (which could echo response-body fragments back into a
    persisted manifest). The raw exception only ever reaches Write-Verbose.
#>

function Invoke-PulseTypedPolicyExpansion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Policies,

        [Parameter(Mandatory)]
        [ValidateSet('compliance', 'deviceConfiguration')]
        [string] $PolicyType,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $TypeMap,

        [Parameter(Mandatory)]
        [string] $AssignmentType,

        [Parameter()]
        [string] $Name,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId
    )

    if ([string]::IsNullOrEmpty($Name)) { $Name = $PolicyType }

    function New-PulseTypedGapReason {
        param([string] $Category, [System.Nullable[int]] $StatusCode = $null)
        if ($null -ne $StatusCode) { return "category:$Category;statusCode:$StatusCode" }
        return "category:$Category"
    }

    try {
        Assert-PulseReadOnlyDescriptor -Type $AssignmentType -Operation 'List' -ApiVersion 'v1.0'
    } catch {
        if ($_.Exception.Message -match 'descriptor-version-drift') {
            $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
            return [pscustomobject]@{ Status = 'NotExpanded'; PolicyCount = 0; RowCount = 0; UnresolvedNameCount = 0; RedactedSecretCount = 0; Gaps = @() }
        }
        throw
    }

    $policyList = @($Policies)
    $allRows = [System.Collections.Generic.List[object]]::new()
    $gapEntries = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $policyList) {
        $policyIdRaw = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id'
        $policyId = if ($null -ne $policyIdRaw) { [string] $policyIdRaw } else { $null }

        if ([string]::IsNullOrWhiteSpace($policyId)) {
            $gapEntries.Add([pscustomobject]@{ policyId = ''; reason = (New-PulseTypedGapReason -Category 'EmptyPolicyId') }) | Out-Null
            continue
        }

        $policyNameRaw = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'name'
        $policyName = if ($null -eq $policyNameRaw) {
            $displayNameRaw = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'displayName'
            if ($null -ne $displayNameRaw) { [string] $displayNameRaw } else { $null }
        } else { [string] $policyNameRaw }

        $odataTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName '@odata.type'
        $odataType = if ($null -ne $odataTypeRaw) { [string] $odataTypeRaw } else { $null }

        $typeEntry = $null
        if (-not [string]::IsNullOrEmpty($odataType) -and $TypeMap.Contains($odataType)) {
            $typeEntry = $TypeMap[$odataType]
        }

        if ($null -eq $typeEntry) {
            $typeLabel = if ([string]::IsNullOrEmpty($odataType)) { '(no @odata.type)' } else { $odataType }
            $detail = Protect-PulseReason -Message "collected, not setting-expanded: no property map for $typeLabel" `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            $gapEntries.Add([pscustomobject]@{ policyId = $policyId; reason = $detail }) | Out-Null
            continue
        }

        # ASSIGNMENT FAN-OUT (RELEASED, not deferred - see this file's own docstring). The
        # read-only descriptor is already asserted once, up front, before this loop starts
        # (this driver is sequential-only - see this file's own docstring for why the
        # T2.2 parallel-path's SECOND, per-worker assertion point does not apply here).
        try {
            $rawAssignments = @(Get-GraphObject -Context $Context -Type $AssignmentType -Operation 'List' -Parameters @{ id = $policyId } -ErrorAction Stop)
        } catch {
            Write-Verbose "Invoke-PulseTypedPolicyExpansion: assignment fetch failed for policy '$policyId': $($_.Exception.Message)"
            $failureClass = Get-PulseFailureClass -ErrorRecord $_
            $category = switch ($failureClass) {
                'PermissionDenied' { 'AssignmentPermissionDenied' }
                'AuthFailure' { 'AssignmentAuthFailure' }
                default { 'AssignmentFetchFailed' }
            }
            $gapEntries.Add([pscustomobject]@{ policyId = $policyId; reason = (New-PulseTypedGapReason -Category $category) }) | Out-Null
            continue
        }

        $normalizedAssignments = @()
        foreach ($assignment in $rawAssignments) {
            $target = Get-PulseSettingsCatalogValueProperty -Node $assignment -PropertyName 'target'
            if ($null -eq $target) { continue }
            $targetTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName '@odata.type'
            $targetType = if ($null -ne $targetTypeRaw) { [string] $targetTypeRaw -replace '^#microsoft\.graph\.', '' -replace 'AssignmentTarget$', '' } else { $null }
            $groupIdRaw = Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName 'groupId'
            $filterIdRaw = Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName 'deviceAndAppManagementAssignmentFilterId'
            $filterTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $target -PropertyName 'deviceAndAppManagementAssignmentFilterType'
            $normalizedAssignments += [pscustomobject]@{
                intent     = $null
                targetType = $targetType
                groupId    = if ($null -ne $groupIdRaw) { [string] $groupIdRaw } else { $null }
                filterId   = if ($null -ne $filterIdRaw) { [string] $filterIdRaw } else { $null }
                filterType = if ($null -ne $filterTypeRaw) { [string] $filterTypeRaw } else { $null }
            }
        }

        try {
            $walkResult = ConvertTo-PulseTypedPolicyRows -PolicyId $policyId -PolicyType $PolicyType -PolicyName $policyName `
                -Policy $policy -TypeEntry $typeEntry -Assignments $normalizedAssignments
        } catch {
            Write-Verbose "Invoke-PulseTypedPolicyExpansion: walk failed for policy '$policyId': $($_.Exception.Message)"
            $gapEntries.Add([pscustomobject]@{ policyId = $policyId; reason = (New-PulseTypedGapReason -Category 'WalkFailed') }) | Out-Null
            continue
        }

        foreach ($row in $walkResult.Rows) { $allRows.Add($row) | Out-Null }
    }

    $sortedGaps = @($gapEntries.ToArray())
    $gapComparison = [System.Comparison[object]] {
        param($a, $b)
        $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string] $a.reason, [string] $b.reason)
    }
    [System.Array]::Sort($sortedGaps, $gapComparison)

    return Publish-PulseExpansionRows -Store $Store -Name $Name -Rows $allRows.ToArray() -Gaps $sortedGaps `
        -PolicyCount $policyList.Count -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}
