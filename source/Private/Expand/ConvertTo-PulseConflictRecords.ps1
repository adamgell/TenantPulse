<#
    Private: pure builder - turn a flat stream of row-schema-v1 rows (from ANY combination
    of the settingsCatalog/compliance/deviceConfiguration expansion families) into Task
    2.6's conflict records. No Graph, no disk I/O, no manifest writes - mirrors
    ConvertTo-PulseSettingRows/ConvertTo-PulseTypedPolicyRows's own "pure walk, caller owns
    every side effect" split; Invoke-PulseConflictDetection (the driver) owns reading the
    jsonl files and publishing the result.

    ONE PASS, NO PAIRWISE POLICY COMPARISON (Task 2.6 P0 constraint): -Rows is walked
    exactly once, in a single foreach loop, folding each row directly into
    defId -> canonicalValue -> [{policyId; policyName}] - never a second loop comparing one
    policy's rows against another's. The only place this function ever compares two
    POLICIES against each other is Get-PulseConflictAssignmentOverlap below, and that
    comparison is bounded to the handful of policies ALREADY discovered to disagree on one
    setting (a conflict's own policy count, not the corpus size) - see that function's own
    docstring for why this is not the corpus-wide pairwise scan the constraint forbids.

    CANONICAL VALUE KEYING: a row's typed -value is turned into a grouping key via
    ConvertTo-PulseCanonicalJson (ordinal property order, deterministic - the same
    serializer every dataset hash depends on), so two rows carrying structurally identical
    values (regardless of hashtable/array construction order) fall into the SAME group.

    REDACTION NEVER UN-REDACTS (SECRET CONTRACT, Task 2.6's own clause): a row with
    redacted:true carries value:null on the row itself already, but this function does not
    even key redacted rows on that shared null - every redacted row across every policy and
    every defId is grouped under ONE fixed, reserved sentinel key
    ($script:PulseConflictRedactedGroupKey, an embedded NUL character that can never appear
    in real ConvertTo-PulseCanonicalJson output) so a conflict can be detected (a defId
    where one policy redacts a secret and another sets a plain value, or where two policies
    redact independently different secrets) without EVER comparing, hashing, or otherwise
    depending on the underlying secret value - the true value never reaches this function
    at all (the row itself already nulled it out upstream). The emitted conflict record
    carries redacted:true and a null canonicalValue for that group, never the sentinel.

    ASSIGNMENTS-DEFERRED (G-gate core slice, Task 2.6's own clause): a settingsCatalog row
    carries assignments:null unconditionally (T2.2's own deferred-assignments contract).
    Any conflict that includes at least one row whose assignments are $null cannot have its
    real-world overlap determined at all - that conflict's assignmentOverlap is 'unknown'
    with the deferred reason, unconditionally, without even attempting the target-set logic
    below (which requires every contributing policy's assignments to be real data).

    A defId only becomes a CONFLICT when it has >= 2 distinct canonical-value groups AND
    those groups collectively name >= 2 DISTINCT policy ids - a single policy that happens
    to emit the same definitionId twice with two different values (a Settings Catalog
    collection referencing the same child definitionId under two different parents, for
    example) disagrees only with itself, not with another policy, and is not a conflict.

    OUTPUT ORDERING (canonical, ordinal by construction): the returned array is sorted by
    settingDefinitionId ([string]::CompareOrdinal); within each conflict, value groups are
    sorted by their own canonical-value text (redacted groups sort using the reserved
    sentinel text itself, which is fine - it is never emitted, only used as a stable,
    deterministic sort key), and each group's policies are sorted by policyId. Byte-identical
    -Rows in any input order always produce a byte-identical conflicts.json.
#>

# Reserved grouping key for every redacted row, regardless of defId/policy - an embedded
# NUL character makes this string structurally impossible for ConvertTo-PulseCanonicalJson
# to ever produce for a real value (control characters are always escaped, never emitted
# raw, inside a canonical JSON string; a bare top-level NUL is not valid JSON at all) - see
# this file's own SECRET CONTRACT docstring section.
$script:PulseConflictRedactedGroupKey = "`0REDACTED-SETTING-VALUE`0"

function Get-PulseConflictAssignmentTargetProfile {
    <#
        Reduces one policy's already-normalized -Assignments array (schema v1's own
        {intent; targetType; groupId; filterId; filterType} shape) down to exactly the
        facts the overlap comparison below needs: whether ANY assignment carries an
        All-target or a filter or an exclusion-group/unrecognized target (each of which
        makes 'proven'/'none' unprovable per the plan's own four-state rule), plus the set
        of concrete inclusion-group ids (targetType 'group' only) available for an
        identical/disjoint-set comparison when none of those uncertain shapes are present.
    #>
    param([object[]] $Assignments)

    # Named $targetProfile, never $profile (PSScriptAnalyzer PSAvoidAssignmentToAutomaticVariable
    # - $profile is a PowerShell automatic variable naming the current user's profile
    # script path; shadowing it inside this scope is a real, avoidable footgun).
    $targetProfile = [pscustomobject]@{
        HasAllTarget     = $false
        HasFilter        = $false
        HasUncertain     = $false
        ConcreteGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    }

    foreach ($assignment in @($Assignments)) {
        if ($null -eq $assignment) { continue }
        $targetType = [string] $assignment.targetType
        if (-not [string]::IsNullOrEmpty([string] $assignment.filterId)) { $targetProfile.HasFilter = $true }

        if ($targetType -like 'all*') {
            $targetProfile.HasAllTarget = $true
        } elseif ($targetType -eq 'group') {
            if (-not [string]::IsNullOrEmpty([string] $assignment.groupId)) {
                [void] $targetProfile.ConcreteGroupIds.Add([string] $assignment.groupId)
            } else {
                # A 'group' target with no groupId is a malformed/unrecognized shape - fail
                # closed exactly like an exclusionGroup/unknown target rather than silently
                # contributing nothing to either bucket.
                $targetProfile.HasUncertain = $true
            }
        } else {
            # exclusionGroup, configurationManagerCollection, or anything not yet named -
            # membership effect cannot be proven OR ruled out from this shape alone. Fails
            # closed into the same 'possible' bucket a filter or All-target would.
            $targetProfile.HasUncertain = $true
        }
    }

    return $targetProfile
}

function Get-PulseConflictPairOverlap {
    <#
        Pairwise target-set overlap for exactly two policies' assignment profiles, per the
        plan's own four-state rule (never called with 'unknown' inputs - the caller only
        reaches this once every contributing policy's assignments are known to be real,
        non-null data; see this file's own ASSIGNMENTS-DEFERRED docstring section).
    #>
    param($ProfileA, $ProfileB)

    if ($ProfileA.HasAllTarget -or $ProfileB.HasAllTarget -or `
            $ProfileA.HasFilter -or $ProfileB.HasFilter -or `
            $ProfileA.HasUncertain -or $ProfileB.HasUncertain) {
        return 'possible'
    }

    if ($ProfileA.ConcreteGroupIds.Count -eq 0 -or $ProfileB.ConcreteGroupIds.Count -eq 0) {
        # Assigned nowhere (or nowhere concrete) on at least one side - complete data,
        # demonstrably disjoint.
        return 'none'
    }

    $setA = $ProfileA.ConcreteGroupIds
    $setB = $ProfileB.ConcreteGroupIds

    $intersects = $false
    foreach ($id in $setA) { if ($setB.Contains($id)) { $intersects = $true; break } }

    if (-not $intersects) { return 'none' }

    if ($setA.Count -eq $setB.Count) {
        $identical = $true
        foreach ($id in $setA) { if (-not $setB.Contains($id)) { $identical = $false; break } }
        if ($identical) { return 'proven' }
    }

    return 'possible'
}

function Get-PulseConflictAssignmentOverlap {
    <#
        Aggregates assignmentOverlap for ONE conflict (one defId's worth of value groups)
        from the already-collected per-policy assignments -AssignmentsByPolicy holds. Only
        compares policies that disagree on the setting's value (cross-group pairs) - two
        policies that both set the SAME value are not in tension with each other and are
        never compared. This is bounded by the conflict's own (typically tiny) policy
        count, not the corpus - see this file's own top-level docstring for why this does
        not violate the "no pairwise policy comparison" constraint.

        Precedence when multiple cross-group pairs disagree with each other: 'proven' (a
        confirmed real clash exists) beats 'possible' (cannot rule a clash out) beats
        'none' (every disagreeing pair is demonstrably disjoint) - reporting the strongest
        available positive signal is the more actionable/conservative choice for an
        operator deciding whether a conflict is worth investigating.
    #>
    param(
        [object[]] $ValueGroups,
        [System.Collections.IDictionary] $AssignmentsByPolicy
    )

    $anyDeferred = $false
    foreach ($group in $ValueGroups) {
        foreach ($policy in $group.Policies) {
            $assignments = $AssignmentsByPolicy[$policy.policyId]
            if ($null -eq $assignments) { $anyDeferred = $true }
        }
    }
    if ($anyDeferred) {
        return [pscustomobject]@{
            State  = 'unknown'
            Reason = 'assignments-deferred: awaiting GraphKit release'
        }
    }

    $profilesByPolicy = @{}
    foreach ($group in $ValueGroups) {
        foreach ($policy in $group.Policies) {
            if (-not $profilesByPolicy.ContainsKey($policy.policyId)) {
                $profilesByPolicy[$policy.policyId] = Get-PulseConflictAssignmentTargetProfile -Assignments $AssignmentsByPolicy[$policy.policyId]
            }
        }
    }

    $worst = 'none'
    for ($i = 0; $i -lt $ValueGroups.Count; $i++) {
        for ($j = $i + 1; $j -lt $ValueGroups.Count; $j++) {
            foreach ($policyA in $ValueGroups[$i].Policies) {
                foreach ($policyB in $ValueGroups[$j].Policies) {
                    $pairState = Get-PulseConflictPairOverlap -ProfileA $profilesByPolicy[$policyA.policyId] -ProfileB $profilesByPolicy[$policyB.policyId]
                    if ($pairState -eq 'proven') { return [pscustomobject]@{ State = 'proven'; Reason = $null } }
                    if ($pairState -eq 'possible') { $worst = 'possible' }
                }
            }
        }
    }

    return [pscustomobject]@{ State = $worst; Reason = $null }
}

function ConvertTo-PulseConflictRecords {
    <#
        .SYNOPSIS
        Builds Task 2.6's conflict records from a flat stream of row-schema-v1 rows.

        .DESCRIPTION
        Streams -Rows exactly once, folding every row into a defId -> canonicalValue
        index (never a pairwise policy-to-policy scan), then emits one conflict record per
        settingDefinitionId that carries two or more distinct canonical values across two
        or more distinct policies, each with a four-state assignmentOverlap classification
        computed from the already-normalized per-policy assignment data the rows carry. A
        redacted row's true value is never read, compared, or emitted - every redacted row
        groups under one reserved sentinel key regardless of its real secret content. The
        returned array is canonically, ordinally sorted (settingDefinitionId, then
        canonical value text, then policyId) so identical -Rows in any order always
        produce an identical result.

        .PARAMETER Rows
        The already-parsed row-schema-v1 objects to fold into the conflict index - drawn
        from any combination of the settingsCatalog/compliance/deviceConfiguration
        expansion families; order does not matter, the output is sorted independently.

        .EXAMPLE
        ConvertTo-PulseConflictRecords -Rows $allExpansionRows
        Returns the sorted array of conflict records for every setting defined
        differently by two or more policies across the supplied rows.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Rows
    )

    # defId -> [ordered]@{ groupKey -> pscustomobject{ CanonicalValue; Redacted; PolicyIds:HashSet; Policies:List } }
    $defIndex = [ordered]@{}
    $settingNameByDef = @{}
    # Assignments normalized ONCE per policy, referenced (not copied) into every
    # compactRecord that names the same policyId - see this file's own top-level
    # docstring. First-seen wins; every row for the same policy carries the identical
    # assignments array by construction (T2.2/T2.3's own per-policy stamping), so there is
    # nothing to reconcile on a later row.
    $assignmentsByPolicy = @{}

    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $defId = [string] $row.settingDefinitionId
        if ([string]::IsNullOrEmpty($defId)) { continue }
        $policyId = [string] $row.policyId
        if ([string]::IsNullOrEmpty($policyId)) { continue }

        if (-not $assignmentsByPolicy.ContainsKey($policyId)) {
            $assignmentsByPolicy[$policyId] = $row.assignments
        }

        if (-not $settingNameByDef.ContainsKey($defId) -and $row.nameResolved -and -not [string]::IsNullOrEmpty([string] $row.settingName)) {
            $settingNameByDef[$defId] = [string] $row.settingName
        }

        $redacted = [bool] $row.redacted
        $groupKey = if ($redacted) { $script:PulseConflictRedactedGroupKey } else { ConvertTo-PulseCanonicalJson -InputObject $row.value }

        if (-not $defIndex.Contains($defId)) { $defIndex[$defId] = [ordered]@{} }
        $groups = $defIndex[$defId]

        if (-not $groups.Contains($groupKey)) {
            $groups[$groupKey] = [pscustomobject]@{
                CanonicalValue = $groupKey
                Redacted       = $redacted
                PolicyIds      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                Policies       = [System.Collections.Generic.List[object]]::new()
            }
        }

        $group = $groups[$groupKey]
        if ($group.PolicyIds.Add($policyId)) {
            $policyName = if ($null -ne $row.policyName) { [string] $row.policyName } else { $null }
            $group.Policies.Add([pscustomobject]@{ policyId = $policyId; policyName = $policyName }) | Out-Null
        }
    }

    $conflicts = [System.Collections.Generic.List[object]]::new()

    foreach ($defId in $defIndex.Keys) {
        $groups = @($defIndex[$defId].Values)
        if ($groups.Count -lt 2) { continue }

        $distinctPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($group in $groups) { foreach ($id in $group.PolicyIds) { [void] $distinctPolicyIds.Add($id) } }
        if ($distinctPolicyIds.Count -lt 2) { continue }

        $sortedGroups = @($groups)
        $groupComparison = [System.Comparison[object]] {
            param($a, $b)
            return [string]::CompareOrdinal([string] $a.CanonicalValue, [string] $b.CanonicalValue)
        }
        [System.Array]::Sort($sortedGroups, $groupComparison)

        foreach ($group in $sortedGroups) {
            $sortedPolicies = @($group.Policies)
            $policyComparison = [System.Comparison[object]] {
                param($a, $b)
                return [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
            }
            [System.Array]::Sort($sortedPolicies, $policyComparison)
            $group.Policies = $sortedPolicies
        }

        $overlap = Get-PulseConflictAssignmentOverlap -ValueGroups $sortedGroups -AssignmentsByPolicy $assignmentsByPolicy

        $valueRecords = foreach ($group in $sortedGroups) {
            [pscustomobject]@{
                canonicalValue = if ($group.Redacted) { $null } else { ConvertFrom-Json -InputObject $group.CanonicalValue -Depth 64 }
                redacted       = $group.Redacted
                policies       = @($group.Policies)
            }
        }

        $settingName = if ($settingNameByDef.ContainsKey($defId)) { $settingNameByDef[$defId] } else { $null }

        $conflicts.Add([pscustomobject]@{
                settingDefinitionId     = $defId
                settingName             = $settingName
                assignmentOverlap       = $overlap.State
                assignmentOverlapReason = $overlap.Reason
                values                  = @($valueRecords)
            }) | Out-Null
    }

    $sortedConflicts = @($conflicts.ToArray())
    $conflictComparison = [System.Comparison[object]] {
        param($a, $b)
        return [string]::CompareOrdinal([string] $a.settingDefinitionId, [string] $b.settingDefinitionId)
    }
    [System.Array]::Sort($sortedConflicts, $conflictComparison)

    # Comma-wrap: a bare `return $sortedConflicts` unrolls to $null at the call site when
    # the array is empty (PowerShell's own single-object/empty-array pipeline-unrolling
    # trap, the same one Read-PulseDataset/Get-PulseReferenceData's own `return , [object[]]`
    # convention guards against) - zero conflicts is a VALID, common outcome (T2.7's own
    # "zero conflicts is valid" rule) and must come back as an empty array, never $null.
    return , [object[]] @($sortedConflicts)
}
