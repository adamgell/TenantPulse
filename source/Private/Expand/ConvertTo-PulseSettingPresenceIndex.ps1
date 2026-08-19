<#
    Private: pure builder - turn a flat stream of row-schema-v1 rows (from ANY combination
    of the settingsCatalog/compliance/deviceConfiguration expansion families, tagged by
    their own `policyType` field - the same uniform discriminator ConvertTo-PulseTypedPolicyRows'
    own docstring documents) into Part A/T3.4's per-family setting-presence index. No Graph,
    no disk I/O, no manifest writes - mirrors ConvertTo-PulseConflictRecords/
    ConvertTo-PulseSettingRows/ConvertTo-PulseTypedPolicyRows's own "pure walk, caller owns
    every side effect" split; Invoke-PulseSettingPresenceIndexBuild (the driver) owns
    reading the jsonl files and publishing the result.

    PURPOSE (the exact question Part B's checks need answered WITHOUT streaming jsonl):
    "is setting X present in ANY assigned policy of family F, and what is its canonical
    value summary" - this function's output is a compact, hash-verifiable JSON document a
    check can look up by (family, settingDefinitionId) in O(1), never re-reading a raw
    expansion artifact. Each value group also carries the DISTINCT policyIds (and
    assignedPolicyIds) that produced it, sorted ordinally, so a same-policy AND across
    two definitionIds (TP.INT.0017/0018 App Control enforce + active-control) can
    intersect without streaming jsonl. Counts stay; the id arrays are additive.

    ONE PASS, SAME GROUPING DISCIPLINE AS CONFLICTS (Task 2.6's own P0 constraint, carried
    forward unconditionally): -Rows is walked exactly once, folding each row directly into
    family -> defId -> canonicalValue -> policy-count buckets - never a second loop, never a
    pairwise policy comparison of any kind (this index needs none - "is X present" and "what
    values exist" are both single-pass aggregations, unlike conflicts' own assignment-
    overlap classification, which genuinely needs to compare policies pairwise for THAT one
    field).

    ASSIGNED / NOT-ASSIGNED / UNKNOWN, PER POLICY (simpler than conflicts' own four-state
    assignmentOverlap - this index only ever asks about ONE policy's own assignment
    presence, never two policies' relative overlap): a policy's already-normalized
    -Assignments (row.assignments, stamped identically on every row for that policy, T2.2/
    T2.3's own per-policy convention) classifies as:
      - $null            -> Unknown (assignments-deferred, e.g. every settingsCatalog row
                             today - the G-gate's own contract, see
                             Invoke-PulseSettingsCatalogExpansion's own docstring)
      - empty array       -> NotAssigned (real data: zero assignment targets)
      - >= 1 entries       -> Assigned (real data: at least one assignment target exists)
    Classified ONCE per policyId (first-seen wins - every row for the same policy carries
    the identical assignments array by construction, nothing to reconcile on a later row),
    exactly like ConvertTo-PulseConflictRecords' own $assignmentsByPolicy pattern.

    CANONICAL VALUE KEYING AND THE SECRET CONTRACT (byte-for-byte the same discipline
    ConvertTo-PulseConflictRecords already established, reused rather than reinvented): a
    row's typed -value is turned into a grouping key via ConvertTo-PulseCanonicalJson, and a
    row with redacted:true (already carrying value:$null from the T2.2/T2.3 row-level
    secret contract upstream of this function) is grouped under the SAME reserved sentinel
    key every redacted row across every family/defId shares
    ($script:PulseConflictRedactedGroupKey, already defined by ConvertTo-PulseConflictRecords.ps1
    - this file does not redeclare it) - the true value is never read, compared, or emitted
    by this function; it was already gone before this function ever saw the row. A
    Sensitive-flagged or secret-classified setting therefore appears in the index as
    presence-only: its value GROUP carries redacted:true and canonicalValue:$null, but its
    PRESENCE (policyCount/assignedPolicyCount, defId, settingName) is still fully reported -
    "we know this setting exists and is deployed, we do not and cannot know its value" is
    the intended, honest signal for Part B's checks to consume, not a total blackout of the
    setting's existence.

    OUTPUT ORDERING: NOT this function's job for the top-level family/defId lookup
    structure - both are returned as [ordered] hashtables (property insertion order is
    irrelevant; Publish-PulseSettingPresenceIndex's own ConvertTo-PulseCanonicalJson call
    sorts every object's property names ordinally at serialization time, exactly like every
    other canonical artifact in this module - see that serializer's own docstring). The
    TWO places this function DOES sort explicitly: each defId's own `values` ARRAY
    (arrays are never reordered by the canonical serializer, only object keys are) -
    sorted by canonical value text, mirroring ConvertTo-PulseConflictRecords' own
    value-group sort - AND each value group's `policyIds`/`assignedPolicyIds` arrays
    (ordinal), so byte-identical -Rows in any input order always produce a
    byte-identical published artifact.
#>

function ConvertTo-PulseSettingPresenceIndex {
    <#
        .SYNOPSIS
        Builds Part A/T3.4's per-family setting-presence index from a flat stream of
        row-schema-v1 rows.

        .DESCRIPTION
        Streams -Rows exactly once, folding every row into a
        policyType -> settingDefinitionId -> canonicalValue index (never a pairwise
        comparison), then emits one presence entry per (family, settingDefinitionId) pair
        naming how many distinct policies carry it (overall, assigned, and
        assignment-unknown), plus a canonical, redaction-safe value summary. The returned
        object is the exact shape Publish-PulseSettingPresenceIndex serializes.

        .PARAMETER Rows
        The already-parsed row-schema-v1 objects to fold into the presence index - drawn
        from any combination of the settingsCatalog/compliance/deviceConfiguration
        expansion families (each row's own `policyType` field determines which family it
        contributes to); order does not matter, the output is independently deterministic.

        .EXAMPLE
        ConvertTo-PulseSettingPresenceIndex -Rows $allExpansionRows
        Returns the presence index (an [ordered] hashtable keyed by family, each family
        keyed by settingDefinitionId) for every setting observed across the supplied rows.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Rows
    )

    # policyId -> 'Assigned' | 'NotAssigned' | 'Unknown' - classified once, first-seen wins
    # (see this file's own docstring).
    $classificationByPolicy = @{}

    function Get-PulsePresencePolicyClassification {
        param([string] $PolicyId, [object[]] $Assignments, [bool] $AssignmentsWereNull)
        if ($classificationByPolicy.ContainsKey($PolicyId)) { return $classificationByPolicy[$PolicyId] }
        $classification = if ($AssignmentsWereNull) {
            'Unknown'
        } elseif (@($Assignments).Count -eq 0) {
            'NotAssigned'
        } else {
            'Assigned'
        }
        $classificationByPolicy[$PolicyId] = $classification
        return $classification
    }

    # family -> defId -> [ordered]@{ SettingNames:HashSet; PolicyIds:HashSet;
    #   AssignedPolicyIds:HashSet; UnknownAssignmentPolicyIds:HashSet;
    #   Groups: [ordered]@{ groupKey -> { CanonicalValue; Redacted; PolicyIds:HashSet;
    #                                     AssignedPolicyIds:HashSet } } }
    $familyIndex = [ordered]@{}

    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $family = [string] $row.policyType
        if ([string]::IsNullOrEmpty($family)) { continue }
        $defId = [string] $row.settingDefinitionId
        if ([string]::IsNullOrEmpty($defId)) { continue }
        $policyId = [string] $row.policyId
        if ([string]::IsNullOrEmpty($policyId)) { continue }

        $assignmentsWereNull = $null -eq $row.assignments
        $classification = Get-PulsePresencePolicyClassification -PolicyId $policyId -Assignments $row.assignments -AssignmentsWereNull $assignmentsWereNull

        if (-not $familyIndex.Contains($family)) { $familyIndex[$family] = [ordered]@{} }
        $defIndex = $familyIndex[$family]

        if (-not $defIndex.Contains($defId)) {
            $defIndex[$defId] = [pscustomobject]@{
                SettingNames                = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                PolicyIds                   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                AssignedPolicyIds           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                UnknownAssignmentPolicyIds  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                Groups                      = [ordered]@{}
            }
        }
        $entry = $defIndex[$defId]

        if ($row.nameResolved -and -not [string]::IsNullOrEmpty([string] $row.settingName)) {
            [void] $entry.SettingNames.Add([string] $row.settingName)
        }
        [void] $entry.PolicyIds.Add($policyId)
        if ($classification -eq 'Assigned') { [void] $entry.AssignedPolicyIds.Add($policyId) }
        if ($classification -eq 'Unknown') { [void] $entry.UnknownAssignmentPolicyIds.Add($policyId) }

        $redacted = [bool] $row.redacted
        $groupKey = if ($redacted) { $script:PulseConflictRedactedGroupKey } else { ConvertTo-PulseCanonicalJson -InputObject $row.value }

        if (-not $entry.Groups.Contains($groupKey)) {
            $entry.Groups[$groupKey] = [pscustomobject]@{
                CanonicalValue    = $groupKey
                Redacted          = $redacted
                PolicyIds         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                AssignedPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            }
        }
        $group = $entry.Groups[$groupKey]
        [void] $group.PolicyIds.Add($policyId)
        if ($classification -eq 'Assigned') { [void] $group.AssignedPolicyIds.Add($policyId) }
    }

    $resultFamilies = [ordered]@{}
    foreach ($family in $familyIndex.Keys) {
        $defIndex = $familyIndex[$family]
        $resultDefs = [ordered]@{}

        foreach ($defId in $defIndex.Keys) {
            $entry = $defIndex[$defId]

            $sortedNames = @($entry.SettingNames)
            [System.Array]::Sort($sortedNames, [System.StringComparer]::Ordinal)
            $settingName = if ($sortedNames.Count -gt 0) { $sortedNames[0] } else { $null }
            $nameVariants = if ($sortedNames.Count -gt 1) { $sortedNames } else { $null }

            $sortedGroups = @($entry.Groups.Values)
            $groupComparison = [System.Comparison[object]] {
                param($a, $b)
                return [string]::CompareOrdinal([string] $a.CanonicalValue, [string] $b.CanonicalValue)
            }
            [System.Array]::Sort($sortedGroups, $groupComparison)

            $valueRecords = foreach ($group in $sortedGroups) {
                $sortedPolicyIds = @($group.PolicyIds)
                [System.Array]::Sort($sortedPolicyIds, [System.StringComparer]::Ordinal)
                $sortedAssignedPolicyIds = @($group.AssignedPolicyIds)
                [System.Array]::Sort($sortedAssignedPolicyIds, [System.StringComparer]::Ordinal)
                [pscustomobject]@{
                    canonicalValue      = if ($group.Redacted) { $null } else { ConvertFrom-Json -InputObject $group.CanonicalValue -Depth 64 }
                    redacted            = $group.Redacted
                    policyCount         = $group.PolicyIds.Count
                    assignedPolicyCount = $group.AssignedPolicyIds.Count
                    policyIds           = @($sortedPolicyIds)
                    assignedPolicyIds   = @($sortedAssignedPolicyIds)
                }
            }

            $resultDefs[$defId] = [pscustomobject]@{
                settingName                  = $settingName
                nameVariants                 = $nameVariants
                presentPolicyCount           = $entry.PolicyIds.Count
                assignedPolicyCount          = $entry.AssignedPolicyIds.Count
                unknownAssignmentPolicyCount = $entry.UnknownAssignmentPolicyIds.Count
                anyPresent                   = $entry.PolicyIds.Count -gt 0
                anyAssigned                  = $entry.AssignedPolicyIds.Count -gt 0
                anyUnknownAssignment         = $entry.UnknownAssignmentPolicyIds.Count -gt 0
                values                       = @($valueRecords)
            }
        }

        $resultFamilies[$family] = $resultDefs
    }

    return $resultFamilies
}
