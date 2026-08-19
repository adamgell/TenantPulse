<#
    Private: shared helper - classify ONE settingDefinitionId's presence/value state
    against Part A/T3.4's settingPresenceIndex artifact
    ($Context.ArtifactReader.GetSettingPresenceIndex()), for every Part B check that asks
    "is setting X present AND at a required value in an ASSIGNED policy of family F"
    (TP.INT.0016/0031/0032). TP.INT.0017/0018 use the sibling
    Get-PulseSettingPresenceMatchingPolicies below - they need the per-value
    policyIds the presence index now keeps, not these counts, because their bar
    is a same-policy AND. Centralizes the honesty-state handling every one of

      - REDACTED VALUES ARE NEVER EVALUATED AGAINST THE PREDICATE (this function's own
        fail-closed rule): a value GROUP whose `redacted` flag is true is never passed to
        -IsSatisfyingValue - its `canonicalValue` is already `$null` by construction (Part
        A's own redaction discipline), so there is nothing meaningful to compare anyway.
        Its `assignedPolicyCount` is still read (that much IS knowable and safe - presence
        and assignment count are not secret) and surfaced separately as
        RedactedAssignedPolicyCount, so a caller can distinguish "this setting is
        confirmed present in an assigned policy but its value cannot be read" from "this
        setting genuinely is not correctly configured anywhere assigned" - the caller's
        own job is to degrade the FIRST case to Warn, never Pass, per the standing
        redaction-honesty rule (see each check's own docstring).
      - UNKNOWN ASSIGNMENT NEVER COUNTS AS ASSIGNED: `anyUnknownAssignment` (from the
        index entry itself) is surfaced as-is - a caller must never fold it into
        "assigned" when deciding Pass/Fail. It exists purely for disclosure ("N polic(ies)
        with this setting have a deferred/unknown assignment status - dynamic-group/filter
        membership could not be resolved, so a satisfying value on one of them could not
        be ruled out either way").
      - PRESENT-BUT-NEVER-ASSIGNED is tracked separately from PRESENT-AND-ASSIGNED, so a
        caller can answer "the correct value exists somewhere, but never on a policy this
        module could confirm is actually deployed to any device" - a real, disclosable gap
        distinct from "the setting is not configured anywhere at all".

    ARTIFACT-UNAVAILABLE AND ARTIFACT-GAP HANDLING ARE THE CALLER'S JOB, NOT THIS
    FUNCTION'S: this helper assumes -Artifact.Status already checked 'Available' by the
    caller (mirrors Test-PulseConflictingPolicySettings' own NotApplicable-on-unavailable
    pattern) and does not itself inspect -Artifact.Gaps (the "PARTIAL SCAN" disclosure
    prefix TP.INT.0006 already established is a whole-finding-level concern, assembled
    once by the caller from -Artifact.Gaps directly, not per-criterion here).
#>

function Resolve-PulseSettingPresenceCriterion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Artifact,

        [Parameter(Mandatory)]
        [string] $Family,

        [Parameter(Mandatory)]
        [string] $DefinitionId,

        [Parameter(Mandatory)]
        [scriptblock] $IsSatisfyingValue
    )

    $result = [pscustomobject]@{
        Present                      = $false
        Entry                        = $null
        SatisfiedAssignedPolicyCount = 0
        SatisfiedUnassignedPolicyCount = 0
        RedactedAssignedPolicyCount  = 0
        RedactedUnassignedPolicyCount = 0
        AnyUnknownAssignment         = $false
        UnknownAssignmentPolicyCount = 0
    }

    $familiesObj = $Artifact.Families
    if ($null -eq $familiesObj -or -not $familiesObj.PSObject.Properties[$Family]) {
        return $result
    }
    $familyEntry = $familiesObj.$Family
    if ($null -eq $familyEntry -or -not $familyEntry.PSObject.Properties[$DefinitionId]) {
        return $result
    }

    $entry = $familyEntry.$DefinitionId
    $result.Present = $true
    $result.Entry = $entry
    $result.AnyUnknownAssignment = [bool] $entry.anyUnknownAssignment
    $result.UnknownAssignmentPolicyCount = [int] $entry.unknownAssignmentPolicyCount

    foreach ($valueGroup in @($entry.values)) {
        $assignedCount = [int] $valueGroup.assignedPolicyCount
        $totalCount = [int] $valueGroup.policyCount
        $unassignedOrUnknownCount = $totalCount - $assignedCount

        if ([bool] $valueGroup.redacted) {
            # FAIL-CLOSED: never evaluate the predicate against a redacted (canonicalValue
            # $null) group - there is nothing meaningful to compare, and doing so could
            # only ever produce a false negative (predicate(-canonicalValue $null) almost
            # certainly returns $false, silently hiding "we could not verify this" behind
            # an indistinguishable "this is wrong" - the whole point of tracking this
            # separately).
            if ($assignedCount -gt 0) { $result.RedactedAssignedPolicyCount += $assignedCount }
            if ($unassignedOrUnknownCount -gt 0) { $result.RedactedUnassignedPolicyCount += $unassignedOrUnknownCount }
            continue
        }

        if (& $IsSatisfyingValue $valueGroup.canonicalValue) {
            if ($assignedCount -gt 0) { $result.SatisfiedAssignedPolicyCount += $assignedCount }
            if ($unassignedOrUnknownCount -gt 0) { $result.SatisfiedUnassignedPolicyCount += $unassignedOrUnknownCount }
        }
    }

    return $result
}

<#
    Private: sibling of Resolve-PulseSettingPresenceCriterion - return the DISTINCT
    policyIds whose (non-redacted) value for one (family, definitionId) satisfies
    -IsSatisfyingValue, plus the policyIds whose value for that definition is
    redacted. Used by TP.INT.0017/0018 to intersect enforce × active-control
    (× Managed Installer) on the SAME policy without streaming jsonl.

    FAIL-CLOSED ON A MISSING policyIds ARRAY: a pre-extension presence-index
    artifact (counts only) yields empty MatchingPolicyIds/RedactedPolicyIds, so
    a same-policy AND cannot false-Pass. Rebuild the index (any -ExpandSettings
    snapshot after this change) to populate the arrays.

    Redacted groups are never passed to -IsSatisfyingValue (same rule as the
    count helper). Their policyIds land only in RedactedPolicyIds.
#>

function Get-PulseSettingPresenceMatchingPolicies {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Artifact,

        [Parameter(Mandatory)]
        [string] $Family,

        [Parameter(Mandatory)]
        [string] $DefinitionId,

        [Parameter(Mandatory)]
        [scriptblock] $IsSatisfyingValue
    )

    $matching = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $redacted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $result = [pscustomobject]@{
        Present            = $false
        MatchingPolicyIds  = [string[]] @()
        RedactedPolicyIds  = [string[]] @()
        AnyUnknownAssignment = $false
    }

    $familiesObj = $Artifact.Families
    if ($null -eq $familiesObj -or -not $familiesObj.PSObject.Properties[$Family]) {
        return $result
    }
    $familyEntry = $familiesObj.$Family
    if ($null -eq $familyEntry -or -not $familyEntry.PSObject.Properties[$DefinitionId]) {
        return $result
    }

    $entry = $familyEntry.$DefinitionId
    $result.Present = $true
    $result.AnyUnknownAssignment = [bool] $entry.anyUnknownAssignment

    foreach ($valueGroup in @($entry.values)) {
        $ids = @($valueGroup.policyIds)
        if ([bool] $valueGroup.redacted) {
            foreach ($id in $ids) {
                if (-not [string]::IsNullOrEmpty([string] $id)) {
                    [void] $redacted.Add([string] $id)
                }
            }
            continue
        }
        if (& $IsSatisfyingValue $valueGroup.canonicalValue) {
            foreach ($id in $ids) {
                if (-not [string]::IsNullOrEmpty([string] $id)) {
                    [void] $matching.Add([string] $id)
                }
            }
        }
    }

    $sortedMatching = @($matching)
    [System.Array]::Sort($sortedMatching, [System.StringComparer]::Ordinal)
    $sortedRedacted = @($redacted)
    [System.Array]::Sort($sortedRedacted, [System.StringComparer]::Ordinal)
    $result.MatchingPolicyIds = [string[]] @($sortedMatching)
    $result.RedactedPolicyIds = [string[]] @($sortedRedacted)
    return $result
}
