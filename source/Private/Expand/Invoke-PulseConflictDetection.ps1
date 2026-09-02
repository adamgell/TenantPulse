<#
    Private: orchestration glue for Task 2.6 - reads back whichever of the
    settingsCatalog/compliance/deviceConfiguration expansion families are currently
    verified-usable, folds their rows through ConvertTo-PulseConflictRecords (one pass,
    never Graph - conflicts are entirely derived from already-produced expansion
    artifacts), and publishes expanded/conflicts.json via Publish-PulseConflictArtifact.
    Called from Get-PulseTenantSnapshot's -ExpandSettings block (immediately after the
    settingsCatalog/typed-policy expansion pipelines have run) AND, via
    Resolve-PulseConflictSnapshotExpansion, from -FromSnapshot re-derivation - this
    function itself never touches Graph either way, so there is no live/-FromCapturedPayloads
    split the way T2.2/T2.3's drivers need: "from existing jsonl artifacts, never Graph" is
    this function's ONLY mode.

    PER-FAMILY AVAILABILITY: a family whose own manifest.expansions entry does not exist
    is an EXPECTED absence (the G-gate core slice never ran that family this snapshot) -
    it is silently skipped, contributing no rows and no gap. A NotExpanded family whose
    raw dataset was never collected (pipeline reason like 'deviceCompliancePolicies
    unavailable', no recorded gaps) is the same expected absence. A family that is
    Failed, NotExpanded with recorded source gaps (all-policies-failed / authentication
    abort), or NotExpanded because authentication aborted the walk, is NOT expected
    absence: those families contribute every recorded source gap AND a FamilyUnavailable
    disclosure so a 1-of-3 scan cannot publish Expanded with empty gaps. A family whose
    entry claims Expanded/Partial but whose on-disk file is missing or no longer matches
    its recorded hash IS a genuine integrity failure (tampering, disk corruption, a stale
    manifest) and is recorded as a conflicts-artifact gap so it is visible in the
    manifest rather than silently dropped. A verified Partial family contributes both
    its usable rows AND every recorded source gap: a policy rejected upstream cannot
    disappear and turn a partial scan into a bare zero-conflict result.

    ZERO FAMILIES AVAILABLE -> NotExpanded (Publish-PulseConflictArtifact's own
    -FamilyCount 0 path), naming which case applies. ZERO CONFLICTS FOUND from >=1 usable
    family is a VALID Expanded outcome ONLY when no omitted family contributed a gap
    (detection proven by fixtures, not corpus luck - the plan's own T2.7 rule).
#>

function Invoke-PulseConflictDetection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId
    )

    $familyNames = @('settingsCatalog', 'compliance', 'deviceConfiguration')

    $allRows = [System.Collections.Generic.List[object]]::new()
    $gapEntries = [System.Collections.Generic.List[object]]::new()
    $verifiedFamilyCount = 0

    $manifest = Get-PulseSnapshotManifest -Store $Store

    foreach ($familyName in $familyNames) {
        $hasEntry = $manifest.expansions -and $manifest.expansions.ContainsKey($familyName)
        if (-not $hasEntry) { continue }

        $sourceEntry = $manifest.expansions[$familyName]
        $entryStatus = $sourceEntry.status
        if ($entryStatus -ne 'Expanded' -and $entryStatus -ne 'Partial') {
            $gapCountBefore = $gapEntries.Count
            Add-PulseConflictCopiedSourceGaps -Target $gapEntries -SourceEntry $sourceEntry -FamilyName $familyName `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            $copiedSourceGaps = $gapEntries.Count -gt $gapCountBefore

            $reasonText = ''
            if ($sourceEntry -is [System.Collections.IDictionary] -and $sourceEntry.Contains('reason')) {
                $reasonText = [string] $sourceEntry['reason']
            }
            $authenticationOmitted = $reasonText.IndexOf('authentication-failed', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
            if ($copiedSourceGaps -or $authenticationOmitted -or $entryStatus -eq 'Failed') {
                $detail = Protect-PulseReason -Message "category:FamilyUnavailable;family:$familyName" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                $gapEntries.Add([pscustomobject]@{ policyId = ''; reason = $detail }) | Out-Null
            }
            continue
        }

        try {
            $familyRows = Get-PulseExpansionRows -Store $Store -Name $familyName
            $familyGaps = [System.Collections.Generic.List[object]]::new()
            if ($entryStatus -eq 'Partial') {
                Add-PulseConflictCopiedSourceGaps -Target $familyGaps -SourceEntry $sourceEntry -FamilyName $familyName `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId -Required
            }
            foreach ($row in $familyRows) { $allRows.Add($row) | Out-Null }
            foreach ($sourceGap in $familyGaps) { $gapEntries.Add($sourceGap) | Out-Null }
            $verifiedFamilyCount++
        } catch {
            Write-Verbose "Invoke-PulseConflictDetection: could not read verified rows for family '$familyName': $($_.Exception.Message)"
            $detail = Protect-PulseReason -Message "category:FamilyUnavailable;family:$familyName" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            $gapEntries.Add([pscustomobject]@{ policyId = ''; reason = $detail }) | Out-Null
        }
    }

    $sortedGaps = @($gapEntries.ToArray())
    $gapComparison = [System.Comparison[object]] {
        param($a, $b)
        $policyComparison = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
        if ($policyComparison -ne 0) { return $policyComparison }
        return [string]::CompareOrdinal([string] $a.reason, [string] $b.reason)
    }
    [System.Array]::Sort($sortedGaps, $gapComparison)

    if ($verifiedFamilyCount -eq 0) {
        $reason = if ($sortedGaps.Count -gt 0) {
            Protect-PulseReason -Message "all $($sortedGaps.Count) attempted family(ies) unavailable, zero usable rows" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        } else {
            'no expansion families available for conflict detection'
        }
        return Publish-PulseConflictArtifact -Store $Store -Conflicts @() -Gaps $sortedGaps -FamilyCount 0 -Reason $reason
    }

    $conflicts = ConvertTo-PulseConflictRecords -Rows $allRows.ToArray()

    return Publish-PulseConflictArtifact -Store $Store -Conflicts $conflicts -Gaps $sortedGaps -FamilyCount $verifiedFamilyCount
}

function Add-PulseConflictCopiedSourceGaps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Target,

        [Parameter(Mandatory)]
        [AllowNull()]
        $SourceEntry,

        [Parameter(Mandatory)]
        [string] $FamilyName,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId,

        [Parameter()]
        [switch] $Required
    )

    $sourceGaps = $null
    if ($null -ne $SourceEntry -and $SourceEntry -is [System.Collections.IDictionary] -and $SourceEntry.Contains('gaps')) {
        $sourceGaps = $SourceEntry['gaps']
    }
    if ($sourceGaps -isnot [System.Collections.IList] -or $sourceGaps.Count -eq 0) {
        if ($Required) {
            throw "Partial source expansion '$FamilyName' has no usable gap array."
        }
        return
    }

    foreach ($sourceGap in $sourceGaps) {
        if ($sourceGap -isnot [System.Collections.IDictionary] -or
            -not $sourceGap.Contains('policyId') -or $sourceGap['policyId'] -isnot [string] -or
            -not $sourceGap.Contains('reason') -or $sourceGap['reason'] -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string] $sourceGap['reason'])) {
            if ($Required) {
                throw "Partial source expansion '$FamilyName' has a malformed gap entry."
            }
            continue
        }

        $sourcePolicyId = [string] $sourceGap['policyId']
        $sourceReason = [string] $sourceGap['reason']
        $safePolicyId = Protect-PulseReason -Message $sourcePolicyId -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        $safeReason = Protect-PulseReason -Message $sourceReason -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        if (-not [string]::Equals($sourcePolicyId, $safePolicyId, [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($sourceReason, $safeReason, [System.StringComparison]::Ordinal)) {
            if ($Required) {
                throw "Partial source expansion '$FamilyName' has a privacy-unsafe gap entry."
            }
            continue
        }

        $Target.Add([pscustomobject]@{ policyId = $sourcePolicyId; reason = $sourceReason }) | Out-Null
    }
}
