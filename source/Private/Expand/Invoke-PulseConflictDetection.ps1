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

    PER-FAMILY AVAILABILITY, NOT A GAP (mirrors Invoke-PulseTypedPolicyExpansionPipeline's
    own per-family independence): a family whose own manifest.expansions entry does not
    exist, or is NotExpanded/Failed, is an EXPECTED absence (the G-gate core slice never
    ran that family this snapshot, or it genuinely had nothing to expand) - it is silently
    skipped, contributing no rows and no gap. A family whose entry claims Expanded/Partial
    but whose on-disk file is missing or no longer matches its recorded hash IS a genuine
    integrity failure (tampering, disk corruption, a stale manifest) and is recorded as a
    conflicts-artifact gap so it is visible in the manifest rather than silently dropped.

    ZERO FAMILIES AVAILABLE -> NotExpanded (Publish-PulseConflictArtifact's own
    -FamilyCount 0 path), naming which case applies. ZERO CONFLICTS FOUND from >=1 usable
    family is a VALID, Expanded outcome (detection proven by fixtures, not corpus luck -
    the plan's own T2.7 rule, already true here since this function never special-cases an
    empty result).
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

        $entryStatus = $manifest.expansions[$familyName].status
        if ($entryStatus -ne 'Expanded' -and $entryStatus -ne 'Partial') {
            # Expected absence of usable data for this family this snapshot - not a gap.
            continue
        }

        try {
            $familyRows = Get-PulseExpansionRows -Store $Store -Name $familyName
            foreach ($row in $familyRows) { $allRows.Add($row) | Out-Null }
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
