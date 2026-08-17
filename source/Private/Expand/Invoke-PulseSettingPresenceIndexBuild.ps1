<#
    Private: orchestration glue for Part A/T3.4 - reads back whichever of the
    settingsCatalog/compliance/deviceConfiguration expansion families are currently
    verified-usable, folds their rows through ConvertTo-PulseSettingPresenceIndex (one
    pass, never Graph - the index is entirely derived from already-produced expansion
    artifacts, mirroring Invoke-PulseConflictDetection's own identical family-availability
    pattern byte-for-byte), and publishes expanded/settingPresenceIndex.<sha256>.json via
    Publish-PulseSettingPresenceIndex. Called from Get-PulseTenantSnapshot's
    -ExpandSettings block (immediately after conflict detection has run) AND, via
    Resolve-PulseSettingPresenceIndexSnapshotExpansion, from -FromSnapshot re-derivation -
    this function itself never touches Graph either way, same as its conflicts sibling.

    PER-FAMILY AVAILABILITY, NOT A GAP (identical rule to Invoke-PulseConflictDetection's
    own docstring, reused unmodified here): a family whose own manifest.expansions entry
    does not exist, or is NotExpanded/Failed, is an EXPECTED absence - it is silently
    skipped, contributing no rows and no gap. A family whose entry claims Expanded/Partial
    but whose on-disk file is missing or no longer matches its recorded hash IS a genuine
    integrity failure and is recorded as an index-artifact gap so it is visible in the
    manifest rather than silently dropped.

    ZERO FAMILIES AVAILABLE -> NotExpanded (Publish-PulseSettingPresenceIndex's own
    -PolicyCount 0 path), naming which case applies. ZERO DISTINCT SETTINGS from >=1 usable
    family (every usable family happened to expand to zero rows) is still a VALID, Expanded
    outcome - this function never special-cases an empty index, matching the plan's own
    "empty is not automatically a gap" rule already established for conflicts.
#>

function Invoke-PulseSettingPresenceIndexBuild {
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
            # Counted once per family whose read succeeded, regardless of row count - a
            # verified family with zero rows (a legitimate "Expanded, empty" outcome) still
            # counts as ONE verified family, never zero (see Publish-PulseSettingPresenceIndex's
            # own -FamilyCount docstring for why this must not be conflated with the
            # distinct-policy/row counts).
            $verifiedFamilyCount++
        } catch {
            Write-Verbose "Invoke-PulseSettingPresenceIndexBuild: could not read verified rows for family '$familyName': $($_.Exception.Message)"
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
            'no expansion families available for the setting-presence index'
        }
        return Publish-PulseSettingPresenceIndex -Store $Store -Families ([ordered]@{}) -Gaps $sortedGaps -FamilyCount 0 -Reason $reason
    }

    $families = ConvertTo-PulseSettingPresenceIndex -Rows $allRows.ToArray()

    return Publish-PulseSettingPresenceIndex -Store $Store -Families $families -Gaps $sortedGaps -FamilyCount $verifiedFamilyCount
}
