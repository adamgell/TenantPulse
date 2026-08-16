<#
    Private: -FromSnapshot decision wiring for the Settings Catalog expansion (P1-11
    review fix - this was previously wired nowhere: Invoke-PulseAssessment's -FromSnapshot
    path opened the store and re-evaluated it, full stop, never looking at whether a
    settingsCatalog expansion existed, was still valid, or needed re-deriving).

    Called once, right after a -FromSnapshot store is opened. Does nothing at all (no
    Graph, no re-expansion, no write) unless the store's own manifest shows
    `configurationPolicies` was collected - a store from a run that never used
    -ExpandSettings has nothing for this function to verify or re-derive, and this
    function must not invent Settings Catalog data for a snapshot that never asked for it.

    DECISION, in order:
      1. No `configurationPolicies` dataset in the manifest at all -> return immediately.
         -ExpandSettings was not used when this snapshot was collected.
      2. manifest.expansions.settingsCatalog exists with status 'Expanded' or 'Partial' AND
         its recorded file re-hashes to the recorded sha256 -> VERIFIED, already usable as
         written; nothing to do. (A 'NotExpanded'/'Failed' status, or a missing/renamed
         file, or a hash mismatch, all fall through to step 3 - "absent or invalid" are
         treated identically, matching this module's own "no silent gaps" convention: a
         corrupted artifact is never silently trusted just because a status field claims
         it once was fine.)
      2a. NEVER-EXPANDED, NO CAPTURED PAYLOADS (rider fix): step 2 found no
          manifest.expansions.settingsCatalog entry at all (expansion was never attempted
          for this snapshot), AND neither payload source step 3 depends on - the
          `settingDefinitions` reference, or at least one per-policy
          `configurationPolicySettings-<id>` dataset - is present in the manifest -> skip
          re-derivation entirely and return. Attempting step 3 here is guaranteed-futile
          (Get-PulseReferenceData would throw on the missing reference before a single
          policy could even be attempted); this function no longer pays for (or logs) that
          predictable failure.
      3. Re-expand via -FromCapturedPayloads: NEVER Graph. Reads the policy list back from
         the `configurationPolicies` dataset (Read-PulseDataset, hash-verified) and the
         definitions index back from the `settingDefinitions` reference
         (Get-PulseReferenceData, hash-verified, then rebuilt into the compact index via
         Get-PulseSettingDefinitionIndex - the reference file holds the full raw corpus,
         never the index itself). Runs -Sequential (this path only ever re-derives from
         data already durably on disk; there is no Graph latency to amortize with a worker
         pool here, and -Sequential keeps this call's own behavior simple and directly
         testable without a runspace pool).

    BEST-EFFORT, NEVER ABORTS THE ASSESSMENT: any failure in this function's own pipeline
    (a missing/corrupt configurationPolicies dataset, a missing/corrupt settingDefinitions
    reference) is caught and swallowed - Invoke-PulseAssessment's own evaluation/scoring/
    render pipeline does not depend on the Settings Catalog expansion at all (see the
    plan's own "checks do NOT stream jsonl" scoping), so a failure here must never abort an
    otherwise-successful re-evaluation of an existing snapshot. Whatever expansion state
    was already on disk (verified-valid, or unchanged if verification/re-expansion itself
    failed) is left as the final state - UNLESS step 2 had already found an existing
    Expanded/Partial entry to be stale (missing file or hash mismatch): in that one case,
    a re-derivation attempt that then throws (rider fix) explicitly overwrites the entry to
    'Failed' with a reason, rather than leaving a manifest claiming 'Expanded'/'Partial'
    status for a file that step 2 just proved is missing or no longer matches its recorded
    hash - a stale-but-successfully-verified-once entry must never keep pointing readers
    (e.g. Get-PulseExpansionRows) at an artifact already known to be untrustworthy.
#>

function Resolve-PulseSettingsCatalogSnapshotExpansion {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    # Set $true only once an EXISTING Expanded/Partial entry is found to be stale (file
    # missing/renamed, or hash mismatch) - see the catch block below (rider fix (b)): a
    # stale entry must not silently survive pointing at a now-invalid artifact if the
    # re-derivation attempted to replace it then throws before it can publish anything.
    $priorEntryWasStaleExpanded = $false

    try {
        $manifest = Get-PulseSnapshotManifest -Store $Store

        if (-not $manifest.datasets -or -not $manifest.datasets.ContainsKey('configurationPolicies')) {
            return
        }
        if ($manifest.datasets['configurationPolicies'].status -ne 'Collected') {
            return
        }

        $hasExpansionEntry = $manifest.expansions -and $manifest.expansions.ContainsKey('settingsCatalog')

        if ($hasExpansionEntry) {
            $entry = $manifest.expansions['settingsCatalog']
            if ($entry.status -eq 'Expanded' -or $entry.status -eq 'Partial') {
                $filePath = Join-Path $Store.Root $entry.path
                if (Test-Path -LiteralPath $filePath -PathType Leaf) {
                    $actualSha256 = Get-PulseFileSha256 -Path $filePath
                    if ($actualSha256 -eq $entry.sha256) {
                        # VERIFIED - already usable as written. Nothing to do.
                        return
                    }
                }
                $priorEntryWasStaleExpanded = $true
            }
        }

        # NEVER-EXPANDED, NO CAPTURED PAYLOADS (rider fix (a)): the raw dataset was
        # collected but expansion was never attempted at all (no manifest.expansions
        # entry) AND neither payload source -FromCapturedPayloads depends on (the
        # settingDefinitions reference, or at least one per-policy
        # configurationPolicySettings-<id> dataset) exists on disk. Re-derivation here
        # would be a guaranteed-futile attempt - Get-PulseReferenceData would just throw
        # on the missing reference, or every policy would gap on its missing captured
        # payload - so skip cleanly instead of paying for (and logging) that failure.
        if (-not $hasExpansionEntry) {
            $hasSettingDefinitionsReference = $manifest.references -and $manifest.references.ContainsKey('settingDefinitions')
            $hasCapturedPolicySettings = $manifest.datasets -and `
                @($manifest.datasets.Keys | Where-Object { $_ -like 'configurationPolicySettings-*' }).Count -gt 0
            if (-not $hasSettingDefinitionsReference -and -not $hasCapturedPolicySettings) {
                return
            }
        }

        # ABSENT OR INVALID - re-expand from captured payloads, never Graph.
        $policies = Read-PulseDataset -Store $Store -Name 'configurationPolicies'

        $rawDefinitions = Get-PulseReferenceData -Store $Store -Name 'settingDefinitions'
        $definitionIndex = Get-PulseSettingDefinitionIndex -Data $rawDefinitions

        $null = Invoke-PulseSettingsCatalogExpansion -Store $Store -Context $null -Policies $policies `
            -DefinitionIndex $definitionIndex -FromCapturedPayloads -Sequential
    } catch {
        # Rider fix (b): a previously-verified-stale Expanded/Partial entry that we just
        # attempted (and failed) to replace must not be left claiming a status that no
        # longer has a trustworthy backing file - overwrite it to Failed, with a reason,
        # rather than silently leaving the stale claim in place for a reader to trust.
        if ($priorEntryWasStaleExpanded) {
            $failureReason = Protect-PulseReason -Message "re-derivation failed after the recorded artifact could not be verified: $($_.Exception.Message)" -ProfileId '' -Pseudonym 'tp-unknown'
            try {
                Set-PulseExpansionEntry -Store $Store -Name 'settingsCatalog' -Status 'Failed' -Reason $failureReason
            } catch {
                Write-Verbose "Resolve-PulseSettingsCatalogSnapshotExpansion: could not record the Failed status for 'settingsCatalog' on '$($Store.Root)': $($_.Exception.Message)"
            }
        }
        Write-Verbose "Resolve-PulseSettingsCatalogSnapshotExpansion: could not verify or re-derive the settingsCatalog expansion for '$($Store.Root)': $($_.Exception.Message)"
    }
}
