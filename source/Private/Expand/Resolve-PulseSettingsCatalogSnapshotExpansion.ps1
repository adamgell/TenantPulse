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
    failed) is left as the final state.
#>

function Resolve-PulseSettingsCatalogSnapshotExpansion {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    try {
        $manifest = Get-PulseSnapshotManifest -Store $Store

        if (-not $manifest.datasets -or -not $manifest.datasets.ContainsKey('configurationPolicies')) {
            return
        }
        if ($manifest.datasets['configurationPolicies'].status -ne 'Collected') {
            return
        }

        if ($manifest.expansions -and $manifest.expansions.ContainsKey('settingsCatalog')) {
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
            }
        }

        # ABSENT OR INVALID - re-expand from captured payloads, never Graph.
        $policies = Read-PulseDataset -Store $Store -Name 'configurationPolicies'

        $rawDefinitions = Get-PulseReferenceData -Store $Store -Name 'settingDefinitions'
        $definitionIndex = Get-PulseSettingDefinitionIndex -Data $rawDefinitions

        $null = Invoke-PulseSettingsCatalogExpansion -Store $Store -Context $null -Policies $policies `
            -DefinitionIndex $definitionIndex -FromCapturedPayloads -Sequential
    } catch {
        Write-Verbose "Resolve-PulseSettingsCatalogSnapshotExpansion: could not verify or re-derive the settingsCatalog expansion for '$($Store.Root)': $($_.Exception.Message)"
    }
}
