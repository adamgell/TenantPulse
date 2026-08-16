<#
    Private: -FromSnapshot decision wiring for Task 2.6's conflicts artifact - the sibling
    of Resolve-PulseSettingsCatalogSnapshotExpansion/Resolve-PulseTypedPolicySnapshotExpansion,
    called alongside them once a -FromSnapshot store is opened (see Invoke-PulseAssessment's
    own wiring). Unlike those two, Invoke-PulseConflictDetection (the function this
    delegates rebuilding to) never touches Graph in the first place - "re-derive" here
    means re-reading the family jsonl artifacts already durable on disk, exactly what a
    live run's own post-expansion step does, so there is no separate
    -FromCapturedPayloads mode to plumb through.

    DECISION:
      1. manifest.expansions.conflicts exists with status 'Expanded'/'Partial'/'NotExpanded'
         AND (for Expanded/Partial) its recorded file re-hashes to the recorded sha256 ->
         VERIFIED, already usable as written (a verified 'NotExpanded' needs no file check -
         there is no file to verify); nothing to do. Any other status, a missing/renamed
         file, or a hash mismatch falls through to step 2.
      2. Re-run Invoke-PulseConflictDetection - it reads back whichever source families are
         currently verified-usable and republishes conflicts.json from them, exactly like a
         live run's own post-expansion step.

    BEST-EFFORT, NEVER ABORTS THE ASSESSMENT (mirrors both sibling Resolve-* functions):
    any unexpected failure here is caught and swallowed - Invoke-PulseAssessment's own
    evaluation/scoring/render pipeline does not depend on the conflicts artifact, so a
    failure here must never abort an otherwise-successful re-evaluation of an existing
    snapshot.
#>

function Resolve-PulseConflictSnapshotExpansion {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    try {
        $manifest = Get-PulseSnapshotManifest -Store $Store

        if ($manifest.expansions -and $manifest.expansions.ContainsKey('conflicts')) {
            $entry = $manifest.expansions['conflicts']

            if ($entry.status -eq 'NotExpanded') {
                # Nothing was ever produced, and nothing about a -FromSnapshot re-open
                # changes that on its own - a fresh attempt is still made below only if
                # the source families themselves might now verify differently, but a
                # cheap, conservative re-run costs nothing meaningful here and keeps this
                # function's own decision tree the same shape as its two siblings' Verified
                # branch. Falls through to step 2 deliberately (re-attempt, do not just
                # trust a prior NotExpanded forever).
            } elseif ($entry.status -eq 'Expanded' -or $entry.status -eq 'Partial') {
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

        $null = Invoke-PulseConflictDetection -Store $Store
    } catch {
        Write-Verbose "Resolve-PulseConflictSnapshotExpansion: could not verify or re-derive 'conflicts' for '$($Store.Root)': $($_.Exception.Message)"
    }
}
