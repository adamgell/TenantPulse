<#
    Private: -FromSnapshot decision wiring for Part A/T3.4's setting-presence-index
    artifact - the sibling of Resolve-PulseConflictSnapshotExpansion (T2.6's own conflicts
    artifact), called alongside it once a -FromSnapshot store is opened (see
    Invoke-PulseAssessment's own wiring). Unlike the raw-payload expansions,
    Invoke-PulseSettingPresenceIndexBuild (the function this delegates rebuilding to) never
    touches Graph in the first place - "re-derive" here means re-reading the family jsonl
    artifacts already durable on disk, exactly what a live run's own post-expansion step
    does, so there is no separate -FromCapturedPayloads mode to plumb through.

    DECISION (identical shape to Resolve-PulseConflictSnapshotExpansion's own):
      1. manifest.expansions.settingPresenceIndex exists with status
         'Expanded'/'Partial'/'NotExpanded' AND (for Expanded/Partial) its recorded file
         re-hashes to the recorded sha256 -> VERIFIED, already usable as written; nothing
         to do. Any other status, a missing/renamed file, or a hash mismatch falls through
         to step 2.
      2. Re-run Invoke-PulseSettingPresenceIndexBuild - it reads back whichever source
         families are currently verified-usable and republishes the index from them,
         exactly like a live run's own post-expansion step.

    BEST-EFFORT, NEVER ABORTS THE ASSESSMENT (mirrors Resolve-PulseConflictSnapshotExpansion
    and its two typed-policy/settings-catalog siblings): any unexpected failure here is
    caught and swallowed - Invoke-PulseAssessment's own evaluation/scoring/render pipeline
    does not depend on the setting-presence index, so a failure here must never abort an
    otherwise-successful re-evaluation of an existing snapshot.
#>

function Resolve-PulseSettingPresenceIndexSnapshotExpansion {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    try {
        $manifest = Get-PulseSnapshotManifest -Store $Store

        if ($manifest.expansions -and $manifest.expansions.ContainsKey('settingPresenceIndex')) {
            $entry = $manifest.expansions['settingPresenceIndex']

            if ($entry.status -eq 'NotExpanded') {
                # Nothing was ever produced - falls through to step 2 deliberately (a
                # cheap, conservative re-attempt, matching the conflicts sibling's own
                # identical rationale), rather than trusting a prior NotExpanded forever.
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

        $null = Invoke-PulseSettingPresenceIndexBuild -Store $Store
    } catch {
        Write-Verbose "Resolve-PulseSettingPresenceIndexSnapshotExpansion: could not verify or re-derive 'settingPresenceIndex' for '$($Store.Root)': $($_.Exception.Message)"
    }
}
