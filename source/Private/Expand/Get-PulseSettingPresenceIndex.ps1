<#
    Private: read Part A/T3.4's setting-presence-index artifact back out of a snapshot
    store, for a Function rule to consume via $Context.ArtifactReader.GetSettingPresenceIndex()
    - the same read shape Get-PulseConflictArtifact already established for TP.INT.0006
    (Task 3.1), against manifest.expansions.settingPresenceIndex (Set-PulseExpansionEntry's
    own entry shape) and ONE canonical JSON document (Publish-PulseSettingPresenceIndex's
    own -Format 'json' contract), never a line-delimited jsonl file - checks NEVER stream
    jsonl (the standing rule this whole artifact exists to satisfy for Part B's checks).

    FOUR-WAY OUTCOME (never throws for an ordinary "nothing to read" case - only for actual
    data-integrity failures, matching Get-PulseConflictArtifact's own behavior exactly):
      - No manifest.expansions.settingPresenceIndex entry at all (a pre-Part-A snapshot, or
        one collected without -ExpandSettings) -> Status 'NotAvailable', Reason explains no
        entry exists.
      - Entry status 'NotExpanded' or 'Failed' -> Status 'NotAvailable', Reason is the
        entry's OWN recorded reason, quoted verbatim.
      - Entry status 'Expanded' or 'Partial' but the recorded file is missing or its
        sha256 no longer matches -> THROWS (fail-closed hash-mismatch, mirrors
        Get-PulseConflictArtifact/Get-PulseReferenceData) - this is "the manifest claims
        data exists and it cannot be trusted", which must surface as the calling check's
        Error status, never a confident Pass/Warn/Fail built on unverifiable data.
      - Entry status 'Expanded' or 'Partial' and the file verifies -> Status 'Available',
        -Families holds the parsed family -> settingDefinitionId -> presence-entry tree
        (possibly an entry with zero families if every family was legitimately unavailable
        this snapshot, though that specific shape is a 'NotExpanded' outcome in practice -
        see Publish-PulseSettingPresenceIndex's own docstring) and -Gaps holds whatever
        partial-coverage gaps the manifest recorded (empty for 'Expanded').

    Any other/unrecognized entry status also degrades to 'NotAvailable', matching
    Get-PulseConflictArtifact's own fail-closed rule for an unrecognized status.
#>

function Get-PulseSettingPresenceIndex {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    $manifest = Get-PulseSnapshotManifest -Store $Store

    if (-not $manifest.expansions -or $manifest.expansions -isnot [System.Collections.IDictionary] -or -not $manifest.expansions.ContainsKey('settingPresenceIndex')) {
        return [pscustomobject]@{
            Status   = 'NotAvailable'
            Reason   = 'no expansions.settingPresenceIndex entry in the snapshot manifest - settings expansion was not run for this snapshot.'
            Families = [pscustomobject]@{}
            Gaps     = @()
        }
    }

    $entry = $manifest.expansions['settingPresenceIndex']
    $status = [string] $entry.status

    if ($status -eq 'NotExpanded' -or $status -eq 'Failed') {
        $reason = [string] $entry.reason
        if ([string]::IsNullOrEmpty($reason)) {
            $reason = "expansions.settingPresenceIndex has status '$status' with no reason recorded."
        }
        return [pscustomobject]@{
            Status   = 'NotAvailable'
            Reason   = $reason
            Families = [pscustomobject]@{}
            Gaps     = @()
        }
    }

    if ($status -ne 'Expanded' -and $status -ne 'Partial') {
        return [pscustomobject]@{
            Status   = 'NotAvailable'
            Reason   = "expansions.settingPresenceIndex has an unrecognized status '$status'."
            Families = [pscustomobject]@{}
            Gaps     = @()
        }
    }

    $filePath = Join-Path $Store.Root $entry.path
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Get-PulseSettingPresenceIndex: setting-presence-index artifact file '$($entry.path)' is missing from the snapshot store, even though the manifest records status '$status'."
    }

    # RAW BYTES, not decoded-then-re-encoded text - same fail-closed hashing discipline as
    # Get-PulseConflictArtifact/Get-PulseReferenceData/Read-PulseDataset (see their own
    # docstrings for the reproduced-bypass story this guards against).
    $rawBytes = [System.IO.File]::ReadAllBytes($filePath)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($rawBytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Get-PulseSettingPresenceIndex: hash mismatch for setting-presence-index artifact '$($entry.path)' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at publish time."
    }

    $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    $parsed = ConvertFrom-Json -InputObject $content -Depth 64

    $familiesResult = if ($null -ne $parsed.families) { $parsed.families } else { [pscustomobject]@{} }
    $gapsArray = [object[]] @($entry.gaps)

    return [pscustomobject]@{
        Status   = 'Available'
        Reason   = $null
        Families = $familiesResult
        Gaps     = $gapsArray
    }
}
