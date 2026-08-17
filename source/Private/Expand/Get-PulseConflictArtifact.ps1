<#
    Private: read Task 2.6's conflicts.json artifact back out of a snapshot store, for a
    Function rule to consume (TP.INT.0006, Task 3.1's own check) - the
    Get-PulseReferenceData-style read this task's brief calls for, but against
    manifest.expansions.conflicts (T2.6/Set-PulseExpansionEntry's own entry shape) rather
    than manifest.references, and against ONE canonical JSON document (Publish-
    PulseConflictArtifact's own -Format 'json' contract), never a line-delimited jsonl file
    - see that function's own docstring for why conflicts.json is not row-schema-v1 shaped.

    FOUR-WAY OUTCOME (never throws for an ordinary "nothing to read" case - only for actual
    data-integrity failures, matching Get-PulseReferenceData's own hash-mismatch behavior):
      - No manifest.expansions.conflicts entry at all (a pre-Task-2.6 snapshot, or one
        collected without -ExpandSettings) -> Status 'NotAvailable', Reason explains no
        entry exists.
      - Entry status 'NotExpanded' or 'Failed' -> Status 'NotAvailable', Reason is the
        entry's OWN recorded reason, quoted verbatim (Publish-PulseConflictArtifact/
        Set-PulseExpansionEntry both require -Reason for either status, so this is always
        present) - TP.INT.0006's own NotApplicable reason is meant to quote this text
        directly, not paraphrase it.
      - Entry status 'Expanded' or 'Partial' but the recorded file is missing or its
        sha256 no longer matches -> THROWS (mirrors Get-PulseReferenceData's own
        fail-closed hash-mismatch behavior) - this is not "expansion wasn't run", it is
        "the manifest claims data exists and it cannot be trusted", which must surface as
        the calling check's Error status, never a confident Pass/Warn/Fail built on
        unverifiable data.
      - Entry status 'Expanded' or 'Partial' and the file verifies -> Status 'Available',
        -Conflicts holds the parsed conflicts array (possibly empty - zero conflicts from
        a real expansion is a valid 'Expanded' outcome, see Publish-PulseConflictArtifact's
        own tests) and -Gaps holds whatever partial-coverage gaps the manifest recorded
        (empty for 'Expanded').

    Any other/unrecognized entry status also degrades to 'NotAvailable' (fail-closed on an
    unrecognized status the same way Invoke-PulseCheckEvaluation's own dataset-status gate
    does, rather than assuming it behaves like a known-good one).
#>

function Get-PulseConflictArtifact {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    $manifest = Get-PulseSnapshotManifest -Store $Store

    if (-not $manifest.expansions -or $manifest.expansions -isnot [System.Collections.IDictionary] -or -not $manifest.expansions.ContainsKey('conflicts')) {
        return [pscustomobject]@{
            Status    = 'NotAvailable'
            Reason    = 'no expansions.conflicts entry in the snapshot manifest - settings expansion was not run for this snapshot.'
            Conflicts = @()
            Gaps      = @()
        }
    }

    $entry = $manifest.expansions['conflicts']
    $status = [string] $entry.status

    if ($status -eq 'NotExpanded' -or $status -eq 'Failed') {
        $reason = [string] $entry.reason
        if ([string]::IsNullOrEmpty($reason)) {
            $reason = "expansions.conflicts has status '$status' with no reason recorded."
        }
        return [pscustomobject]@{
            Status    = 'NotAvailable'
            Reason    = $reason
            Conflicts = @()
            Gaps      = @()
        }
    }

    if ($status -ne 'Expanded' -and $status -ne 'Partial') {
        return [pscustomobject]@{
            Status    = 'NotAvailable'
            Reason    = "expansions.conflicts has an unrecognized status '$status'."
            Conflicts = @()
            Gaps      = @()
        }
    }

    $filePath = Join-Path $Store.Root $entry.path
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Get-PulseConflictArtifact: conflicts artifact file '$($entry.path)' is missing from the snapshot store, even though the manifest records status '$status'."
    }

    # RAW BYTES, not decoded-then-re-encoded text - same fail-closed hashing discipline as
    # Get-PulseReferenceData/Read-PulseDataset (see their own docstrings for the
    # reproduced-bypass story this guards against).
    $rawBytes = [System.IO.File]::ReadAllBytes($filePath)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($rawBytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Get-PulseConflictArtifact: hash mismatch for conflicts artifact '$($entry.path)' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at publish time."
    }

    $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    $parsed = ConvertFrom-Json -InputObject $content -Depth 64

    # NO comma-wrap here (unlike a bare `return $array` elsewhere in this module): this is
    # a HASHTABLE-LITERAL PROPERTY ASSIGNMENT, not a pipeline return - the comma operator
    # still builds an array unconditionally in this position too, so prepending one here
    # would wrap the already-correct [object[]] into a ONE-ELEMENT array containing that
    # whole array (Count 1 for a zero-conflict result, not 0) - a real bug caught by this
    # task's own zero-conflict fixture test. [object[]] @(...) alone already guarantees an
    # array (never unrolled to $null/a bare scalar) for a plain assignment target.
    $conflictsArray = [object[]] @($parsed.conflicts)
    $gapsArray = [object[]] @($entry.gaps)

    return [pscustomobject]@{
        Status    = 'Available'
        Reason    = $null
        Conflicts = $conflictsArray
        Gaps      = $gapsArray
    }
}
