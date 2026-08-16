<#
    Private: read one reference-data file back out of a snapshot store.

    Mirrors Read-PulseDataset exactly, against manifest.references instead of
    manifest.datasets and reference/ instead of datasets/: re-hashes the on-disk bytes and
    compares against the sha256 recorded in the manifest at write time, throwing naming the
    file on a mismatch (tampering, partial write, disk corruption - the data can no longer
    be trusted to be what was captured).

    HASHES RAW FILE BYTES, NOT RE-ENCODED TEXT - see Read-PulseDataset's own docstring for
    the full reproduced-bypass story (omp finding #2, the identical defect existed here too):
    the hash below is computed from `[System.IO.File]::ReadAllBytes`, never from
    re-encoding a `Get-Content -Raw`-decoded string, so a file swapped for a different
    encoding that happens to decode to the same text no longer passes the integrity check.

    STATUS + STRUCTURAL VALIDATION (post-review fix, omp finding #5 - a reproduced hole): a
    reference entry with -Status other than 'Captured' (e.g. 'Failed') previously reached
    the file-read/hash logic below anyway if a reference/<name>.json file HAPPENED to exist
    on disk (a stale file from a prior run, or one written out-of-band) - this function
    would then happily read and return that file's content even though the manifest itself
    says the capture that was supposed to produce it FAILED, silently treating explicitly
    unusable data as good. This function now checks -Status is 'Captured' FIRST and throws,
    naming the actual status (and the recorded failure reason, if any), before ever touching
    the filesystem. A 'Captured' entry is also now required to be structurally complete
    (path/format/schemaVersion/sha256/itemCount/retrievedUtc all present) before this
    function trusts it enough to read the file - Set-PulseReferenceEntry enforces this same
    invariant at write time (see its own docstring), so a structurally incomplete 'Captured'
    entry here means the manifest was hand-edited or corrupted after the fact, not a normal
    write-time gap.

    A '1.0.0'-schema store (pre-Task-2.1) or a '1.1.0' store where this reference was never
    captured both surface identically here: no manifest.references entry for -Name, so this
    throws "no manifest entry" - the same shape Read-PulseDataset already uses for an
    unknown dataset name. A caller that needs to distinguish "not captured" from "capture
    failed" without throwing should inspect the manifest's references.<name>.status
    directly (via Get-PulseSnapshotManifest) rather than calling this function, which is
    read-the-actual-data-or-throw by design, matching Read-PulseDataset's own contract.
#>

function Get-PulseReferenceData {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name
    )

    Assert-PulseDatasetName -Name $Name -Kind 'reference name'

    $manifest = Get-PulseSnapshotManifest -Store $Store
    $fileName = "$Name.json"

    if (-not $manifest.references -or -not $manifest.references.ContainsKey($Name)) {
        throw "Get-PulseReferenceData: no manifest entry for reference '$Name' ($fileName)."
    }

    $entry = $manifest.references[$Name]

    if ($entry.status -ne 'Captured') {
        $reasonText = if ([string]::IsNullOrEmpty([string] $entry.reason)) { '(no reason recorded)' } else { [string] $entry.reason }
        throw "Get-PulseReferenceData: reference '$Name' has status '$($entry.status)', not 'Captured' - there is no valid data to read (reason: $reasonText)."
    }

    $requiredFields = @('path', 'format', 'schemaVersion', 'sha256', 'retrievedUtc')
    $missingFields = [System.Collections.Generic.List[string]]::new()
    foreach ($field in $requiredFields) {
        if ([string]::IsNullOrEmpty([string] $entry.$field)) {
            $missingFields.Add($field)
        }
    }
    if ($null -eq $entry.itemCount) {
        $missingFields.Add('itemCount')
    }
    if ($missingFields.Count -gt 0) {
        throw "Get-PulseReferenceData: reference '$Name' has status 'Captured' but is missing $($missingFields -join ', ') - the manifest entry is structurally incomplete and cannot be trusted."
    }

    $referencePath = Join-Path $Store.ReferencePath $fileName

    if (-not (Test-Path -LiteralPath $referencePath -PathType Leaf)) {
        throw "Get-PulseReferenceData: reference file '$fileName' is missing from the snapshot store."
    }

    # RAW BYTES, not decoded-then-re-encoded text (see this file's own docstring, omp
    # finding #2) - the hash below is always of exactly what is on disk.
    $rawBytes = [System.IO.File]::ReadAllBytes($referencePath)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($rawBytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Get-PulseReferenceData: hash mismatch for reference file '$fileName' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at capture time."
    }

    $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    $parsed = ConvertFrom-Json -InputObject $content -Depth 64

    return , [object[]] @($parsed)
}
