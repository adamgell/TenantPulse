<#
    Private: read one row-schema-v1 jsonl expansion artifact back out of a snapshot store,
    verified. Sibling of Get-PulseReferenceData (manifest.references + reference/) against
    manifest.expansions + expanded/ instead - re-hashes the on-disk bytes against the
    sha256 Set-PulseExpansionEntry recorded at write time and throws, naming the file, on
    any mismatch (tampering, partial write, disk corruption).

    STATUS GATE: only -Status 'Expanded' or 'Partial' entries name a real, readable file
    (Set-PulseExpansionEntry's own status-dependent field invariants guarantee Path/
    SchemaVersion/Sha256 are present for both) - 'NotExpanded'/'Failed', or no entry at
    all, throw a distinct, named message so a caller (Invoke-PulseConflictDetection) can
    tell "this family was never expanded / expansion failed" (an expected, non-corrupt
    outcome - see that file's own docstring for why this is NOT treated as a gap) apart
    from "the file exists but no longer matches its recorded hash" (a genuine integrity
    failure, which IS surfaced as a gap).

    ONE-PASS PARSE, HASH VERIFIED AGAINST THE SAME BYTES: the file's raw bytes are read
    once, hashed via the same incremental SHA-256 primitive the writer used, THEN (only
    after the hash check passes) each line is parsed independently via ConvertFrom-Json -
    never re-encoded from a decoded string before hashing (Read-PulseDataset/
    Get-PulseReferenceData's own omp finding #2 lesson: hash the literal on-disk bytes, not
    a re-encoded text representation that could silently drift from what a tampered file
    actually contains).
#>

function Get-PulseExpansionRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        # Drivers that inspect several expansion families can pin one call-scoped
        # manifest view and avoid reparsing the same large datasets namespace for each
        # family. File bytes are still hashed on every read; writers never receive this
        # view and continue to re-read the latest manifest under their mutex.
        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $ManifestSnapshot
    )

    Assert-PulseDatasetName -Name $Name -Kind 'expansion name'

    if ($PSBoundParameters.ContainsKey('ManifestSnapshot')) {
        if ($null -eq $ManifestSnapshot) {
            throw 'Get-PulseExpansionRows: -ManifestSnapshot was explicitly supplied as null.'
        }
        if (-not $ManifestSnapshot.Contains('expansions') -or
            $ManifestSnapshot['expansions'] -isnot [System.Collections.IDictionary]) {
            throw 'Get-PulseExpansionRows: -ManifestSnapshot has no valid expansions dictionary.'
        }
        $manifest = $ManifestSnapshot
    } else {
        $manifest = Get-PulseSnapshotManifest -Store $Store
    }

    if ($manifest -isnot [System.Collections.IDictionary] -or
        -not $manifest.Contains('expansions') -or
        $manifest['expansions'] -isnot [System.Collections.IDictionary]) {
        throw 'Get-PulseExpansionRows: loaded manifest has no valid expansions dictionary.'
    }
    $expansions = $manifest['expansions']

    if (-not $expansions.Contains($Name)) {
        throw "Get-PulseExpansionRows: no manifest entry for expansion '$Name'."
    }

    $entry = $expansions[$Name]

    if ($entry.status -ne 'Expanded' -and $entry.status -ne 'Partial') {
        $reasonText = if ([string]::IsNullOrEmpty([string] $entry.reason)) { '(no reason recorded)' } else { [string] $entry.reason }
        throw "Get-PulseExpansionRows: expansion '$Name' has status '$($entry.status)', not 'Expanded'/'Partial' - there is no valid file to read (reason: $reasonText)."
    }

    if ([string]::IsNullOrEmpty([string] $entry.path) -or [string]::IsNullOrEmpty([string] $entry.sha256)) {
        throw "Get-PulseExpansionRows: expansion '$Name' has status '$($entry.status)' but is missing path/sha256 - the manifest entry is structurally incomplete and cannot be trusted."
    }

    $filePath = Join-Path $Store.Root $entry.path

    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Get-PulseExpansionRows: expansion file for '$Name' is missing from the snapshot store."
    }

    $rawBytes = [System.IO.File]::ReadAllBytes($filePath)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($rawBytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Get-PulseExpansionRows: hash mismatch for expansion '$Name' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at publish time."
    }

    $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    $lines = $content -split "`n"

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $lines) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        $rows.Add((ConvertFrom-Json -InputObject $line -Depth 64)) | Out-Null
    }

    return , [object[]] @($rows.ToArray())
}
