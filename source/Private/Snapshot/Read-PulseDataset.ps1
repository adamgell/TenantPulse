<#
    Private: read one dataset back out of a snapshot store.

    Re-hashes the on-disk bytes and compares against the sha256 recorded in the manifest at
    write time; a mismatch throws naming the file, since it means the dataset file and the
    manifest have drifted apart (tampering, partial write, disk corruption) and the data can
    no longer be trusted to be what was collected.

    HASHES RAW FILE BYTES, NOT RE-ENCODED TEXT (post-review fix, omp finding #2 - a
    reproduced integrity bypass): the pre-fix code called `Get-Content -Raw` (which DECODES
    the file into a .NET string, auto-detecting encoding from a BOM if one is present, or
    guessing otherwise) and then re-encoded that decoded string back to UTF8 bytes to hash -
    hashing a RE-ENCODING of what PowerShell decided the text was, not the bytes actually on
    disk. This is a real bypass, not a theoretical one: a file re-saved as UTF-16 (with a
    BOM) carrying the EXACT SAME decoded text content round-trips through `Get-Content -Raw`
    to an identical string, which then re-encodes to IDENTICAL UTF8 bytes and hashes
    IDENTICAL to what was recorded at write time - the hash check silently PASSES even
    though the actual on-disk bytes were completely swapped out for a different encoding
    (tampering or corruption that happens to preserve decoded text is exactly the case a
    hash check exists to catch, and this bypass defeated it). Fixed by reading the file as
    raw BYTES via `[System.IO.File]::ReadAllBytes` and hashing those bytes directly, with NO
    decode-then-re-encode step in between - the hash this function computes is now
    ALWAYS of the literal bytes on disk. The same raw byte array is then decoded to UTF8 text
    (this writer always writes UTF8-no-BOM, so this decode is exact for every file this
    module itself wrote) only AFTER the hash has already been verified against it, for JSON
    parsing.
#>

function Read-PulseDataset {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        # A captured expansion may read thousands of datasets governed by the same
        # immutable-on-disk manifest generation. Let that caller pin one explicit,
        # call-scoped view instead of reparsing manifest.json for every dataset. This is
        # deliberately not a store/global cache: manifest writers must always re-read the
        # latest generation while holding their mutex.
        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $ManifestSnapshot
    )

    Assert-PulseDatasetName -Name $Name

    if ($PSBoundParameters.ContainsKey('ManifestSnapshot')) {
        if ($null -eq $ManifestSnapshot) {
            throw 'Read-PulseDataset: -ManifestSnapshot was explicitly supplied as null.'
        }
        if (-not $ManifestSnapshot.Contains('datasets') -or
            $ManifestSnapshot['datasets'] -isnot [System.Collections.IDictionary]) {
            throw 'Read-PulseDataset: -ManifestSnapshot has no valid datasets dictionary.'
        }
        $manifest = $ManifestSnapshot
    } else {
        $manifest = Get-PulseSnapshotManifest -Store $Store
    }

    $datasets = $manifest['datasets']
    $fileName = "$Name.json"

    if (-not $datasets.Contains($Name)) {
        throw "Read-PulseDataset: no manifest entry for dataset '$Name' ($fileName)."
    }

    $entry = $datasets[$Name]
    if ($entry.status -in @('Failed', 'Skipped')) {
        throw "Read-PulseDataset: dataset '$Name' has status '$($entry.status)' and has no usable rows (failureClass=$($entry.failureClass), reasonCode=$($entry.reasonCode))."
    }
    if ($entry.status -notin @('Collected', 'Partial')) {
        throw "Read-PulseDataset: dataset '$Name' has unsupported status '$($entry.status)'."
    }
    $datasetPath = Join-Path $Store.DatasetsPath $fileName

    if (-not (Test-Path -LiteralPath $datasetPath -PathType Leaf)) {
        throw "Read-PulseDataset: dataset file '$fileName' is missing from the snapshot store."
    }

    # Two-pass file read: hash the literal on-disk bytes, then parse without decoding the
    # whole document into a single .NET string (the previous GetString + ConvertFrom-Json
    # path doubled the UTF-16 working set of a large dataset).
    $fileStream = [System.IO.File]::Open($datasetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha.ComputeHash($fileStream)
        } finally {
            $sha.Dispose()
        }
        $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        if ($actualSha256 -ne $entry.sha256) {
            throw "Read-PulseDataset: hash mismatch for dataset file '$fileName' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at write time."
        }

        $fileStream.Position = 0
        $document = [System.Text.Json.JsonDocument]::Parse($fileStream)
        try {
            $root = $document.RootElement
            $rows = [System.Collections.Generic.List[object]]::new()
            if ($root.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                # Parse bounded batches rather than invoking ConvertFrom-Json once per
                # element. The per-element form preserved the no-whole-document-UTF16
                # memory boundary, but paid cmdlet/parser startup 50,000 times for the
                # scale fixture (about 3x the former read time). A 128-row batch keeps the
                # temporary UTF-16 surface bounded while amortizing that startup cost.
                $batchSize = 128
                $batchBuilder = [System.Text.StringBuilder]::new()
                [void] $batchBuilder.Append('[')
                $batchCount = 0
                foreach ($element in $root.EnumerateArray()) {
                    if ($batchCount -gt 0) { [void] $batchBuilder.Append(',') }
                    [void] $batchBuilder.Append($element.GetRawText())
                    $batchCount++

                    if ($batchCount -ge $batchSize) {
                        [void] $batchBuilder.Append(']')
                        foreach ($parsedRow in @(ConvertFrom-Json -InputObject $batchBuilder.ToString() -Depth 64)) {
                            $rows.Add($parsedRow) | Out-Null
                        }
                        [void] $batchBuilder.Clear()
                        [void] $batchBuilder.Append('[')
                        $batchCount = 0
                    }
                }
                if ($batchCount -gt 0) {
                    [void] $batchBuilder.Append(']')
                    foreach ($parsedRow in @(ConvertFrom-Json -InputObject $batchBuilder.ToString() -Depth 64)) {
                        $rows.Add($parsedRow) | Out-Null
                    }
                }
            } elseif ($root.ValueKind -eq [System.Text.Json.JsonValueKind]::Null) {
                # empty
            } else {
                $rows.Add((ConvertFrom-Json -InputObject $root.GetRawText() -Depth 64)) | Out-Null
            }
        } finally {
            $document.Dispose()
        }
    } finally {
        $fileStream.Dispose()
    }

    $rowArray = [object[]] @($rows.ToArray())
    if ($null -ne $entry.itemCount -and $entry.itemCount -ne '' -and [int] $entry.itemCount -ne $rowArray.Count) {
        throw "Read-PulseDataset: itemCount mismatch for dataset file '$fileName' - expected $($entry.itemCount), got $($rowArray.Count). The file is truncated or corrupt."
    }

    return , $rowArray
}
