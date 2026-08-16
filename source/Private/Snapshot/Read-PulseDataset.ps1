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
        [string] $Name
    )

    Assert-PulseDatasetName -Name $Name

    $manifest = Get-PulseSnapshotManifest -Store $Store
    $fileName = "$Name.json"

    if (-not $manifest.datasets -or -not $manifest.datasets.ContainsKey($Name)) {
        throw "Read-PulseDataset: no manifest entry for dataset '$Name' ($fileName)."
    }

    $entry = $manifest.datasets[$Name]
    $datasetPath = Join-Path $Store.DatasetsPath $fileName

    if (-not (Test-Path -LiteralPath $datasetPath -PathType Leaf)) {
        throw "Read-PulseDataset: dataset file '$fileName' is missing from the snapshot store."
    }

    # RAW BYTES, not decoded-then-re-encoded text (see this file's own docstring, omp
    # finding #2) - the hash below is always of exactly what is on disk.
    $rawBytes = [System.IO.File]::ReadAllBytes($datasetPath)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($rawBytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Read-PulseDataset: hash mismatch for dataset file '$fileName' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at write time."
    }

    $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    $parsed = ConvertFrom-Json -InputObject $content -Depth 64

    return , [object[]] @($parsed)
}
