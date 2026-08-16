<#
    Private: read one dataset back out of a snapshot store.

    Re-hashes the on-disk bytes and compares against the sha256 recorded in the manifest at
    write time; a mismatch throws naming the file, since it means the dataset file and the
    manifest have drifted apart (tampering, partial write, disk corruption) and the data can
    no longer be trusted to be what was collected.
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

    $content = Get-Content -LiteralPath $datasetPath -Raw

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Read-PulseDataset: hash mismatch for dataset file '$fileName' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at write time."
    }

    $parsed = ConvertFrom-Json -InputObject $content -Depth 64

    return , [object[]] @($parsed)
}
