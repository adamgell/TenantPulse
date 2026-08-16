<#
    Private: read one reference-data file back out of a snapshot store.

    Mirrors Read-PulseDataset exactly, against manifest.references instead of
    manifest.datasets and reference/ instead of datasets/: re-hashes the on-disk bytes and
    compares against the sha256 recorded in the manifest at write time, throwing naming the
    file on a mismatch (tampering, partial write, disk corruption - the data can no longer
    be trusted to be what was captured).

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
    $referencePath = Join-Path $Store.ReferencePath $fileName

    if (-not (Test-Path -LiteralPath $referencePath -PathType Leaf)) {
        throw "Get-PulseReferenceData: reference file '$fileName' is missing from the snapshot store."
    }

    $content = Get-Content -LiteralPath $referencePath -Raw

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    if ($actualSha256 -ne $entry.sha256) {
        throw "Get-PulseReferenceData: hash mismatch for reference file '$fileName' - expected $($entry.sha256), got $actualSha256. The file no longer matches what the manifest recorded at capture time."
    }

    $parsed = ConvertFrom-Json -InputObject $content -Depth 64

    return , [object[]] @($parsed)
}
