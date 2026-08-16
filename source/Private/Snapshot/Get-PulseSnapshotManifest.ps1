<#
    Private: read and parse a snapshot store's manifest.json.

    Returns the manifest as a mutable hashtable tree (ConvertFrom-Json -AsHashtable), so
    both this function's own callers and Set-PulseManifestEntry (which reads, mutates and
    rewrites the same structure) work with one consistent shape. This is the evaluator's
    source for NA-with-reason: dataset statuses, reasons and hashes all come from here.
#>

function Get-PulseSnapshotManifest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject] $Store
    )

    $raw = Get-Content -LiteralPath $Store.ManifestPath -Raw
    return ConvertFrom-Json -InputObject $raw -AsHashtable -Depth 64
}
