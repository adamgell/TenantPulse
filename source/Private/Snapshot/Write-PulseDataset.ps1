<#
    Private: write one collected dataset into a snapshot store.

    For -Status Collected, strips GraphKit's per-row provenance stamps (_Tenant,
    _RetrievedUtc, _GraphPath, _ApiVersion - see Remove-PulseGraphRowProvenance for why:
    all four duplicate a manifest field this dataset's own entry already carries, or carry
    nothing TenantPulse's schema needs), serializes -Data through the canonical JSON
    primitive, writes datasets/<Name>.json, hashes the exact bytes written, and records
    status/apiVersion/sha256/itemCount/collectedUtc in the manifest. For -Status Failed or
    -Status Skipped, no dataset file is written - only the manifest entry, via
    Set-PulseManifestEntry, which is the sole function allowed to touch manifest.json.
#>

function Write-PulseDataset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [object[]] $Data = @(),

        [Parameter(Mandatory)]
        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion,

        [Parameter(Mandatory)]
        [ValidateSet('Collected', 'Failed', 'Skipped')]
        [string] $Status,

        # Deliberately untyped: a [string] parameter left unbound here defaults to ""
        # rather than $null (PowerShell's normal behavior for value-shaped types), which
        # would turn "no reason given" into a stored empty string instead of the absent/
        # null the manifest schema and Set-PulseManifestEntry distinguish.
        [Parameter()]
        [AllowNull()]
        $Reason
    )

    Assert-PulseDatasetName -Name $Name

    if ($Status -ne 'Collected') {
        Set-PulseManifestEntry -Store $Store -Name $Name -Status $Status -Reason $Reason -ApiVersion $ApiVersion
        return
    }

    $items = @($Data)
    # NOT wrapped in @(...): Remove-PulseGraphRowProvenance already returns a proper
    # array via the unary comma operator (`return , $Data`) so PowerShell's pipeline
    # never unrolls it to individual rows. Wrapping that call in @(...) here would
    # capture the whole returned array as pipeline output and re-wrap IT in a second
    # one-element array - silently truncating every dataset with more than one row down
    # to itemCount 1 (caught by this file's own test suite; verified empirically that a
    # direct assignment does not have this problem, only @(functionCall) around a
    # comma-protected return does).
    $items = Remove-PulseGraphRowProvenance -Data $items
    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $items
    $datasetPath = Join-Path $Store.DatasetsPath "$Name.json"
    Set-Content -LiteralPath $datasetPath -Value $canonicalJson -NoNewline -Encoding utf8NoBOM

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    $collectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)

    Set-PulseManifestEntry -Store $Store -Name $Name -Status $Status -Reason $Reason -ApiVersion $ApiVersion `
        -Sha256 $sha256 -ItemCount $items.Count -CollectedUtc $collectedUtc
}
