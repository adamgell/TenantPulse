<#
    Private: the single funnel for every manifest.json write.

    Two mutually exclusive usages: update one dataset's status/reason/provenance entry
    (the path Write-PulseDataset uses internally for every status, including the
    Failed/Skipped case where no dataset file is written), or set the top-level
    collectionFailure field. No other function in the snapshot store writes manifest.json
    directly - this keeps every mutation going through one canonical-serialization path.
#>

function Set-PulseManifestEntry {
    [CmdletBinding(DefaultParameterSetName = 'Dataset')]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory, ParameterSetName = 'Dataset')]
        [string] $Name,

        [Parameter(Mandatory, ParameterSetName = 'Dataset')]
        [ValidateSet('Collected', 'Failed', 'Skipped')]
        [string] $Status,

        # Reason, ApiVersion, Sha256 and CollectedUtc are deliberately left untyped:
        # Write-PulseDataset always passes these explicitly (including an explicit $null
        # for a Failed/Skipped dataset with no reason, or for the fields only Collected
        # populates). A [string] parameter type would coerce an explicit $null argument
        # into an empty string during binding - PowerShell does this even with
        # [AllowNull()] - which would corrupt the null/absent distinction the manifest
        # schema relies on.
        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $Reason,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $ApiVersion,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $Sha256,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        [System.Nullable[int]] $ItemCount,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $CollectedUtc,

        [Parameter(Mandatory, ParameterSetName = 'CollectionFailure')]
        [string] $CollectionFailure
    )

    $manifest = Get-PulseSnapshotManifest -Store $Store

    if ($PSCmdlet.ParameterSetName -eq 'CollectionFailure') {
        $manifest.collectionFailure = $CollectionFailure
    }
    else {
        if (-not $manifest.ContainsKey('datasets') -or $null -eq $manifest.datasets) {
            $manifest.datasets = [ordered]@{}
        }

        $manifest.datasets[$Name] = [ordered]@{
            status       = $Status
            apiVersion   = $ApiVersion
            reason       = $Reason
            sha256       = $Sha256
            itemCount    = $ItemCount
            collectedUtc = $CollectedUtc
        }
    }

    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
    Set-Content -LiteralPath $Store.ManifestPath -Value $canonicalJson -NoNewline -Encoding utf8NoBOM
}
