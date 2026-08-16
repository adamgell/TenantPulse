<#
    Private: the single funnel for every manifest.json write.

    Two mutually exclusive usages: update one dataset's status/reason/provenance entry
    (the path Write-PulseDataset uses internally for every status, including the
    Failed/Skipped case where no dataset file is written), or set the top-level
    collectionFailure field. No other function in the snapshot store writes manifest.json
    directly - this keeps every mutation going through one canonical-serialization path.

    The whole read-modify-write cycle is guarded by a named Mutex scoped to this store's
    root path, so two writers (same process, different threads, or different processes)
    never interleave a read-modify-write and silently drop one another's update. The write
    itself goes to manifest.json.tmp and is published with an atomic File.Move/replace, so
    a crash mid-write can never leave manifest.json truncated or half-written - readers see
    either the old manifest or the new one, never a partial one.
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

    if ($PSCmdlet.ParameterSetName -eq 'Dataset') {
        Assert-PulseDatasetName -Name $Name
    }

    # Mutex name is derived from a hash of the store root so every writer targeting the
    # same store - regardless of process - contends on the same named lock, while stores
    # at different paths never block each other.
    $rootHashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Store.Root))
    $rootHash = ([System.BitConverter]::ToString($rootHashBytes) -replace '-', '').ToLowerInvariant()
    $mutex = [System.Threading.Mutex]::new($false, "TenantPulse-SnapshotManifest-$rootHash")
    $acquired = $false

    try {
        $acquired = $mutex.WaitOne([System.TimeSpan]::FromSeconds(30))
        if (-not $acquired) {
            throw "Set-PulseManifestEntry: timed out waiting for the manifest lock on '$($Store.Root)'."
        }

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

        # Write-then-rename: the temp file lives beside the manifest so the rename is
        # same-volume (required for it to be atomic), and it is always gone again by the
        # time this function returns - either renamed into place, or removed in the
        # `finally` below if the write/move itself throws.
        $tempPath = "$($Store.ManifestPath).tmp"
        try {
            Set-Content -LiteralPath $tempPath -Value $canonicalJson -NoNewline -Encoding utf8NoBOM
            [System.IO.File]::Move($tempPath, $Store.ManifestPath, $true)
        }
        finally {
            if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
                Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        if ($acquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}
