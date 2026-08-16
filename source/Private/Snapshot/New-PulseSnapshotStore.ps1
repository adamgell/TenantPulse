<#
    Private: create a snapshot store on disk.

    A snapshot store is a directory-with-manifest that every later TenantPulse component
    (collector, evaluator, renderers) builds on: datasets/ holds the raw collected data,
    reference/ holds supporting reference data, expanded/ holds derived/expanded artifacts,
    and manifest.json tracks the status, provenance and hash of every dataset written into
    the store. This is the FINAL snapshot-manifest schema - later tasks consume it and must
    not extend it; scoringModelVersion belongs to the findings document, not the snapshot.
#>

function New-PulseSnapshotStore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Path
    )

    $root = New-Item -Path $Path -ItemType Directory -Force
    $datasetsPath = New-Item -Path (Join-Path $root.FullName 'datasets') -ItemType Directory -Force
    $referencePath = New-Item -Path (Join-Path $root.FullName 'reference') -ItemType Directory -Force
    $expandedPath = New-Item -Path (Join-Path $root.FullName 'expanded') -ItemType Directory -Force
    $manifestPath = Join-Path $root.FullName 'manifest.json'

    $moduleVersion = $null
    if ($MyInvocation.MyCommand.Module) {
        $moduleVersion = $MyInvocation.MyCommand.Module.Version.ToString()
    }

    $manifest = [ordered]@{
        schemaVersion     = '1.0.0'
        createdUtc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        tenant            = $null
        producer          = [ordered]@{
            tenantPulse = $moduleVersion
            graphKit    = $null
        }
        collectionFailure = $null
        datasets          = [ordered]@{}
    }

    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
    Set-Content -LiteralPath $manifestPath -Value $canonicalJson -NoNewline -Encoding utf8NoBOM

    return [pscustomobject]@{
        Root          = $root.FullName
        DatasetsPath  = $datasetsPath.FullName
        ReferencePath = $referencePath.FullName
        ExpandedPath  = $expandedPath.FullName
        ManifestPath  = $manifestPath
    }
}
