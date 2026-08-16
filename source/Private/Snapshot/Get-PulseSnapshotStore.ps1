<#
    Private: open an EXISTING snapshot directory as a store handle, for -FromSnapshot use
    (Task 1.8's Invoke-PulseAssessment).

    Unlike New-PulseSnapshotStore, this function creates NOTHING on disk - it is a pure
    read/open operation. It validates that -Path actually looks like a snapshot root (a
    manifest.json directly under it, parseable as JSON, with a non-empty schemaVersion
    property - the same "is this a snapshot root" check Get-PulseOperatorKey's own guard
    performs inline) and throws a clear, actionable error naming the path if not. This is
    the guard that lets Invoke-PulseAssessment -FromSnapshot skip collection entirely and
    still be confident it is about to evaluate something real, rather than an arbitrary or
    empty directory.

    The returned handle has the exact same shape New-PulseSnapshotStore returns (Root/
    DatasetsPath/ReferencePath/ExpandedPath/ManifestPath), so every downstream consumer
    (Get-PulseSnapshotManifest, Read-PulseDataset, Invoke-PulseEvaluation, ...) works
    identically against either a freshly-created or a re-opened store. DatasetsPath/
    ReferencePath/ExpandedPath are NOT required to already exist as directories - this
    function's job is only to validate the manifest and hand back the path shape; a
    missing subdirectory surfaces naturally and specifically later, the first time
    something actually tries to read from it (Read-PulseDataset etc.), rather than being
    pre-emptively (and possibly wrongly) rejected here.
#>

function Get-PulseSnapshotStore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Get-PulseSnapshotStore: '$Path' does not exist or is not a directory - it cannot be opened as a snapshot store."
    }

    $resolvedRoot = (Resolve-Path -LiteralPath $Path).ProviderPath
    $manifestPath = Join-Path $resolvedRoot 'manifest.json'

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Get-PulseSnapshotStore: '$resolvedRoot' does not contain a manifest.json - it is not a valid snapshot root."
    }

    try {
        $manifestContent = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Get-PulseSnapshotStore: '$manifestPath' could not be parsed as JSON - '$resolvedRoot' is not a valid snapshot root. $($_.Exception.Message)"
    }

    if ($manifestContent.PSObject.Properties.Name -notcontains 'schemaVersion' -or
        [string]::IsNullOrEmpty([string] $manifestContent.schemaVersion)) {
        throw "Get-PulseSnapshotStore: '$manifestPath' has no non-empty schemaVersion property - '$resolvedRoot' is not a valid snapshot root."
    }

    return [pscustomobject]@{
        Root          = $resolvedRoot
        DatasetsPath  = Join-Path $resolvedRoot 'datasets'
        ReferencePath = Join-Path $resolvedRoot 'reference'
        ExpandedPath  = Join-Path $resolvedRoot 'expanded'
        ManifestPath  = $manifestPath
    }
}
