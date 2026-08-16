<#
    Private: open an EXISTING snapshot directory as a store handle, for -FromSnapshot use
    (Task 1.8's Invoke-PulseAssessment).

    Unlike New-PulseSnapshotStore, this function creates NOTHING on disk - it is a pure
    read/open operation. It validates that -Path actually looks like a snapshot root this
    module's own writer produced, and throws a clear, actionable error naming both the
    path and the offending field if not. This is the guard that lets
    Invoke-PulseAssessment -FromSnapshot skip collection entirely and still be confident
    it is about to evaluate something real, rather than an arbitrary, empty, or
    foreign-schema directory.

    SCHEMA VERSION GUARD (post-review fix - closes a real silent-gap hole): the original
    guard only checked that a schemaVersion property existed and was non-empty - ANY
    string satisfied it, including one this module never wrote (reproduced:
    {"schemaVersion":"9999.0.0"} opened cleanly and re-evaluated into a confident-looking,
    entirely NotApplicable scored report with a null tenant and null generatedUtc - the
    exact silent-gap failure this module forbids everywhere else). schemaVersion must now
    equal $script:PulseSnapshotSchemaVersion EXACTLY (kept as one module-level constant,
    matching the literal '1.0.0' New-PulseSnapshotStore itself writes - if that literal
    ever changes, this is the only other place that has to change with it). createdUtc,
    producer and datasets must also be present as real members - the same four fields
    Invoke-PulseEvaluation actually reads off the manifest later - so a structurally
    foreign or hand-edited manifest.json is rejected here, at open time, with a specific
    field name, rather than surfacing later as null/missing data quietly baked into a
    "successful" scored report.

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

# The one schemaVersion this module's writer (New-PulseSnapshotStore) actually produces -
# see that function's own literal. Kept as a single named constant so Get-PulseSnapshotStore
# never has to duplicate (and risk drifting from) the literal string.
$script:PulseSnapshotSchemaVersion = '1.0.0'

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

    $actualSchemaVersion = [string] $manifestContent.schemaVersion
    if (-not [string]::Equals($actualSchemaVersion, $script:PulseSnapshotSchemaVersion, [System.StringComparison]::Ordinal)) {
        throw "Get-PulseSnapshotStore: '$manifestPath' declares schemaVersion '$actualSchemaVersion', but this module only supports '$script:PulseSnapshotSchemaVersion' - '$resolvedRoot' is not a snapshot root this version of TenantPulse can safely re-evaluate."
    }

    foreach ($requiredMember in @('createdUtc', 'producer', 'datasets')) {
        if ($manifestContent.PSObject.Properties.Name -notcontains $requiredMember) {
            throw "Get-PulseSnapshotStore: '$manifestPath' is missing required member '$requiredMember' - '$resolvedRoot' is not a valid snapshot root."
        }
    }

    if ([string]::IsNullOrEmpty([string] $manifestContent.createdUtc)) {
        throw "Get-PulseSnapshotStore: '$manifestPath' has a null or empty createdUtc - '$resolvedRoot' is not a valid snapshot root."
    }

    return [pscustomobject]@{
        Root          = $resolvedRoot
        DatasetsPath  = Join-Path $resolvedRoot 'datasets'
        ReferencePath = Join-Path $resolvedRoot 'reference'
        ExpandedPath  = Join-Path $resolvedRoot 'expanded'
        ManifestPath  = $manifestPath
    }
}
