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
    equal one of $script:PulseSnapshotSupportedSchemaVersions EXACTLY (kept as one
    module-level array, matching the literals New-PulseSnapshotStore has ever written - if
    those literals ever change, this is the only other place that has to change with them).
    createdUtc, producer and datasets must also be present as real members - the same four
    fields Invoke-PulseEvaluation actually reads off the manifest later - so a structurally
    foreign or hand-edited manifest.json is rejected here, at open time, with a specific
    field name, rather than surfacing later as null/missing data quietly baked into a
    "successful" scored report.

    SCHEMA 1.1.0 (Task 2.1): New-PulseSnapshotStore now writes schemaVersion '1.1.0' (adds
    the `references`/`expansions` manifest namespaces - see that function's own
    docstring), but a schemaVersion '1.0.0' snapshot written by an earlier release must
    still open here successfully - readonly-compatible, not rejected. '1.0.0' is kept in
    $script:PulseSnapshotSupportedSchemaVersions for exactly that reason. A '1.0.0'
    manifest has no `references`/`expansions` members at all; this function does not
    require or backfill them - every reader of those namespaces (Get-PulseReferenceData,
    a future expansion reader) treats an absent member as "nothing captured/expanded for
    this store," not as a validation failure, so opening an old-schema store never throws
    here on that account.

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

# Every schemaVersion this module's writer (New-PulseSnapshotStore) has ever produced -
# '1.1.0' is the current literal it writes today; '1.0.0' is the pre-Task-2.1 literal,
# kept here so an older snapshot on disk still opens read-only-compatible (see this
# function's own SCHEMA 1.1.0 docstring section). Kept as a single named array so
# Get-PulseSnapshotStore never has to duplicate (and risk drifting from) either literal.
$script:PulseSnapshotSupportedSchemaVersions = @('1.0.0', '1.1.0')

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
    if ($script:PulseSnapshotSupportedSchemaVersions -notcontains $actualSchemaVersion) {
        $supportedText = $script:PulseSnapshotSupportedSchemaVersions -join ', '
        throw "Get-PulseSnapshotStore: '$manifestPath' declares schemaVersion '$actualSchemaVersion', but this module only supports '$supportedText' - '$resolvedRoot' is not a snapshot root this version of TenantPulse can safely re-evaluate."
    }

    foreach ($requiredMember in @('createdUtc', 'producer', 'datasets')) {
        if ($manifestContent.PSObject.Properties.Name -notcontains $requiredMember) {
            throw "Get-PulseSnapshotStore: '$manifestPath' is missing required member '$requiredMember' - '$resolvedRoot' is not a valid snapshot root."
        }
    }

    if ([string]::IsNullOrEmpty([string] $manifestContent.createdUtc)) {
        throw "Get-PulseSnapshotStore: '$manifestPath' has a null or empty createdUtc - '$resolvedRoot' is not a valid snapshot root."
    }

    # TYPE VALIDATION (post-review fix, three reproduced holes): the presence/non-empty
    # checks above are not enough - a manifest can carry a member that EXISTS and is
    # non-empty-as-a-string but is the WRONG SHAPE, and every one of these silently
    # corrupted a later stage instead of failing here, at open time, with a specific field
    # name (this module's own "no silent gaps" rule):
    #   - "datasets":null - PSObject.Properties still reports 'datasets' present, and
    #     [string] $null is "" which IS empty (caught above)... except a NULL JSON value
    #     round-trips through ConvertFrom-Json as $null while STILL satisfying the
    #     'contains' member-presence check, so it reached here in the pre-fix code, and
    #     downstream evaluation over a null datasets object previously produced a confident
    #     all-NotApplicable report with no error at all.
    #   - "datasets":"x" - a bare string is not $null (the check above never even runs a
    #     type check) and previously reached Invoke-PulseEvaluation, which expects an
    #     object with named members - it crashed later, mid-run, far from this function.
    #   - "createdUtc":"banana" - a non-empty string that is not a parseable timestamp
    #     previously passed the null/empty check above and was later fed straight into
    #     generatedUtc, garbage in, garbage out, with nothing catching it here.
    if ($null -eq $manifestContent.datasets -or $manifestContent.datasets -isnot [System.Management.Automation.PSObject]) {
        $actualDescription = if ($null -eq $manifestContent.datasets) { 'null' } else { $manifestContent.datasets.GetType().Name }
        throw "Get-PulseSnapshotStore: '$manifestPath' has a 'datasets' member that is not a non-null object (got: $actualDescription) - '$resolvedRoot' is not a valid snapshot root."
    }

    $createdUtcText = [string] $manifestContent.createdUtc
    $parsedCreatedUtc = [datetime]::MinValue
    if (-not [datetime]::TryParse($createdUtcText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref] $parsedCreatedUtc)) {
        throw "Get-PulseSnapshotStore: '$manifestPath' has a 'createdUtc' value ('$createdUtcText') that cannot be parsed as a timestamp - '$resolvedRoot' is not a valid snapshot root."
    }

    if ($null -eq $manifestContent.producer -or $manifestContent.producer -isnot [System.Management.Automation.PSObject]) {
        $actualDescription = if ($null -eq $manifestContent.producer) { 'null' } else { $manifestContent.producer.GetType().Name }
        throw "Get-PulseSnapshotStore: '$manifestPath' has a 'producer' member that is not a non-null object (got: $actualDescription) - '$resolvedRoot' is not a valid snapshot root."
    }

    return [pscustomobject]@{
        Root          = $resolvedRoot
        DatasetsPath  = Join-Path $resolvedRoot 'datasets'
        ReferencePath = Join-Path $resolvedRoot 'reference'
        ExpandedPath  = Join-Path $resolvedRoot 'expanded'
        ManifestPath  = $manifestPath
    }
}
