<#
    Private: create a snapshot store on disk.

    A snapshot store is a directory-with-manifest that every later TenantPulse component
    (collector, evaluator, renderers) builds on: datasets/ holds the raw collected data,
    reference/ holds supporting reference data, expanded/ holds derived/expanded artifacts,
    and manifest.json tracks the status, provenance and hash of every dataset written into
    the store.

    SCHEMA 1.1.0 (Task 2.1 - the schema is no longer frozen; the "later tasks must not
    extend it" note above this comment was wrong and is corrected here): the manifest gains
    two new top-level namespaces this function initializes empty on every fresh store -
    `references` (one entry per captured reference-data file, e.g. the settings-catalog
    definitions corpus; written by Set-PulseReferenceEntry) and `expansions` (one entry per
    derived/expanded artifact, e.g. a per-policy settings walk; written by
    Set-PulseExpansionEntry). Both reuse Set-PulseManifestEntry's own mutex/atomic
    tmp+rename machinery - see that function's docstring - rather than forking a second
    read-modify-write path. scoringModelVersion still belongs to the findings document, not
    the snapshot; that one boundary has not moved. A snapshot opened via Get-PulseSnapshotStore
    that declares schemaVersion 1.0.0 (written before this task) has NO `references`/
    `expansions` members at all - every reader of those namespaces treats an absent member
    exactly like an absent entry (nothing captured/expanded), never as an error; see
    Get-PulseSnapshotStore's own docstring for the read-side half of this compatibility
    contract.

    -Tenant (Task 1.5 handshake): the manifest's `tenant` field previously had no writer.
    The collector (Get-PulseTenantSnapshot) is the sole caller expected to pass this - it
    is always the PSEUDONYM of the tenant id (Get-PulsePseudonym's 'tp-...' output), never
    the raw id; see the module-wide pseudonymization rule. Defaults to $null so every
    existing caller (including every test that does not care about the tenant field) is
    unaffected.

    -GraphKitVersion (post-review fix, previously always null): producer.graphKit records
    the GraphKit module version that actually performed collection - was always $null with
    no writer at all before this fix. The caller (Get-PulseTenantSnapshot) resolves
    (Get-Module GraphKit).Version itself and passes it through - this function does not
    resolve it independently, since a caller that has no GraphKit context at all (the
    total-collection-failure path) legitimately has nothing to pass, and this parameter
    defaults to $null for exactly that case (documented, not a bug - see
    Get-PulseTenantSnapshot's own docstring).

    CLEAR-ON-REUSE (post-review fix, reproduced leak): calling this function on an EXISTING
    store path no longer just leaves whatever was already in datasets/, reference/ and
    expanded/ sitting there. A prior run's dataset file (or a foreign one dropped into the
    directory by something else entirely) would otherwise silently survive into the new
    run's store, undetectable from the fresh manifest.json this function writes - a stale
    or foreign file with no corresponding manifest entry, invisible to every reader that
    (correctly) trusts the manifest as the index of what is actually in the store. This
    function deliberately does NOT require an opt-in -Force flag for this - "reusing this
    path" and "starting a clean store at this path" are the same operation from a caller's
    perspective (Get-PulseTenantSnapshot never intends to layer one run's collection on top
    of another's), so clear-on-reuse is unconditional, not opt-in. Only the THREE
    subdirectories this function itself owns and recreates are cleared (datasets/,
    reference/, expanded/) - a path that is not yet a snapshot store at all (first call) has
    nothing to clear, and a caller-provided -Path that happens to contain OTHER files
    outside those three subdirectories is left alone; this function does not scrub the
    whole root, only the store-owned subtrees it is about to repopulate.
#>

function New-PulseSnapshotStore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Path,

        [Parameter()]
        [string] $Tenant = $null,

        [Parameter()]
        [string] $GraphKitVersion = $null
    )

    $root = New-Item -Path $Path -ItemType Directory -Force

    # Clear-on-reuse (see docstring above): remove each store-owned subdirectory entirely
    # before recreating it empty, so a prior run's (or a foreign) file left behind under
    # datasets/, reference/ or expanded/ never silently survives into this new store.
    foreach ($subdirName in @('datasets', 'reference', 'expanded')) {
        $subdirPath = Join-Path $root.FullName $subdirName
        if (Test-Path -LiteralPath $subdirPath) {
            Remove-Item -LiteralPath $subdirPath -Recurse -Force
        }
    }

    $datasetsPath = New-Item -Path (Join-Path $root.FullName 'datasets') -ItemType Directory -Force
    $referencePath = New-Item -Path (Join-Path $root.FullName 'reference') -ItemType Directory -Force
    $expandedPath = New-Item -Path (Join-Path $root.FullName 'expanded') -ItemType Directory -Force
    $manifestPath = Join-Path $root.FullName 'manifest.json'

    $moduleVersion = $null
    if ($MyInvocation.MyCommand.Module) {
        $moduleVersion = $MyInvocation.MyCommand.Module.Version.ToString()
    }

    $manifest = [ordered]@{
        schemaVersion     = '1.1.0'
        createdUtc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        tenant            = $Tenant
        producer          = [ordered]@{
            tenantPulse = $moduleVersion
            graphKit    = $GraphKitVersion
        }
        collectionFailure = $null
        datasets          = [ordered]@{}
        references        = [ordered]@{}
        expansions        = [ordered]@{}
    }

    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
    # Atomic write via the shared helper (post-review fix - see its own docstring), matching
    # every other manifest/dataset write in this codebase.
    Set-PulseAtomicFileContent -Path $manifestPath -Value $canonicalJson

    return [pscustomobject]@{
        Root          = $root.FullName
        DatasetsPath  = $datasetsPath.FullName
        ReferencePath = $referencePath.FullName
        ExpandedPath  = $expandedPath.FullName
        ManifestPath  = $manifestPath
    }
}
