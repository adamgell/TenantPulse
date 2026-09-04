<#
    Private: read and parse a snapshot store's manifest.json.

    Returns the manifest as a mutable IDictionary tree, so both this function's own callers
    and Set-PulseManifestEntry (which reads, mutates and rewrites the same structure) work
    with one consistent shape. Native PowerShell dictionary dot/index access is deliberately
    left intact; synthetic PSNoteProperty mirrors are not added because they become stale
    when a key is replaced and adapting every key turns a large manifest walk quadratic.
    This is the evaluator's source for NA-with-reason: dataset
    statuses, reasons and hashes all come from here - and, critically, createdUtc, which
    Invoke-PulseEvaluation reads straight off this function's return value as both
    'generatedUtc' (the findings document's own timestamp) and $Context.SnapshotCreatedUtc/
    EvaluationCutoffBase (the deterministic "as of when" every staleness-style rule
    compares against).

    CULTURE-COERCION FIX (Part E, T3.4, carried from the T3.3 review): this used to call
    plain `ConvertFrom-Json -InputObject $raw -AsHashtable -Depth 64`. Even WITH
    -AsHashtable, ConvertFrom-Json's default string handling still auto-parses any
    ISO-8601-looking JSON string value into a real [datetime] object - createdUtc included.
    That [datetime] then flowed, unconverted, into generatedUtc/SnapshotCreatedUtc/
    EvaluationCutoffBase, and every one of this module's own consumers of those context
    keys does `[string] $Context.EvaluationCutoffBase` before re-parsing it - but casting a
    [datetime] to [string] formats it with the CURRENT THREAD CULTURE (day-first on a
    day-first-locale host) at second precision, silently losing both correctness (wrong
    field order on a non-invariant host) and any sub-second fraction the original JSON
    string carried (a Graph timestamp can carry 7 fractional digits; ToString() drops all
    of them). ConvertFrom-PulseJsonPreservingStrings -AsHashtable is the same fix this
    module already applies to the findings-read path (Export-PulseReport.ps1,
    Export-PulseJsonReport.ps1) for exactly this class of bug: createdUtc (and every other
    string in the manifest) now round-trips as the EXACT original string, never coerced
    into any other CLR type, so every downstream consumer's own InvariantCulture re-parse
    sees the byte-identical source text.
#>

function ConvertTo-PulseMigratedManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Manifest
    )

    $schemaVersion = [string] $Manifest.schemaVersion
    if ($schemaVersion -notin @('1.0.0', '1.1.0')) {
        return $Manifest
    }

    if ($null -eq $Manifest.datasets -or $Manifest.datasets -isnot [System.Collections.IDictionary]) {
        throw "Get-PulseSnapshotManifest: legacy manifest schema '$schemaVersion' has no valid datasets object."
    }

    $migratedDatasets = [ordered]@{}
    foreach ($datasetName in @($Manifest.datasets.Keys)) {
        $legacyEntry = $Manifest.datasets[$datasetName]
        if ($null -eq $legacyEntry -or $legacyEntry -isnot [System.Collections.IDictionary]) {
            throw "Get-PulseSnapshotManifest: legacy manifest dataset '$datasetName' is not an object."
        }

        $status = [string] $legacyEntry.status
        if ($status -notin @('Collected', 'Failed', 'Skipped')) {
            throw "Get-PulseSnapshotManifest: legacy dataset '$datasetName' has unsupported status '$status'."
        }

        $legacyReason = if ($legacyEntry.Contains('reason')) { $legacyEntry.reason } else { $null }
        $reasonCode = "legacy-$($status.ToLowerInvariant())"
        $failureClass = switch ($status) {
            'Collected' { $null }
            'Failed' { 'ProviderFailed' }
            'Skipped' { 'GateUnknown' }
        }

        $migratedDatasets[$datasetName] = [ordered]@{
            status       = $status
            apiVersion   = if ($legacyEntry.Contains('apiVersion')) { $legacyEntry.apiVersion } else { $null }
            failureClass = $failureClass
            reasonCode   = $reasonCode
            detail       = $null
            provider     = $null
            operations   = @()
            gaps         = @()
            reason       = $legacyReason
            sha256       = if ($legacyEntry.Contains('sha256')) { $legacyEntry.sha256 } else { $null }
            itemCount    = if ($legacyEntry.Contains('itemCount')) { $legacyEntry.itemCount } else { $null }
            collectedUtc = if ($legacyEntry.Contains('collectedUtc')) { $legacyEntry.collectedUtc } else { $null }
        }
    }

    # Migration enriches legacy dataset entries in memory but deliberately preserves the
    # declared schema and namespace capability. A 1.0.0 store must remain unable to accept
    # reference/expansion writes; adding namespaces here would create a fake upgrade that
    # could be serialized by a later manifest write.
    $Manifest.datasets = $migratedDatasets

    return $Manifest
}

function Get-PulseSnapshotManifest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject] $Store
    )

    $raw = Get-Content -LiteralPath $Store.ManifestPath -Raw
    $manifest = ConvertFrom-PulseJsonPreservingStrings -Json $raw -Depth 64 -AsHashtable
    $manifest = ConvertTo-PulseMigratedManifest -Manifest $manifest
    return $manifest
}
