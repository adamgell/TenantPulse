<#
    Private: read and parse a snapshot store's manifest.json.

    Returns the manifest as a mutable hashtable tree, so both this function's own callers
    and Set-PulseManifestEntry (which reads, mutates and rewrites the same structure) work
    with one consistent shape. This is the evaluator's source for NA-with-reason: dataset
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

function Get-PulseSnapshotManifest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject] $Store
    )

    $raw = Get-Content -LiteralPath $Store.ManifestPath -Raw
    return ConvertFrom-PulseJsonPreservingStrings -Json $raw -Depth 64 -AsHashtable
}
