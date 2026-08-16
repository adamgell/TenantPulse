<#
    Private: render a scored findings document to canonical JSON on disk (Task 1.8's JSON
    renderer - the only renderer Phase 1 ships).

    Always writes <OutputPath>/tenantpulse-findings.json via ConvertTo-PulseCanonicalJson,
    the same determinism primitive every other TenantPulse artifact serializes through.

    REDACTION-MAP HANDLING (T1.6 DEFERRED CONTRACT - READ BEFORE CHANGING): Invoke-
    PulseEvaluation returns [pscustomobject]@{ Document; RedactionMap } specifically so a
    generic serializer is never handed the wrapper directly - under ANY generic serializer
    (including ConvertTo-PulseCanonicalJson itself) BOTH members would serialize, meaning
    the redaction map (raw evidence identity -> pseudonym) would leak into a report file if
    the wrapper were ever passed straight through. This function is one of the only two
    callers in the codebase allowed to see a RedactionMap at all (the other being its own
    caller, Invoke-PulseAssessment) - it accepts -Document and -RedactionMap as SEPARATE
    parameters for exactly this reason, and only ever calls ConvertTo-PulseCanonicalJson on
    a plain findings document, never on anything RedactionMap-shaped.

    -RedactionMap substitutes each finding's evidence[].identity value with its mapped
    'tp-...' pseudonym (never .detail, never any other field), on a DEEP CLONE of -Document
    (the same ConvertTo-PulseCanonicalJson -> ConvertFrom-Json round-trip clone pattern
    Add-PulseScores/ConvertTo-PulseClonedDatasets already establish elsewhere in this
    codebase) - -Document itself is never mutated in place, so a caller holding the
    original scored document (e.g. to report .scores/.coverage back to its own caller)
    never sees it change out from under it. An identity absent from the map (should not
    happen for a map built from the SAME evaluation run this document came from, but this
    function is defensive rather than assuming that invariant) is left unredacted rather
    than thrown on - this function cannot tell an intentional absence from a real gap, and
    "no silent gaps" is about dataset/check degradation reasons, not a mandate to invent a
    placeholder pseudonym here.

    evidence[].sortKey is redacted through the SAME map lookup, using the sortKey value
    itself as the key: New-PulseFinding defaults an evidence entry's sortKey to its raw
    Identity whenever no explicit SortKey is supplied (see that function's own docstring),
    so an untouched default sortKey is exactly as much of a raw-identity leak as the
    identity field would be. A sortKey that is genuinely a custom, non-identity value is
    never a key in -RedactionMap (the map is built only from evidence Identity values) and
    is therefore left untouched, correctly.

    CHOKE-POINT GUARD (post-review fix): -Document is rejected outright, before anything
    else, if its own top-level properties include a member literally named 'RedactionMap'
    - reproduced proof that handing this function the T1.6 wrapper object directly (instead
    of its .Document member) serializes the raw redaction map straight into the report.
    This is the last line of defense for the "never serialize the wrapper" rule described
    above: every current caller already destructures .Document/.RedactionMap correctly, but
    a future caller that forgets to now fails loudly at this function's own boundary
    instead of silently leaking raw evidence identities into a file on disk.

    Returns the full path to the file written.
#>

function Export-PulseJsonReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Document,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath,

        [Parameter()]
        [AllowNull()]
        [hashtable] $RedactionMap
    )

    if ($Document.PSObject.Properties.Name -contains 'RedactionMap') {
        throw 'Export-PulseJsonReport: -Document has a top-level RedactionMap property - this looks like the Invoke-PulseEvaluation wrapper {Document;RedactionMap} was passed directly instead of its .Document member. Pass -Document $evaluation.Document and -RedactionMap $evaluation.RedactionMap separately; never serialize the wrapper itself.'
    }

    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $documentToWrite = $Document

    if ($null -ne $RedactionMap -and $RedactionMap.Count -gt 0) {
        # Deep clone before mutating - see NON-MUTATION note above. Reuses the same
        # canonical-JSON round-trip clone pattern the rest of this codebase already uses.
        # ConvertFrom-PulseJsonPreservingStrings (CI BLOCKER fix - see that function's own
        # docstring): behaves exactly like `ConvertFrom-Json -DateKind String` on every
        # supported PowerShell version, including the 7.4 module floor where -DateKind
        # does not exist as a parameter at all. Without the -DateKind String behavior,
        # ConvertFrom-Json parses an ISO-8601-looking timestamp string into [datetime], and
        # re-serializing it below reformats it at millisecond precision - silently
        # dropping a 7-digit-fraction Graph timestamp's extra digits and making a -Redact
        # report's untouched timestamp fields diverge, byte-for-byte, from the same field
        # in an unredacted report of the same run. See Export-PulseReport's own read path
        # for the matching fix.
        $json = ConvertTo-PulseCanonicalJson -InputObject $Document
        $documentToWrite = ConvertFrom-PulseJsonPreservingStrings -Json $json -Depth 64

        foreach ($finding in @($documentToWrite.findings)) {
            foreach ($evidence in @($finding.evidence)) {
                $identity = [string] $evidence.identity
                if ($RedactionMap.ContainsKey($identity)) {
                    $evidence.identity = $RedactionMap[$identity]
                }

                # New-PulseFinding defaults an evidence entry's sortKey to its raw Identity
                # when no explicit SortKey is given (see that function's own docstring) -
                # a sortKey that happens to equal a raw identity is therefore just as much
                # a leak as the identity field itself, and is redacted through the SAME
                # map lookup. A sortKey that is NOT a raw identity (a custom, non-identity
                # sort key) is never present as a RedactionMap key and is correctly left
                # untouched.
                $sortKey = [string] $evidence.sortKey
                if ($RedactionMap.ContainsKey($sortKey)) {
                    $evidence.sortKey = $RedactionMap[$sortKey]
                }
            }
        }
    }

    $resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $reportPath = Join-Path $resolvedOutputPath 'tenantpulse-findings.json'
    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $documentToWrite
    Set-Content -LiteralPath $reportPath -Value $canonicalJson -NoNewline -Encoding utf8NoBOM

    return $reportPath
}
