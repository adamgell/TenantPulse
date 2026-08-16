<#
    .SYNOPSIS
        Re-renders an already-scored findings JSON file - render-only, no redaction.

    .DESCRIPTION
        Export-PulseReport is TenantPulse's render-only path: it reads an existing findings
        document (already produced and scored by Invoke-PulseAssessment or Invoke-PulseCheck)
        from -FindingsPath, and re-serializes it through the same canonical-JSON renderer
        (ConvertTo-PulseCanonicalJson) to <OutputPath>/tenantpulse-findings.json. Because
        canonical JSON is a deterministic function of the object graph, re-rendering the
        SAME findings document is byte-identical to the original file - this command adds
        no wall-clock timestamp, no re-evaluation, no re-scoring, nothing that could make
        two renders of the same input differ.

        NO -Redact PARAMETER: this command has none, deliberately, and cannot be made to
        accept one. Redaction depends on a per-evaluation redaction map (raw evidence
        identity -> pseudonym) that Invoke-PulseEvaluation builds fresh, in memory, for the
        one call that produced it (see that function's own docstring, Task 1.6) - the map
        is never persisted to disk, never embedded in the findings JSON, and therefore
        simply does not exist by the time Export-PulseReport ever runs. A findings file
        that was written unredacted cannot be redacted after the fact by this command; the
        only way to get a redacted report is Invoke-PulseAssessment -Redact (a fresh
        evaluation) or Invoke-PulseAssessment -FromSnapshot ... -Redact (a re-evaluation of
        an existing snapshot, which rebuilds the map fresh and deterministically, since the
        pseudonym HMAC is keyed and stable).

    .EXAMPLE
        Export-PulseReport -FindingsPath './out/tenantpulse-findings.json' -Format Json -OutputPath './copy'

        Reads an existing findings document and re-renders it, unchanged, to
        ./copy/tenantpulse-findings.json.

    .PARAMETER FindingsPath
        Path to an existing findings JSON file (as written by Invoke-PulseAssessment or
        Invoke-PulseCheck) to read and re-render.

    .PARAMETER Format
        Output report format. Phase 1 supports only 'Json', the default and only accepted
        value today - kept as an explicit parameter so a future renderer is additive.

    .PARAMETER OutputPath
        Directory to write the re-rendered tenantpulse-findings.json into. Created if it
        does not already exist.
#>
function Export-PulseReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $FindingsPath,

        [Parameter()]
        [ValidateSet('Json')]
        [string] $Format = 'Json',

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath
    )

    if (-not (Test-Path -LiteralPath $FindingsPath -PathType Leaf)) {
        throw "Export-PulseReport: findings file not found at '$FindingsPath'."
    }

    # ConvertFrom-PulseJsonPreservingStrings (CI BLOCKER fix - module floor is PS 7.4,
    # where ConvertFrom-Json's -DateKind parameter does not exist at all): behaves exactly
    # like `ConvertFrom-Json -DateKind String` - every JSON string round-trips as a
    # [string], never inferred into a [datetime] - on every supported PowerShell version,
    # including 7.4, where it uses a JsonDocument-based fallback instead. Plain
    # ConvertFrom-Json (no -DateKind) is FORBIDDEN here: its default behavior parses any
    # ISO-8601-looking string into [datetime], which the canonical serializer then
    # reformats at millisecond precision - silently dropping the extra digits of a
    # 7-digit-fraction Graph timestamp and making a re-rendered report diverge, byte-for-
    # byte, from the file it was read from. See that function's own docstring for the full
    # 7.4/7.5+ accounting, and Export-PulseJsonReport's own -RedactionMap clone path, which
    # needs the identical fix.
    $rawFindingsJson = Get-Content -LiteralPath $FindingsPath -Raw -ErrorAction Stop
    $document = ConvertFrom-PulseJsonPreservingStrings -Json $rawFindingsJson -Depth 64

    # Dispatches on -Format even though ValidateSet allows only 'Json' today - kept
    # explicit (rather than always calling the Json renderer unconditionally) so a future
    # renderer is additive here, not a rewrite of this dispatch.
    $reportPath = switch ($Format) {
        'Json' { Export-PulseJsonReport -Document $document -OutputPath $OutputPath }
        default { throw "Export-PulseReport: unsupported -Format '$Format'." }
    }

    return [pscustomobject]@{
        FindingsPath = $FindingsPath
        ReportPaths  = [pscustomobject]@{ Json = $reportPath }
    }
}
