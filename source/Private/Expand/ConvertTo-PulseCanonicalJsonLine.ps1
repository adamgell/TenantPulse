<#
    Private: serialize a single object to one compact, canonical JSON-Lines line.

    Sibling of ConvertTo-PulseCanonicalJson (the pretty, indented serializer every dataset/
    reference file uses) rather than a forked duplicate: both call the SAME internal writer,
    Write-PulseCanonicalJsonValue, which now takes a -Compact switch. Ordering (object keys
    sorted ordinally) and escaping (ConvertTo-PulseCanonicalJsonString - the same function
    handles `\n`/`\r`/`\t`/control-character escaping either way) are therefore identical
    between the two output shapes by construction - only whitespace differs. This closes the
    "duplicate-helper seam" the T2.1 re-review flagged as the codebase's current smell: a
    second, independently-maintained ordering/escaping implementation for jsonl output would
    have been exactly that seam.

    Output shape: one JSON object, ordinal-sorted properties, no whitespace between tokens
    (no indentation, no newlines inside the object/array structure - embedded newlines
    WITHIN a string VALUE are still escaped to the two-character sequence `\n`, never a raw
    line break, so the line-per-record jsonl invariant can never be broken by a value that
    happens to contain a real newline), followed by exactly one trailing LF (`\n`) - never
    the two-character CRLF and never a BOM - so the emitted text is safe to concatenate
    directly into a `.jsonl` file one call at a time: each call's own trailing LF is the
    separator, and there is no line without one, including the file's last line.
#>

function ConvertTo-PulseCanonicalJsonLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int] $Depth = 64
    )

    $builder = [System.Text.StringBuilder]::new()

    Write-PulseCanonicalJsonValue -Value $InputObject -Builder $builder -IndentLevel 0 -MaxDepth $Depth -CurrentDepth 0 -Compact

    [void] $builder.Append("`n")

    return $builder.ToString()
}
