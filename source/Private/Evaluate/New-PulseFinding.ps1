<#
    Private: build a rule result for a Function-type check rule.

    This is the rule-result contract every Function rule (Test-Pulse* -Datasets <hashtable>)
    must return, and the ONLY way a rule can produce Warn or evidence - an Expression rule
    can only ever resolve to Pass/Fail with no evidence (see Invoke-PulseEvaluation). The
    engine never constructs NotApplicable or Error results this way: those two statuses are
    engine-assigned (missing/degraded dataset, unsatisfied gate, or a thrown rule), never
    something a rule function returns.

    -Evidence accepts loosely-shaped input (hashtables or objects with Identity/Detail/
    SortKey members, matched case-insensitively) and normalizes every entry to a plain
    {Identity; Detail; SortKey} pscustomobject with SortKey defaulted to Identity when
    omitted or blank, via the shared ConvertTo-PulseNormalizedEvidence helper (same file).
    That helper is ALSO called directly by Invoke-PulseEvaluation against whatever a rule
    function actually returned - a rule is not obligated to build its result through
    New-PulseFinding, so the evaluator cannot trust that normalization already happened here
    and re-validates independently (see that function's own H2 fix note: a duck-typed
    RuleResult with a bad evidence entry must degrade that one check to Error, never crash
    the whole run).

    Deliberately carries PSTypeName 'TenantPulse.RuleResult': this object is an internal
    engine intermediate a rule function hands back to Invoke-PulseEvaluation, never
    serialized directly into the findings document (the evaluator extracts Status/Evidence/
    Reason into plain, PSTypeName-free structures first - see that function's own
    serialization-caveat note). It never reaches ConvertTo-PulseCanonicalJson as-is, so the
    "PSTypeName shows up as a visible JSON property" trap does not apply here.
#>

function New-PulseFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warn', 'Fail')]
        [string] $Status,

        [Parameter()]
        [AllowNull()]
        [object[]] $Evidence,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Reason
    )

    $normalized = ConvertTo-PulseNormalizedEvidence -Evidence $Evidence

    return [pscustomobject]@{
        PSTypeName = 'TenantPulse.RuleResult'
        Status     = $Status
        Evidence   = $normalized
        Reason     = $Reason
    }
}

# Private helper (not exported): shared evidence normalization/validation used by both
# New-PulseFinding (a rule building its own result) and Invoke-PulseEvaluation (validating
# whatever a rule actually returned, trusted or duck-typed). Throws on the first invalid
# entry - callers that need "one bad entry degrades this check to Error, run continues"
# (Invoke-PulseEvaluation) call this from inside their own per-check try/catch rather than
# swallowing the error here, so the failure is attributable to the right check and never
# aborts the whole evaluation.
function ConvertTo-PulseNormalizedEvidence {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]] $Evidence
    )

    $normalized = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($item in @($Evidence)) {
        if ($null -eq $item) {
            continue
        }

        $identity = $null
        $detail = $null
        $sortKey = $null

        # Key/property matching is case-insensitive (PowerShell's default string -eq),
        # deliberately - a duck-typed RuleResult a rule author hand-builds without going
        # through New-PulseFinding may not match casing exactly.
        if ($item -is [System.Collections.IDictionary]) {
            foreach ($key in @($item.Keys)) {
                if ($key -eq 'Identity') { $identity = $item[$key] }
                elseif ($key -eq 'Detail') { $detail = $item[$key] }
                elseif ($key -eq 'SortKey') { $sortKey = $item[$key] }
            }
        } else {
            foreach ($propertyName in $item.PSObject.Properties.Name) {
                if ($propertyName -eq 'Identity') { $identity = $item.$propertyName }
                elseif ($propertyName -eq 'Detail') { $detail = $item.$propertyName }
                elseif ($propertyName -eq 'SortKey') { $sortKey = $item.$propertyName }
            }
        }

        if ($null -eq $identity -or [string]::IsNullOrEmpty([string] $identity)) {
            throw 'evidence entry has no non-empty Identity.'
        }

        if ($null -eq $sortKey -or [string]::IsNullOrEmpty([string] $sortKey)) {
            $sortKey = $identity
        }

        # Detail serialization safety: it is going straight into the findings document,
        # so it must both survive ConvertTo-PulseCanonicalJson (arbitrary rule-authored
        # objects are not guaranteed to - e.g. a live .NET object with a circular
        # reference or an unsupported type) and never itself carry a PSTypeName key (the
        # same "visible property in JSON" trap Invoke-PulseEvaluation's own docstring
        # warns about for the finding/document objects it builds).
        if ($null -ne $detail) {
            try {
                $detailJson = ConvertTo-PulseCanonicalJson -InputObject $detail
            } catch {
                throw "evidence Detail for identity '$identity' is not serializable: $($_.Exception.Message)"
            }
            if ($detailJson -match '"PSTypeName"') {
                throw "evidence Detail for identity '$identity' carries a PSTypeName property, which the findings document may never contain."
            }
        }

        $normalized.Add([pscustomobject]@{
            Identity = [string] $identity
            Detail   = $detail
            SortKey  = [string] $sortKey
        })
    }

    return $normalized.ToArray()
}
