<#
    Private: build a rule result for a Function-type check rule.

    This is the rule-result contract every Function rule (Test-Pulse* -Datasets <hashtable>)
    must return, and the ONLY way a rule can produce Warn or evidence - an Expression rule
    can only ever resolve to Pass/Fail with no evidence (see Invoke-PulseEvaluation).

    NOT APPLICABLE (post-review, adjudicated): a rule MAY now also return Status
    'NotApplicable' - not only the engine (missing/degraded dataset, unsatisfied gate). This
    closes a real gap: a check whose condition genuinely does not apply given what the rule
    itself observed in $Datasets (e.g. TP.ENT.0001 once Conditional Access supersedes
    Security Defaults as the control that matters) has no honest way to say so under a
    Pass/Warn/Fail-only contract - Pass-with-a-caveat-Reason silently inflates the tenant's
    score with unearned credit, since Add-PulseScores treats every Pass as fully earned
    regardless of Reason text. Rule-returned NotApplicable is threaded through
    Invoke-PulseEvaluation into the exact same status string as engine-assigned
    NotApplicable, so it lands in the identical scoring-exclusion bucket (Add-PulseScores
    keys off the finding's `status` string alone - it has no notion of who assigned it).
    `Reason` is MANDATORY when Status is 'NotApplicable' (enforced below) - unlike
    engine-assigned NotApplicable, whose reason is a manifest dataset/gate reason that
    always exists by construction, a rule choosing NotApplicable must always explain why, or
    the finding is meaningless to a reader.

    Error remains engine-assigned only (a thrown rule, or a shape the engine could not
    interpret) - no rule function or expression can ever construct an Error result.

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
        [ValidateSet('Pass', 'Warn', 'Fail', 'NotApplicable')]
        [string] $Status,

        [Parameter()]
        [AllowNull()]
        [object[]] $Evidence,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Reason
    )

    if ($Status -eq 'NotApplicable' -and [string]::IsNullOrEmpty($Reason)) {
        throw "New-PulseFinding: -Reason is mandatory when -Status is 'NotApplicable' - a rule declaring its own check inapplicable must always say why."
    }

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
