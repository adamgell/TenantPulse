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
    SortKey/RedactDetailKeys members, matched case-insensitively) and normalizes every
    entry to a plain {Identity; Detail; SortKey; RedactDetailKeys} pscustomobject with
    SortKey defaulted to Identity when omitted or blank and RedactDetailKeys defaulted to
    an empty array when omitted, via the shared ConvertTo-PulseNormalizedEvidence helper
    (same file).

    REDACT-DETAIL-KEYS (Phase 3 closing fix series, item 4 - minimal contract extension):
    an evidence entry MAY additionally carry -RedactDetailKeys, a string array naming
    identity-bearing keys WITHIN that entry's own Detail (e.g. `@('appleIdentifier')`) -
    for a value that is itself person-identifying (a UPN, email address, or person name)
    but lives only inside Detail, never as the entry's own Identity, and so would
    otherwise never be pseudonymized even under Invoke-PulseAssessment -Redact (which,
    before this extension, only ever substituted evidence.identity/evidence.sortKey - see
    Export-PulseJsonReport's own docstring). Invoke-PulseEvaluation's redaction-map-
    building loop reads each entry's RedactDetailKeys and, for each named key present in
    that entry's Detail with a non-null/non-empty value, adds THAT RAW VALUE to the SAME
    per-evaluation HMAC redaction map an evidence Identity would be added to - one
    map, one key derivation, no second pseudonymization mechanism. Export-PulseJsonReport
    then substitutes any Detail property, on any evidence entry, whose CURRENT raw value
    is a key in the redaction map (see that function's own docstring) - so a value never
    marked via RedactDetailKeys is never added to the map in the first place and is
    therefore never touched, regardless of what it looks like. Marking a key that does not
    exist in that entry's Detail, or whose value is $null/empty, is a harmless no-op - this
    function does not require the marked key to actually be present, since a rule may
    reuse a fixed RedactDetailKeys array across evidence rows whose Detail shape varies
    row to row (e.g. TP.INT.0021's organizationName, absent on some VPP token rows).
    Judgment boundary this extension does NOT change: tenant-resource GUIDs and policy
    display names stay unredacted (the documented -Redact boundary,
    Invoke-PulseAssessment's own docstring); only actually person-identifying Detail
    values (UPN/email/person-name/device-name-class) are candidates for marking.
    That helper is ALSO called directly by Invoke-PulseEvaluation against whatever a rule
    function actually returned - a rule is not obligated to build its result through
    New-PulseFinding, so the evaluator cannot trust that normalization already happened here
    and re-validates independently (see that function's own H2 fix note: a duck-typed
    RuleResult with a bad evidence entry must degrade that one check to Error, never crash
    the whole run).

    EVIDENCE-CONSTRUCTION IDIOM (Task 3.5 fold-in decision, RECORDED): this codebase has two
    idioms for building the -Evidence array a rule hands back - a hand-rolled
    `@{ Identity = ...; Detail = @{ ... }; SortKey = ... }` hashtable literal (the majority
    idiom, used throughout Task 3.3/3.4's Test-Pulse* rule functions and TP.ENT.0004/0005's
    Task 3.5 exclusion-honoring evidence) versus routing each entry through a dedicated
    ConvertTo-PulseMaesterEvidence-shaped helper before assembly. THE RULE: hand-rolled is
    fine; a per-entry helper is optional, never required. ConvertTo-PulseNormalizedEvidence
    above is the one and only place shape/validity is actually enforced - it accepts either
    idiom identically (loosely-shaped, case-insensitive member matching, is the whole point)
    - so a per-entry construction helper can only ever be sugar over an author's own
    call site, never a correctness requirement. Do NOT mass-rewrite an existing, working,
    tested rule function's evidence construction from one idiom to the other purely for
    idiom purity - that is pure churn against a passing test suite for zero behavioral
    gain. A new rule function is free to pick whichever idiom its author finds more
    readable for that rule's own evidence shape.

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
        $redactDetailKeys = $null

        # Key/property matching is case-insensitive (PowerShell's default string -eq),
        # deliberately - a duck-typed RuleResult a rule author hand-builds without going
        # through New-PulseFinding may not match casing exactly.
        if ($item -is [System.Collections.IDictionary]) {
            foreach ($key in @($item.Keys)) {
                if ($key -eq 'Identity') { $identity = $item[$key] }
                elseif ($key -eq 'Detail') { $detail = $item[$key] }
                elseif ($key -eq 'SortKey') { $sortKey = $item[$key] }
                elseif ($key -eq 'RedactDetailKeys') { $redactDetailKeys = $item[$key] }
            }
        } else {
            foreach ($propertyName in $item.PSObject.Properties.Name) {
                if ($propertyName -eq 'Identity') { $identity = $item.$propertyName }
                elseif ($propertyName -eq 'Detail') { $detail = $item.$propertyName }
                elseif ($propertyName -eq 'SortKey') { $sortKey = $item.$propertyName }
                elseif ($propertyName -eq 'RedactDetailKeys') { $redactDetailKeys = $item.$propertyName }
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

        # RedactDetailKeys normalizes to a possibly-empty [string[]] - every non-null,
        # non-empty element cast to [string]; a scalar single value (e.g. a bare string
        # instead of an array) is wrapped the same way `@()` around any scalar always
        # wraps it elsewhere in this codebase.
        $normalizedRedactDetailKeys = @()
        if ($null -ne $redactDetailKeys) {
            $normalizedRedactDetailKeys = @(
                foreach ($key in @($redactDetailKeys)) {
                    if ($null -ne $key -and -not [string]::IsNullOrEmpty([string] $key)) {
                        [string] $key
                    }
                }
            )
        }

        $normalized.Add([pscustomobject]@{
            Identity         = [string] $identity
            Detail           = $detail
            SortKey          = [string] $sortKey
            RedactDetailKeys = $normalizedRedactDetailKeys
        })
    }

    return $normalized.ToArray()
}
