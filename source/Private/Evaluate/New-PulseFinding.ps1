<#
    Private: build a rule result for a Function-type check rule.

    This is the rule-result contract every Function rule (Test-Pulse* -Datasets <hashtable>)
    must return, and the ONLY way a rule can produce Warn or evidence - an Expression rule
    can only ever resolve to Pass/Fail with no evidence (see Invoke-PulseEvaluation). The
    engine never constructs NotApplicable or Error results this way: those two statuses are
    engine-assigned (missing/degraded dataset, unsatisfied gate, or a thrown rule), never
    something a rule function returns.

    -Evidence accepts loosely-shaped input (hashtables or objects with Identity/Detail/
    SortKey members) and normalizes every entry to a plain {Identity; Detail; SortKey}
    pscustomobject with SortKey defaulted to Identity when omitted or blank. Every entry
    must carry a non-empty Identity - that is the only mandatory piece of evidence shape,
    since Identity is both what the redaction map is keyed on and the tie-breaker for
    evidence ordering.

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

    $normalized = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($item in @($Evidence)) {
        if ($null -eq $item) {
            continue
        }

        $identity = $null
        $detail = $null
        $sortKey = $null

        if ($item -is [System.Collections.IDictionary]) {
            if ($item.Contains('Identity')) { $identity = $item['Identity'] }
            if ($item.Contains('Detail')) { $detail = $item['Detail'] }
            if ($item.Contains('SortKey')) { $sortKey = $item['SortKey'] }
        } else {
            $propertyNames = $item.PSObject.Properties.Name
            if ($propertyNames -contains 'Identity') { $identity = $item.Identity }
            if ($propertyNames -contains 'Detail') { $detail = $item.Detail }
            if ($propertyNames -contains 'SortKey') { $sortKey = $item.SortKey }
        }

        if ($null -eq $identity -or [string]::IsNullOrEmpty([string] $identity)) {
            throw 'New-PulseFinding: every evidence entry must have a non-empty Identity.'
        }

        if ($null -eq $sortKey -or [string]::IsNullOrEmpty([string] $sortKey)) {
            $sortKey = $identity
        }

        $normalized.Add([pscustomobject]@{
            Identity = [string] $identity
            Detail   = $detail
            SortKey  = [string] $sortKey
        })
    }

    return [pscustomobject]@{
        PSTypeName = 'TenantPulse.RuleResult'
        Status     = $Status
        Evidence   = $normalized.ToArray()
        Reason     = $Reason
    }
}
