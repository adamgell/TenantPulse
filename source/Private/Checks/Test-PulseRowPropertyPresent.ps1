<#
    Private: shape-neutral "does this row actually carry this property at all" check for a
    check rule function (Task 3.2, post-review field-absence-lens fix).

    TRAP THIS EXISTS TO AVOID (already independently discovered and documented elsewhere in
    this module - see Resolve-PulseSettingsCatalogValueClassification.ps1's own
    Get-PulseSettingsCatalogValueProperty docstring, and Protect-PulseGraphRowTenantId.ps1's
    own docstring, for the earlier instances of this exact bug class): a check rule function
    receives its -Datasets rows AFTER Invoke-PulseEvaluation's own
    ConvertTo-PulseClonedDatasets deep-clone, which round-trips every dataset through
    ConvertTo-PulseCanonicalJson -> ConvertFrom-Json -AsHashtable. That means every row a
    rule actually sees is a Hashtable (System.Collections.IDictionary), never the
    [pscustomobject] a fixture test's own hand-authored Data array used to build it.
    `.PSObject.Properties[name]` on a Hashtable ALWAYS returns the fixed IDictionary
    adapter member set (Count/Keys/Values/...), never the hashtable's own entries - a
    presence check built on it silently reads "property absent" for every field, on every
    row, regardless of what the row actually contains. This function checks BOTH shapes
    correctly, so it is safe to call whether $Row is (still) a pscustomobject (e.g. a rule
    unit test invoking the function directly, bypassing the evaluator's clone) or the
    Hashtable shape every row is in a real, engine-run evaluation.
#>

function Test-PulseRowPropertyPresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Row,

        [Parameter(Mandatory)]
        [string] $PropertyName
    )

    if ($null -eq $Row) { return $false }

    if ($Row -is [System.Collections.IDictionary]) {
        return $Row.Contains($PropertyName)
    }

    return $null -ne $Row.PSObject.Properties[$PropertyName]
}
