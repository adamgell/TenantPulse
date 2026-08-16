<#
    Private: structurally validate one parsed check descriptor hashtable.

    Returns an array of human-readable error strings (empty array when the descriptor is
    valid) rather than throwing, so the caller (Import-PulseCheckCatalog) can aggregate
    errors across every descriptor in a directory into a single thrown error instead of
    failing fast on the first bad file. Each returned line is
    "<Label>: <Property>: <problem>" - the caller is responsible for prefixing the source
    filename onto each line before it reaches an operator (see Import-PulseCheckCatalog),
    since this function is never told which file it is validating.

    This function only checks one descriptor in isolation - duplicate-Id detection across
    a whole catalog is the loader's job, not this function's.

    Type enforcement: Import-PowerShellDataFile happily hands back whatever shape a .psd1
    author wrote - PowerShell's loose typing means `Id = @('TP.ENT.0001')` parses without
    error and then silently coerces through `-notmatch`/`-notin` string comparisons and
    lands array-typed in the output object. Every field below is therefore explicitly
    type-checked (scalar [string] vs. required-array [string[]]) BEFORE any
    pattern/enum/emptiness check runs on it, and a type mismatch is reported as its own
    "must be a <expected>, got <actual type>" error rather than silently passing or
    producing a confusing downstream error.

    Dataset map cross-check (T1.5 handshake): -DatasetMap is the ALREADY-PARSED shared
    dataset map hashtable (source/Data/DatasetMap.psd1, created by Task 1.5), or $null.
    Import-PulseCheckCatalog parses that file exactly once per catalog load (not once per
    descriptor - re-parsing per descriptor was wasteful and let a malformed map explode
    with a raw error instead of an aggregated one) and passes the same hashtable into
    every descriptor's validation call. $null means "no map available yet" and the
    cross-check is skipped for every descriptor.
#>

function Test-PulseCheckDescriptor {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable] $Descriptor,

        [Parameter(Mandatory)]
        [string] $Label,

        [Parameter()]
        [AllowNull()]
        [hashtable] $DatasetMap,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $DatasetMapPath
    )

    $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info')
    $validEffortImpact = @('Low', 'Medium', 'High')
    $validRuleTypes = @('Function', 'Expression')
    $errors = [System.Collections.Generic.List[string]]::new()

    function Get-PulseTypeDisplayName {
        param($Value)
        if ($null -eq $Value) { return 'null' }
        return $Value.GetType().Name
    }

    # Validates a required-or-optional SCALAR string field. Adds "is required." if the key
    # is absent/blank (only when -Required), "must be a string, got <Type>." if present
    # but not a [string] (e.g. an array, a number, a hashtable). Returns the validated
    # string, or $null if the field is missing/blank/wrong-typed, so callers only run
    # further pattern/enum checks against a confirmed real string.
    function Test-PulseScalarStringField {
        param(
            [hashtable] $Container,
            [string] $Key,
            [string] $FieldPath,
            [switch] $Required
        )

        if (-not $Container.ContainsKey($Key)) {
            if ($Required) { $errors.Add("${Label}: ${FieldPath}: is required.") }
            return $null
        }

        $value = $Container[$Key]

        if ($null -ne $value -and $value -isnot [string]) {
            $errors.Add("${Label}: ${FieldPath}: must be a string, got $(Get-PulseTypeDisplayName $value).")
            return $null
        }

        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string] $value)) {
            if ($Required) { $errors.Add("${Label}: ${FieldPath}: is required.") }
            return $null
        }

        return [string] $value
    }

    # Validates a required-array-of-strings field (Data.Datasets, References.Authorities,
    # Consulting.Remediation, Consulting.PortalLinks) or an allowed-empty one (Data.Gates).
    # Adds "must be a string array, got <Type>." for anything that is not an [array]
    # (including a bare scalar string - `Datasets = 'foo'` is a common authoring mistake
    # that would otherwise silently iterate over individual characters), "must not be
    # empty." when empty and not -AllowEmpty, and a per-element error for any element that
    # is not itself a non-blank [string]. Returns the validated string[] on success, $null
    # otherwise.
    function Test-PulseStringArrayField {
        param(
            [hashtable] $Container,
            [string] $Key,
            [string] $FieldPath,
            [switch] $AllowEmpty
        )

        if (-not $Container.ContainsKey($Key)) {
            $errors.Add("${Label}: ${FieldPath}: is required.")
            return $null
        }

        $value = $Container[$Key]

        if ($null -eq $value -or $value -isnot [array]) {
            $errors.Add("${Label}: ${FieldPath}: must be a string array, got $(Get-PulseTypeDisplayName $value).")
            return $null
        }

        $items = @($value)

        if (-not $AllowEmpty -and $items.Count -eq 0) {
            $errors.Add("${Label}: ${FieldPath}: must not be empty.")
            return $null
        }

        $ok = $true
        for ($i = 0; $i -lt $items.Count; $i++) {
            $item = $items[$i]
            if ($item -isnot [string]) {
                $errors.Add("${Label}: ${FieldPath}[$i]: must be a string, got $(Get-PulseTypeDisplayName $item).")
                $ok = $false
            } elseif ([string]::IsNullOrWhiteSpace($item)) {
                $errors.Add("${Label}: ${FieldPath}: contains a blank element.")
                $ok = $false
            }
        }

        if (-not $ok) { return $null }
        return [string[]] $items
    }

    # Id
    $id = Test-PulseScalarStringField -Container $Descriptor -Key 'Id' -FieldPath 'Id' -Required
    if ($null -ne $id -and $id -notmatch '^TP\.(INT|ENT)\.\d{4}$') {
        $errors.Add("${Label}: Id: '$id' does not match the required pattern ^TP\.(INT|ENT)\.\d{4}$.")
    }

    # Title / Category
    Test-PulseScalarStringField -Container $Descriptor -Key 'Title' -FieldPath 'Title' -Required | Out-Null
    Test-PulseScalarStringField -Container $Descriptor -Key 'Category' -FieldPath 'Category' -Required | Out-Null

    # Severity
    $severity = Test-PulseScalarStringField -Container $Descriptor -Key 'Severity' -FieldPath 'Severity' -Required
    if ($null -ne $severity -and $severity -notin $validSeverities) {
        $errors.Add("${Label}: Severity: '$severity' is not one of: $($validSeverities -join '|').")
    }

    # Effort
    $effort = Test-PulseScalarStringField -Container $Descriptor -Key 'Effort' -FieldPath 'Effort' -Required
    if ($null -ne $effort -and $effort -notin $validEffortImpact) {
        $errors.Add("${Label}: Effort: '$effort' is not one of: $($validEffortImpact -join '|').")
    }

    # Impact
    $impact = Test-PulseScalarStringField -Container $Descriptor -Key 'Impact' -FieldPath 'Impact' -Required
    if ($null -ne $impact -and $impact -notin $validEffortImpact) {
        $errors.Add("${Label}: Impact: '$impact' is not one of: $($validEffortImpact -join '|').")
    }

    # Data.Datasets / Data.Gates
    $datasets = $null
    if (-not $Descriptor.ContainsKey('Data') -or $Descriptor.Data -isnot [hashtable]) {
        $errors.Add("${Label}: Data: is required and must be a hashtable.")
    } else {
        $data = $Descriptor.Data
        $datasets = Test-PulseStringArrayField -Container $data -Key 'Datasets' -FieldPath 'Data.Datasets'
        Test-PulseStringArrayField -Container $data -Key 'Gates' -FieldPath 'Data.Gates' -AllowEmpty | Out-Null
    }

    # Dataset map cross-check - $DatasetMap is $null until Task 1.5 lands DatasetMap.psd1
    # (or the loader could not parse it, which it reports as its own catalog-level error).
    if ($datasets -and $DatasetMap) {
        foreach ($name in $datasets) {
            if ($DatasetMap.Keys -notcontains $name) {
                $mapSuffix = if ($DatasetMapPath) { " ($DatasetMapPath)" } else { '' }
                $errors.Add("${Label}: Data.Datasets: dataset '$name' is not present in the shared dataset map${mapSuffix}.")
            }
        }
    }

    # Rule
    if (-not $Descriptor.ContainsKey('Rule') -or $Descriptor.Rule -isnot [hashtable]) {
        $errors.Add("${Label}: Rule: is required and must be a hashtable.")
    } else {
        $rule = $Descriptor.Rule
        $ruleType = Test-PulseScalarStringField -Container $rule -Key 'Type' -FieldPath 'Rule.Type' -Required
        if ($null -ne $ruleType -and $ruleType -notin $validRuleTypes) {
            $errors.Add("${Label}: Rule.Type: '$ruleType' is not one of: $($validRuleTypes -join '|').")
        } elseif ($ruleType -eq 'Function') {
            $ruleFunction = Test-PulseScalarStringField -Container $rule -Key 'Function' -FieldPath 'Rule.Function' -Required
            if ($null -ne $ruleFunction -and -not (Get-Command -Name $ruleFunction -ErrorAction SilentlyContinue)) {
                $errors.Add("${Label}: Rule.Function: command '$ruleFunction' does not resolve at import time.")
            }
        } elseif ($ruleType -eq 'Expression') {
            Test-PulseScalarStringField -Container $rule -Key 'Expression' -FieldPath 'Rule.Expression' -Required | Out-Null
        }
    }

    # Consulting
    if (-not $Descriptor.ContainsKey('Consulting') -or $Descriptor.Consulting -isnot [hashtable]) {
        $errors.Add("${Label}: Consulting: is required and must be a hashtable.")
    } else {
        $consulting = $Descriptor.Consulting
        Test-PulseScalarStringField -Container $consulting -Key 'WhatItMeans' -FieldPath 'Consulting.WhatItMeans' -Required | Out-Null
        Test-PulseScalarStringField -Container $consulting -Key 'WhyItMatters' -FieldPath 'Consulting.WhyItMatters' -Required | Out-Null
        Test-PulseStringArrayField -Container $consulting -Key 'Remediation' -FieldPath 'Consulting.Remediation' | Out-Null
        Test-PulseStringArrayField -Container $consulting -Key 'PortalLinks' -FieldPath 'Consulting.PortalLinks' | Out-Null
    }

    # References
    if (-not $Descriptor.ContainsKey('References') -or $Descriptor.References -isnot [hashtable]) {
        $errors.Add("${Label}: References: is required and must be a hashtable.")
    } else {
        $references = $Descriptor.References
        Test-PulseScalarStringField -Container $references -Key 'Research' -FieldPath 'References.Research' -Required | Out-Null
        Test-PulseStringArrayField -Container $references -Key 'Authorities' -FieldPath 'References.Authorities' | Out-Null
    }

    # Origin - optional, but if present must be $null or a hashtable.
    if ($Descriptor.ContainsKey('Origin') -and $null -ne $Descriptor.Origin -and $Descriptor.Origin -isnot [hashtable]) {
        $errors.Add("${Label}: Origin: must be `$null or a hashtable.")
    }

    # Deliberately NOT `return , $errors.ToArray()`: the unary comma would suppress
    # pipeline unrolling and hand callers back a single object (an array) instead of the
    # flat set of error strings, corrupting every `@(Test-PulseCheckDescriptor ...)` call
    # site (0 errors would still come back as a 1-element array wrapping an empty array).
    # Plain unrolling - 0 strings out for a valid descriptor, N strings out for N problems
    # - is what every caller here expects, and what `@()` around the call reconstitutes.
    return $errors.ToArray()
}
