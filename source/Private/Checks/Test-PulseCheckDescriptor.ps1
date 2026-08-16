<#
    Private: structurally validate one parsed check descriptor hashtable.

    Returns an array of human-readable error strings (empty array when the descriptor is
    valid) rather than throwing, so the caller (Import-PulseCheckCatalog) can aggregate
    errors across every descriptor in a directory into a single thrown error instead of
    failing fast on the first bad file. Each returned line is
    "<Label>: <Property>: <problem>" so a human can jump straight to the offending
    descriptor and field.

    This function only checks one descriptor in isolation - duplicate-Id detection across
    a whole catalog is the loader's job, not this function's.

    Dataset map cross-check (T1.5 handshake): -DatasetMapPath is expected to point at a
    .psd1 whose top-level keys are the tenant-wide dataset names GraphKit knows how to
    collect (source/Data/DatasetMap.psd1, created by Task 1.5). If the path is $null/empty
    or the file does not exist yet, the cross-check is skipped with a Write-Verbose note -
    the loader is responsible for resolving/omitting the path before calling in here.
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
        [AllowEmptyString()]
        [string] $DatasetMapPath
    )

    $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info')
    $validEffortImpact = @('Low', 'Medium', 'High')
    $validRuleTypes = @('Function', 'Expression')
    $consultingFields = @('WhatItMeans', 'WhyItMatters', 'Remediation', 'PortalLinks')

    $errors = [System.Collections.Generic.List[string]]::new()

    function Test-PulseIsBlank {
        param($Value)
        if ($null -eq $Value) { return $true }
        if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace($Value) }
        return $false
    }

    $addError = {
        param([string] $Property, [string] $Message)
        $errors.Add("${Label}: ${Property}: ${Message}")
    }

    # Id
    if (-not $Descriptor.ContainsKey('Id') -or (Test-PulseIsBlank $Descriptor.Id)) {
        & $addError 'Id' 'is required.'
    } elseif ($Descriptor.Id -notmatch '^TP\.(INT|ENT)\.\d{4}$') {
        & $addError 'Id' "'$($Descriptor.Id)' does not match the required pattern ^TP\.(INT|ENT)\.\d{4}$."
    }

    # Title / Category - required non-empty strings
    if (-not $Descriptor.ContainsKey('Title') -or (Test-PulseIsBlank $Descriptor.Title)) {
        & $addError 'Title' 'is required.'
    }
    if (-not $Descriptor.ContainsKey('Category') -or (Test-PulseIsBlank $Descriptor.Category)) {
        & $addError 'Category' 'is required.'
    }

    # Severity
    if (-not $Descriptor.ContainsKey('Severity') -or (Test-PulseIsBlank $Descriptor.Severity)) {
        & $addError 'Severity' 'is required.'
    } elseif ($Descriptor.Severity -notin $validSeverities) {
        & $addError 'Severity' "'$($Descriptor.Severity)' is not one of: $($validSeverities -join '|')."
    }

    # Effort
    if (-not $Descriptor.ContainsKey('Effort') -or (Test-PulseIsBlank $Descriptor.Effort)) {
        & $addError 'Effort' 'is required.'
    } elseif ($Descriptor.Effort -notin $validEffortImpact) {
        & $addError 'Effort' "'$($Descriptor.Effort)' is not one of: $($validEffortImpact -join '|')."
    }

    # Impact
    if (-not $Descriptor.ContainsKey('Impact') -or (Test-PulseIsBlank $Descriptor.Impact)) {
        & $addError 'Impact' 'is required.'
    } elseif ($Descriptor.Impact -notin $validEffortImpact) {
        & $addError 'Impact' "'$($Descriptor.Impact)' is not one of: $($validEffortImpact -join '|')."
    }

    # Data.Datasets / Data.Gates
    $datasets = $null
    if (-not $Descriptor.ContainsKey('Data') -or $Descriptor.Data -isnot [hashtable]) {
        & $addError 'Data' 'is required and must be a hashtable.'
    } else {
        $data = $Descriptor.Data
        if (-not $data.ContainsKey('Datasets') -or $null -eq $data.Datasets -or @($data.Datasets).Count -eq 0) {
            & $addError 'Data.Datasets' 'must contain at least one dataset name.'
        } else {
            $datasets = @($data.Datasets)
            foreach ($name in $datasets) {
                if (Test-PulseIsBlank $name) {
                    & $addError 'Data.Datasets' 'contains a blank dataset name.'
                }
            }
        }
    }

    # Dataset map cross-check - skipped until T1.5 lands DatasetMap.psd1.
    if ($datasets -and -not [string]::IsNullOrEmpty($DatasetMapPath) -and (Test-Path -LiteralPath $DatasetMapPath -PathType Leaf)) {
        $map = Import-PowerShellDataFile -LiteralPath $DatasetMapPath
        foreach ($name in $datasets) {
            if (-not (Test-PulseIsBlank $name) -and $map.Keys -notcontains $name) {
                & $addError 'Data.Datasets' "dataset '$name' is not present in the shared dataset map ($DatasetMapPath)."
            }
        }
    } elseif ($datasets -and [string]::IsNullOrEmpty($DatasetMapPath)) {
        Write-Verbose "Skipping Data.Datasets membership cross-check for '$Label': no dataset map found (Task 1.5 has not landed yet)."
    }

    # Rule
    if (-not $Descriptor.ContainsKey('Rule') -or $Descriptor.Rule -isnot [hashtable]) {
        & $addError 'Rule' 'is required and must be a hashtable.'
    } else {
        $rule = $Descriptor.Rule
        if (-not $rule.ContainsKey('Type') -or (Test-PulseIsBlank $rule.Type)) {
            & $addError 'Rule.Type' 'is required.'
        } elseif ($rule.Type -notin $validRuleTypes) {
            & $addError 'Rule.Type' "'$($rule.Type)' is not one of: $($validRuleTypes -join '|')."
        } elseif ($rule.Type -eq 'Function') {
            if (-not $rule.ContainsKey('Function') -or (Test-PulseIsBlank $rule.Function)) {
                & $addError 'Rule.Function' 'is required when Rule.Type is Function.'
            } elseif (-not (Get-Command -Name $rule.Function -ErrorAction SilentlyContinue)) {
                & $addError 'Rule.Function' "command '$($rule.Function)' does not resolve at import time."
            }
        } elseif ($rule.Type -eq 'Expression') {
            if (-not $rule.ContainsKey('Expression') -or (Test-PulseIsBlank $rule.Expression)) {
                & $addError 'Rule.Expression' 'is required when Rule.Type is Expression.'
            }
        }
    }

    # Consulting
    if (-not $Descriptor.ContainsKey('Consulting') -or $Descriptor.Consulting -isnot [hashtable]) {
        & $addError 'Consulting' 'is required and must be a hashtable.'
    } else {
        $consulting = $Descriptor.Consulting
        foreach ($field in $consultingFields) {
            if (-not $consulting.ContainsKey($field) -or (Test-PulseIsBlank $consulting[$field])) {
                & $addError "Consulting.$field" 'is required.'
            }
        }
    }

    # References
    if (-not $Descriptor.ContainsKey('References') -or $Descriptor.References -isnot [hashtable]) {
        & $addError 'References' 'is required and must be a hashtable.'
    } else {
        $references = $Descriptor.References
        if (-not $references.ContainsKey('Research') -or (Test-PulseIsBlank $references.Research)) {
            & $addError 'References.Research' 'is required.'
        }
        if (-not $references.ContainsKey('Authorities') -or $null -eq $references.Authorities -or @($references.Authorities).Count -eq 0) {
            & $addError 'References.Authorities' 'must not be empty.'
        }
    }

    # Origin - optional, but if present must be $null or a hashtable.
    if ($Descriptor.ContainsKey('Origin') -and $null -ne $Descriptor.Origin -and $Descriptor.Origin -isnot [hashtable]) {
        & $addError 'Origin' 'must be $null or a hashtable.'
    }

    # Deliberately NOT `return , $errors.ToArray()`: the unary comma would suppress
    # pipeline unrolling and hand callers back a single object (an array) instead of the
    # flat set of error strings, corrupting every `@(Test-PulseCheckDescriptor ...)` call
    # site (0 errors would still come back as a 1-element array wrapping an empty array).
    # Plain unrolling - 0 strings out for a valid descriptor, N strings out for N problems
    # - is what every caller here expects, and what `@()` around the call reconstitutes.
    return $errors.ToArray()
}
