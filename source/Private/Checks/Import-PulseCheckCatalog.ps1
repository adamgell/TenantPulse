<#
    Private: load and validate every check descriptor .psd1 in a directory.

    This is the catalog layer every assessment run starts from: it reads the .psd1 check
    descriptors with Import-PowerShellDataFile (safe - no code execution, unlike dot-
    sourcing or Invoke-Expression), validates every one of them via
    Test-PulseCheckDescriptor, cross-checks Ids for catalog-wide duplicates, and returns an
    ordinally-sorted-by-Id array of PSTypeName 'TenantPulse.CheckDescriptor' objects.

    All-or-nothing, aggregated errors: a catalog with even one invalid descriptor throws a
    single error whose message has one line per problem (across every descriptor in the
    directory, not just the first bad file). Every line is prefixed with the source
    filename (the one unambiguous identifier - two files can share the same, possibly
    malformed, Id) followed by the descriptor's Id-or-filename label and the offending
    property: "<filename>: <Id-or-filename>: <property>: <problem>". This is deliberate -
    a partially-loaded catalog would silently run fewer checks than the operator expects,
    which conflicts with the "no silent gaps" principle the rest of the engine follows.
    Rule.Function resolution failures are treated as hard catalog-import failures (a bad
    function name is a module authoring bug caught at load time), not as per-check runtime
    errors - a resolvable function that itself throws at evaluation time is a different,
    later concern (the evaluator's per-check Error status, Task 1.6).

    Empty catalog is not an error: an empty/missing -Path (e.g. source/Data/Checks before
    Task 1.9 adds real descriptors) returns an empty array rather than throwing, so the
    rest of the pipeline can run against a still-being-built check set.

    Ordinal sort: Sort-Object -Property Id is culture-aware (case-insensitive collation
    under the default comparer), which is non-deterministic across locales/hosts for this
    codebase's "deterministic ordering everywhere" rule. Ids are sorted the same way
    ConvertTo-PulseCanonicalJson sorts JSON object keys: build an index array and sort that
    with a [System.Comparison[int]] delegate driving [string]::CompareOrdinal, then read
    descriptors back out through the sorted index - not the two-array
    [Array]::Sort(keys, items) overload, which (per that function's inline note) does not
    reliably reorder the paired array under PowerShell's method binder in this
    environment.

    Dataset map cross-check (T1.5 handshake): -DatasetMapPath defaults to
    <ModuleBase>/Data/DatasetMap.psd1, which Task 1.5 creates. The file is parsed exactly
    ONCE per catalog load (not once per descriptor) and validated to be a hashtable; a
    missing file skips the cross-check (Write-Verbose note) for every descriptor, while a
    present-but-malformed file is surfaced through the same aggregated-errors mechanism as
    any other catalog problem rather than throwing a raw, unrelated error. A file literally
    named 'DatasetMap.psd1' living inside the catalog -Path itself is excluded from
    descriptor scanning (it is the map, not a check).
#>

function Import-PulseCheckCatalog {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [string] $Path,

        [Parameter()]
        [string] $DatasetMapPath
    )

    $moduleBase = if ($MyInvocation.MyCommand.Module) {
        $MyInvocation.MyCommand.Module.ModuleBase
    } else {
        $PSScriptRoot
    }

    if (-not $PSBoundParameters.ContainsKey('Path') -or [string]::IsNullOrEmpty($Path)) {
        $Path = Join-Path $moduleBase 'Data/Checks'
    }

    if (-not $PSBoundParameters.ContainsKey('DatasetMapPath') -or [string]::IsNullOrEmpty($DatasetMapPath)) {
        $DatasetMapPath = Join-Path $moduleBase 'Data/DatasetMap.psd1'
    }

    $allErrors = [System.Collections.Generic.List[string]]::new()

    # Parse the shared dataset map exactly once per catalog load. A missing file just means
    # Task 1.5 has not landed yet (skip the cross-check); a present-but-malformed file is a
    # real catalog problem, reported through the same aggregated-errors path as every other
    # descriptor problem instead of exploding with a raw, unhandled error.
    $datasetMap = $null
    if (-not (Test-Path -LiteralPath $DatasetMapPath -PathType Leaf)) {
        Write-Verbose "Dataset map not found at '$DatasetMapPath' (Task 1.5 has not landed yet); skipping the Data.Datasets membership cross-check for every descriptor in this catalog."
    } else {
        $datasetMapFileName = Split-Path -Path $DatasetMapPath -Leaf
        try {
            $parsedMap = Import-PowerShellDataFile -LiteralPath $DatasetMapPath -ErrorAction Stop
            if ($parsedMap -isnot [hashtable]) {
                $allErrors.Add("${datasetMapFileName}: (dataset map): must be a hashtable, got $(if ($null -eq $parsedMap) { 'null' } else { $parsedMap.GetType().Name }).")
            } else {
                $datasetMap = $parsedMap
            }
        } catch {
            $allErrors.Add("${datasetMapFileName}: (dataset map): failed to parse as a PowerShell data file: $($_.Exception.Message)")
        }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        if ($allErrors.Count -gt 0) {
            throw ($allErrors -join [System.Environment]::NewLine)
        }
        return
    }

    # 'DatasetMap.psd1' living inside the catalog directory is the shared map, not a check
    # descriptor - excluded by name so it is never scanned/validated as one.
    $files = @(
        Get-ChildItem -LiteralPath $Path -Filter '*.psd1' -File |
            Where-Object { $_.Name -ne 'DatasetMap.psd1' } |
            Sort-Object -Property Name
    )

    if ($files.Count -eq 0) {
        if ($allErrors.Count -gt 0) {
            throw ($allErrors -join [System.Environment]::NewLine)
        }
        return
    }

    $validDescriptors = [System.Collections.Generic.List[hashtable]]::new()
    $seenIds = @{}

    foreach ($file in $files) {
        try {
            $data = Import-PowerShellDataFile -LiteralPath $file.FullName -ErrorAction Stop
        } catch {
            $allErrors.Add("$($file.Name): (file): failed to parse as a PowerShell data file: $($_.Exception.Message)")
            continue
        }

        $label = if ($data.ContainsKey('Id') -and $data.Id -is [string] -and -not [string]::IsNullOrWhiteSpace($data.Id)) {
            $data.Id
        } else {
            $file.Name
        }

        $fieldErrors = @(Test-PulseCheckDescriptor -Descriptor $data -Label $label -DatasetMap $datasetMap -DatasetMapPath $DatasetMapPath)
        if ($fieldErrors.Count -gt 0) {
            foreach ($fieldError in $fieldErrors) {
                $allErrors.Add("$($file.Name): $fieldError")
            }
            continue
        }

        # Belt-and-braces alongside Test-PulseCheckDescriptor's own Id type check: key the
        # duplicate-detection dictionary with an explicit [string] cast so a coercible-but-
        # wrong-typed Id (already rejected above in the normal path) can never collide with,
        # or mask, a real duplicate under a hashtable key that isn't a plain string.
        $idKey = [string] $data.Id
        if ($seenIds.ContainsKey($idKey)) {
            $allErrors.Add("$($file.Name): ${idKey}: Id: duplicate check Id, also used by '$($seenIds[$idKey])'.")
            continue
        }

        $seenIds[$idKey] = $file.Name
        $validDescriptors.Add($data)
    }

    if ($allErrors.Count -gt 0) {
        throw ($allErrors -join [System.Environment]::NewLine)
    }

    if ($validDescriptors.Count -eq 0) {
        return
    }

    $objects = [pscustomobject[]] @(foreach ($d in $validDescriptors) {
        [pscustomobject]@{
            PSTypeName = 'TenantPulse.CheckDescriptor'
            Id         = $d.Id
            Title      = $d.Title
            Category   = $d.Category
            Severity   = $d.Severity
            Effort     = $d.Effort
            Impact     = $d.Impact
            Data       = $d.Data
            Rule       = $d.Rule
            Consulting = $d.Consulting
            References = $d.References
            Origin     = $d.Origin
        }
    })

    # Ordinal sort by Id - see docblock. Index-sort rather than [Array]::Sort(keys, items):
    # that two-array overload does not reliably reorder the paired array under PowerShell's
    # method binder here (see ConvertTo-PulseCanonicalJson's inline note - same trap).
    $ids = [string[]] @($objects | ForEach-Object { [string] $_.Id })
    $order = [int[]] (0 .. ($objects.Count - 1))
    $comparison = [System.Comparison[int]] { param($a, $b) [string]::CompareOrdinal($ids[$a], $ids[$b]) }
    [System.Array]::Sort($order, $comparison)

    return @(foreach ($i in $order) { $objects[$i] })
}
