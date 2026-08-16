<#
    Private: load and validate every check descriptor .psd1 in a directory.

    This is the catalog layer every assessment run starts from: it reads the .psd1 check
    descriptors with Import-PowerShellDataFile (safe - no code execution, unlike dot-
    sourcing or Invoke-Expression), validates every one of them via
    Test-PulseCheckDescriptor, cross-checks Ids for catalog-wide duplicates, and returns a
    sorted-by-Id array of PSTypeName 'TenantPulse.CheckDescriptor' objects.

    All-or-nothing, aggregated errors: a catalog with even one invalid descriptor throws a
    single error whose message has one line per problem (across every descriptor in the
    directory, not just the first bad file), each line naming the offending descriptor's Id
    (or its filename, when the Id itself is missing/malformed) and the offending property.
    This is deliberate - a partially-loaded catalog would silently run fewer checks than
    the operator expects, which conflicts with the "no silent gaps" principle the rest of
    the engine follows. Rule.Function resolution failures are treated as hard catalog-
    import failures (a bad function name is a module authoring bug caught at load time),
    not as per-check runtime errors - a resolvable function that itself throws at
    evaluation time is a different, later concern (the evaluator's per-check Error status,
    Task 1.6).

    Empty catalog is not an error: an empty/missing -Path (e.g. source/Data/Checks before
    Task 1.9 adds real descriptors) returns an empty array rather than throwing, so the
    rest of the pipeline can run against a still-being-built check set.

    Dataset map cross-check (T1.5 handshake): -DatasetMapPath defaults to
    <ModuleBase>/Data/DatasetMap.psd1, which Task 1.5 creates. Until that file exists, the
    Data.Datasets membership cross-check is skipped (with a Write-Verbose note per
    descriptor) rather than failing catalog import - see Test-PulseCheckDescriptor.
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

    if (-not (Test-Path -LiteralPath $DatasetMapPath -PathType Leaf)) {
        Write-Verbose "Dataset map not found at '$DatasetMapPath' (Task 1.5 has not landed yet); skipping the Data.Datasets membership cross-check for every descriptor in this catalog."
        $DatasetMapPath = $null
    }

    # Deliberately no `return , @()` anywhere below: the unary comma suppresses pipeline
    # unrolling and hands callers back a single object (an empty array) instead of zero
    # pipeline objects, corrupting every `@(Import-PulseCheckCatalog ...)` call site. Plain
    # unrolling - zero objects out for an empty catalog, N objects out for N descriptors -
    # is what callers reconstitute into an array with `@()`.
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    $files = @(Get-ChildItem -LiteralPath $Path -Filter '*.psd1' -File | Sort-Object -Property Name)
    if ($files.Count -eq 0) {
        return
    }

    $allErrors = [System.Collections.Generic.List[string]]::new()
    $validDescriptors = [System.Collections.Generic.List[hashtable]]::new()
    $seenIds = @{}

    foreach ($file in $files) {
        try {
            $data = Import-PowerShellDataFile -LiteralPath $file.FullName -ErrorAction Stop
        } catch {
            $allErrors.Add("$($file.Name): (file): failed to parse as a PowerShell data file: $($_.Exception.Message)")
            continue
        }

        $label = if ($data.ContainsKey('Id') -and -not [string]::IsNullOrWhiteSpace([string] $data.Id)) {
            $data.Id
        } else {
            $file.Name
        }

        $fieldErrors = @(Test-PulseCheckDescriptor -Descriptor $data -Label $label -DatasetMapPath $DatasetMapPath)
        if ($fieldErrors.Count -gt 0) {
            $allErrors.AddRange([string[]] $fieldErrors)
            continue
        }

        if ($seenIds.ContainsKey($data.Id)) {
            $allErrors.Add("${label}: Id: duplicate check Id, also used by '$($seenIds[$data.Id])'.")
            continue
        }

        $seenIds[$data.Id] = $file.Name
        $validDescriptors.Add($data)
    }

    if ($allErrors.Count -gt 0) {
        throw ($allErrors -join [System.Environment]::NewLine)
    }

    $result = foreach ($d in $validDescriptors) {
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
    }

    return @($result | Sort-Object -Property Id)
}
