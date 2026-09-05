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

    Data.Expansions (Task 3.2): a descriptor's artifact-dependency declaration is no
    longer just Data.Datasets - a check whose real input is a compact expansion artifact
    (e.g. expanded/conflicts.json, never a raw Graph dataset - see TP.INT.0006) declares
    that via Data.Expansions instead of inventing a dummy Data.Datasets entry a rule never
    reads (the wart TP.INT.0006 carried until this task). Both fields are now OPTIONAL
    individually (a check may declare only Datasets, only Expansions, or - after this
    task - both), but Data.Datasets and Data.Expansions MAY NOT BOTH BE EMPTY: a check
    with neither declares no artifact input at all, which is never a valid check. Every
    Data.Expansions name is cross-checked against a small, hardcoded KNOWN-ARTIFACT
    REGISTRY ('conflicts' and, since Part A/T3.4, 'settingPresenceIndex') rather than the
    dataset map's live cross-check, since expansion artifacts are not GraphKit-collected
    datasets and have no DatasetMap.psd1 entry to check against; a future expansion family
    is added to this same registry, not to the dataset map.

    References.Research path and heading (DOC1): the required scalar is not just non-empty
    text. It must be a repository-relative path plus a Markdown heading fragment
    (`docs/research/iha-v2/<file>.md#<anchor>`), never rooted/absolute and never containing
    `..`. When -RepoRoot is supplied, the path is resolved from that root with ordinal
    (case-exact) directory walking, the leaf must exist, and the fragment must match
    exactly one unique normalized ATX heading anchor in that file. Normalization is
    lowercase, fold Unicode dashes (U+2013/U+2014/U+2012) to ASCII hyphen, strip every
    character except `[a-z0-9 _-]`, then spaces to hyphens without collapsing consecutive
    hyphens. Each heading also accepts the historical stripped-dash slug and the
    en/figure-dash-only fold so restored research matches catalog fragments generated
    either way. Callers that omit -RepoRoot still get the structural
    checks so fixture catalogs with synthetic paths keep loading.
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
        [string] $DatasetMapPath,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RepoRoot
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
    # Known-artifact registry (Task 3.2; grown by Part A/T3.4): the only expansion artifact
    # names a Data.Expansions entry may legally name today. 'settingPresenceIndex' is the
    # second family (Part A/T3.4's per-family setting-presence index, consumed via
    # $Context.ArtifactReader.GetSettingPresenceIndex() - see New-PulseArtifactReader.ps1's
    # own docstring). Growing this further means adding its name here, nowhere else - see
    # this file's own top-level docstring.
    $knownExpansionArtifacts = @('administrativeTemplates', 'conflicts', 'expansionSummary', 'settingPresenceIndex')

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
            [switch] $AllowEmpty,
            # AllowMissing (Task 3.2): the key may be absent from $Container entirely
            # without an "is required" error - the caller treats absence the same as an
            # empty array. Used for Data.Datasets/Data.Expansions, which are now each
            # individually optional (see this file's own docstring) - unlike every other
            # caller of this function, which still requires the key to be present.
            [switch] $AllowMissing
        )

        if (-not $Container.ContainsKey($Key)) {
            if ($AllowMissing) { return [string[]] @() }
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

    function Get-PulseMarkdownHeadingAnchors {
        param([string] $HeadingText)
        # Fold figure/en/em dashes so restored headings like "AM01–AM04" match ASCII
        # hyphen fragments, but keep the stripped-dash slug too: other restored headings
        # (and spaced em-dashes) were catalogued without that fold.
        $anchors = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($dashClass in @($null, '[\u2012\u2013]', '[\u2012\u2013\u2014]')) {
            $text = $HeadingText.ToLowerInvariant()
            if ($null -ne $dashClass) {
                $text = [regex]::Replace($text, $dashClass, '-')
            }
            $text = [regex]::Replace($text, '[^a-z0-9 _-]', '')
            [void] $anchors.Add($text.Replace(' ', '-'))
        }
        return $anchors
    }

    function Test-PulseResearchReference {
        param(
            [string] $Value,
            [string] $ResearchRepoRoot
        )

        $hashIndex = $Value.IndexOf('#')
        if ($hashIndex -lt 0) {
            $errors.Add("${Label}: References.Research: must include a heading fragment.")
            return
        }

        $relativePath = $Value.Substring(0, $hashIndex)
        $fragment = $Value.Substring($hashIndex + 1)

        if ([string]::IsNullOrWhiteSpace($relativePath) -or [System.IO.Path]::IsPathRooted($relativePath)) {
            $errors.Add("${Label}: References.Research: path must be repository-relative, not absolute.")
            return
        }

        if ([string]::IsNullOrWhiteSpace($fragment)) {
            $errors.Add("${Label}: References.Research: must include a heading fragment.")
            return
        }

        $segments = @($relativePath -split '[\\/]+' | Where-Object { $_ -ne '' })
        if ($segments -contains '..') {
            $errors.Add("${Label}: References.Research: path must not contain '..'.")
            return
        }

        if ([string]::IsNullOrWhiteSpace($ResearchRepoRoot)) {
            return
        }

        if (-not (Test-Path -LiteralPath $ResearchRepoRoot -PathType Container)) {
            $errors.Add("${Label}: References.Research: repository root is not a directory.")
            return
        }

        $current = [System.IO.Path]::GetFullPath($ResearchRepoRoot)
        $rootFull = $current.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )

        foreach ($segment in $segments) {
            if ($segment -eq '.') {
                continue
            }

            $children = @(Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue)
            $ordinal = @($children | Where-Object {
                    [string]::Equals($_.Name, $segment, [System.StringComparison]::Ordinal)
                })
            if ($ordinal.Count -eq 1) {
                $current = $ordinal[0].FullName
                continue
            }

            $ignoreCase = @($children | Where-Object {
                    [string]::Equals($_.Name, $segment, [System.StringComparison]::OrdinalIgnoreCase)
                })
            if ($ignoreCase.Count -ge 1) {
                $errors.Add("${Label}: References.Research: file '$relativePath' does not match on-disk path casing.")
                return
            }

            $errors.Add("${Label}: References.Research: file '$relativePath' is not present.")
            return
        }

        if (-not (Test-Path -LiteralPath $current -PathType Leaf)) {
            $errors.Add("${Label}: References.Research: file '$relativePath' is not present.")
            return
        }

        $currentFull = [System.IO.Path]::GetFullPath($current)
        $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
        if (-not (
                $currentFull.Equals($rootFull, [System.StringComparison]::Ordinal) -or
                $currentFull.StartsWith($rootPrefix, [System.StringComparison]::Ordinal)
            )) {
            $errors.Add("${Label}: References.Research: path must not contain '..'.")
            return
        }

        $markdown = [System.IO.File]::ReadAllText($current)
        $headingMatches = [regex]::Matches($markdown, '(?m)^#{1,6} (.+)$')
        $counts = [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($match in $headingMatches) {
            foreach ($anchor in @(Get-PulseMarkdownHeadingAnchors -HeadingText $match.Groups[1].Value)) {
                if ($counts.ContainsKey($anchor)) {
                    $counts[$anchor]++
                } else {
                    $counts[$anchor] = 1
                }
            }
        }

        if (-not $counts.ContainsKey($fragment)) {
            $errors.Add("${Label}: References.Research: heading anchor '$fragment' is not present.")
            return
        }

        if ($counts[$fragment] -ne 1) {
            $errors.Add("${Label}: References.Research: heading anchor '$fragment' is not unique.")
        }
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

    # Data.Datasets / Data.Expansions / Data.Gates / Data.PartialDatasets
    $datasets = $null
    $partialDatasets = $null
    $partialDatasetsPresent = $false
    if (-not $Descriptor.ContainsKey('Data') -or $Descriptor.Data -isnot [hashtable]) {
        $errors.Add("${Label}: Data: is required and must be a hashtable.")
    } else {
        $data = $Descriptor.Data

        # Both individually optional now (Task 3.2) - neither call adds an "is required"
        # error just for being absent; AllowEmpty means an explicitly-present-but-empty
        # array is not an error EITHER, since "both empty" is checked once, together,
        # below, with its own combined error message rather than two separate
        # "must not be empty" errors that would misdescribe the actual rule.
        $datasets = Test-PulseStringArrayField -Container $data -Key 'Datasets' -FieldPath 'Data.Datasets' -AllowEmpty -AllowMissing
        $expansions = Test-PulseStringArrayField -Container $data -Key 'Expansions' -FieldPath 'Data.Expansions' -AllowEmpty -AllowMissing
        Test-PulseStringArrayField -Container $data -Key 'Gates' -FieldPath 'Data.Gates' -AllowEmpty | Out-Null

        # R1a: PartialDatasets is an explicit evaluation opt-in, not another collection
        # dependency. Omission preserves the existing fail-closed behavior. Presence is a
        # positive contract and therefore cannot be null or empty; the ordinary string-
        # array helper supplies the same strict scalar/element checks as Data.Datasets.
        $partialDatasetsPresent = $data.ContainsKey('PartialDatasets')
        if ($partialDatasetsPresent) {
            $partialDatasets = Test-PulseStringArrayField `
                -Container $data `
                -Key 'PartialDatasets' `
                -FieldPath 'Data.PartialDatasets'
        }

        foreach ($name in @($expansions)) {
            if ($knownExpansionArtifacts -notcontains $name) {
                $errors.Add("${Label}: Data.Expansions: artifact '$name' is not a known expansion artifact (known: $($knownExpansionArtifacts -join '|')).")
            }
        }

        # Combined non-emptiness rule (Task 3.2, replaces the old standalone
        # "Data.Datasets: must not be empty"): a check with NEITHER a dataset NOR an
        # expansion artifact input declares no data source at all, which is never valid -
        # but an empty Data.Datasets is perfectly fine on its own when Data.Expansions
        # covers it (TP.INT.0006's own post-migration shape), and vice versa. $datasets/
        # $expansions can be $null here only if Test-PulseStringArrayField already
        # reported a TYPE error for that field (e.g. a scalar instead of an array) - @()
        # around a $null coerces to a zero-count array so this check still fires (a type
        # error alone does not silently satisfy the non-emptiness rule).
        if (@($datasets).Count -eq 0 -and @($expansions).Count -eq 0) {
            $errors.Add("${Label}: Data: Datasets and Expansions may not both be empty - a check needs at least one artifact input.")
        }
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

    # PartialDatasets has deliberately stricter identity rules than the older
    # Data.Datasets field. A partial-aware check will use these names to select rows and
    # structured outcomes at evaluation time, so case aliases and duplicates must not
    # create two spellings for one logical dataset. Compare explicitly with ordinal .NET
    # comparers: PowerShell's -contains and ordinary hashtables are case-insensitive and
    # would otherwise accept precisely the aliases this contract forbids.
    $partialDatasetMapAvailable = $null -ne $DatasetMap
    if ($partialDatasetsPresent -and -not $partialDatasetMapAvailable) {
        $errors.Add("${Label}: Data.PartialDatasets: canonical dataset identity cannot be verified because the shared dataset map is unavailable.")
    }

    if ($null -ne $partialDatasets) {
        $seenPartialDatasets = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $datasetNames = [string[]] @($datasets)
        $mapNames = if ($partialDatasetMapAvailable) { [string[]] @($DatasetMap.Keys | ForEach-Object { [string] $_ }) } else { [string[]] @() }

        foreach ($name in $partialDatasets) {
            if (-not $seenPartialDatasets.Add($name)) {
                $errors.Add("${Label}: Data.PartialDatasets: duplicate dataset '$name' under OrdinalIgnoreCase uniqueness.")
            }

            $declaredExact = @($datasetNames | Where-Object {
                    [string]::Equals($_, $name, [System.StringComparison]::Ordinal)
                })
            if ($declaredExact.Count -eq 0) {
                $declaredAlias = @($datasetNames | Where-Object {
                        [string]::Equals($_, $name, [System.StringComparison]::OrdinalIgnoreCase)
                    })
                if ($declaredAlias.Count -gt 0) {
                    $errors.Add("${Label}: Data.PartialDatasets: dataset '$name' must use exact Data.Datasets casing '$($declaredAlias[0])'.")
                } else {
                    $errors.Add("${Label}: Data.PartialDatasets: dataset '$name' must also be listed in Data.Datasets.")
                }
            }

            if ($partialDatasetMapAvailable) {
                $mapExact = @($mapNames | Where-Object {
                        [string]::Equals($_, $name, [System.StringComparison]::Ordinal)
                    })
                if ($mapExact.Count -eq 0) {
                    $mapAlias = @($mapNames | Where-Object {
                            [string]::Equals($_, $name, [System.StringComparison]::OrdinalIgnoreCase)
                        })
                    if ($mapAlias.Count -gt 0) {
                        $errors.Add("${Label}: Data.PartialDatasets: dataset '$name' must use exact dataset-map casing '$($mapAlias[0])'.")
                    } else {
                        $mapSuffix = if ($DatasetMapPath) { " ($DatasetMapPath)" } else { '' }
                        $errors.Add("${Label}: Data.PartialDatasets: dataset '$name' is not present in the shared dataset map${mapSuffix}.")
                    }
                }
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
            if ($null -ne $ruleFunction) {
                # Get-Command -Name accepts wildcard syntax and can return several
                # commands. It can also resolve applications/cmdlets whose Parameters
                # surface is absent or irrelevant to a Function rule. Escape the lookup,
                # retain ordinal-exact names only, and require one unambiguous Function
                # before inspecting metadata. This makes malformed descriptors aggregate
                # as validation errors instead of throwing from a Boolean array or a null
                # Parameters property.
                $containsWildcard = [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($ruleFunction)
                $ruleCommands = @()
                if (-not $containsWildcard) {
                    $escapedRuleFunction = [System.Management.Automation.WildcardPattern]::Escape($ruleFunction)
                    # Restrict the normal lookup to Function commands. Without this
                    # filter, Get-Command -All scans every command family for every one
                    # of the catalog's descriptors, turning catalog validation into a
                    # repeated hundreds-of-milliseconds operation. Non-Function lookup
                    # is needed only on the invalid zero-Function path below.
                    $ruleCommands = @(Get-Command -Name $escapedRuleFunction -CommandType Function -All -ErrorAction SilentlyContinue | Where-Object {
                            [string]::Equals([string] $_.Name, $ruleFunction, [System.StringComparison]::Ordinal)
                        })
                }

                if ($containsWildcard -or $ruleCommands.Count -gt 1) {
                    $errors.Add("${Label}: Rule.Function: command '$ruleFunction' must resolve to exactly one exact Function command.")
                } elseif ($ruleCommands.Count -eq 0) {
                    $anyExactCommand = @(Get-Command -Name $escapedRuleFunction -All -ErrorAction SilentlyContinue | Where-Object {
                            [string]::Equals([string] $_.Name, $ruleFunction, [System.StringComparison]::Ordinal)
                        })
                    if ($anyExactCommand.Count -eq 0) {
                        $errors.Add("${Label}: Rule.Function: command '$ruleFunction' does not resolve at import time.")
                    } else {
                        $errors.Add("${Label}: Rule.Function: command '$ruleFunction' must resolve to exactly one exact Function command.")
                    }
                } else {
                    $ruleParameters = $ruleCommands[0].Parameters
                    if ($partialDatasetsPresent -and
                        ($null -eq $ruleParameters -or -not $ruleParameters.ContainsKey('DatasetOutcomes'))) {
                        $errors.Add("${Label}: Rule.Function: command '$ruleFunction' must declare a DatasetOutcomes parameter when Data.PartialDatasets is present.")
                    }
                }
            }
        } elseif ($ruleType -eq 'Expression') {
            if ($partialDatasetsPresent) {
                $errors.Add("${Label}: Data.PartialDatasets: is valid only when Rule.Type is Function.")
            }
            $expressionText = Test-PulseScalarStringField -Container $rule -Key 'Expression' -FieldPath 'Rule.Expression' -Required
            # Parse-check at import time (post-review, do-now minor): a syntax typo in
            # Rule.Expression previously only surfaced as a per-check Error at evaluation
            # time, with no file/line context. [scriptblock]::Create parses without
            # executing - it never runs the expression, just confirms it is valid
            # PowerShell - so a bad expression is caught here, aggregated with every other
            # catalog problem, and reported against the descriptor's own file/Id/property.
            if ($null -ne $expressionText) {
                try {
                    [void] [scriptblock]::Create($expressionText)
                } catch {
                    $errors.Add("${Label}: Rule.Expression: does not parse as PowerShell: $($_.Exception.Message)")
                }
            }
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
        $research = Test-PulseScalarStringField -Container $references -Key 'Research' -FieldPath 'References.Research' -Required
        if ($null -ne $research) {
            Test-PulseResearchReference -Value $research -ResearchRepoRoot $RepoRoot
        }
        Test-PulseStringArrayField -Container $references -Key 'Authorities' -FieldPath 'References.Authorities' | Out-Null

        # References.Cis - OPTIONAL, cite-only CIS benchmark cross-references (Task 4.5).
        # Unlike Authorities (required-array), Cis is validated only when the key is
        # present at all - most checks carry none, since the Phase 4 research entries
        # this catalog was authored from carry zero CIS mappings (see
        # docs/licensing/cis-cite-only.md, this repo's own vendored licensing summary, for
        # the full rule and why: cite-only, never bulk-populated ahead of a verified
        # per-check mapping). Each element is a bare "benchmark name + version, Rec. <id>
        # (<profile>)" ID-ONLY string - benchmark ID, version, and profile level, and
        # NOTHING else. This is stricter than "no bulk text": a CIS recommendation's TITLE
        # is itself CIS's copyrighted expression, not a fact, so titles are excluded here
        # exactly like Description/Rationale/Audit/Remediation prose - including one would
        # pull this MIT-licensed catalog into CIS's incompatible CC BY-NC-SA license.
        # NOT -AllowEmpty (Task 4.5 fix round, NEW-3): the field is optional - a check with
        # no CIS mapping simply omits the `Cis` key entirely (see the schema doc, source/
        # Data/Checks/README.md) - but a descriptor that DOES include the key is making an
        # explicit claim to have one, and `Cis = @()` is a contradiction of that claim, not
        # a valid "no mapping" spelling. Same "empty is an error, omission is fine" rule
        # `References.Authorities` already enforces (that field is required, so it cannot
        # be omitted, but the emptiness rule is the same principle either way).
        if ($references.ContainsKey('Cis')) {
            $rawCisValues = Test-PulseStringArrayField -Container $references -Key 'Cis' -FieldPath 'References.Cis'

            # FORMAT ENFORCEMENT (merge-review fix, MAJOR-adjacent): the ID-only rule above
            # was previously prose-only - a check author could still write a real
            # recommendation TITLE or free-text description into `Cis` and nothing would
            # catch it before this shipped. Every element must now match the exact
            # "<Benchmark name> Benchmark v<semver>, Rec. <dotted-id> (<profile level>)"
            # shape - benchmark name/version/recommendation-id/profile level, structurally
            # incapable of matching a sentence of prose (no verb phrases, no lowercase-led
            # narrative text survives this pattern). A string that fails the pattern is
            # rejected with a message showing the required shape, not merely "invalid".
            #
            # $null CHECKED BEFORE @()-WRAPPING, DELIBERATELY (merge-review round-2 fix):
            # Test-PulseStringArrayField returns $null on a type/emptiness failure (already
            # reported as its own error above) - @()-wrapping THAT first would turn $null
            # into a real one-element array containing $null, which then survives the
            # `$null -ne` gate and reaches -notmatch as an empty string, adding a confusing
            # SECOND error on top of the real one. Only a genuinely non-null return is
            # wrapped in @() - required because a single-element array returned through a
            # PowerShell function's output stream unwraps to a scalar [string] unless
            # forced back into array shape, and a bare `$cisValues[0]` on that unwrapped
            # scalar indexes into its CHARACTERS ('C', not the whole string), not its
            # (nonexistent) array elements - reproduced and fixed during this same round.
            if ($null -ne $rawCisValues) {
                $cisValues = @($rawCisValues)
                $cisPattern = '^CIS [A-Za-z0-9 ]+ Benchmark v\d+\.\d+\.\d+, Rec\. \d+(\.\d+)+ \(E[35] Level [12]\)$'
                for ($i = 0; $i -lt $cisValues.Count; $i++) {
                    # -cnotmatch, not -notmatch: PowerShell's -notmatch is case-INsensitive, which
                    # would let a fully-lowercase CIS-shaped string satisfy the literal-case tokens
                    # ('CIS', 'Benchmark', 'Rec.', 'E3'/'E5', 'Level') the format requires.
                    if ($cisValues[$i] -cnotmatch $cisPattern) {
                        $errors.Add("${Label}: References.Cis[$i]: '$($cisValues[$i])' does not match the required ID-only format 'CIS <Benchmark name> Benchmark v<version>, Rec. <id> (<E3|E5> Level <1|2>)' - see docs/licensing/cis-cite-only.md.")
                    }
                }
            }
        }
    }

    # Origin - optional, but if present must be $null or a hashtable.
    if ($Descriptor.ContainsKey('Origin') -and $null -ne $Descriptor.Origin -and $Descriptor.Origin -isnot [hashtable]) {
        $errors.Add("${Label}: Origin: must be `$null or a hashtable.")
    }

    # Privacy (TP9A): optional. Catalog static fields are BoundedReviewedText /
    # SafeOperatorLabel by contract. Tenant-derived evidence fields MAY be declared
    # under Privacy.EvidenceFields = @{ key = '<class>' }. Unknown class names fail
    # closed at catalog load. Absence is the compatibility path (local-only).
    if ($Descriptor.ContainsKey('Privacy') -and $null -ne $Descriptor.Privacy) {
        if ($Descriptor.Privacy -isnot [hashtable]) {
            $errors.Add("${Label}: Privacy: must be a hashtable.")
        } else {
            $privacy = $Descriptor.Privacy
            $privacyMaps = @('EvidenceFields', 'CatalogFields')
            foreach ($privacyKey in @($privacy.Keys)) {
                if ($privacyMaps -notcontains [string] $privacyKey) {
                    $errors.Add("${Label}: Privacy.${privacyKey}: is not supported; allowed keys are EvidenceFields and CatalogFields.")
                }
            }
            foreach ($mapName in $privacyMaps) {
                if (-not $privacy.ContainsKey($mapName) -or $null -eq $privacy[$mapName]) {
                    continue
                }
                $map = $privacy[$mapName]
                if ($map -isnot [hashtable]) {
                    $errors.Add("${Label}: Privacy.${mapName}: must be a hashtable.")
                    continue
                }
                foreach ($fieldName in @($map.Keys)) {
                    $className = $map[$fieldName]
                    if ($className -isnot [string] -or -not (Test-PulsePrivacyClassName -Class $className)) {
                        $errors.Add("${Label}: Privacy.${mapName}.${fieldName}: '$className' is not a 1.0 privacy class (Identity|SecretSensitive|SafeTechnical|SafeOperatorLabel|BoundedReviewedText).")
                    }
                }
            }
        }
    }

    # Deliberately NOT `return , $errors.ToArray()`: the unary comma would suppress
    # pipeline unrolling and hand callers back a single object (an array) instead of the
    # flat set of error strings, corrupting every `@(Test-PulseCheckDescriptor ...)` call
    # site (0 errors would still come back as a 1-element array wrapping an empty array).
    # Plain unrolling - 0 strings out for a valid descriptor, N strings out for N problems
    # - is what every caller here expects, and what `@()` around the call reconstitutes.
    return $errors.ToArray()
}
