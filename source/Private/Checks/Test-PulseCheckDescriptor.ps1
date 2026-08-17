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
    REGISTRY (currently just 'conflicts' - the one expansion family that exists) rather
    than the dataset map's live cross-check, since expansion artifacts are not
    GraphKit-collected datasets and have no DatasetMap.psd1 entry to check against; a
    future expansion family (a "future family name" per the task brief) is added to this
    same registry, not to the dataset map.
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
    # Known-artifact registry (Task 3.2): the only expansion artifact names a
    # Data.Expansions entry may legally name today. Growing this to a second family later
    # means adding its name here, nowhere else - see this file's own top-level docstring.
    $knownExpansionArtifacts = @('conflicts')

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

    # Data.Datasets / Data.Expansions / Data.Gates
    $datasets = $null
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
        Test-PulseScalarStringField -Container $references -Key 'Research' -FieldPath 'References.Research' -Required | Out-Null
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

    # Deliberately NOT `return , $errors.ToArray()`: the unary comma would suppress
    # pipeline unrolling and hand callers back a single object (an array) instead of the
    # flat set of error strings, corrupting every `@(Test-PulseCheckDescriptor ...)` call
    # site (0 errors would still come back as a 1-element array wrapping an empty array).
    # Plain unrolling - 0 strings out for a valid descriptor, N strings out for N problems
    # - is what every caller here expects, and what `@()` around the call reconstitutes.
    return $errors.ToArray()
}
