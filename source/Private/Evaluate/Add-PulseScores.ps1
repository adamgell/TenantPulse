<#
    Private: turn a findings document's findings[] into scores/coverage (spec Task 1.7 -
    the scoring roll-up T1.6's evaluator leaves as {coverage=$null; scores=$null}
    placeholders).

    SCORING MODEL 1.0 (spec section 2e - pinned, implement exactly):
        Weight by severity: Critical 10, High 6, Medium 3, Low 1, Info 0.
        Per finding: Pass earns the full weight, Warn earns HALF the weight, Fail earns 0 -
        but Fail's weight still counts toward `possible` (it was assessable, it just didn't
        pass). NotApplicable and Error contribute to NEITHER `earned` NOR `possible` - they
        are excluded from the score's denominator entirely, not merely zero-weighted. This
        is what makes "3 NA checks" and "those 3 checks never existed" score identically:
        the score answers "of what could meaningfully be assessed, how much passed", not
        "of everything in the catalog".

    COVERAGE is the separate metric that DOES notice NA/Error: `assessed` is the
    Pass+Warn+Fail count, `applicable` is assessed + notAssessed (notAssessed being the
    NotApplicable+Error count) - i.e. every finding in the category, bucketed by whether it
    was actually assessable. A tenant with three NotApplicable checks scores identically to
    one missing those checks outright, but its coverage.percent is lower - the roll-up
    still tells you three checks couldn't be assessed, even though they didn't move the
    score.

    `percent` fields are [double], rounded to one decimal place with
    MidpointRounding.AwayFromZero (never banker's rounding - this codebase's rounding must
    be deterministic and match ordinary human expectation, not floating-point-parity
    convention), and explicitly 0.0 - never a division-by-zero throw - when the
    denominator (possible / applicable) is 0.

    `byCategory` is keyed by a finding's FULL dotted category path (e.g.
    'Entra.ConditionalAccess'), not just its first segment - top-segment aggregation
    (Entra/Intune) is the renderer's job later (YAGNI here: this task does not know what a
    later renderer needs beyond the full path, so it does not guess at an extra bucket).

    NON-MUTATION: the input -Findings document is never mutated in place. A deep clone
    (via the same canonical-JSON round-trip ConvertTo-PulseClonedDatasets uses in the
    evaluator) is scored and returned instead, so a caller holding the original document
    (already-computed hashes, redaction maps keyed against it, etc.) never sees it change
    out from under them, and calling this function twice against the same input is
    trivially side-effect-free.

    DETERMINISM: accumulation into `categoryStats` (and, from it, `overallEarned` /
    `overallPossible` / `overallAssessed` / `overallApplicable`) iterates category names in
    ordinal sort order (the same [string]::CompareOrdinal index-sort pattern used
    throughout this codebase - see ConvertTo-PulseCanonicalJson and
    Invoke-PulseEvaluation's own docstrings for why: Sort-Object -Culture collation is
    culture-dependent and therefore non-deterministic across locales). That is what this
    sort actually buys: a fixed, reproducible ORDER OF ACCUMULATION for sums that are
    (in floating point) not strictly order-independent. It does NOT control - and must not
    be relied on to control - the in-memory enumeration order of the `$scoresByCategory` /
    `$coverageByCategory` hashtables themselves: .NET Hashtable/Dictionary key enumeration
    is bucket-ordered and hash-randomized per process, not insertion-ordered, even though
    entries were added in sorted order (verified empirically: the same insertion sequence
    enumerates differently across two processes). The actual guarantee that the JSON this
    document eventually serializes to is byte-identical across runs comes from
    ConvertTo-PulseCanonicalJson's own ordinal re-sort of every object's keys at
    serialization time - that re-sort is load-bearing; this function's accumulation-order
    sort is not a substitute for it and a caller must never assume `.Keys` on the returned
    byCategory hashtables comes back in any particular order.
#>

function Add-PulseScores {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Findings
    )

    if ($null -eq $Findings.producer -or [string]::IsNullOrEmpty($Findings.producer.scoringModelVersion)) {
        throw 'Add-PulseScores: input document is missing producer.scoringModelVersion.'
    }

    # This function implements ONE scoring model, 1.0, exactly as pinned by spec section
    # 2e. A document that claims a different scoringModelVersion must never silently be
    # run through 1.0's math anyway - that would be a silent gap (a v2.0-tagged document
    # scored as if it were v1.0, with nothing in the output revealing the mismatch). Fail
    # loudly instead, naming both the version the document claims and the version this
    # function actually implements.
    if ($Findings.producer.scoringModelVersion -ne '1.0') {
        throw "Add-PulseScores: input document declares producer.scoringModelVersion '$($Findings.producer.scoringModelVersion)', but this function only implements scoring model '1.0'."
    }

    # Deep clone - see NON-MUTATION note above. Reuses the same
    # ConvertTo-PulseCanonicalJson -> ConvertFrom-Json round-trip pattern
    # ConvertTo-PulseClonedDatasets (Invoke-PulseEvaluation.ps1) already established for
    # this codebase, rather than hand-rolling a second recursive clone.
    $json = ConvertTo-PulseCanonicalJson -InputObject $Findings
    $document = ConvertFrom-Json -InputObject $json -Depth 64

    $weights = @{
        Critical = 10.0
        High     = 6.0
        Medium   = 3.0
        Low      = 1.0
        Info     = 0.0
    }

    # Per-category accumulators, keyed by the finding's full dotted category path.
    # @{ Earned; Possible; Assessed; NotAssessed } - see docstring for what each means.
    $categoryStats = @{}

    foreach ($finding in @($document.findings)) {
        $category = [string] $finding.category
        $severity = [string] $finding.severity
        $status = [string] $finding.status

        if (-not $weights.ContainsKey($severity)) {
            throw "Add-PulseScores: finding '$($finding.id)' has unrecognized severity '$severity'."
        }

        if (-not $categoryStats.ContainsKey($category)) {
            $categoryStats[$category] = @{
                Earned      = 0.0
                Possible    = 0.0
                Assessed    = 0
                NotAssessed = 0
            }
        }
        $stat = $categoryStats[$category]
        $weight = [double] $weights[$severity]

        switch ($status) {
            'Pass' {
                $stat.Earned += $weight
                $stat.Possible += $weight
                $stat.Assessed += 1
            }
            'Warn' {
                $stat.Earned += ($weight / 2.0)
                $stat.Possible += $weight
                $stat.Assessed += 1
            }
            'Fail' {
                # Earns nothing, but the weight was assessable - it still counts toward
                # `possible` (the denominator), unlike NotApplicable/Error below.
                $stat.Possible += $weight
                $stat.Assessed += 1
            }
            'NotApplicable' {
                $stat.NotAssessed += 1
            }
            'Error' {
                $stat.NotAssessed += 1
            }
            default {
                throw "Add-PulseScores: finding '$($finding.id)' has unrecognized status '$status'."
            }
        }
    }

    # Ordinal sort of category names - index-sort pattern (see docstring), never
    # Sort-Object without -Culture and never the two-array [Array]::Sort(keys, items)
    # overload (Import-PulseCheckCatalog / Invoke-PulseEvaluation document the same
    # avoidance for the same reason: that overload does not reliably reorder the second
    # array under PowerShell's method binder in this environment).
    $categoryNames = [string[]] @($categoryStats.Keys)
    if ($categoryNames.Count -gt 1) {
        $order = [int[]] (0 .. ($categoryNames.Count - 1))
        $comparison = [System.Comparison[int]] { param($a, $b) [string]::CompareOrdinal($categoryNames[$a], $categoryNames[$b]) }
        [System.Array]::Sort($order, $comparison)
        $categoryNames = [string[]] @(foreach ($i in $order) { $categoryNames[$i] })
    }

    $scoresByCategory = @{}
    $coverageByCategory = @{}

    $overallEarned = 0.0
    $overallPossible = 0.0
    $overallAssessed = 0
    $overallApplicable = 0

    foreach ($name in $categoryNames) {
        $stat = $categoryStats[$name]

        $possible = [double] $stat.Possible
        $earned = [double] $stat.Earned
        $percent = if ($possible -eq 0.0) {
            0.0
        } else {
            [double] [math]::Round(($earned / $possible) * 100.0, 1, [System.MidpointRounding]::AwayFromZero)
        }
        $scoresByCategory[$name] = [pscustomobject]@{
            earned   = $earned
            possible = $possible
            percent  = $percent
        }

        $assessed = [int] $stat.Assessed
        $applicable = [int] ($stat.Assessed + $stat.NotAssessed)
        $coveragePercent = if ($applicable -eq 0) {
            0.0
        } else {
            [double] [math]::Round(($assessed / $applicable) * 100.0, 1, [System.MidpointRounding]::AwayFromZero)
        }
        $coverageByCategory[$name] = [pscustomobject]@{
            assessed    = $assessed
            applicable  = $applicable
            percent     = $coveragePercent
        }

        $overallEarned += $earned
        $overallPossible += $possible
        $overallAssessed += $assessed
        $overallApplicable += $applicable
    }

    $overallPercent = if ($overallPossible -eq 0.0) {
        0.0
    } else {
        [double] [math]::Round(($overallEarned / $overallPossible) * 100.0, 1, [System.MidpointRounding]::AwayFromZero)
    }
    $overallCoveragePercent = if ($overallApplicable -eq 0) {
        0.0
    } else {
        [double] [math]::Round(($overallAssessed / $overallApplicable) * 100.0, 1, [System.MidpointRounding]::AwayFromZero)
    }

    $document.scores = [pscustomobject]@{
        overall    = [pscustomobject]@{
            earned   = [double] $overallEarned
            possible = [double] $overallPossible
            percent  = [double] $overallPercent
        }
        byCategory = $scoresByCategory
    }

    $document.coverage = [pscustomobject]@{
        overall    = [pscustomobject]@{
            assessed   = [int] $overallAssessed
            applicable = [int] $overallApplicable
            percent    = [double] $overallCoveragePercent
        }
        byCategory = $coverageByCategory
    }

    return $document
}
