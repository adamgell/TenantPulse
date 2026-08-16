<#
    Gate on the WHOLE Pester result, not just the failed-assertion count.

    A discovery or container failure prevents tests from running without looking
    like a failed assertion - which is exactly how a CI suite can stay green while
    testing nothing. This helper parses the NUnit XML Sampler/Pester emits and fails
    the run unless every one of these holds:

        - the overall result is Passed
        - zero failed tests
        - zero failed containers / discovery errors
        - the errors attribute is empty (no test errors)
        - total test count is at or above an expected minimum
        - skipped tests stay within an explicit allowance (default zero)
        - NotRun blocks (see below) stay within an explicit allowance (default zero)

    Every condition is checked independently and reported with an actionable message;
    any violation exits non-zero.

    NotRun accounting (Pester object XML): a Describe block driven entirely by
    `-ForEach $testCases -AllowNullOrEmptyForEach` with an empty $testCases produces
    zero leaf tests. Zero leaf tests means the block never appears as a <test-case> in
    the NUnit XML at all - it simply isn't there, which is indistinguishable from "this
    Describe was deleted" by looking at the NUnit file alone. If test-case generation
    silently breaks later (e.g. `Get-Command -Module` starts returning nothing for a
    reason nobody intended), the NUnit-only gate above would stay green while an entire
    Describe quietly stopped asserting anything. Pester's own object dump
    (PesterObject_*.xml, produced by Export-Clixml alongside the NUnit file) still
    records that block with Result = 'NotRun', and its captured ScriptBlock text still
    contains the `It` statements that never ran - so this script also parses that file,
    walks every block recursively, and for each block whose Result is 'NotRun' counts
    the `It` statements its script text defines. That count must stay within
    -AllowNotRun (default 0); the CI caller passes an explicit, commented allowance
    while functions are still absent and must lower it as they land.

    This is a helper script, not a Pester test: its name does not end in .Tests.ps1,
    so Pester discovery never runs it as part of the suite.

    Run:  pwsh -File ./tests/QA/Assert-GateResult.ps1 -ResultPath output/testResults/NUnitXml_*.xml -MinimumTests 500 -AllowedSkips 0 -AllowNotRun 0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ResultPath,

    [Parameter()]
    [int] $MinimumTests = 500,

    # Skips are permitted only up to an explicit budget. The default of zero means a new
    # skip must be argued for at the call site rather than absorbed silently.
    [int] $AllowedSkips = 0,

    # Path to the Pester object CLIXML (PesterObject_*.xml) produced alongside the NUnit
    # result file. Defaults to auto-discovering a single such file next to -ResultPath.
    [Parameter()]
    [string] $PesterObjectPath,

    # NotRun blocks (see NotRun accounting above) are permitted only up to an explicit
    # budget, mirroring -AllowedSkips: the default of zero means any NotRun block must be
    # argued for at the call site rather than absorbed silently.
    [Parameter()]
    [int] $AllowNotRun = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
    Write-Error "Result file not found: $ResultPath"
    exit 1
}

try {
    [xml] $doc = Get-Content -LiteralPath $ResultPath -Raw
} catch {
    Write-Error "Result file is not valid XML: $ResultPath`n$($_.Exception.Message)"
    exit 1
}

$root = $doc.SelectSingleNode('/test-results')
if ($null -eq $root) {
    Write-Error "Result file has no <test-results> root element: $ResultPath"
    exit 1
}

function ConvertTo-Count {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref] $parsed)) { return -1 }
    return $parsed
}

$violations = [System.Collections.Generic.List[string]]::new()

# 0. Skips, evaluated first because a single skipped test turns the whole NUnit result
# into 'Ignored'. Without this the gate reports "the suite did not pass" for a suite in
# which nothing failed, which is a confident diagnosis of the wrong problem - the same
# failure shape this repository keeps finding elsewhere. Skips are allowed only up to an
# explicit budget, so they stay a deliberate decision rather than a silent drift.
$skipped = ConvertTo-Count $root.GetAttribute('skipped')
$skipsWithinBudget = $false
if ($skipped -lt 0) {
    $violations.Add("skipped attribute is unreadable: '$($root.GetAttribute('skipped'))'.")
} elseif ($skipped -gt $AllowedSkips) {
    $violations.Add("$skipped test(s) skipped - the allowance is $AllowedSkips. If the skip is deliberate, raise -AllowedSkips and say why; if it is not, a test is being silently dropped.")
} else {
    $skipsWithinBudget = $true
}

# 1. Overall result is Passed (top-level suite result attribute).
$topSuite = $root.SelectSingleNode('test-suite')
if ($null -eq $topSuite) {
    $violations.Add('No top-level <test-suite> found - the result is structurally invalid.')
} else {
    $overallResult = [string] $topSuite.GetAttribute('result')
    $ignoredByAllowedSkips = ($overallResult -eq 'Ignored' -and $skipped -gt 0 -and $skipsWithinBudget)
    if ($overallResult -notin @('Success', 'Passed') -and -not $ignoredByAllowedSkips) {
        $violations.Add("Overall result is '$overallResult' - expected Passed. The suite did not pass.")
    }
}

# 2. Zero failed tests (failures attribute counts failed assertions).
$failures = ConvertTo-Count $root.GetAttribute('failures')
if ($failures -lt 0) {
    $violations.Add("failures attribute is unreadable: '$($root.GetAttribute('failures'))'.")
} elseif ($failures -ne 0) {
    $violations.Add("$failures test(s) failed - expected 0 failed tests.")
}

# 3. Zero failed containers / discovery errors (any suite-level Failure or Error node).
$failedSuites = $root.SelectNodes('//test-suite[@result="Failure" or @result="Error"]')
$failedSuiteCount = if ($null -eq $failedSuites) { 0 } else { $failedSuites.Count }
if ($failedSuiteCount -gt 0) {
    $names = @($failedSuites | ForEach-Object { [string] $_.GetAttribute('name') }) -join '; '
    $violations.Add("$failedSuiteCount failed container(s) / discovery error(s): $names")
}

# 4. errors attribute empty (no test errors).
$errorsRaw = ([string] $root.GetAttribute('errors')).Trim()
if ($errorsRaw -notin @('', '0')) {
    $violations.Add("errors attribute is '$errorsRaw' - expected empty (0 test errors).")
}

# 5. Total test count meets the expected minimum.
$total = ConvertTo-Count $root.GetAttribute('total')
if ($total -lt 0) {
    $violations.Add("total attribute is unreadable: '$($root.GetAttribute('total'))'.")
} elseif ($total -lt $MinimumTests) {
    $violations.Add("Total test count $total is below the expected minimum $MinimumTests - discovery may be silently dropping tests.")
}

# 6. NotRun blocks (see the NotRun accounting note above) stay within an explicit
# allowance. This is the check the NUnit XML alone cannot make: a block with zero leaf
# tests never appears there at all.
function Get-AllPesterBlocks {
    # Recurse through the Pester object's Container/Block tree. Blocks can nest
    # (a Describe inside a Describe), so this must not assume a flat one level.
    param([Parameter(ValueFromPipeline = $true)] $Block)
    process {
        $Block
        foreach ($child in @($Block.Blocks)) {
            Get-AllPesterBlocks -Block $child
        }
    }
}

if (-not $PSBoundParameters.ContainsKey('PesterObjectPath')) {
    $objectCandidates = @(Get-ChildItem -Path (Join-Path (Split-Path -Path $ResultPath -Parent) 'PesterObject_*.xml') -ErrorAction SilentlyContinue)
    if ($objectCandidates.Count -eq 1) {
        $PesterObjectPath = $objectCandidates[0].FullName
    } elseif ($objectCandidates.Count -eq 0) {
        $violations.Add('No Pester object XML (PesterObject_*.xml) found next to the NUnit result file - cannot verify NotRun blocks this run. Pass -PesterObjectPath explicitly, or check the Pester TestResult configuration still exports it.')
    } else {
        $violations.Add("Multiple Pester object XML files found next to the NUnit result file: $($objectCandidates.Name -join ', '). Pass -PesterObjectPath explicitly.")
    }
}

if ($PesterObjectPath) {
    if (-not (Test-Path -LiteralPath $PesterObjectPath -PathType Leaf)) {
        $violations.Add("Pester object XML not found: $PesterObjectPath")
    } else {
        try {
            $pesterRun = Import-Clixml -LiteralPath $PesterObjectPath
        } catch {
            $violations.Add("Pester object XML is not readable: $PesterObjectPath`n$($_.Exception.Message)")
            $pesterRun = $null
        }

        if ($pesterRun) {
            $notRunBlocks = @($pesterRun.Containers | Get-AllPesterBlocks | Where-Object { $_.Result -eq 'NotRun' })

            $notRunTestCount = 0
            $notRunSummary = [System.Collections.Generic.List[string]]::new()
            foreach ($block in $notRunBlocks) {
                # The block ran nothing (Tests is empty), but Pester still captured its
                # source text - count the `It` statements it defines so a real number of
                # missing tests is reported, not just a block name.
                $itCount = @([regex]::Matches([string] $block.ScriptBlock, "(?m)^\s*It\s+['\`"]")).Count
                $notRunTestCount += $itCount
                $notRunSummary.Add("$($block.Name) ($itCount It statement(s))")
            }

            if ($notRunTestCount -gt $AllowNotRun) {
                $violations.Add("$notRunTestCount NotRun test(s) across block(s) [$($notRunSummary -join '; ')] - the allowance is $AllowNotRun. A NotRun block has zero leaf tests and is invisible in the NUnit result; if this is expected (e.g. no functions exist yet to drive a -ForEach), raise -AllowNotRun and say why in the caller; if it is not, test-case generation is silently producing nothing.")
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host ''
    Write-Host 'GATE FAILED: Pester result did not satisfy the whole-result conditions.' -ForegroundColor Red
    for ($i = 0; $i -lt $violations.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $violations[$i]) -ForegroundColor Red
    }
    Write-Host ''
    exit 1
}

$notRunTestCount = if ($null -ne $notRunTestCount) { $notRunTestCount } else { 0 }
Write-Host "GATE PASSED: $total tests, $failures failed, $errorsRaw errors, $skipped skipped (allowance $AllowedSkips), $notRunTestCount NotRun (allowance $AllowNotRun), total >= $MinimumTests." -ForegroundColor Green
exit 0
