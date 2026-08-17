<#
    QA gate (Phase 3 closing fix series, item 2 - NEW STANDING GATE): the MinimumTests
    ratchet exists in FOUR separate locations that must all carry the SAME number in the
    same commit (this project's own standing "four locations, same commit" rule - see
    docs/STATUS.md's T4.2 retrospective entry for the exact regression this rule exists to
    prevent: the ratchet was bumped in .build/AssertGateResult.tasks.ps1 but missed in
    .github/workflows/ci.yml, letting CI silently enforce a stale floor). Before this gate,
    "all four locations agree" was enforced only by a human grepping for the old value
    before editing - this test makes a drift between any two of the four locations a real,
    automated test failure instead of something that depends on someone remembering to
    check.

    Each location's number is parsed directly out of its own real, on-disk text - never
    hand-copied into this file as a second source of truth that could itself drift - so
    this gate stays honest about what the four files actually say, not what a prior test
    author believed they said:
        1. .build/AssertGateResult.tasks.ps1  - $script:tenantPulseGateMinimumTests = <N>
        2. .github/workflows/ci.yml            - -MinimumTests <N> (the real CI invocation
                                                  of tests/QA/Assert-GateResult.ps1, not a
                                                  comment referencing it)
        3. scripts/Publish-TenantPulsePackage.ps1 - BOTH of that script's own two
                                                  -MinimumTests N lines (the live gate call
                                                  AND the error-message hint text that
                                                  quotes the same number back to the
                                                  operator - the task brief's own "both
                                                  lines" instruction exists because a past
                                                  edit could update one and miss the other)
        4. tests/QA/PublishTenantPulsePackage.tests.ps1 - the fabricated NUnit fixture's own
                                                  total="<N>" attribute (must track
                                                  Publish-TenantPulsePackage.ps1's own
                                                  -MinimumTests exactly, per that test
                                                  file's own docstring)

    PROVE-IT-CAN-FAIL discipline (matching SettingDefinitionCorpusCrossCheck.tests.ps1's own
    precedent): the parsing helper is unit-tested against small synthetic in-memory text
    first, including a case that deliberately disagrees, before it is ever pointed at the
    real repo tree.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath

    <#
        Parses the single integer MinimumTests number a given ratchet location's real text
        is expected to carry, using that location's own KIND-specific pattern (each of the
        four locations spells the same concept slightly differently - see this file's own
        docstring). Throws (naming the location and pattern) if the pattern is not found at
        all, or is found with more than one DISTINCT numeric value - either shape means this
        helper's own assumption about that file's format no longer holds, which must fail
        loudly rather than silently returning $null and letting a real drift go unnoticed.
    #>
    function Get-PulseMinimumTestsRatchetValue {
        [CmdletBinding()]
        [OutputType([int])]
        param(
            [Parameter(Mandatory)]
            [string] $Text,

            [Parameter(Mandatory)]
            [ValidateSet('AssertGateResultTask', 'CiYml', 'PublishScript', 'PublishScriptErrorHint', 'PublishFixtureTotal')]
            [string] $Kind,

            [Parameter(Mandatory)]
            [string] $LocationName
        )

        $pattern = switch ($Kind) {
            'AssertGateResultTask' { '\$script:tenantPulseGateMinimumTests\s*=\s*(\d+)' }
            'CiYml' { '-MinimumTests\s+(\d+)\s' }
            'PublishScript' { '-MinimumTests\s+(\d+)\s+-AllowedSkips' }
            'PublishScriptErrorHint' { "-MinimumTests\s+'?(\d+)'?\`"" }
            'PublishFixtureTotal' { 'total="(\d+)"' }
        }

        $regex = [regex] $pattern
        $matches = @($regex.Matches($Text))
        if ($matches.Count -eq 0) {
            throw "Get-PulseMinimumTestsRatchetValue: pattern for '$Kind' matched nothing in '$LocationName' - this helper's assumption about that file's format no longer holds."
        }

        $distinctValues = @($matches | ForEach-Object { [int] $_.Groups[1].Value } | Select-Object -Unique)
        if ($distinctValues.Count -gt 1) {
            throw "Get-PulseMinimumTestsRatchetValue: pattern for '$Kind' matched $($distinctValues.Count) DISTINCT numeric values in '$LocationName' ($($distinctValues -join ', ')) - expected exactly one."
        }

        return $distinctValues[0]
    }
}

Describe 'Get-PulseMinimumTestsRatchetValue (self-check against synthetic input)' {
    It 'parses the AssertGateResultTask shape' {
        Get-PulseMinimumTestsRatchetValue -Text '$script:tenantPulseGateMinimumTests = 1956' -Kind AssertGateResultTask -LocationName 'synthetic' | Should -Be 1956
    }

    It 'parses the CiYml shape, ignoring an unrelated -MinimumTests mention with a different trailing token' {
        $text = "pwsh -File ./tests/QA/Assert-GateResult.ps1 -MinimumTests 1956 -AllowedSkips 0 -AllowNotRun 1"
        Get-PulseMinimumTestsRatchetValue -Text $text -Kind CiYml -LocationName 'synthetic' | Should -Be 1956
    }

    It 'PROVES THE GATE CAN FAIL: throws when two distinct numeric values are found for the same Kind' {
        $text = "`$script:tenantPulseGateMinimumTests = 1956`n`$script:tenantPulseGateMinimumTests = 1955"
        { Get-PulseMinimumTestsRatchetValue -Text $text -Kind AssertGateResultTask -LocationName 'synthetic' } | Should -Throw -ExpectedMessage '*DISTINCT*'
    }

    It 'PROVES THE GATE CAN FAIL: throws when the pattern matches nothing at all' {
        { Get-PulseMinimumTestsRatchetValue -Text 'no ratchet number here' -Kind AssertGateResultTask -LocationName 'synthetic' } | Should -Throw -ExpectedMessage '*matched nothing*'
    }
}

Describe 'MinimumTests ratchet - all four locations agree (real repo tree)' {
    It 'parses a single, identical MinimumTests value from every one of the four tracked locations' {
        $assertGateResultTaskPath = Join-Path $script:repoRoot '.build/AssertGateResult.tasks.ps1'
        $ciYmlPath = Join-Path $script:repoRoot '.github/workflows/ci.yml'
        $publishScriptPath = Join-Path $script:repoRoot 'scripts/Publish-TenantPulsePackage.ps1'
        $publishFixtureTestPath = Join-Path $script:repoRoot 'tests/QA/PublishTenantPulsePackage.tests.ps1'

        foreach ($path in @($assertGateResultTaskPath, $ciYmlPath, $publishScriptPath, $publishFixtureTestPath)) {
            Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue -Because "'$path' must exist for this gate to mean anything"
        }

        $assertGateResultTaskValue = Get-PulseMinimumTestsRatchetValue -Text (Get-Content -LiteralPath $assertGateResultTaskPath -Raw) -Kind AssertGateResultTask -LocationName '.build/AssertGateResult.tasks.ps1'
        $ciYmlValue = Get-PulseMinimumTestsRatchetValue -Text (Get-Content -LiteralPath $ciYmlPath -Raw) -Kind CiYml -LocationName '.github/workflows/ci.yml'

        $publishScriptText = Get-Content -LiteralPath $publishScriptPath -Raw
        $publishScriptGateCallValue = Get-PulseMinimumTestsRatchetValue -Text $publishScriptText -Kind PublishScript -LocationName 'scripts/Publish-TenantPulsePackage.ps1 (gate call)'
        $publishScriptErrorHintValue = Get-PulseMinimumTestsRatchetValue -Text $publishScriptText -Kind PublishScriptErrorHint -LocationName 'scripts/Publish-TenantPulsePackage.ps1 (error-message hint)'

        $publishFixtureTotalValue = Get-PulseMinimumTestsRatchetValue -Text (Get-Content -LiteralPath $publishFixtureTestPath -Raw) -Kind PublishFixtureTotal -LocationName 'tests/QA/PublishTenantPulsePackage.tests.ps1'

        # Report every parsed value together on failure (Pester's own -Because text below,
        # per value) rather than letting the FIRST mismatched assertion hide the others -
        # a drift-fixing pass benefits from seeing the whole picture in one failed run.
        $allValues = @{
            '.build/AssertGateResult.tasks.ps1'                              = $assertGateResultTaskValue
            '.github/workflows/ci.yml'                                       = $ciYmlValue
            'scripts/Publish-TenantPulsePackage.ps1 (gate call)'             = $publishScriptGateCallValue
            'scripts/Publish-TenantPulsePackage.ps1 (error-message hint)'    = $publishScriptErrorHintValue
            'tests/QA/PublishTenantPulsePackage.tests.ps1 (fixture total)'   = $publishFixtureTotalValue
        }
        $distinctValues = @($allValues.Values | Select-Object -Unique)

        ($distinctValues.Count -eq 1) | Should -BeTrue -Because (
            "every MinimumTests ratchet location must carry the SAME number; found: " +
            (($allValues.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        )
    }
}
