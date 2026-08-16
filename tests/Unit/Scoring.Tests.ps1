BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    # Import the BUILT module (never dot-source source files: they would redefine module
    # classes and Add-Type types in test scope). Pester discovers tests per file, so each
    # file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    # Plain-PowerShell helper (outside the module) that builds a fixture finding shaped
    # exactly like Invoke-PulseEvaluation's output - only the fields Add-PulseScores
    # actually reads (id/category/severity/status) are given real values.
    function script:New-PulseFixtureFinding {
        param(
            [string] $Id = 'TP.INT.0001',
            [string] $Category = 'Intune.Compliance',
            [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
            [string] $Severity = 'Medium',
            [ValidateSet('Pass', 'Warn', 'Fail', 'NotApplicable', 'Error')]
            [string] $Status = 'Pass'
        )

        [pscustomobject]@{
            id       = $Id
            title    = "Fixture $Id"
            category = $Category
            severity = $Severity
            status   = $Status
            evidence = @()
            reason   = $null
            effort   = 'Low'
            impact   = 'Medium'
        }
    }

    # Plain-PowerShell helper that wraps a findings array into a document shaped like
    # Invoke-PulseEvaluation's Document output - coverage/scores still $null placeholders,
    # producer.scoringModelVersion set, exactly as Task 1.6 leaves it.
    function script:New-PulseFixtureScoringDocument {
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]] $Findings,

            [string] $ScoringModelVersion = '1.0'
        )

        [pscustomobject]@{
            schemaVersion = '1.0'
            generatedUtc  = '2026-08-15T00:00:00.000Z'
            tenant        = 'tp-fixturetenant'
            producer      = [pscustomobject]@{
                tenantPulse         = '0.1.0'
                graphKit             = $null
                scoringModelVersion = $ScoringModelVersion
            }
            coverage      = $null
            scores        = $null
            findings      = @($Findings)
        }
    }

    function script:Invoke-PulseFixtureScoring {
        param(
            [Parameter(Mandatory)]
            [pscustomobject] $Document
        )

        InModuleScope TenantPulse -ArgumentList $Document {
            param($Document)
            Add-PulseScores -Findings $Document
        }
    }
}

Describe 'Add-PulseScores' {

    It 'scores an all-Pass document at 100 percent' {
        $doc = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'Critical' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'High' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0003' -Severity 'Low' -Status 'Pass')
        )

        $result = Invoke-PulseFixtureScoring -Document $doc

        $result.scores.overall.earned | Should -Be 17.0
        $result.scores.overall.possible | Should -Be 17.0
        $result.scores.overall.percent | Should -Be 100.0
    }

    It 'drops exactly the Critical weight (10) from earned when one Critical check fails' {
        $baseline = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'Critical' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'High' -Status 'Pass')
        )
        $withFail = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'Critical' -Status 'Fail'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'High' -Status 'Pass')
        )

        $baselineResult = Invoke-PulseFixtureScoring -Document $baseline
        $failResult = Invoke-PulseFixtureScoring -Document $withFail

        $failResult.scores.overall.possible | Should -Be $baselineResult.scores.overall.possible
        ($baselineResult.scores.overall.earned - $failResult.scores.overall.earned) | Should -Be 10.0
    }

    It 'earns exactly half weight for a Warn status' {
        $doc = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Warn')
        )

        $result = Invoke-PulseFixtureScoring -Document $doc

        $result.scores.overall.earned | Should -Be 3.0
        $result.scores.overall.possible | Should -Be 6.0
        $result.scores.overall.percent | Should -Be 50.0
    }

    It 'scores identically whether checks are NotApplicable or entirely absent, but coverage differs' {
        $withNA = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'Medium' -Status 'NotApplicable'),
            (New-PulseFixtureFinding -Id 'TP.INT.0003' -Severity 'Low' -Status 'NotApplicable'),
            (New-PulseFixtureFinding -Id 'TP.INT.0004' -Severity 'Critical' -Status 'NotApplicable')
        )
        $withoutThose = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass')
        )

        $naResult = Invoke-PulseFixtureScoring -Document $withNA
        $strippedResult = Invoke-PulseFixtureScoring -Document $withoutThose

        $naResult.scores.overall.earned | Should -Be $strippedResult.scores.overall.earned
        $naResult.scores.overall.possible | Should -Be $strippedResult.scores.overall.possible
        $naResult.scores.overall.percent | Should -Be $strippedResult.scores.overall.percent

        $naResult.coverage.overall.percent | Should -BeLessThan $strippedResult.coverage.overall.percent
    }

    It 'never lets an Error finding change the overall percent' {
        $withoutError = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'Low' -Status 'Fail')
        )
        $withError = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'Low' -Status 'Fail'),
            (New-PulseFixtureFinding -Id 'TP.INT.0003' -Severity 'Critical' -Status 'Error')
        )

        $withoutErrorResult = Invoke-PulseFixtureScoring -Document $withoutError
        $withErrorResult = Invoke-PulseFixtureScoring -Document $withError

        $withErrorResult.scores.overall.percent | Should -Be $withoutErrorResult.scores.overall.percent
        $withErrorResult.scores.overall.earned | Should -Be $withoutErrorResult.scores.overall.earned
        $withErrorResult.scores.overall.possible | Should -Be $withoutErrorResult.scores.overall.possible
    }

    It 'never lets an Info-severity finding (weight 0) change the score, regardless of its status' {
        $withoutInfo = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass')
        )
        $withInfoFail = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'Info' -Status 'Fail')
        )

        $withoutInfoResult = Invoke-PulseFixtureScoring -Document $withoutInfo
        $withInfoFailResult = Invoke-PulseFixtureScoring -Document $withInfoFail

        $withInfoFailResult.scores.overall.percent | Should -Be $withoutInfoResult.scores.overall.percent
        $withInfoFailResult.scores.overall.earned | Should -Be $withoutInfoResult.scores.overall.earned
        $withInfoFailResult.scores.overall.possible | Should -Be $withoutInfoResult.scores.overall.possible
    }

    It 'sums byCategory earned/possible/assessed/applicable up to the overall totals' {
        $doc = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.ENT.0001' -Category 'Entra.ConditionalAccess' -Severity 'Critical' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.ENT.0002' -Category 'Entra.ConditionalAccess' -Severity 'High' -Status 'Fail'),
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Category 'Intune.Compliance' -Severity 'Medium' -Status 'Warn'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Category 'Intune.Compliance' -Severity 'Low' -Status 'NotApplicable')
        )

        $result = Invoke-PulseFixtureScoring -Document $doc

        $categorySumEarned = 0.0
        $categorySumPossible = 0.0
        $categorySumAssessed = 0
        $categorySumApplicable = 0
        foreach ($category in $result.scores.byCategory.Keys) {
            $categorySumEarned += $result.scores.byCategory[$category].earned
            $categorySumPossible += $result.scores.byCategory[$category].possible
        }
        foreach ($category in $result.coverage.byCategory.Keys) {
            $categorySumAssessed += $result.coverage.byCategory[$category].assessed
            $categorySumApplicable += $result.coverage.byCategory[$category].applicable
        }

        $categorySumEarned | Should -Be $result.scores.overall.earned
        $categorySumPossible | Should -Be $result.scores.overall.possible
        $categorySumAssessed | Should -Be $result.coverage.overall.assessed
        $categorySumApplicable | Should -Be $result.coverage.overall.applicable

        $result.scores.byCategory.Keys | Should -Contain 'Entra.ConditionalAccess'
        $result.scores.byCategory.Keys | Should -Contain 'Intune.Compliance'
    }

    It 'reports percent 0 (not a division-by-zero error) when possible is 0' {
        $doc = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'Info' -Status 'Pass')
        )

        $result = Invoke-PulseFixtureScoring -Document $doc

        $result.scores.overall.possible | Should -Be 0.0
        $result.scores.overall.percent | Should -Be 0.0
    }

    It 'reports coverage percent 0 (not a division-by-zero error) when there are no findings' {
        $doc = New-PulseFixtureScoringDocument -Findings @()

        $result = Invoke-PulseFixtureScoring -Document $doc

        $result.coverage.overall.applicable | Should -Be 0
        $result.coverage.overall.percent | Should -Be 0.0
        $result.scores.overall.possible | Should -Be 0.0
        $result.scores.overall.percent | Should -Be 0.0
    }

    It 'rounds percent to one decimal place using away-from-zero rounding' {
        # 1 of 3 equal-weight Pass -> 33.33...% -> 33.3
        $doc = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'Low' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0002' -Severity 'Low' -Status 'Fail'),
            (New-PulseFixtureFinding -Id 'TP.INT.0003' -Severity 'Low' -Status 'Fail')
        )

        $result = Invoke-PulseFixtureScoring -Document $doc

        $result.scores.overall.percent | Should -Be 33.3
    }

    It 'rounds 0.05 percent away from zero to 0.1, not to 0.0 (discriminates AwayFromZero from banker''s/ToEven rounding)' {
        # 1 Low Warn (earned 0.5, possible 1) + 99 Critical Fail (possible 990) + 1 High
        # Fail (possible 6) + 1 Medium Fail (possible 3) -> earned 0.5, possible 1000 ->
        # exactly 0.05%. AwayFromZero rounds 0.05 up to 0.1; ToEven (banker's rounding)
        # would round it down to 0.0 (0 is the even digit) - this fixture is the one that
        # actually tells the two rounding modes apart, unlike the 33.3% case above.
        $findings = [System.Collections.Generic.List[object]]::new()
        $findings.Add((New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'Low' -Status 'Warn'))
        for ($i = 1; $i -le 99; $i++) {
            $findings.Add((New-PulseFixtureFinding -Id ('TP.INT.{0:D4}' -f (1000 + $i)) -Severity 'Critical' -Status 'Fail'))
        }
        $findings.Add((New-PulseFixtureFinding -Id 'TP.INT.2000' -Severity 'High' -Status 'Fail'))
        $findings.Add((New-PulseFixtureFinding -Id 'TP.INT.2001' -Severity 'Medium' -Status 'Fail'))

        $doc = New-PulseFixtureScoringDocument -Findings $findings.ToArray()

        $result = Invoke-PulseFixtureScoring -Document $doc

        $result.scores.overall.earned | Should -Be 0.5
        $result.scores.overall.possible | Should -Be 1000.0
        $result.scores.overall.percent | Should -Be 0.1
    }

    It 'does not mutate the input document in place' {
        $doc = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass')
        )

        [void] (Invoke-PulseFixtureScoring -Document $doc)

        $doc.scores | Should -BeNullOrEmpty
        $doc.coverage | Should -BeNullOrEmpty
    }

    It 'produces byte-identical scored documents across two independent calls on the same findings' {
        $docA = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.ENT.0001' -Category 'Entra.ConditionalAccess' -Severity 'Critical' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Category 'Intune.Compliance' -Severity 'Medium' -Status 'Warn')
        )
        $docB = New-PulseFixtureScoringDocument -Findings @(
            (New-PulseFixtureFinding -Id 'TP.ENT.0001' -Category 'Entra.ConditionalAccess' -Severity 'Critical' -Status 'Pass'),
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Category 'Intune.Compliance' -Severity 'Medium' -Status 'Warn')
        )

        $resultA = Invoke-PulseFixtureScoring -Document $docA
        $resultB = Invoke-PulseFixtureScoring -Document $docB

        $jsonA = InModuleScope TenantPulse -ArgumentList $resultA {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }
        $jsonB = InModuleScope TenantPulse -ArgumentList $resultB {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }

        [System.Text.Encoding]::UTF8.GetBytes($jsonA) | Should -Be ([System.Text.Encoding]::UTF8.GetBytes($jsonB))
    }

    It 'throws instead of silently scoring a document that declares a different scoringModelVersion' {
        $doc = New-PulseFixtureScoringDocument -ScoringModelVersion '2.0' -Findings @(
            (New-PulseFixtureFinding -Id 'TP.INT.0001' -Severity 'High' -Status 'Pass')
        )

        { Invoke-PulseFixtureScoring -Document $doc } | Should -Throw '*2.0*1.0*'
    }
}
