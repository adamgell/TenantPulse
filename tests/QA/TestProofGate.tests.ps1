<#
    Regression coverage for the release-proof creation boundary.

    The real Invoke-Build tasks run against a throwaway build root. The test workflow must
    capture the exact candidate before the synthetic Pester run, reject any artifact drift,
    require one unambiguous NUnit/Pester-object pair, and emit one proof binding all of those
    bytes only after the whole-result gate passes.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:taskFilePath = Join-Path $script:repoRoot '.build/AssertGateResult.tasks.ps1'
    $script:gateFilePath = Join-Path $script:repoRoot 'tests/QA/Assert-GateResult.ps1'
    $script:invokeBuildPath = Join-Path $script:repoRoot 'output/RequiredModules/InvokeBuild/5.14.23/Invoke-Build.ps1'

    function New-PulseTestProofGateFixture {
        param(
            [Parameter(Mandatory)]
            [ValidateSet('Pass', 'Floor', 'Skip', 'NotRun', 'ModuleDrift', 'PackageDrift', 'AmbiguousResults', 'MismatchedPair')]
            [string] $FailureKind
        )

        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('tp-proof-gate-' + [guid]::NewGuid().ToString())
        $moduleDir = Join-Path $fixtureRoot 'output/module/TenantPulse/9.9.9'
        $resultsDir = Join-Path $fixtureRoot 'output/testResults'
        $gateDir = Join-Path $fixtureRoot 'tests/QA'
        New-Item -ItemType Directory -Path $moduleDir, $resultsDir, $gateDir -Force | Out-Null

        $modulePath = Join-Path $moduleDir 'TenantPulse.psm1'
        $packagePath = Join-Path $fixtureRoot 'output/TenantPulse.9.9.9.nupkg'
        Set-Content -LiteralPath $modulePath -Value '# fixture module' -NoNewline -Encoding utf8
        $placeholderDir = Join-Path $moduleDir 'Data'
        New-Item -ItemType Directory -Path $placeholderDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $placeholderDir '.gitkeep') -Value '' -NoNewline -Encoding utf8
        Set-Content -LiteralPath $packagePath -Value 'fixture package' -NoNewline -Encoding utf8
        Copy-Item -LiteralPath $script:gateFilePath -Destination (Join-Path $gateDir 'Assert-GateResult.ps1')

        # A new test attempt must invalidate every prior publication proof before Pester.
        Set-Content -LiteralPath (Join-Path $resultsDir 'tested-module-digest.txt') -Value 'STALE'
        Set-Content -LiteralPath (Join-Path $resultsDir 'tested-package-digest.txt') -Value 'STALE'
        Set-Content -LiteralPath (Join-Path $resultsDir 'tested-release-proof.json') -Value 'STALE'

        $buildFilePath = Join-Path $fixtureRoot 'proof-gate.build.ps1'
        Set-Content -LiteralPath $buildFilePath -Encoding utf8 -Value @'
. $env:TP_TEST_PROOF_TASK_FILE

task Write_Synthetic_Test_Result {
    $failureKind = $env:TP_TEST_PROOF_FAILURE_KIND
    $resultsDir = Join-Path $BuildRoot 'output/testResults'
    $total = if ($failureKind -eq 'Floor') { 3576 } else { 3577 }
    # The real gate permits two known Windows-only permission skips. Three is above
    # every platform's allowance, so this fixture always exercises the rejection path.
    $skipped = if ($failureKind -eq 'Skip') { 3 } else { 0 }
    $overallResult = if ($failureKind -eq 'Skip') { 'Ignored' } else { 'Passed' }

    $nunitSuffix = 'TenantPulse_v9.9.9.Fixture.xml'
    $pesterSuffix = if ($failureKind -eq 'MismatchedPair') {
        'TenantPulse_v9.9.9.Other.xml'
    }
    else {
        $nunitSuffix
    }

    Set-Content -LiteralPath (Join-Path $resultsDir "NUnitXml_$nunitSuffix") -Encoding utf8 -Value @"
<?xml version="1.0" encoding="utf-8"?>
<test-results name="TenantPulse 9.9.9" total="$total" failures="0" errors="0" skipped="$skipped">
  <test-suite type="TestFixture" name="Fixture" result="$overallResult">
    <results><test-case name="fixture test" result="Success" /></results>
  </test-suite>
</test-results>
"@

    $containers = if ($failureKind -eq 'NotRun') {
        @(
            [pscustomobject]@{
                Name        = 'Dropped generated cases'
                Result      = 'NotRun'
                ScriptBlock = "It 'missing one' { }`nIt 'missing two' { }"
                Blocks      = @()
            }
        )
    }
    else {
        @(
            [pscustomobject]@{
                Name        = 'Passing fixture container'
                Result      = 'Passed'
                ScriptBlock = "It 'fixture test' { }"
                Blocks      = @()
            }
        )
    }
    ([pscustomobject]@{ Containers = $containers }) |
        Export-Clixml -LiteralPath (Join-Path $resultsDir "PesterObject_$pesterSuffix")

    if ($failureKind -eq 'AmbiguousResults') {
        Copy-Item -LiteralPath (Join-Path $resultsDir "NUnitXml_$nunitSuffix") `
            -Destination (Join-Path $resultsDir 'NUnitXml_TenantPulse_v9.9.9.Stale.xml')
        Copy-Item -LiteralPath (Join-Path $resultsDir "PesterObject_$pesterSuffix") `
            -Destination (Join-Path $resultsDir 'PesterObject_TenantPulse_v9.9.9.Stale.xml')
    }
    elseif ($failureKind -eq 'ModuleDrift') {
        Add-Content -LiteralPath (Join-Path $BuildRoot 'output/module/TenantPulse/9.9.9/TenantPulse.psm1') `
            -Value '# changed after capture'
    }
    elseif ($failureKind -eq 'PackageDrift') {
        Add-Content -LiteralPath (Join-Path $BuildRoot 'output/TenantPulse.9.9.9.nupkg') `
            -Value 'changed after capture'
    }
}

task . Capture_Candidate_Proof_Input, Write_Synthetic_Test_Result, Record_Tested_Module_Digest
'@

        [pscustomobject]@{
            Root              = $fixtureRoot
            BuildFilePath     = $buildFilePath
            ModulePath        = $modulePath
            PackagePath       = $packagePath
            ModuleProofPath   = Join-Path $resultsDir 'tested-module-digest.txt'
            PackageProofPath  = Join-Path $resultsDir 'tested-package-digest.txt'
            ReleaseProofPath  = Join-Path $resultsDir 'tested-release-proof.json'
            CandidatePath     = Join-Path $resultsDir 'candidate-proof-input.json'
            NUnitPath         = Join-Path $resultsDir 'NUnitXml_TenantPulse_v9.9.9.Fixture.xml'
            PesterObjectPath  = Join-Path $resultsDir 'PesterObject_TenantPulse_v9.9.9.Fixture.xml'
        }
    }

    function Invoke-PulseTestProofFixture {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [string] $FailureKind
        )

        $oldTaskFile = $env:TP_TEST_PROOF_TASK_FILE
        $oldFailureKind = $env:TP_TEST_PROOF_FAILURE_KIND
        try {
            $env:TP_TEST_PROOF_TASK_FILE = $script:taskFilePath
            $env:TP_TEST_PROOF_FAILURE_KIND = $FailureKind
            $output = & pwsh -NoProfile -File $script:invokeBuildPath `
                '.' `
                $Fixture.BuildFilePath 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
        }
        finally {
            $env:TP_TEST_PROOF_TASK_FILE = $oldTaskFile
            $env:TP_TEST_PROOF_FAILURE_KIND = $oldFailureKind
        }

        [pscustomobject]@{
            Output = $output
            ExitCode = $exitCode
        }
    }
}

Describe 'Release proof whole-result and immutability boundary' {
    AfterEach {
        if ($script:fixture) {
            Remove-Item -LiteralPath $script:fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
            $script:fixture = $null
        }
    }

    It 'leaves no tested proof when the whole-result gate rejects <FailureKind>' -ForEach @(
        @{ FailureKind = 'Floor' }
        @{ FailureKind = 'Skip' }
        @{ FailureKind = 'NotRun' }
    ) {
        $script:fixture = New-PulseTestProofGateFixture -FailureKind $FailureKind
        $result = Invoke-PulseTestProofFixture -Fixture $script:fixture -FailureKind $FailureKind

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'GATE FAILED'
        Test-Path -LiteralPath $script:fixture.ModuleProofPath | Should -BeFalse
        Test-Path -LiteralPath $script:fixture.PackageProofPath | Should -BeFalse
        Test-Path -LiteralPath $script:fixture.ReleaseProofPath | Should -BeFalse
    }

    It 'rejects <FailureKind> after the pre-test candidate capture' -ForEach @(
        @{ FailureKind = 'ModuleDrift'; ExpectedMessage = 'module candidate changed' }
        @{ FailureKind = 'PackageDrift'; ExpectedMessage = 'package candidate changed' }
    ) {
        $script:fixture = New-PulseTestProofGateFixture -FailureKind $FailureKind
        $result = Invoke-PulseTestProofFixture -Fixture $script:fixture -FailureKind $FailureKind

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match $ExpectedMessage
        Test-Path -LiteralPath $script:fixture.ReleaseProofPath | Should -BeFalse
    }

    It 'rejects <FailureKind> instead of choosing a result by modification time' -ForEach @(
        @{ FailureKind = 'AmbiguousResults'; ExpectedMessage = 'exactly one NUnit' }
        @{ FailureKind = 'MismatchedPair'; ExpectedMessage = 'same result suffix' }
    ) {
        $script:fixture = New-PulseTestProofGateFixture -FailureKind $FailureKind
        $result = Invoke-PulseTestProofFixture -Fixture $script:fixture -FailureKind $FailureKind

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match $ExpectedMessage
        Test-Path -LiteralPath $script:fixture.ReleaseProofPath | Should -BeFalse
    }

    It 'emits one release proof binding the unchanged candidate and exact result pair' {
        $script:fixture = New-PulseTestProofGateFixture -FailureKind Pass
        $result = Invoke-PulseTestProofFixture -Fixture $script:fixture -FailureKind Pass

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'GATE PASSED'
        Test-Path -LiteralPath $script:fixture.ReleaseProofPath -PathType Leaf | Should -BeTrue

        $proof = Get-Content -LiteralPath $script:fixture.ReleaseProofPath -Raw | ConvertFrom-Json
        $proof.schemaVersion | Should -Be 1
        [guid] $proof.runId | Should -Not -Be ([guid]::Empty)
        $proof.module.version | Should -Be '9.9.9'
        @($proof.module.files).Count | Should -Be 1
        $proof.module.files[0].path | Should -Be 'TenantPulse.psm1'
        $proof.module.files[0].sha256 | Should -Be (
            (Get-FileHash -LiteralPath $script:fixture.ModulePath -Algorithm SHA256).Hash.ToLowerInvariant()
        )
        $proof.package.name | Should -Be 'TenantPulse.9.9.9.nupkg'
        $proof.package.sha256 | Should -Be (
            (Get-FileHash -LiteralPath $script:fixture.PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        )
        $proof.testRun.nunit.name | Should -Be (Split-Path -Leaf $script:fixture.NUnitPath)
        $proof.testRun.nunit.sha256 | Should -Be (
            (Get-FileHash -LiteralPath $script:fixture.NUnitPath -Algorithm SHA256).Hash.ToLowerInvariant()
        )
        $proof.testRun.pesterObject.name | Should -Be (Split-Path -Leaf $script:fixture.PesterObjectPath)
        $proof.testRun.pesterObject.sha256 | Should -Be (
            (Get-FileHash -LiteralPath $script:fixture.PesterObjectPath -Algorithm SHA256).Hash.ToLowerInvariant()
        )
        Test-Path -LiteralPath $script:fixture.CandidatePath | Should -BeFalse
    }
}
