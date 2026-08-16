<#
    Tests scripts/Publish-TenantPulsePackage.ps1's core safety property: pack-first-then-
    verify. This script is not a module function - it is a standalone, param-block script
    invoked directly (Adam runs it by hand; nothing in the build/test/CI pipeline calls
    it) - so it is exercised here as a real subprocess (`pwsh -File`) against a throwaway
    fixture "repo" rather than dot-sourced or InModuleScope'd. That fixture reproduces
    exactly the directory shape the script's own $repoRoot-relative paths expect:

        <fixture>/scripts/Publish-TenantPulsePackage.ps1   (a copy of the real script)
        <fixture>/tests/QA/Assert-GateResult.ps1            (a copy of the real gate)
        <fixture>/output/module/TenantPulse/<version>/TenantPulse.psm1
        <fixture>/output/testResults/NUnitXml_*.xml + PesterObject_*.xml

    The NUnit/PesterObject test-result fixture is fabricated (not a real 657+ test Pester
    run) with just enough shape - root attributes, one Passed test-suite, an empty
    Containers list - to satisfy Assert-GateResult.ps1's own whole-result gate, so these
    tests stay fast and independent of the real suite while still exercising the actual
    gate script the publish script actually calls.

    Focus: the digest-comparison logic (the one check that turns "publish only the
    already-tested artifact" from a procedural rule into something enforced) and the
    dry-run-by-default publish gate. Publish-PSResource itself is never invoked by any
    test here - every case below stays in dry-run mode (no -NuGetApiKey), so nothing ever
    reaches PSGallery.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:realScriptPath = Join-Path $repoRoot 'scripts/Publish-TenantPulsePackage.ps1'
    $script:realGatePath = Join-Path $repoRoot 'tests/QA/Assert-GateResult.ps1'

    if (-not (Test-Path -LiteralPath $script:realScriptPath -PathType Leaf)) {
        throw "scripts/Publish-TenantPulsePackage.ps1 not found at '$script:realScriptPath'."
    }

    function New-PulsePublishFixture {
        param(
            [string] $Version = '9.9.9',
            [string] $BuiltPsm1Content = "# built module content A`n",
            [string] $PackagedPsm1Content = "# built module content A`n",
            [string] $NuGetPackageModuleName = 'TenantPulse'
        )

        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('tp-publish-fixture-' + [guid]::NewGuid().ToString())

        $scriptsDir = Join-Path $fixtureRoot 'scripts'
        $gateDir = Join-Path $fixtureRoot 'tests/QA'
        $builtModuleDir = Join-Path $fixtureRoot "output/module/TenantPulse/$Version"
        $testResultsDir = Join-Path $fixtureRoot 'output/testResults'

        New-Item -ItemType Directory -Path $scriptsDir, $gateDir, $builtModuleDir, $testResultsDir -Force | Out-Null

        Copy-Item -LiteralPath $script:realScriptPath -Destination (Join-Path $scriptsDir 'Publish-TenantPulsePackage.ps1')
        Copy-Item -LiteralPath $script:realGatePath -Destination (Join-Path $gateDir 'Assert-GateResult.ps1')

        $builtPsm1Path = Join-Path $builtModuleDir 'TenantPulse.psm1'
        Set-Content -LiteralPath $builtPsm1Path -Value $BuiltPsm1Content -NoNewline -Encoding utf8

        # A fabricated .nupkg - a plain zip with a top-level '<NuGetPackageModuleName>.psm1'
        # entry, exactly the shape the script's ZipFile-based extraction expects.
        $packagePath = Join-Path $fixtureRoot "$NuGetPackageModuleName.$Version.nupkg"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($packagePath, 'Create')
        try {
            $entry = $archive.CreateEntry("$NuGetPackageModuleName.psm1")
            $entryStream = $entry.Open()
            try {
                $writer = New-Object System.IO.StreamWriter($entryStream)
                $writer.Write($PackagedPsm1Content)
                $writer.Flush()
            }
            finally { $entryStream.Dispose() }
        }
        finally { $archive.Dispose() }

        # A fabricated but gate-passing NUnit result + sibling PesterObject CLIXML, so
        # Assert-GateResult.ps1's own whole-result checks pass without a real 657-test run.
        $resultPath = Join-Path $testResultsDir "NUnitXml_TenantPulse_v$Version.Fixture.xml"
        $nunitXml = @"
<?xml version="1.0" encoding="utf-8"?>
<test-results name="TenantPulse $Version" total="657" failures="0" errors="0" skipped="0">
  <test-suite type="TestFixture" name="Fixture" result="Passed">
    <results>
      <test-case name="fixture test" result="Success" />
    </results>
  </test-suite>
</test-results>
"@
        Set-Content -LiteralPath $resultPath -Value $nunitXml -Encoding utf8

        $pesterObjectPath = Join-Path $testResultsDir "PesterObject_TenantPulse_v$Version.Fixture.xml"
        ([pscustomobject]@{ Containers = @() }) | Export-Clixml -LiteralPath $pesterObjectPath

        [pscustomobject]@{
            FixtureRoot   = $fixtureRoot
            ScriptPath    = Join-Path $scriptsDir 'Publish-TenantPulsePackage.ps1'
            PackagePath   = $packagePath
            ResultPath    = $resultPath
            BuiltPsm1Path = $builtPsm1Path
            Version       = $Version
        }
    }

    function Invoke-PulsePublishScript {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [string[]] $ExtraArgs = @()
        )

        $args = @(
            '-NoProfile', '-File', $Fixture.ScriptPath,
            '-PackagePath', $Fixture.PackagePath,
            '-TestResultPath', $Fixture.ResultPath
        ) + $ExtraArgs

        $output = & pwsh @args 2>&1 | Out-String
        [pscustomobject]@{
            Output   = $output
            ExitCode = $LASTEXITCODE
        }
    }
}

Describe 'Publish-TenantPulsePackage: pack-first-then-verify digest check' {
    AfterEach {
        if ($script:fixture) {
            Remove-Item -LiteralPath $script:fixture.FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'stays in dry run (no publish attempted, exit 0) when the packaged psm1 matches the tested build byte-for-byte' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "identical content`n" -PackagedPsm1Content "identical content`n"

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'DRY RUN'
        $result.Output | Should -Match 'Adam'
        # Distinct from the dry-run report's own "Nothing was published." sentence: this
        # checks for the SUCCESS line ("Published <module> <version> to <repo>") that only
        # a real Publish-PSResource call would print, which none of these tests trigger.
        $result.Output | Should -Not -Match 'Published TenantPulse'
    }

    It 'refuses (non-zero exit, no dry-run report) when the packaged psm1 differs from the tested build' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content "tested build content`n" -PackagedPsm1Content "rebuilt-after-test content`n"

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'NOT the one the tests ran against'
        $result.Output | Should -Not -Match 'DRY RUN'
    }

    It 'refuses when the built module directory the tests imported no longer exists' {
        $script:fixture = New-PulsePublishFixture
        Remove-Item -LiteralPath $script:fixture.BuiltPsm1Path -Force

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'built module.*is gone'
    }

    It 'refuses when the package name is not TenantPulse' {
        $script:fixture = New-PulsePublishFixture -NuGetPackageModuleName 'SomeOtherModule'
        # Re-point PackagePath is unnecessary - New-PulsePublishFixture already named the
        # .nupkg after -NuGetPackageModuleName.

        $result = Invoke-PulsePublishScript -Fixture $script:fixture

        # PowerShell wraps a thrown error's rendered message across terminal-width lines
        # (inserting its own '|' continuation markers), so match the distinguishing
        # fragments independently rather than a single contiguous phrase.
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match "is 'SomeOtherModule'"
        $result.Output | Should -Match 'not\s*(\||\s)*\s*TenantPulse'
    }

    It 'refuses when no -TestResultPath is given and -SkipTestProof is not either' {
        $script:fixture = New-PulsePublishFixture

        $args = @('-NoProfile', '-File', $script:fixture.ScriptPath, '-PackagePath', $script:fixture.PackagePath)
        $output = & pwsh @args 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        $exitCode | Should -Not -Be 0
        $output | Should -Match 'A -TestResultPath is required'
    }

    It 'skips both test-proof and digest verification under -SkipTestProof, warning loudly, and still stays dry-run without -NuGetApiKey' {
        $script:fixture = New-PulsePublishFixture -BuiltPsm1Content 'A' -PackagedPsm1Content 'DIFFERENT'

        $args = @('-NoProfile', '-File', $script:fixture.ScriptPath, '-PackagePath', $script:fixture.PackagePath, '-SkipTestProof')
        $output = & pwsh @args 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        $exitCode | Should -Be 0
        $output | Should -Match 'PUBLISHING WITHOUT TEST PROOF'
        $output | Should -Match 'DRY RUN'
    }

    It 'never publishes (stays dry-run) even when -Confirm is passed, if -NuGetApiKey is not' {
        $script:fixture = New-PulsePublishFixture

        $result = Invoke-PulsePublishScript -Fixture $script:fixture -ExtraArgs @('-Confirm:$false')

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'DRY RUN'
    }
}
