<#
    Custom Invoke-Build task (Task 2.7): the dedicated, SERIAL performance/scale/memory
    container for tests/Perf/. Deliberately NOT part of the default `.`/`test` Sampler
    workflow (see build.yaml's own Pester.Configuration.Run.Path, which now enumerates
    tests/QA and tests/Unit explicitly rather than letting Pester's default "scan the whole
    tests/ tree" behavior silently pick up tests/Perf too) - perf assertions measure wall
    time and memory on THIS machine, are comparatively slow (the 5k-policy synthetic
    pipeline alone takes low-single-digit minutes), and would make ordinary `./build.ps1`
    runs slow and machine-dependent-flaky if they ran on every commit alongside the
    functional suite. They still run - explicitly, deliberately, serially (one Describe at
    a time, never interleaved with anything else that might steal CPU/IO and skew a timing
    assertion) - via this separate task.

    INVOCATION: `./build.ps1 -Tasks build,perftest` (the module must already be built - this
    task does not build it itself, matching every tests/Unit/*.Tests.ps1 file's own
    "run ./build.ps1 -Tasks build first" BeforeAll guard, which tests/Perf/*.Tests.ps1 reuses
    verbatim). CI does not run this task; it is an operator/reviewer-invoked gate, run at
    least once per T2.7-and-later change that touches the settings-expansion pipeline, the
    conflict-detection pipeline, or Write-PulseDataset/Read-PulseDataset - see
    docs/spike/2026-08-16-t27-perf-container.md for the recorded hardware/method/numbers
    this task's own budgets were derived from.

    Every budget asserted under tests/Perf/ is [measured locally] x 1.5 headroom, per the
    plan's own instruction - never a guessed round number. A budget failure here means an
    actual regression against THIS machine's own prior measurement, not an arbitrary
    external SLA.
#>

task perftest {
    $moduleRoot = Join-Path $BuildRoot 'output/module/TenantPulse'
    if (-not (Test-Path -LiteralPath $moduleRoot)) {
        throw "perftest: no built module found under '$moduleRoot' - run './build.ps1 -Tasks build' first."
    }

    $perfPath = Join-Path $BuildRoot 'tests/Perf'
    if (-not (Test-Path -LiteralPath $perfPath)) {
        throw "perftest: '$perfPath' does not exist."
    }

    $config = New-PesterConfiguration
    $config.Run.Path = $perfPath
    $config.Run.PassThru = $true
    $config.Run.Exit = $false
    $config.Output.Verbosity = 'Detailed'
    $config.Should.ErrorAction = 'Continue'

    $testResultsDir = Join-Path $BuildRoot 'output/testResults'
    if (-not (Test-Path -LiteralPath $testResultsDir -PathType Container)) {
        New-Item -Path $testResultsDir -ItemType Directory -Force | Out-Null
    }
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = Join-Path $testResultsDir 'NUnitXml_perftest.xml'

    Write-Build Magenta "perftest: running the dedicated, SERIAL perf/scale/memory container from '$perfPath' (NOT part of the default test workflow - see this task's own docstring)."
    $result = Invoke-Pester -Configuration $config

    if ($null -eq $result -or $result.FailedCount -gt 0 -or $result.TotalCount -eq 0) {
        throw "perftest: perf container did not pass cleanly (FailedCount=$($result.FailedCount), TotalCount=$($result.TotalCount)) - see the Pester output above for the specific budget violated."
    }

    Write-Build Green "perftest: $($result.PassedCount)/$($result.TotalCount) perf assertions passed."
}
