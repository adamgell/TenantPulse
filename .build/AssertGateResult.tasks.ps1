<#
    Custom Invoke-Build tasks (post-review fix, Task: final fix wave items 15 & 27),
    loaded from .build/ per build.ps1's own convention (see its "Loading Build Tasks
    defined in the .build/ folder" step).

    Record_Tested_Module_Digest: records a manifest of SHA-256 hashes for every file the
    built module ships (psm1, psd1, Data/**, en-US/**) IMMEDIATELY after the Pester suite
    passes, to output/testResults/tested-module-digest.txt. Publish-TenantPulsePackage.ps1
    compares the packaged .nupkg's own files against THIS recorded manifest, not against
    whatever happens to be sitting in output/module/ at publish time - closing the gap
    where a built-module file could be silently edited (not rebuilt, just edited) between
    a passing test run and a later publish, with nothing catching the drift because the
    old check only ever re-hashed "whatever is on disk right now" and compared that
    against itself.

    Assert_Gate_Result: runs tests/QA/Assert-GateResult.ps1's whole-result gate (the same
    -MinimumTests/-AllowedSkips/-AllowNotRun ratchet ci.yml already enforces) against the
    NUnit result this same local `./build.ps1 -Tasks test` run just produced, so a
    developer running tests locally gets the same "did discovery silently drop tests"
    protection CI has always had - previously this gate only ever ran in CI, so a local
    green `test` run could still hide a discovery regression until CI caught it.
#>

$script:tenantPulseGateMinimumTests = 702

task Record_Tested_Module_Digest {
    $moduleRoot = Join-Path $BuildRoot 'output/module/TenantPulse'
    $builtVersionDir = Get-ChildItem -LiteralPath $moduleRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1

    if (-not $builtVersionDir) {
        throw "Record_Tested_Module_Digest: no built module found under '$moduleRoot' - run the 'build' workflow before 'test'."
    }

    $shippedFiles = @(Get-ChildItem -LiteralPath $builtVersionDir.FullName -Recurse -File | Sort-Object { $_.FullName })

    $testResultsDir = Join-Path $BuildRoot 'output/testResults'
    if (-not (Test-Path -LiteralPath $testResultsDir -PathType Container)) {
        New-Item -Path $testResultsDir -ItemType Directory -Force | Out-Null
    }

    $digestPath = Join-Path $testResultsDir 'tested-module-digest.txt'
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $shippedFiles) {
        $relativePath = $file.FullName.Substring($builtVersionDir.FullName.Length + 1) -replace '\\', '/'
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("$relativePath  $hash")
    }

    # Ordinal sort of the recorded lines (relative path first) - deterministic file
    # content regardless of filesystem enumeration order, matching this codebase's
    # "deterministic ordering everywhere" rule elsewhere.
    $sortedLines = [string[]] @($lines)
    [System.Array]::Sort($sortedLines, [System.StringComparer]::Ordinal)

    Set-Content -LiteralPath $digestPath -Value ($sortedLines -join [System.Environment]::NewLine) -NoNewline -Encoding utf8NoBOM
    Write-Build Green "Recorded $($sortedLines.Count) shipped-file digests to '$digestPath' for module version $($builtVersionDir.Name)."
}

task Assert_Gate_Result {
    $resultsDir = Join-Path $BuildRoot 'output/testResults'
    $resultFiles = @(Get-ChildItem -LiteralPath $resultsDir -Filter 'NUnitXml_*.xml' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($resultFiles.Count -eq 0) {
        throw "Assert_Gate_Result: no NUnit test result file found under '$resultsDir' - the Pester task must run before this one."
    }

    $gate = Join-Path $BuildRoot 'tests/QA/Assert-GateResult.ps1'
    & $gate -ResultPath $resultFiles[0].FullName -MinimumTests $script:tenantPulseGateMinimumTests -AllowedSkips 0 -AllowNotRun 0
    if ($LASTEXITCODE -ne 0) {
        throw "Assert_Gate_Result: the local test run did not pass the whole-result gate (MinimumTests $script:tenantPulseGateMinimumTests) - see the Assert-GateResult.ps1 output above for the specific violation."
    }
}
