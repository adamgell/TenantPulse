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

# 814 -> 905 (Task 2.2 review-fix round): +91 tests - shape-neutrality coverage
# (PSObject/IDictionary parity across all 15 golden fixtures), the fan-out driver's
# prevalidation/worker-drain/depth-alignment/all-failed-NotExpanded regressions, the
# -FromSnapshot re-derivation wiring (Resolve-PulseSettingsCatalogSnapshotExpansion), and
# the shared value-classification helper's own dedicated suite - see task-2.2-report.md's
# review-fix addendum for the full accounting. Matches .github/workflows/ci.yml's own
# -MinimumTests, which must be bumped together with this value - see this file's own
# docstring for why the same ratchet exists in both places.
# 905 -> 912 (Task 2.2 re-review fix): +7 - IsNullOrWhiteSpace policy-id prevalidation
# (a whitespace-only id previously passed IsNullOrEmpty and reached Get-GraphObject) plus
# its own WHITESPACE-ID regression test.
# 912 -> 916 (Task 2.2 re-review round 2): +4 - the known-safe-value-shape suffix-match
# secret-leak bypass fix (exact fully-qualified string match, mirroring P1-9's instance-type
# fix) plus its own regression suite (suffix-bypass for both known-safe shapes, the
# real-type-still-matches control, and an end-to-end walker-level plaintext-never-leaks
# assertion). Set to the REAL total, not a headroom-padded number - the gate IS the count.
# 916 -> 947 (Task 2.3): +31 - the compliance/legacy typed-policy walk (shape-neutrality,
# Sensitive nested-property redaction, Nested object vs array-element walking, unpopulated-
# shell shape), the per-family fan-out driver (real assignment fetch, unmapped-type gap
# wording, exact-match dispatch, assignment-fetch-failure whole-policy gap, planted-secret-
# never-leaks, empty-policy-list Expanded), and the two-family pipeline (both datasets
# unavailable, one family independent of the other).
$script:tenantPulseGateMinimumTests = 947

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

    # AllowNotRun 1 (GraphKit 0.1.1 migration, Task 1.11): tests/QA/ReadOnly.tests.ps1's
    # "every Pending dataset declares an expected Read/Safe descriptor" block is
    # legitimately empty now - all six datasets that used to be Pending shipped in
    # GraphKit 0.1.1 and had Pending dropped from DatasetMap.psd1 (see that file), leaving
    # zero Pending entries to drive the -ForEach. The mechanism itself stays covered by a
    # synthetic Pending fixture in Get-PulseTenantSnapshot.Tests.ps1's Invoke-PulseCollection
    # Describe block; this allowance only covers the QA gate's now-empty live-catalog block,
    # which will go back to 0 the moment a future descriptor ships Pending again.
    $gate = Join-Path $BuildRoot 'tests/QA/Assert-GateResult.ps1'
    & $gate -ResultPath $resultFiles[0].FullName -MinimumTests $script:tenantPulseGateMinimumTests -AllowedSkips 0 -AllowNotRun 1
    if ($LASTEXITCODE -ne 0) {
        throw "Assert_Gate_Result: the local test run did not pass the whole-result gate (MinimumTests $script:tenantPulseGateMinimumTests) - see the Assert-GateResult.ps1 output above for the specific violation."
    }
}
