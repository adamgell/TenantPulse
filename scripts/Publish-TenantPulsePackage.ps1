<#
    .SYNOPSIS
        Publishes an already-built, already-tested TenantPulse package to PSGallery.

    .DESCRIPTION
        Task 1.11 publish-prep step. Ported from GraphKit's own
        scripts/Publish-GraphKitPackage.ps1 (see that file for the channel-abstraction
        version this was adapted from) and narrowed to TenantPulse's actual target:
        TenantPulse publishes to the public PSGallery, not a private FileSystem/GitHub
        channel, so this script drops the -Channel/-Destination/pin-record machinery and
        publishes straight to -Repository (default 'PSGallery') via Publish-PSResource.

        THE SAFETY PROPERTY THIS SCRIPT EXISTS TO ENFORCE, preserved EXACTLY from the
        GraphKit original: pack-first-then-verify. This script never builds. The 'pack'
        build task begins with Clean, so a build/test/pack ordering silently rebuilds the
        module after the suite ran and would ship a .psm1 no test ever saw - packaging
        bytes nothing tested is precisely the failure this script refuses to let through.
        It takes a .nupkg that already exists and requires one authoritative release proof
        binding that archive and module file set to the exact NUnit/Pester-object pair that
        passed the whole-result gate (unless -SkipTestProof, which is for a mechanics dry
        run only and says so loudly).

        DIGEST-MANIFEST VERIFICATION (post-review fix, extended coverage): the comparison
        is no longer just TenantPulse.psm1 re-hashed from whatever is CURRENTLY on disk in
        output/module/ - that only ever proved "the file on disk right now matches the file
        on disk right now", which cannot detect a built-module file silently EDITED (not
        rebuilt, just edited) between a passing test run and a later publish. Instead, the
        'test' build workflow captures every shipped-file digest and the package hash before
        Pester, then writes output/testResults/tested-release-proof.json only after the
        whole-result gate and post-gate byte checks pass. The proof binds the candidate to
        one exact NUnit/Pester-object pair; the compatibility text manifests must agree with
        it. This script checks TWO artifact properties: (1) every recorded file still matches,
        byte-for-byte, in the CURRENT output/module/ build directory (proves the build
        directory was not touched after the test run that produced the manifest), and (2)
        every one of those same files, at the same relative path, inside the .nupkg matches
        the SAME recorded hash (proves the package was built from those exact tested bytes).
        A mismatch or a missing file on EITHER side REFUSES to publish. Only once every
        entry in the manifest is confirmed on both sides does this script publish the
        exact verified .nupkg through Publish-PSResource's -NupkgPath parameter. The
        built-module directory remains one side of the test-time byte proof, but it is
        never re-packaged for publication: PSGallery receives the same archive whose
        hash and contents this script reports.

        DRY RUN BY DEFAULT. Every release-capable run goes through digest verification;
        that proof is never optional on a path that can reach Publish-PSResource.
        -SkipTestProof is a mechanics-only escape hatch and now forces report-only mode
        even when an API key and -Confirm are also supplied. For a verified run, -WhatIf
        (SupportsShouldProcess's own mechanism) or simply omitting BOTH -Confirm and a
        non-empty API key also leaves this script in report-only mode. An actual outward
        publication to PSGallery requires ALL of: the whole-result proof passing, the
        digest check passing, explicit -Publish authorization, an explicit API key, and
        confirmation. Sending a package to a public, permanent gallery must never happen
        as a side effect of checking the publisher mechanics.

        THIS SCRIPT DOES NOT RUN ITSELF. It is the explicit operator boundary for the
        permanent PSGallery action; nothing in this repository's build or CI pipeline
        invokes it automatically.

    .PARAMETER PackagePath
        Path to the already-built .nupkg (produced by ./build.ps1 -Tasks pack).

    .PARAMETER Repository
        The registered PSResourceGet repository name to publish to. Defaults to
        'PSGallery'.

    .PARAMETER TestResultPath
        NUnit result file proving this build passed. It must be the exact file bound by
        tested-release-proof.json and is required unless -SkipTestProof is given.

    .PARAMETER SkipTestProof
        Exists only for a dry-run of the script's own mechanics against a package with no
        test result handy. This switch forces dry-run mode even when a key and confirmation
        are supplied; an unverified package can never reach Publish-PSResource.

    .PARAMETER Publish
        Explicitly authorizes the outward publication step after every package and test
        proof passes. Suppressing the normal confirmation prompt with -Confirm:$false does
        not replace this named authorization. Omitting -Publish always produces a dry run.

    .PARAMETER NuGetApiKeySecure
        The PSGallery API key, as a [SecureString]. Required (along with -Publish and the
        normal ShouldProcess confirmation) to
        actually publish; without it (and without $env:TENANTPULSE_NUGET_API_KEY - see
        below) the script always stays in dry-run/report-only mode regardless of -Publish
        or -Confirm.
        NO PLAIN-[string] API KEY PARAMETER EXISTS (post-review fix): a plain-string
        parameter is trivially captured in shell history, process listings, and CI job
        logs. Pass a real SecureString, or set $env:TENANTPULSE_NUGET_API_KEY instead
        (read automatically when -NuGetApiKeySecure is not bound) - never type the key
        directly on a command line.

    .EXAMPLE
        ./scripts/Publish-TenantPulsePackage.ps1 -PackagePath output/TenantPulse.0.2.0.nupkg `
            -TestResultPath output/testResults/NUnitXml_TenantPulse_v0.2.0.MacOS.PSv.7.6.5.xml

        Dry run: verifies the exact package digest, module-file manifest, and test proof,
        prints what would be published, and exits without publishing anything.

    .EXAMPLE
        $env:TENANTPULSE_NUGET_API_KEY = '<key>'
        ./scripts/Publish-TenantPulsePackage.ps1 -PackagePath output/TenantPulse.0.2.0.nupkg `
            -TestResultPath output/testResults/NUnitXml_TenantPulse_v0.2.0.MacOS.PSv.7.6.5.xml -Publish -Confirm

        Real publish via the environment variable: only proceeds if the whole-result,
        exact-archive, and module-file proofs pass, then publishes that verified .nupkg to
        PSGallery.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $PackagePath,

    [string] $Repository = 'PSGallery',

    [string] $TestResultPath,

    [switch] $SkipTestProof,

    [switch] $Publish,

    [SecureString] $NuGetApiKeySecure
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repoRoot = Split-Path $PSScriptRoot -Parent

# Resolve the API key from ONLY a SecureString parameter or the TENANTPULSE_NUGET_API_KEY
# environment variable (post-review fix - see -NuGetApiKeySecure's own docstring for why a
# plain-[string] parameter was removed entirely). Converted to plain text only right here,
# in memory, immediately before use - never logged, never echoed.
$resolvedNuGetApiKey = $null
if ($PSBoundParameters.ContainsKey('NuGetApiKeySecure') -and $null -ne $NuGetApiKeySecure -and $NuGetApiKeySecure.Length -gt 0) {
    $resolvedNuGetApiKey = [System.Net.NetworkCredential]::new('', $NuGetApiKeySecure).Password
} elseif (-not [string]::IsNullOrWhiteSpace($env:TENANTPULSE_NUGET_API_KEY)) {
    $resolvedNuGetApiKey = $env:TENANTPULSE_NUGET_API_KEY
}

if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    throw "Package '$PackagePath' does not exist. Build it first with ./build.ps1 -Tasks pack; this script deliberately does not build, so that what ships is what was tested."
}

$package = Get-Item -LiteralPath $PackagePath
if ($package.Extension -ne '.nupkg') {
    throw "Package '$PackagePath' is not a .nupkg."
}

# Version comes from the file name, which is what PSGallery will key on.
if ($package.BaseName -notmatch '^(?<name>.+?)\.(?<version>\d+\.\d+\.\d+(?:-[A-Za-z0-9.\-]+)?)$') {
    throw "Cannot parse a module name and version from '$($package.Name)'. Expected <Name>.<Version>.nupkg."
}
$moduleName = $Matches['name']
$moduleVersion = $Matches['version']

if ($moduleName -ne 'TenantPulse') {
    throw "Package '$($package.Name)' is '$moduleName', not TenantPulse."
}

# --- Proof that these exact bits passed their tests -------------------------------------
if ($SkipTestProof) {
    Write-Warning 'UNVERIFIED MECHANICS DRY RUN. -SkipTestProof was given, so this package is not known to have passed its suite and cannot be published by this invocation.'
}
else {
    if ([string]::IsNullOrWhiteSpace($TestResultPath)) {
        throw 'A -TestResultPath is required: the contract is to publish only the already-tested artifact. Pass the NUnit result for this build, or pass -SkipTestProof and accept that the package is unverified.'
    }
    if (-not (Test-Path -LiteralPath $TestResultPath -PathType Leaf)) {
        throw "Test result '$TestResultPath' does not exist."
    }

    # A single manifest is the publication authority for this run. Capture_Candidate_Proof_Input
    # deletes old results and proof files before Pester; Record_Tested_Module_Digest writes this
    # manifest only after the whole-result gate and post-gate byte checks. The two legacy text
    # manifests below remain independently checked, but cannot authorize a package by themselves.
    $testResultsDir = Join-Path $repoRoot 'output/testResults'
    $releaseProofPath = Join-Path $testResultsDir 'tested-release-proof.json'
    if (-not (Test-Path -LiteralPath $releaseProofPath -PathType Leaf)) {
        throw "No tested release proof found at '$releaseProofPath'. Run ./build.ps1 -Tasks pack then ./build.ps1 -Tasks test; the publisher will not combine separately supplied result and digest files."
    }

    try {
        $releaseProof = Get-Content -LiteralPath $releaseProofPath -Raw | ConvertFrom-Json -Depth 8
        $proofSchemaVersion = [int] $releaseProof.schemaVersion
        $proofRunIdText = [string] $releaseProof.runId
        $proofModuleName = [string] $releaseProof.module.name
        $proofModuleVersion = [string] $releaseProof.module.version
        $proofModuleFiles = @($releaseProof.module.files)
        $proofPackageName = [string] $releaseProof.package.name
        $proofPackageHash = [string] $releaseProof.package.sha256
        $proofNUnitName = [string] $releaseProof.testRun.nunit.name
        $proofNUnitHash = [string] $releaseProof.testRun.nunit.sha256
        $proofPesterObjectName = [string] $releaseProof.testRun.pesterObject.name
        $proofPesterObjectHash = [string] $releaseProof.testRun.pesterObject.sha256
    }
    catch {
        throw "The tested release proof '$releaseProofPath' is unreadable or incomplete: $($_.Exception.Message)"
    }

    $parsedProofRunId = [guid]::Empty
    if ($proofSchemaVersion -ne 1 -or
        -not [guid]::TryParse($proofRunIdText, [ref] $parsedProofRunId) -or
        $parsedProofRunId -eq [guid]::Empty) {
        throw "The tested release proof '$releaseProofPath' has an unsupported schema version or invalid run id."
    }
    if (-not [string]::Equals($proofModuleName, $moduleName, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($proofModuleVersion, $moduleVersion, [System.StringComparison]::Ordinal)) {
        throw "The tested release proof names module '$proofModuleName' version '$proofModuleVersion', not '$moduleName' version '$moduleVersion'."
    }
    if (-not [string]::Equals($proofPackageName, $package.Name, [System.StringComparison]::Ordinal) -or
        $proofPackageHash -notmatch '^[0-9a-fA-F]{64}$') {
        throw "The tested release proof does not name a valid hash for package '$($package.Name)'."
    }
    $proofPackageHash = $proofPackageHash.ToLowerInvariant()

    foreach ($resultName in @($proofNUnitName, $proofPesterObjectName)) {
        if ([string]::IsNullOrWhiteSpace($resultName) -or
            $resultName.IndexOfAny([char[]] @('/', '\')) -ge 0 -or
            -not [string]::Equals([System.IO.Path]::GetFileName($resultName), $resultName, [System.StringComparison]::Ordinal)) {
            throw "The tested release proof contains an unsafe result filename '$resultName'."
        }
    }
    $nunitNameMatch = [regex]::Match($proofNUnitName, '^NUnitXml_(?<suffix>.+\.xml)$', [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $pesterObjectNameMatch = [regex]::Match($proofPesterObjectName, '^PesterObject_(?<suffix>.+\.xml)$', [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $nunitNameMatch.Success -or -not $pesterObjectNameMatch.Success -or
        -not [string]::Equals($nunitNameMatch.Groups['suffix'].Value, $pesterObjectNameMatch.Groups['suffix'].Value, [System.StringComparison]::Ordinal)) {
        throw "The tested release proof does not bind a matching NUnit/Pester result pair."
    }
    if ($proofNUnitHash -notmatch '^[0-9a-fA-F]{64}$' -or $proofPesterObjectHash -notmatch '^[0-9a-fA-F]{64}$') {
        throw "The tested release proof contains an invalid NUnit or Pester-object hash."
    }
    $proofNUnitHash = $proofNUnitHash.ToLowerInvariant()
    $proofPesterObjectHash = $proofPesterObjectHash.ToLowerInvariant()

    $boundNUnitPath = Join-Path $testResultsDir $proofNUnitName
    $boundPesterObjectPath = Join-Path $testResultsDir $proofPesterObjectName
    if (-not (Test-Path -LiteralPath $boundNUnitPath -PathType Leaf)) {
        throw "The NUnit result bound by the tested release proof is missing at '$boundNUnitPath'."
    }
    if (-not (Test-Path -LiteralPath $boundPesterObjectPath -PathType Leaf)) {
        throw "The Pester object bound by the tested release proof is missing at '$boundPesterObjectPath'."
    }

    $resolvedSuppliedResultPath = (Resolve-Path -LiteralPath $TestResultPath).ProviderPath
    $resolvedBoundNUnitPath = (Resolve-Path -LiteralPath $boundNUnitPath).ProviderPath
    $pathComparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparison]::Ordinal
    }
    if (-not [string]::Equals($resolvedSuppliedResultPath, $resolvedBoundNUnitPath, $pathComparison)) {
        throw "NUnit result bound by the tested release proof mismatch. Use '$boundNUnitPath'; separately supplied results cannot authorize this package."
    }

    $currentNUnitHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $boundNUnitPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals($currentNUnitHash, $proofNUnitHash, [System.StringComparison]::Ordinal)) {
        throw "The NUnit result bound by the tested release proof changed after proof creation."
    }
    $currentPesterObjectHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $boundPesterObjectPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals($currentPesterObjectHash, $proofPesterObjectHash, [System.StringComparison]::Ordinal)) {
        throw "The Pester object bound by the tested release proof changed after proof creation."
    }

    # MinimumTests 3323 / -AllowNotRun 0 (see
    # .build/AssertGateResult.tasks.ps1's own $script:tenantPulseGateMinimumTests
    # accounting comment for the full per-commit history on both pre-merge lineages,
    # including the 1325 -> 1355 correction from an ad hoc test-run artifact; this
    # file's own value must stay in sync with that one. 1800 is the REAL measured
    # ./build.ps1 -Tasks build,test total for the merged tree, set once post-merge
    # per the merge review's ratchet step - not the sum of the two pre-merge branch
    # totals (1465 + 1402), which would double-count shared history. 1956 -> 1971 at
    # the Phase 3 closing fix series; 1971 -> 1972 at the TP.INT.0005 RedactDetailKeys
    # follow-up; 1972 -> 1973 at the TP.ENT.0012 AP08 v1.0 projection remap;
    # 1973 -> 2009 at TP.INT.0017/0018; 2009 -> 2016 at R0 source/release truth;
    # 2123 -> 2135 at the default-plan/current-and-legacy baseline coverage;
    # 2135 -> 2142 at the security-baseline provider-shape closeout; 2142 -> 2162
    # at the integrated 0.2.0 typed-assignment, transitive-packaging, wrapper-integrity,
    # and clean-restore closeout; 2162 -> 2175 at the final independent-review
    # provider-validation/default-workflow/publisher-safety closeout; 2175 -> 2187 at
    # the post-review source-gap/typed-id/unknown-principal/malformed-baseline/exact-
    # archive-publisher closeout; 2187 -> 2199 for persisted license-gate evidence,
    # nullable RBAC flag coverage, and dataset-map contract coverage; 2199 -> 2220 for
    # fail-closed license-evidence, assignment-filter typing, and publisher archive/
    # authorization boundary coverage; 2220 -> 2247 for the final evidence-coherence,
    # filter/gap, dependency-byte, proof-ordering, command-resolution, and archive-TOCTOU
    # regressions; 2247 -> 2255 for pre-test artifact/result-pair proof binding and its
    # multiline ratchet-parser regression.
    # 2255 -> 2288 after publication closeout: 2277 was the exact pre-closeout
    # merged-main baseline; 2288 is the measured post-closeout gate, incorporating +5 current-release truth tests, +2 per-file safety scans for the tracked plan, +3 stable qualified-provenance policy-count cases, and +1 fail-closed legacy-Partial regression.
    # 2288 -> 2508 for R1a: +2 plan-discovery safety cases, +118 canonical Graph-failure/
    # adapter cases, +21 PartialDatasets catalog cases, +31 isolated partial-evaluator
    # cases, and +48 monotonic-check/scoring/privacy cases.
    # 2508 -> 2510 after the whole-branch provider-plan review correction: +2 thrown
    # structured Graph-failure regressions preserving the canonical outcome and
    # authentication abort. The authoritative pre-ratchet run had zero NotRun, so
    # publication accepts no NotRun block.
    # 2510 -> 2517 after independent review: +2 provider classification,
    # +2 pipeline-manifest, and +3 missing-policy-id regressions; existing
    # expansion-abort cases now also assert complete gap ledgers.
    # 2517 -> 2998 after product-program integration and the final +17 policy-
    # assignment relevance/cardinality/deadline-shape/contract-sync regressions.
    # 2998 -> 3006 after Endpoint Security assignment-certainty closeout:
    # +2 provider-plan and +6 BitLocker/LAPS assignment-certainty regressions.
    # 3006 -> 3258 after Conditional Access certainty closeout: +252 effective-
    # scope, grant, admin-role, privacy-alias, and evidence-identity regressions.
    # 3258 -> 3303 after core-program hardening: +45 default-workflow privacy,
    # envelope, ARM, provenance, version-routing, terminal-outcome,
    # assignment-certainty, catalog, and application-report regressions.
    # 3303 -> 3319 after final audit hardening: +16 primitive-privacy,
    # fixed-schema, assignment-evidence, report-counter, and paging regressions.
    # 3319 -> 3320 adds malformed ARM continuation coverage; the paged-failure
    # interop correction strengthens an existing three-case parameterization.
    # 3320 -> 3323 adds thrown ARM transport normalization plus ambiguous and
    # known retry-exhaustion/no-final-delay contracts.
    # The four tests/Perf assertions are deliberately outside the QA+Unit release
    # workflow and are not included in its measured 3323-test floor.
    # NotRun remains forbidden.
    $gate = Join-Path $repoRoot 'tests/QA/Assert-GateResult.ps1'
    $allowedSkips = if ($IsWindows) { 2 } else { 0 }
    & pwsh -NoProfile -File $gate `
        -ResultPath $boundNUnitPath `
        -PesterObjectPath $boundPesterObjectPath `
        -MinimumTests 3323 `
        -AllowedSkips $allowedSkips `
        -AllowNotRun 0 | Write-Verbose
    if ($LASTEXITCODE -ne 0) {
        throw "The result pair bound by the tested release proof did not pass the whole-result gate, so this package must not be published."
    }

    # The proof hashes are checked on both sides of the gate. A concurrent replacement
    # cannot be validated as one byte sequence and retained as a different sequence.
    $postGateNUnitHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $boundNUnitPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals($postGateNUnitHash, $proofNUnitHash, [System.StringComparison]::Ordinal)) {
        throw "The NUnit result bound by the tested release proof changed while the whole-result gate was running."
    }
    $postGatePesterObjectHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $boundPesterObjectPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals($postGatePesterObjectHash, $proofPesterObjectHash, [System.StringComparison]::Ordinal)) {
        throw "The Pester object bound by the tested release proof changed while the whole-result gate was running."
    }

    # The result must belong to this version, or it proves nothing about these bits.
    [xml] $resultDoc = Get-Content -LiteralPath $boundNUnitPath -Raw
    $resultName = [string] $resultDoc.SelectSingleNode('/test-results').GetAttribute('name')
    if ($proofNUnitName -notmatch [regex]::Escape($moduleVersion) -and $resultName -notmatch [regex]::Escape($moduleVersion)) {
        throw "Test result '$boundNUnitPath' does not reference version $moduleVersion. Publishing a package against another build's result would make the proof meaningless."
    }

    # Matching version numbers are not proof that these bytes are the tested bytes: the
    # 'pack' task begins with Clean, so a build/test/pack ordering silently rebuilds the
    # module after the suite ran and ships something no test ever saw. Compare every
    # shipped file inside the package against the SAME file's hash as recorded, at test
    # time, in the digest manifest - not against whatever is currently on disk (see this
    # script's own DIGEST-MANIFEST VERIFICATION docstring section for why).
    $builtModuleDirForDigest = Join-Path $repoRoot "output/module/TenantPulse/$moduleVersion"
    if (-not (Test-Path -LiteralPath $builtModuleDirForDigest -PathType Container)) {
        throw "The built module directory '$builtModuleDirForDigest' is gone, so this package cannot be tied back to the tested bits. Run ./build.ps1 -Tasks pack FIRST and ./build.ps1 -Tasks test SECOND - test does not clean, pack does."
    }

    $digestManifestPath = Join-Path $repoRoot 'output/testResults/tested-module-digest.txt'
    if (-not (Test-Path -LiteralPath $digestManifestPath -PathType Leaf)) {
        throw "No tested-module digest manifest found at '$digestManifestPath'. Run ./build.ps1 -Tasks test - its Record_Tested_Module_Digest task writes this manifest right after the suite passes, and this script refuses to publish without it (or pass -SkipTestProof for a mechanics-only dry run)."
    }

    $digestManifest = [ordered]@{}
    foreach ($line in (Get-Content -LiteralPath $digestManifestPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?<relPath>.+?)\s\s(?<hash>[0-9a-fA-F]{64})$') {
            throw "The tested-module digest manifest '$digestManifestPath' has an unparseable line: '$line'."
        }
        $digestRelativePath = $Matches['relPath']
        if ($digestManifest.Contains($digestRelativePath)) {
            throw "The tested-module digest manifest '$digestManifestPath' contains duplicate path '$digestRelativePath'."
        }
        $digestManifest[$digestRelativePath] = $Matches['hash'].ToLowerInvariant()
    }

    if ($digestManifest.Count -eq 0) {
        throw "The tested-module digest manifest '$digestManifestPath' recorded zero files - nothing to verify. Re-run ./build.ps1 -Tasks test."
    }

    $proofDigestManifest = [ordered] @{}
    foreach ($proofFile in $proofModuleFiles) {
        try {
            $proofRelativePath = [string] $proofFile.path
            $proofRelativeHash = [string] $proofFile.sha256
        }
        catch {
            throw "The tested release proof '$releaseProofPath' contains an incomplete module-file record."
        }
        $proofPathSegments = @($proofRelativePath -split '[/\\]')
        if ([string]::IsNullOrWhiteSpace($proofRelativePath) -or
            [System.IO.Path]::IsPathRooted($proofRelativePath) -or
            $proofRelativePath.IndexOf('\') -ge 0 -or
            $proofPathSegments -contains '.' -or
            $proofPathSegments -contains '..' -or
            $proofRelativeHash -notmatch '^[0-9a-fA-F]{64}$' -or
            $proofDigestManifest.Contains($proofRelativePath)) {
            throw "The tested release proof '$releaseProofPath' contains an invalid or duplicate module-file record for '$proofRelativePath'."
        }
        $proofDigestManifest[$proofRelativePath] = $proofRelativeHash.ToLowerInvariant()
    }
    if ($proofDigestManifest.Count -eq 0 -or $proofDigestManifest.Count -ne $digestManifest.Count) {
        throw "The tested-module digest manifest does not match the module file set bound by the tested release proof."
    }
    foreach ($proofRelativePath in $proofDigestManifest.Keys) {
        if (-not $digestManifest.Contains($proofRelativePath) -or
            -not [string]::Equals($digestManifest[$proofRelativePath], $proofDigestManifest[$proofRelativePath], [System.StringComparison]::Ordinal)) {
            throw "The tested-module digest manifest does not match the module bytes bound by the tested release proof for '$proofRelativePath'."
        }
    }

    # The module-file manifest proves the code/data payload. The exact archive digest also
    # binds NuGet metadata, wrapper records, entry ordering, and duplicate/extra entries to
    # the package that existed when the passing test workflow completed.
    $packageDigestPath = Join-Path $repoRoot 'output/testResults/tested-package-digest.txt'
    if (-not (Test-Path -LiteralPath $packageDigestPath -PathType Leaf)) {
        throw "No exact package-archive test proof found at '$packageDigestPath'. Run ./build.ps1 -Tasks pack then ./build.ps1 -Tasks test."
    }

    $packageDigestLines = @(Get-Content -LiteralPath $packageDigestPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($packageDigestLines.Count -ne 1 -or
        $packageDigestLines[0] -notmatch '^(?<packageName>.+?\.nupkg)  (?<hash>[0-9a-fA-F]{64})$') {
        throw "The exact package-archive test proof '$packageDigestPath' must contain one '<package>.nupkg  <sha256>' record."
    }
    $testedPackageName = $Matches['packageName']
    $testedPackageHash = $Matches['hash'].ToLowerInvariant()
    if (-not [string]::Equals($testedPackageName, $package.Name, [System.StringComparison]::Ordinal)) {
        throw "The package archive '$($package.Name)' does not match the package '$testedPackageName' named by the test proof."
    }
    if (-not [string]::Equals($testedPackageName, $proofPackageName, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($testedPackageHash, $proofPackageHash, [System.StringComparison]::Ordinal)) {
        throw "The exact package-archive text proof does not match the package bound by the tested release proof."
    }
    $currentPackageHash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals($currentPackageHash, $testedPackageHash, [System.StringComparison]::Ordinal)) {
        throw "The package archive '$($package.Name)' does not match its exact test proof. The archive was rebuilt or altered after the passing test workflow."
    }

    # The publisher sends the entire built-module directory, not only the paths the
    # manifest happens to mention. Require the exact file set here so an unrecorded file
    # added after the test cannot ride along with otherwise matching tested bytes.
    $currentBuiltFiles = @(
        Get-ChildItem -LiteralPath $builtModuleDirForDigest -Recurse -File -Force |
            # ModuleBuilder may copy repository-only .gitkeep placeholders that NuGet does
            # not ship. Exclude them explicitly on every OS; do not depend on whether the
            # host treats dotfiles as hidden.
            Where-Object { $_.Name -cne '.gitkeep' } |
            ForEach-Object {
                $_.FullName.Substring($builtModuleDirForDigest.Length + 1) -replace '\\', '/'
            } |
            Sort-Object
    )
    $recordedBuiltFiles = @($digestManifest.Keys | Sort-Object)
    $fileSetDifferences = @(Compare-Object -ReferenceObject $recordedBuiltFiles -DifferenceObject $currentBuiltFiles -CaseSensitive)
    if ($fileSetDifferences.Count -ne 0) {
        $differenceSummary = ($fileSetDifferences | ForEach-Object { "$($_.SideIndicator):$($_.InputObject)" }) -join ', '
        throw "The built module file set differs from the tested-module digest manifest. Unrecorded or missing file(s): $differenceSummary. Re-run ./build.ps1 -Tasks pack then ./build.ps1 -Tasks test, in that order, then publish."
    }
    # Side 1: every recorded file must still match, byte-for-byte, in the CURRENT built
    # module directory - proves the build directory was not touched (edited, not rebuilt)
    # after the test run that produced the manifest.
    foreach ($relPath in $digestManifest.Keys) {
        $currentFilePath = Join-Path $builtModuleDirForDigest $relPath
        if (-not (Test-Path -LiteralPath $currentFilePath -PathType Leaf)) {
            throw "The tested-module digest manifest recorded '$relPath', but it is missing from '$builtModuleDirForDigest' now. The build directory changed since the test run that produced the digest - re-run ./build.ps1 -Tasks pack then test, in that order, then publish."
        }
        $currentHash = (Get-FileHash -LiteralPath $currentFilePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not [string]::Equals($currentHash, $digestManifest[$relPath], [System.StringComparison]::Ordinal)) {
            throw "'$relPath' in '$builtModuleDirForDigest' ($currentHash) does not match the digest recorded at test time ($($digestManifest[$relPath])). The built module was edited after the test run - re-run ./build.ps1 -Tasks pack then test, in that order, then publish."
        }
    }

    # Side 2: every recorded file must ALSO be present, at the same relative path, inside
    # the .nupkg, matching the SAME recorded hash - proves the package was built from
    # those exact tested bytes, not a later edit.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    try {
        $seenArchivePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($archiveEntry in $archive.Entries) {
            if (-not $seenArchivePaths.Add($archiveEntry.FullName)) {
                throw "Package archive '$($package.Name)' contains a duplicate entry path '$($archiveEntry.FullName)'."
            }
        }

        $nuspecPath = "$moduleName.nuspec"
        $nuspecEntries = @($archive.Entries | Where-Object { $_.FullName -ceq $nuspecPath })
        if ($nuspecEntries.Count -ne 1) {
            throw "Package archive '$($package.Name)' must contain exactly one '$nuspecPath' metadata record."
        }

        $nuspecReader = [System.IO.StreamReader]::new($nuspecEntries[0].Open())
        try {
            [xml] $nuspec = $nuspecReader.ReadToEnd()
        }
        finally {
            $nuspecReader.Dispose()
        }
        $nuspecMetadata = $nuspec.SelectSingleNode("//*[local-name()='metadata']")
        $nuspecId = [string] $nuspecMetadata.SelectSingleNode("./*[local-name()='id']").InnerText
        $nuspecVersion = [string] $nuspecMetadata.SelectSingleNode("./*[local-name()='version']").InnerText
        if (-not [string]::Equals($nuspecId, $moduleName, [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($nuspecVersion, $moduleVersion, [System.StringComparison]::Ordinal)) {
            throw "Package archive '$($package.Name)' nuspec identity '$nuspecId' version '$nuspecVersion' does not match '$moduleName' version '$moduleVersion'."
        }

        $recordedPayloadPaths = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($recordedPath in $digestManifest.Keys) {
            $null = $recordedPayloadPaths.Add([string] $recordedPath)
        }
        foreach ($archiveEntry in $archive.Entries) {
            if ($archiveEntry.FullName.EndsWith('/', [System.StringComparison]::Ordinal)) { continue }
            if ($recordedPayloadPaths.Contains($archiveEntry.FullName)) { continue }
            if ($archiveEntry.FullName -ceq $nuspecPath -or
                $archiveEntry.FullName -ceq '[Content_Types].xml' -or
                $archiveEntry.FullName -ceq '_rels/.rels' -or
                $archiveEntry.FullName -ceq '.signature.p7s' -or
                $archiveEntry.FullName -cmatch '^package/services/metadata/core-properties/[^/]+\.psmdcp$') {
                continue
            }
            throw "Package archive '$($package.Name)' contains untested payload '$($archiveEntry.FullName)' outside the recorded module file set."
        }

        foreach ($relPath in $digestManifest.Keys) {
            $entry = $archive.Entries | Where-Object { $_.FullName -ceq $relPath } | Select-Object -First 1
            if ($null -eq $entry) {
                throw "Package '$($package.Name)' contains no '$relPath', which the tested-module digest manifest recorded as a shipped file."
            }

            $stream = $entry.Open()
            try {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $packagedHash = [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
            }

            finally { $stream.Dispose() }

            if (-not [string]::Equals($packagedHash, $digestManifest[$relPath], [System.StringComparison]::Ordinal)) {
                throw "The '$relPath' inside '$($package.Name)' ($packagedHash) is NOT the one the tests ran against ($($digestManifest[$relPath])). The module was rebuilt or edited between testing and packaging, so this package is unverified. Run ./build.ps1 -Tasks pack, then ./build.ps1 -Tasks test, then publish."
            }
        }
    }
    finally { $archive.Dispose() }

    Write-Verbose "Every one of $($digestManifest.Count) shipped file(s) in '$($package.Name)' matches the tested-module digest manifest."
}

$hash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash

Write-Host ''
Write-Host "  package    : $($package.Name) ($($package.Length) bytes)" -ForegroundColor Cyan
Write-Host "  version    : $moduleVersion" -ForegroundColor Cyan
Write-Host "  sha256     : $hash" -ForegroundColor Cyan
Write-Host "  repository : $Repository" -ForegroundColor Cyan
Write-Host ''

# --- Publish gate: dry-run unless explicit -Publish and a resolved API key are given ----
# -Publish is the durable affirmative authorization; -Confirm:$false may suppress the
# standard ShouldProcess prompt but cannot substitute for that named intent. No resolved API
# key (neither -NuGetApiKeySecure nor $env:TENANTPULSE_NUGET_API_KEY) also keeps the script in
# report-only mode.
if ($SkipTestProof) {
    Write-Host '  DRY RUN: -SkipTestProof disables publication. Nothing was published.' -ForegroundColor Yellow
    Write-Host '  Re-run with a passing -TestResultPath and without -SkipTestProof for a release-capable verification.' -ForegroundColor Yellow
    Write-Host ''
    return
}

if (-not $Publish) {
    Write-Host '  DRY RUN: no explicit -Publish authorization supplied. Nothing was published.' -ForegroundColor Yellow
    Write-Host '  PSGallery publishing remains an explicit operator action.' -ForegroundColor Yellow
    Write-Host ''
    return
}

if ([string]::IsNullOrWhiteSpace($resolvedNuGetApiKey)) {
    Write-Host '  DRY RUN: no API key supplied. Nothing was published.' -ForegroundColor Yellow
    Write-Host "  To publish for real: set `$env:TENANTPULSE_NUGET_API_KEY (or pass -NuGetApiKeySecure) and re-run with -Publish -Confirm - ./scripts/Publish-TenantPulsePackage.ps1 -PackagePath '$PackagePath' -TestResultPath '$TestResultPath' -Publish -Confirm" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  PSGallery publishing remains an explicit operator action.' -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess("$Repository (module $moduleName $moduleVersion)", 'Publish-PSResource')) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet)) {
        throw 'Microsoft.PowerShell.PSResourceGet is required to publish and was not found. Install it, or install PSGallery publishing tooling, before running with -Confirm.'
    }

    Import-Module Microsoft.PowerShell.PSResourceGet -ErrorAction Stop

    # Verification happened before ShouldProcess so an interactive confirmation cannot
    # silently widen the archive's mutation window. Rehash after confirmation and module
    # load, immediately before handing the path and plaintext key to the real command.
    $confirmedPackageHash = (Microsoft.PowerShell.Utility\Get-FileHash `
        -LiteralPath $package.FullName `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals($confirmedPackageHash, $testedPackageHash, [System.StringComparison]::Ordinal)) {
        throw "The package archive '$($package.Name)' changed after confirmation. Publication was refused; re-run verification against the intended archive."
    }

    Microsoft.PowerShell.PSResourceGet\Publish-PSResource `
        -NupkgPath $package.FullName `
        -Repository $Repository `
        -ApiKey $resolvedNuGetApiKey `
        -ErrorAction Stop
    Write-Host "  Published $moduleName $moduleVersion to $Repository" -ForegroundColor Green
}
else {
    Write-Host '  -WhatIf: nothing was published.' -ForegroundColor Yellow
}

Write-Host ''
[pscustomobject] [ordered] @{
    moduleName    = $moduleName
    version       = $moduleVersion
    sha256        = $hash
    repository    = $Repository
    packageName   = $package.Name
    testProof     = if ($SkipTestProof) { 'NONE - mechanics dry run only' } else { (Resolve-Path -LiteralPath $TestResultPath).Path }
}
