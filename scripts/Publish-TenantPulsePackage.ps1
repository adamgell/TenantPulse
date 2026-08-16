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
        It takes a .nupkg that already exists, requires a passing whole-result test proof
        for the SAME version (unless -SkipTestProof, which is for a mechanics dry run
        only and says so loudly), and then - the check that turns "publish only the
        already-tested artifact" from a procedural rule into a checked one.

        DIGEST-MANIFEST VERIFICATION (post-review fix, extended coverage): the comparison
        is no longer just TenantPulse.psm1 re-hashed from whatever is CURRENTLY on disk in
        output/module/ - that only ever proved "the file on disk right now matches the file
        on disk right now", which cannot detect a built-module file silently EDITED (not
        rebuilt, just edited) between a passing test run and a later publish. Instead, the
        'test' build workflow's own Record_Tested_Module_Digest task
        (.build/AssertGateResult.tasks.ps1) writes output/testResults/tested-module-digest.txt
        - a SHA-256 for every file the built module ships (psm1, psd1, Data/**, en-US/**),
        recorded AT TEST TIME, right after the suite passed. This script reads THAT
        manifest and checks TWO things: (1) every file the manifest recorded still matches,
        byte-for-byte, in the CURRENT output/module/ build directory (proves the build
        directory was not touched after the test run that produced the manifest), and (2)
        every one of those same files, at the same relative path, inside the .nupkg matches
        the SAME recorded hash (proves the package was built from those exact tested bytes).
        A mismatch or a missing file on EITHER side REFUSES to publish. Only once every
        entry in the manifest is confirmed on both sides does this script publish the
        corresponding built-module directory (the exact directory whose files it just
        verified) to PSGallery - never the .nupkg's own extracted content, and never a
        fresh build.

        DRY RUN BY DEFAULT. Every run through the digest verification above happens
        regardless of any switch - that check is not opt-out. What IS opt-in is the
        publish itself: -WhatIf (SupportsShouldProcess's own mechanism) or simply omitting
        BOTH -Confirm and a non-empty -NuGetApiKey leaves this script in report-only mode -
        it prints the package/version/sha256/target it WOULD publish and returns without
        calling Publish-PSResource. An actual outward publication to PSGallery requires
        ALL of: the digest check passing, an explicit -NuGetApiKey, and -Confirm (either
        the switch or an interactive Yes at the ShouldProcess prompt, since ConfirmImpact
        is 'High'). This mirrors -WhatIf's spirit as the default rather than a passed
        flag, because sending a package to a public, permanent gallery is exactly the kind
        of action that must never happen as a side effect of "I was just checking".

        THIS SCRIPT DOES NOT RUN ITSELF. Per Task 1.11: PSGallery publishing is one of
        three operator actions blocked on Adam (the others: GraphKit 0.1.1 release and
        the Policy.Read.All grant on the Ivy24 lab app). This script is publish PREP -
        written, adapted, and unit-testable now - so that when Adam is ready to publish,
        running it is the only remaining step. Adam runs it; nothing in this repository's
        build or CI pipeline invokes it automatically.

    .PARAMETER PackagePath
        Path to the already-built .nupkg (produced by ./build.ps1 -Tasks pack).

    .PARAMETER Repository
        The registered PSResourceGet repository name to publish to. Defaults to
        'PSGallery'.

    .PARAMETER TestResultPath
        NUnit result file proving this build passed. Required unless -SkipTestProof is
        given.

    .PARAMETER SkipTestProof
        Exists only for a dry-run of the script's own mechanics against a package with no
        test result handy. Never use this for a real publish - the resulting package is
        NOT known to have passed its suite.

    .PARAMETER NuGetApiKeySecure
        The PSGallery API key, as a [SecureString]. Required (along with -Confirm) to
        actually publish; without it (and without $env:TENANTPULSE_NUGET_API_KEY - see
        below) the script always stays in dry-run/report-only mode regardless of -Confirm.
        NO PLAIN-[string] API KEY PARAMETER EXISTS (post-review fix): a plain-string
        parameter is trivially captured in shell history, process listings, and CI job
        logs. Pass a real SecureString, or set $env:TENANTPULSE_NUGET_API_KEY instead
        (read automatically when -NuGetApiKeySecure is not bound) - never type the key
        directly on a command line.

    .EXAMPLE
        ./scripts/Publish-TenantPulsePackage.ps1 -PackagePath output/TenantPulse.0.1.0.nupkg `
            -TestResultPath output/testResults/NUnitXml_TenantPulse_v0.1.0.MacOS.PSv.7.6.5.xml

        Dry run: verifies the digest manifest and test proof, prints what would be
        published, and exits without publishing anything (no key, no -Confirm).

    .EXAMPLE
        $env:TENANTPULSE_NUGET_API_KEY = '<key>'
        ./scripts/Publish-TenantPulsePackage.ps1 -PackagePath output/TenantPulse.0.1.0.nupkg `
            -TestResultPath output/testResults/NUnitXml_TenantPulse_v0.1.0.MacOS.PSv.7.6.5.xml -Confirm

        Real publish via the environment variable: only proceeds if the digest-manifest and
        test-proof checks pass, then publishes the verified built-module directory to
        PSGallery.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $PackagePath,

    [string] $Repository = 'PSGallery',

    [string] $TestResultPath,

    [switch] $SkipTestProof,

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
    Write-Warning 'PUBLISHING WITHOUT TEST PROOF. -SkipTestProof was given, so this package is NOT known to have passed its suite. Do not use this for a real PSGallery publish.'
}
else {
    if ([string]::IsNullOrWhiteSpace($TestResultPath)) {
        throw 'A -TestResultPath is required: the contract is to publish only the already-tested artifact. Pass the NUnit result for this build, or pass -SkipTestProof and accept that the package is unverified.'
    }
    if (-not (Test-Path -LiteralPath $TestResultPath -PathType Leaf)) {
        throw "Test result '$TestResultPath' does not exist."
    }

    $gate = Join-Path $repoRoot 'tests/QA/Assert-GateResult.ps1'
    & pwsh -NoProfile -File $gate -ResultPath $TestResultPath -MinimumTests 702 -AllowedSkips 0 -AllowNotRun 0 | Write-Verbose
    if ($LASTEXITCODE -ne 0) {
        throw "The supplied test result did not pass the whole-result gate, so this package must not be published. Run: pwsh -File tests/QA/Assert-GateResult.ps1 -ResultPath '$TestResultPath' -MinimumTests 702"
    }

    # The result must belong to this version, or it proves nothing about these bits.
    [xml] $resultDoc = Get-Content -LiteralPath $TestResultPath -Raw
    $resultName = [string] $resultDoc.SelectSingleNode('/test-results').GetAttribute('name')
    if ($TestResultPath -notmatch [regex]::Escape($moduleVersion) -and $resultName -notmatch [regex]::Escape($moduleVersion)) {
        throw "Test result '$TestResultPath' does not reference version $moduleVersion. Publishing a package against another build's result would make the proof meaningless."
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
        $digestManifest[$Matches['relPath']] = $Matches['hash'].ToLowerInvariant()
    }

    if ($digestManifest.Count -eq 0) {
        throw "The tested-module digest manifest '$digestManifestPath' recorded zero files - nothing to verify. Re-run ./build.ps1 -Tasks test."
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
        foreach ($relPath in $digestManifest.Keys) {
            $entry = $archive.Entries | Where-Object { $_.FullName -eq $relPath } | Select-Object -First 1
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
$builtModuleDir = Join-Path $repoRoot "output/module/TenantPulse/$moduleVersion"

Write-Host ''
Write-Host "  package    : $($package.Name) ($($package.Length) bytes)" -ForegroundColor Cyan
Write-Host "  version    : $moduleVersion" -ForegroundColor Cyan
Write-Host "  sha256     : $hash" -ForegroundColor Cyan
Write-Host "  repository : $Repository" -ForegroundColor Cyan
Write-Host ''

# --- Publish gate: dry-run unless BOTH a resolved API key and -Confirm are given -------
# This is deliberately stricter than plain -WhatIf/ShouldProcess: ConfirmImpact is 'High'
# so an interactive run always prompts, but a NON-interactive run (CI, a forgotten flag)
# must not slip through just because nothing asked - no resolved API key (neither
# -NuGetApiKeySecure nor $env:TENANTPULSE_NUGET_API_KEY) alone keeps this script in
# report-only mode no matter what -Confirm says.
if ([string]::IsNullOrWhiteSpace($resolvedNuGetApiKey)) {
    Write-Host '  DRY RUN: no API key supplied. Nothing was published.' -ForegroundColor Yellow
    Write-Host "  To publish for real: set `$env:TENANTPULSE_NUGET_API_KEY (or pass -NuGetApiKeySecure) and re-run with -Confirm - ./scripts/Publish-TenantPulsePackage.ps1 -PackagePath '$PackagePath' -TestResultPath '$TestResultPath' -Confirm" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  ADAM RUNS THIS STEP. PSGallery publishing is an operator action blocked on Adam - see Task 1.11.' -ForegroundColor Yellow
    return
}

if (-not (Test-Path -LiteralPath $builtModuleDir -PathType Container)) {
    throw "Built module directory '$builtModuleDir' does not exist. Run ./build.ps1 -Tasks pack first - this is the same directory whose shipped files were just verified against the package above, and is what actually gets published (never the .nupkg's own extracted content, never a fresh build)."
}

if ($PSCmdlet.ShouldProcess("$Repository (module $moduleName $moduleVersion)", 'Publish-PSResource')) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet)) {
        throw 'Microsoft.PowerShell.PSResourceGet is required to publish and was not found. Install it, or install PSGallery publishing tooling, before running with -Confirm.'
    }

    Import-Module Microsoft.PowerShell.PSResourceGet -ErrorAction Stop

    Publish-PSResource -Path $builtModuleDir -Repository $Repository -ApiKey $resolvedNuGetApiKey -ErrorAction Stop
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
    testProof     = if ($SkipTestProof) { 'NONE - published without test proof' } else { (Resolve-Path -LiteralPath $TestResultPath).Path }
}
