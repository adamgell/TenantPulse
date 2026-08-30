BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:releaseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:expectedReleaseNotes = @'
## [0.3.0] - Unreleased

### Fixed

- Review finding 6 is implemented: Endpoint Security composite provenance now records the stable qualified primitive set `ConfigurationPolicy.ListBeta` and `ConfigurationPolicySetting.ListBeta`, independent of tenant policy count; child gaps name the setting primitive explicitly.
- Direct, composite, and expansion collection paths now use one canonical Graph failure mapper. A request-time `403` is recorded as `Failed` / `PermissionDenied`; only `AuthenticationFailed` aborts subsequent network collection, while deadline expiration, cancellation, indeterminate certainty, permission denial, and provider failure remain explicit and isolated.

### Changed

- The approved product-program completion work uses a unique successor identity. Published TenantPulse 0.2.0 and its exact GraphKit 0.3.0 dependency remain immutable.
- `Data.PartialDatasets` is a strict Function-only opt-in that requires `DatasetOutcomes`. Exactly four checks opt in: universal checks `TP.INT.0013` and `TP.INT.0029` may Fail on a known offender but cannot Pass with gaps; existential checks `TP.INT.0014` and `TP.INT.0015` may Pass on a known witness but cannot Fail with gaps. BitLocker and LAPS witnesses require native Boolean values.
- The other 49 checks remain `NotApplicable` when their dataset status is `Partial`. For the four opt-ins, a structurally valid non-decisive Partial result is also `NotApplicable`; without decisive proof, zero usable rows or malformed outcomes, gaps, or rows are `Error`.
- Findings schema `1.0`, snapshot schema `2.0.0`, and scoring model `1.0` are unchanged. This deterministic source/package tranche makes no new live-service or publication claim.
- Review finding 14 remains rejected/obsolete on first-party schema evidence: supported schema 1.0.0/1.1.0 writers could not emit `Partial`, so migration rejects that later state without rewriting the manifest.
'@
    $script:sourceReleaseNotes = [string] $script:sourceManifest.PrivateData.PSData.ReleaseNotes
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/TenantPulse/$script:releaseVersion/TenantPulse.psd1"
    $script:packagePath = Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg"

    function Assert-ExactGraphKitRequirement {
        param([Parameter(Mandatory)] [hashtable] $Manifest)

        $requirements = @($Manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'GraphKit' })
        $requirements.Count | Should -Be 1
        [string] $requirements[0].RequiredVersion | Should -Be '0.3.0'
        $requirements[0].ContainsKey('ModuleVersion') | Should -BeFalse
        $requirements[0].ContainsKey('MaximumVersion') | Should -BeFalse
    }

    function Assert-ExactUnreleasedReleaseNotes {
        param([Parameter(Mandatory)] [string] $ReleaseNotes)

        # Sampler materializes CHANGELOG.md's [Unreleased] section into the built package
        # with the build date. Normalize only that generated header; the complete source
        # release-note body must remain byte-for-byte identical.
        $normalizedReleaseNotes = $ReleaseNotes -replace (
            '^## \[0\.3\.0\] - \d{4}-\d{2}-\d{2}',
            '## [0.3.0] - Unreleased'
        )
        $normalizedReleaseNotes.TrimEnd("`r", "`n") |
            Should -Be $script:sourceReleaseNotes.TrimEnd("`r", "`n")
    }
}

Describe 'TenantPulse package identity and GraphKit dependency' -Tag 'QA' {
    It 'uses the unique unreleased 0.3.0 identity for changed runtime and dependency bytes' {
        $script:releaseVersion | Should -Be '0.3.0'
    }

    It 'requires exact GraphKit 0.3.0 and the intended release notes in the source manifest' {
        Assert-ExactGraphKitRequirement -Manifest $script:sourceManifest
        $script:sourceReleaseNotes | Should -Be $script:expectedReleaseNotes
    }

    It 'keeps the independent restore-time GraphKit pin at 0.3.0' {
        $restoreDependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        [string] $restoreDependencies.GraphKit | Should -Be '0.3.0'
    }

    It 'preserves exact GraphKit 0.3.0 and source release notes in the built manifest' {
        Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf | Should -BeTrue
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        Assert-ExactGraphKitRequirement -Manifest $builtManifest
        Assert-ExactUnreleasedReleaseNotes -ReleaseNotes ([string] $builtManifest.PrivateData.PSData.ReleaseNotes)
    }

    It 'preserves exact GraphKit 0.3.0 and source release notes in the 0.3.0 nupkg manifest' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $extractRoot = Join-Path $TestDrive 'package'
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile -Path (Join-Path $extractRoot 'TenantPulse.psd1')
        Assert-ExactGraphKitRequirement -Manifest $packagedManifest
        Assert-ExactUnreleasedReleaseNotes -ReleaseNotes ([string] $packagedManifest.PrivateData.PSData.ReleaseNotes)
    }
}
