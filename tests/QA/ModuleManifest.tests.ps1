BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:releaseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:expectedReleaseNotes = @'
## [0.3.0] - Unreleased

### Fixed

- Endpoint Security composite provenance now records the stable qualified primitive set `ConfigurationPolicy.ListBeta` and `ConfigurationPolicySetting.ListBeta`, independent of tenant policy count; child gaps name the setting primitive explicitly.

### Changed

- The approved product-program completion work uses a unique successor identity. Published TenantPulse 0.2.0 and its exact GraphKit 0.3.0 dependency remain immutable.
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
