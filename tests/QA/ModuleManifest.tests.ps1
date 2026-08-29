BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:releaseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/TenantPulse/$script:releaseVersion/TenantPulse.psd1"
    $script:packagePath = Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg"

    function Assert-ExactGraphKitRequirement {
        param([Parameter(Mandatory)] [hashtable] $Manifest)

        $requirements = @($Manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'GraphKit' })
        $requirements.Count | Should -Be 1
        [string] $requirements[0].RequiredVersion | Should -Be '0.2.2'
        $requirements[0].ContainsKey('ModuleVersion') | Should -BeFalse
        $requirements[0].ContainsKey('MaximumVersion') | Should -BeFalse
    }
    function Assert-CorrectReleaseNotes {
        param([Parameter(Mandatory)] [hashtable] $Manifest)

        $notes = [string] $Manifest.PrivateData.PSData.ReleaseNotes
        $notes | Should -Match '0\.1\.3'
        $notes | Should -Not -Match '(?i)unpublished|candidate-only'
    }
}

Describe 'TenantPulse package identity and GraphKit dependency' -Tag 'QA' {
    It 'uses the corrective 0.1.3 release identity for corrected release metadata' {
        $script:releaseVersion | Should -Be '0.1.3'
    }

    It 'requires exact GraphKit 0.2.2 in the source manifest' {
        Assert-ExactGraphKitRequirement -Manifest $script:sourceManifest
        Assert-CorrectReleaseNotes -Manifest $script:sourceManifest
    }

    It 'keeps the independent restore-time GraphKit pin at 0.2.2' {
        $restoreDependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        [string] $restoreDependencies.GraphKit | Should -Be '0.2.2'
    }

    It 'preserves exact GraphKit 0.2.2 and release notes in the built manifest' {
        Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf | Should -BeTrue
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        Assert-ExactGraphKitRequirement -Manifest $builtManifest
        Assert-CorrectReleaseNotes -Manifest $builtManifest
    }

    It 'preserves exact GraphKit 0.2.2 and release notes in the 0.1.3 nupkg manifest' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $extractRoot = Join-Path $TestDrive 'package'
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile -Path (Join-Path $extractRoot 'TenantPulse.psd1')
        Assert-ExactGraphKitRequirement -Manifest $packagedManifest
        Assert-CorrectReleaseNotes -Manifest $packagedManifest
    }
}
