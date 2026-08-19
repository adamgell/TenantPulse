BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:candidateVersion = [string] $script:sourceManifest.ModuleVersion
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/TenantPulse/$script:candidateVersion/TenantPulse.psd1"
    $script:packagePath = Join-Path $script:repoRoot "output/TenantPulse.$script:candidateVersion.nupkg"

    function Assert-ExactGraphKitRequirement {
        param([Parameter(Mandatory)] [hashtable] $Manifest)

        $requirements = @($Manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'GraphKit' })
        $requirements.Count | Should -Be 1
        [string] $requirements[0].RequiredVersion | Should -Be '0.2.2'
        $requirements[0].ContainsKey('ModuleVersion') | Should -BeFalse
        $requirements[0].ContainsKey('MaximumVersion') | Should -BeFalse
    }
}

Describe 'TenantPulse package identity and GraphKit dependency' -Tag 'QA' {
    It 'uses a new 0.1.2 identity for changed package bytes' {
        $script:candidateVersion | Should -Be '0.1.2'
    }

    It 'requires exact GraphKit 0.2.2 in the source manifest' {
        Assert-ExactGraphKitRequirement -Manifest $script:sourceManifest
    }

    It 'keeps the independent restore-time GraphKit pin at 0.2.2' {
        $restoreDependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        [string] $restoreDependencies.GraphKit | Should -Be '0.2.2'
    }

    It 'preserves exact GraphKit 0.2.2 in the built manifest' {
        Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf | Should -BeTrue
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        Assert-ExactGraphKitRequirement -Manifest $builtManifest
    }

    It 'preserves exact GraphKit 0.2.2 in the candidate nupkg manifest' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $extractRoot = Join-Path $TestDrive 'package'
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile -Path (Join-Path $extractRoot 'TenantPulse.psd1')
        Assert-ExactGraphKitRequirement -Manifest $packagedManifest
    }
}
