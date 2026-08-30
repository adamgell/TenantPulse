<#
    TenantPulse intentionally declares only GraphKit as a runtime dependency. GraphKit
    0.3.0, in turn, declares Microsoft.Graph.Authentication as a real package dependency.

    Sampler's package_module_nupkg task publishes only TenantPulse's direct dependencies
    into its temporary local repository. PowerShellGet therefore cannot publish GraphKit
    unless GraphKit's own hard dependency is staged first. These tests pin both sides of
    that contract: the source manifests must stay semantically clean, and the pack
    workflow must produce a locally resolvable dependency chain before TenantPulse is
    packaged.
#>

BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifest = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'source/TenantPulse.psd1')
    $script:releaseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:restoreDependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
    $script:graphKitManifestPath = Join-Path $script:repoRoot 'output/RequiredModules/GraphKit/0.3.0/GraphKit.psd1'
    $script:graphKitManifest = Import-PowerShellDataFile -Path $script:graphKitManifestPath
    $script:dependencyIntegrityHelper = Join-Path $script:repoRoot '.build/RuntimeDependencyIntegrity.ps1'
    $script:dependencyDigestPath = Join-Path $script:repoRoot '.build/RuntimeDependencyDigests.psd1'

    if (Test-Path -LiteralPath $script:dependencyIntegrityHelper -PathType Leaf) {
        . $script:dependencyIntegrityHelper
    }

    function Get-NuGetDependency {
        param([Parameter(Mandatory)] [string] $PackagePath)

        $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
        try {
            $nuspecEntry = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
            $nuspecEntry.Count | Should -Be 1
            $reader = [System.IO.StreamReader]::new($nuspecEntry[0].Open())
            try {
                [xml] $nuspec = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $archive.Dispose()
        }

        @($nuspec.SelectNodes("//*[local-name()='dependency']") | ForEach-Object {
            [pscustomobject]@{
                Id      = [string] $_.id
                Version = [string] $_.version
            }
        })
    }
}

Describe 'Transitive runtime dependency packaging' -Tag 'QA' {
    It 'keeps the default workflow pack-before-test' {
        $buildYaml = Get-Content -LiteralPath (Join-Path $script:repoRoot 'build.yaml') -Raw
        $defaultWorkflow = [regex]::Match(
            $buildYaml,
            '(?ms)^  ''\.'':[^\r\n]*\r?\n(?<body>.*?)(?=^  [a-zA-Z0-9_.-]+:\s*$)'
        )
        $defaultWorkflow.Success | Should -BeTrue
        $orderedTasks = @([regex]::Matches($defaultWorkflow.Groups['body'].Value, '(?m)^\s+-\s+(?<task>\S+)\s*$') |
            ForEach-Object { $_.Groups['task'].Value })

        $orderedTasks | Should -Be @('pack', 'test')
    }

    It 'keeps TenantPulse dependent only on exact GraphKit 0.3.0 at runtime' {
        $requirements = @($script:sourceManifest.RequiredModules)
        $requirements.Count | Should -Be 1
        [string] $requirements[0].ModuleName | Should -Be 'GraphKit'
        [string] $requirements[0].RequiredVersion | Should -Be '0.3.0'
        @($requirements.ModuleName) | Should -Not -Contain 'Microsoft.Graph.Authentication'
        @($requirements.ModuleName) | Should -Not -Contain 'Microsoft.PowerShell.SecretManagement'
    }

    It 'pins the hard transitive dependency for deterministic restore without restoring SecretManagement' {
        [string] $script:restoreDependencies.GraphKit | Should -Be '0.3.0'
        [string] $script:restoreDependencies.'Microsoft.Graph.Authentication' | Should -Be '2.38.1'
        $script:restoreDependencies.ContainsKey('Microsoft.PowerShell.SecretManagement') | Should -BeFalse

        $graphKitRequirements = @($script:graphKitManifest.RequiredModules)
        $graphKitRequirements.Count | Should -Be 1
        [string] $graphKitRequirements[0].ModuleName | Should -Be 'Microsoft.Graph.Authentication'
        [string] $graphKitRequirements[0].ModuleVersion | Should -Be '2.38.1'
        @($script:graphKitManifest.PrivateData.PSData.ExternalModuleDependencies) |
            Should -Not -Contain 'Microsoft.Graph.Authentication'
    }

    It 'binds every staged runtime dependency to a tracked byte-level tree digest' {
        Test-Path -LiteralPath $script:dependencyIntegrityHelper -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $script:dependencyDigestPath -PathType Leaf | Should -BeTrue
        Get-Command Get-PulseModuleTreeDigest -CommandType Function -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
        Get-Command Assert-PulseStagedModuleDigest -CommandType Function -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty

        $expectedDigests = Import-PowerShellDataFile -LiteralPath $script:dependencyDigestPath
        foreach ($dependency in @(
            @{ Name = 'GraphKit'; Version = '0.3.0' },
            @{ Name = 'Microsoft.Graph.Authentication'; Version = '2.38.1' }
        )) {
            $moduleBase = Join-Path $script:repoRoot (
                'output/RequiredModules/{0}/{1}' -f $dependency.Name, $dependency.Version
            )
            {
                Assert-PulseStagedModuleDigest `
                    -ModuleName $dependency.Name `
                    -Version $dependency.Version `
                    -ModuleBase $moduleBase `
                    -ExpectedDigests $expectedDigests
            } | Should -Not -Throw
        }
    }

    It 'rejects same-version staged bytes after any file content changes' {
        $moduleBase = Join-Path $TestDrive 'SyntheticModule/1.0.0'
        New-Item -ItemType Directory -Path $moduleBase -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $moduleBase 'SyntheticModule.psd1') -Value '@{ ModuleVersion = ''1.0.0'' }'
        Set-Content -LiteralPath (Join-Path $moduleBase 'payload.txt') -Value 'tested bytes'

        $expectedDigests = @{
            'SyntheticModule|1.0.0' = Get-PulseModuleTreeDigest -ModuleBase $moduleBase
        }
        {
            Assert-PulseStagedModuleDigest `
                -ModuleName 'SyntheticModule' `
                -Version '1.0.0' `
                -ModuleBase $moduleBase `
                -ExpectedDigests $expectedDigests
        } | Should -Not -Throw

        Add-Content -LiteralPath (Join-Path $moduleBase 'payload.txt') -Value 'changed after verification'

        {
            Assert-PulseStagedModuleDigest `
                -ModuleName 'SyntheticModule' `
                -Version '1.0.0' `
                -ModuleBase $moduleBase `
                -ExpectedDigests $expectedDigests
        } | Should -Throw -ExpectedMessage '*tree digest mismatch*'
    }

    It 'makes the staging task enforce the tracked digest map before publishing dependencies' {
        $taskText = Get-Content -LiteralPath (
            Join-Path $script:repoRoot '.build/StageTransitiveRuntimeDependencies.tasks.ps1'
        ) -Raw

        $taskText | Should -Match 'RuntimeDependencyDigests\.psd1'
        $taskText | Should -Match 'Assert-PulseStagedModuleDigest'
    }

    It 'stages installed GraphKit module files rather than raw NuGet transport wrappers' {
        $graphKitBase = Split-Path -Parent $script:graphKitManifestPath
        Test-Path -LiteralPath (Join-Path $graphKitBase '[Content_Types].xml') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $graphKitBase '_rels') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $graphKitBase 'package') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $graphKitBase 'GraphKit.nuspec') | Should -BeFalse
    }

    It 'stages transitive runtime dependencies between build and Sampler packaging' {
        $buildYaml = Get-Content -LiteralPath (Join-Path $script:repoRoot 'build.yaml') -Raw
        $packWorkflow = [regex]::Match(
            $buildYaml,
            '(?ms)^  pack:\s*$(?<body>.*?)(?=^  [a-zA-Z0-9_.-]+:\s*$)'
        )
        $packWorkflow.Success | Should -BeTrue
        $orderedTasks = @([regex]::Matches($packWorkflow.Groups['body'].Value, '(?m)^\s+-\s+(?<task>\S+)\s*$') |
            ForEach-Object { $_.Groups['task'].Value })
        $orderedTasks | Should -Be @('build', 'Stage_Transitive_Runtime_Dependencies', 'package_module_nupkg')

        Test-Path -LiteralPath (Join-Path $script:repoRoot '.build/StageTransitiveRuntimeDependencies.tasks.ps1') -PathType Leaf |
            Should -BeTrue
    }

    It 'creates all three packages needed by the local dependency chain' {
        Test-Path -LiteralPath (Join-Path $script:repoRoot 'output/Microsoft.Graph.Authentication.2.38.1.nupkg') -PathType Leaf |
            Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:repoRoot 'output/GraphKit.0.3.0.nupkg') -PathType Leaf |
            Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg") -PathType Leaf |
            Should -BeTrue
    }

    It 'leaves no build-local PowerShell repository registration behind' {
        Get-PSRepository -Name output -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'preserves the exact dependency chain in NuGet metadata' {
        $tenantPulseDependencies = @(Get-NuGetDependency -PackagePath (
            Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg"
        ))
        $tenantPulseDependencies.Count | Should -Be 1
        $tenantPulseDependencies[0].Id | Should -Be 'GraphKit'
        $tenantPulseDependencies[0].Version | Should -Be '[0.3.0]'

        $graphKitDependencies = @(Get-NuGetDependency -PackagePath (
            Join-Path $script:repoRoot 'output/GraphKit.0.3.0.nupkg'
        ))
        $graphKitDependencies.Count | Should -Be 1
        $graphKitDependencies[0].Id | Should -Be 'Microsoft.Graph.Authentication'
        $graphKitDependencies[0].Version | Should -Be '2.38.1'
    }

    It 'contains no duplicate archive entry names caused by nested NuGet wrappers' {
        foreach ($packagePath in @(
            (Join-Path $script:repoRoot 'output/GraphKit.0.3.0.nupkg'),
            (Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg")
        )) {
            $archive = [System.IO.Compression.ZipFile]::OpenRead($packagePath)
            try {
                $duplicates = @($archive.Entries.FullName |
                    Group-Object -CaseSensitive |
                    Where-Object Count -gt 1 |
                    Select-Object -ExpandProperty Name)
            }
            finally {
                $archive.Dispose()
            }

            $duplicates | Should -BeNullOrEmpty -Because "'$packagePath' must contain one physical ZIP entry per path"
        }
    }

    It 'restores exact packages and imports with a newer compatible global dependency already loaded' {
        $feedName = 'TenantPulseTest_' + [guid]::NewGuid().ToString('N')
        $installRoot = Join-Path $TestDrive 'clean-install'
        New-Item -ItemType Directory -Path $installRoot | Out-Null

        try {
            Register-PSRepository `
                -Name $feedName `
                -SourceLocation (Join-Path $script:repoRoot 'output') `
                -PublishLocation (Join-Path $script:repoRoot 'output') `
                -InstallationPolicy Trusted `
                -ErrorAction Stop
            Save-Module `
                -Name TenantPulse `
                -RequiredVersion $script:releaseVersion `
                -Repository $feedName `
                -Path $installRoot `
                -Force `
                -ErrorAction Stop
        }
        finally {
            Unregister-PSRepository -Name $feedName -ErrorAction SilentlyContinue
        }

        Test-Path -LiteralPath (Join-Path $installRoot "TenantPulse/$script:releaseVersion/TenantPulse.psd1") -PathType Leaf |
            Should -BeTrue
        Test-Path -LiteralPath (Join-Path $installRoot 'GraphKit/0.3.0/GraphKit.psd1') -PathType Leaf |
            Should -BeTrue
        Test-Path -LiteralPath (Join-Path $installRoot 'Microsoft.Graph.Authentication/2.38.1/Microsoft.Graph.Authentication.psd1') -PathType Leaf |
            Should -BeTrue
        Test-Path -LiteralPath (Join-Path $installRoot 'Microsoft.PowerShell.SecretManagement') |
            Should -BeFalse

        # GitHub's Ubuntu runner exposes a newer Graph Authentication module through
        # its Azure module path. Reproduce that host contamination explicitly so the
        # probe proves the restored dependency bytes, not whichever compatible module
        # happens to be globally discoverable first.
        $globalModuleRoot = Join-Path $TestDrive 'global-modules'
        $globalModuleParent = Join-Path $globalModuleRoot 'Microsoft.Graph.Authentication'
        $newerGlobalModule = Join-Path $globalModuleParent '2.39.0'
        New-Item -ItemType Directory -Path $globalModuleParent -Force | Out-Null
        Copy-Item `
            -LiteralPath (Join-Path $installRoot 'Microsoft.Graph.Authentication/2.38.1') `
            -Destination $newerGlobalModule `
            -Recurse `
            -Force
        $newerManifestPath = Join-Path $newerGlobalModule 'Microsoft.Graph.Authentication.psd1'
        $newerManifestText = Get-Content -LiteralPath $newerManifestPath -Raw
        $newerManifestText = $newerManifestText -replace "ModuleVersion\s*=\s*'2\.38\.1'", "ModuleVersion = '2.39.0'"
        Set-Content -LiteralPath $newerManifestPath -Value $newerManifestText -NoNewline
        [string] (Import-PowerShellDataFile -LiteralPath $newerManifestPath).ModuleVersion |
            Should -Be '2.39.0'

        $originalModulePath = $env:PSModulePath
        try {
            $env:PSModulePath = @(
                $globalModuleRoot
                $installRoot
                (Join-Path $PSHOME 'Modules')
            ) -join [System.IO.Path]::PathSeparator
            $childOutput = @(& ([System.Environment]::ProcessPath) -NoLogo -NoProfile -Command @'
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
Import-Module TenantPulse -RequiredVersion 0.2.0 -Force
[pscustomobject]@{
    TenantPulse = [string] (Get-Module TenantPulse).Version
    GraphKit = [string] (Get-Module GraphKit).Version
    GraphAuthentication = [string] (Get-Module Microsoft.Graph.Authentication).Version
    SecretManagementLoaded = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)
} | ConvertTo-Json -Compress
'@)
            $childExitCode = $LASTEXITCODE
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $childExitCode | Should -Be 0
        $probe = $childOutput[-1] | ConvertFrom-Json
        $probe.TenantPulse | Should -Be '0.2.0'
        $probe.GraphKit | Should -Be '0.3.0'
        # The build/feed assertions above pin the restored package to 2.38.1.
        # GraphKit's runtime ModuleVersion constraint is a minimum, so a compatible
        # version already loaded in the process must remain valid rather than being
        # replaced behind another module's back.
        $probe.GraphAuthentication | Should -Be '2.39.0'
        $probe.SecretManagementLoaded | Should -BeFalse
    }
}
