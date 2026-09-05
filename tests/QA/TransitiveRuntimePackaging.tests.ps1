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

    function Get-PulseMarkdownHeadingAnchors {
        param([Parameter(Mandatory)] [string] $HeadingText)
        # Fold figure/en/em dashes so restored headings like "AM01–AM04" match ASCII
        # hyphen fragments, but keep the stripped-dash slug too: other restored headings
        # (and spaced em-dashes) were catalogued without that fold.
        $anchors = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($dashClass in @($null, '[\u2012\u2013]', '[\u2012\u2013\u2014]')) {
            $text = $HeadingText.ToLowerInvariant()
            if ($null -ne $dashClass) {
                $text = [regex]::Replace($text, $dashClass, '-')
            }
            $text = [regex]::Replace($text, '[^a-z0-9 _-]', '')
            [void] $anchors.Add($text.Replace(' ', '-'))
        }
        return $anchors
    }

    function Resolve-PulseResearchLeaf {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [string] $RelativePath
        )

        $segments = @($RelativePath -split '[\\/]+' | Where-Object { $_ -ne '' -and $_ -ne '.' })
        if ($segments -contains '..') {
            return @{ Error = "path '$RelativePath' contains '..'." }
        }

        $current = [System.IO.Path]::GetFullPath($Root)
        foreach ($segment in $segments) {
            $children = @(Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue)
            $ordinal = @($children | Where-Object {
                    [string]::Equals($_.Name, $segment, [System.StringComparison]::Ordinal)
                })
            if ($ordinal.Count -eq 1) {
                $current = $ordinal[0].FullName
                continue
            }

            $ignoreCase = @($children | Where-Object {
                    [string]::Equals($_.Name, $segment, [System.StringComparison]::OrdinalIgnoreCase)
                })
            if ($ignoreCase.Count -ge 1) {
                return @{ Error = "file '$RelativePath' does not match on-disk path casing." }
            }

            return @{ Error = "file '$RelativePath' is not present." }
        }

        if (-not (Test-Path -LiteralPath $current -PathType Leaf)) {
            return @{ Error = "file '$RelativePath' is not present." }
        }

        return @{ Path = $current }
    }

    function Get-PulseShippingResearchFailures {
        param([Parameter(Mandatory)] [string] $Root)

        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:repoRoot 'source/Data/Checks') -Filter '*.psd1' -File)
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $files) {
            $descriptor = Import-PowerShellDataFile -LiteralPath $file.FullName
            $research = [string] $descriptor.References.Research
            $hashIndex = $research.IndexOf('#')
            if ($hashIndex -lt 0) {
                $failures.Add("$($descriptor.Id): References.Research must include a heading fragment.")
                continue
            }

            $relativePath = $research.Substring(0, $hashIndex)
            $fragment = $research.Substring($hashIndex + 1)
            $resolved = Resolve-PulseResearchLeaf -Root $Root -RelativePath $relativePath
            if ($resolved.ContainsKey('Error')) {
                $failures.Add("$($descriptor.Id): $($resolved.Error)")
                continue
            }

            $markdown = [System.IO.File]::ReadAllText($resolved.Path)
            $counts = [System.Collections.Generic.Dictionary[string, int]]::new(
                [System.StringComparer]::Ordinal
            )
            foreach ($match in [regex]::Matches($markdown, '(?m)^#{1,6} (.+)$')) {
                foreach ($anchor in @(Get-PulseMarkdownHeadingAnchors -HeadingText $match.Groups[1].Value)) {
                    if ($counts.ContainsKey($anchor)) {
                        $counts[$anchor]++
                    } else {
                        $counts[$anchor] = 1
                    }
                }
            }

            if (-not $counts.ContainsKey($fragment)) {
                $failures.Add("$($descriptor.Id): heading anchor '$fragment' is not present in '$relativePath'.")
            } elseif ($counts[$fragment] -ne 1) {
                $failures.Add("$($descriptor.Id): heading anchor '$fragment' is not unique in '$relativePath'.")
            }
        }

        return @($failures)
    }
}

Describe 'Transitive runtime dependency packaging' -Tag 'QA' {
    It 'makes default and direct test workflows package current source before testing' {
        $buildYaml = Get-Content -LiteralPath (Join-Path $script:repoRoot 'build.yaml') -Raw
        $defaultWorkflow = [regex]::Match(
            $buildYaml,
            '(?ms)^  ''\.'':[^\r\n]*\r?\n(?<body>.*?)(?=^  [a-zA-Z0-9_.-]+:\s*$)'
        )
        $defaultWorkflow.Success | Should -BeTrue
        $orderedTasks = @([regex]::Matches($defaultWorkflow.Groups['body'].Value, '(?m)^\s+-\s+(?<task>\S+)\s*$') |
            ForEach-Object { $_.Groups['task'].Value })

        $orderedTasks | Should -Be @('test')

        $testWorkflow = [regex]::Match(
            $buildYaml,
            '(?ms)^  test:\s*$(?<body>.*?)(?=^  [a-zA-Z0-9_.-]+:\s*$)'
        )
        $testWorkflow.Success | Should -BeTrue
        $testTasks = @([regex]::Matches($testWorkflow.Groups['body'].Value, '(?m)^\s+-\s+(?<task>\S+)\s*$') |
            ForEach-Object { $_.Groups['task'].Value })

        $testTasks | Should -Be @(
            'pack'
            'Capture_Candidate_Proof_Input'
            'Pester_Tests_Stop_On_Fail'
            'Pester_if_Code_Coverage_Under_Threshold'
            'Assert_Gate_Result'
            'Record_Tested_Module_Digest'
        )

        $ciWorkflow = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        @([regex]::Matches($ciWorkflow, '(?m)pwsh -File \./build\.ps1 -Tasks test\s*$')).Count | Should -Be 1
        $ciWorkflow | Should -Not -Match '(?m)pwsh -File \./build\.ps1 -Tasks pack\s*$'
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
            $childScript = @'
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
Import-Module TenantPulse -RequiredVersion __TENANTPULSE_VERSION__ -Force
[pscustomobject]@{
    TenantPulse = [string] (Get-Module TenantPulse).Version
    GraphKit = [string] (Get-Module GraphKit).Version
    GraphAuthentication = [string] (Get-Module Microsoft.Graph.Authentication).Version
    SecretManagementLoaded = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)
} | ConvertTo-Json -Compress
'@
            $childScript = $childScript.Replace('__TENANTPULSE_VERSION__', $script:releaseVersion)
            $childOutput = @(& ([System.Environment]::ProcessPath) -NoLogo -NoProfile -Command $childScript)
            $childExitCode = $LASTEXITCODE
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $childExitCode | Should -Be 0
        $probe = $childOutput[-1] | ConvertFrom-Json
        $probe.TenantPulse | Should -Be $script:releaseVersion
        $probe.GraphKit | Should -Be '0.3.0'
        # The build/feed assertions above pin the restored package to 2.38.1.
        # GraphKit's runtime ModuleVersion constraint is a minimum, so a compatible
        # version already loaded in the process must remain valid rather than being
        # replaced behind another module's back.
        $probe.GraphAuthentication | Should -Be '2.39.0'
        $probe.SecretManagementLoaded | Should -BeFalse
    }
}

Describe 'Packaged research path and heading anchors' -Tag 'QA' {
    It 'copies research into the built module from the build workflow' {
        $buildYaml = Get-Content -LiteralPath (Join-Path $script:repoRoot 'build.yaml') -Raw
        $buildYaml | Should -Match '(?m)^\s*- Copy_Research_Docs\s*$'
        $buildYaml | Should -Match '(?s)Build_Module_ModuleBuilder.*?Copy_Research_Docs.*?package_module_nupkg'
    }

    It 'resolves every shipping descriptor path and unique heading from the built module' {
        $builtRoot = Join-Path $script:repoRoot "output/module/TenantPulse/$script:releaseVersion"
        Test-Path -LiteralPath $builtRoot -PathType Container | Should -BeTrue
        @(Get-PulseShippingResearchFailures -Root $builtRoot) | Should -BeNullOrEmpty
    }

    It 'resolves every shipping descriptor path and unique heading from the nupkg' {
        $packagePath = Join-Path $script:repoRoot "output/TenantPulse.$script:releaseVersion.nupkg"
        Test-Path -LiteralPath $packagePath -PathType Leaf | Should -BeTrue
        $extractRoot = Join-Path $TestDrive 'tenantpulse-nupkg'
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $extractRoot)
        @(Get-PulseShippingResearchFailures -Root $extractRoot) | Should -BeNullOrEmpty
    }
}
