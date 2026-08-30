<#
    Sampler's PowerShellGet package task stages only the module being packaged and its
    direct RequiredModules. TenantPulse directly requires GraphKit, while GraphKit has
    its own hard Microsoft.Graph.Authentication dependency. PowerShellGet validates a
    module's dependencies against the target repository when Publish-Module runs, so a
    Graph Authentication folder on PSModulePath is not enough: a dependency package must
    already exist in the local output feed before Sampler attempts to package GraphKit.

    Stage_Transitive_Runtime_Dependencies closes that packaging-only gap. It walks hard
    transitive dependencies leaf-first, resolves them exclusively from the exact versions
    pinned under output/RequiredModules, and publishes those dependency records into the
    ephemeral local output feed. Direct dependencies remain Sampler's responsibility.

    The locally repacked dependency archives are feed indexes for this build only. They
    are not release artifacts and must never be published to PSGallery. In particular,
    Microsoft.Graph.Authentication's upstream package signature is not reproduced by
    Publish-Module; TenantPulse itself continues to publish only its named package.
#>

$dependencyIntegrityHelperPath = Join-Path $PSScriptRoot 'RuntimeDependencyIntegrity.ps1'
if (-not (Test-Path -LiteralPath $dependencyIntegrityHelperPath -PathType Leaf)) {
    throw "Runtime dependency integrity helper not found at '$dependencyIntegrityHelperPath'."
}
. $dependencyIntegrityHelperPath

function Get-PulseModuleSpecificationName {
    param([Parameter(Mandatory)] [object] $Specification)

    ([Microsoft.PowerShell.Commands.ModuleSpecification] $Specification).Name
}

function Get-PulseExternalModuleDependencyNames {
    param([Parameter(Mandatory)] [hashtable] $Manifest)

    @($Manifest.PrivateData.PSData.ExternalModuleDependencies | ForEach-Object {
        if ($_ -is [string]) {
            $_
        }
        elseif ($_ -is [System.Collections.IDictionary] -and $_.Contains('ModuleName')) {
            [string] $_.ModuleName
        }
        elseif ($_.PSObject.Properties.Name -contains 'ModuleName') {
            [string] $_.ModuleName
        }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Resolve-PulsePinnedStagedModule {
    param(
        [Parameter(Mandatory)] [object] $Specification,
        [Parameter(Mandatory)] [hashtable] $RestorePins,
        [Parameter(Mandatory)] [string] $RequiredModulesRoot,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $ExpectedDigests
    )

    $requested = [Microsoft.PowerShell.Commands.ModuleSpecification] $Specification
    $moduleName = $requested.Name
    if (-not $RestorePins.ContainsKey($moduleName)) {
        throw "Transitive runtime dependency '$moduleName' has no exact version pin in RequiredModules.psd1."
    }

    $requiredVersion = [string] $RestorePins[$moduleName]
    if ([string]::IsNullOrWhiteSpace($requiredVersion) -or $requiredVersion -eq 'latest') {
        throw "Transitive runtime dependency '$moduleName' must have an exact version pin in RequiredModules.psd1."
    }

    $exactSpecification = [Microsoft.PowerShell.Commands.ModuleSpecification] @{
        ModuleName      = $moduleName
        RequiredVersion = $requiredVersion
    }
    $requiredRoot = [System.IO.Path]::GetFullPath($RequiredModulesRoot).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar

    $exactCandidates = @(Get-Module -ListAvailable -FullyQualifiedName $exactSpecification |
        Where-Object {
            $candidateBase = [System.IO.Path]::GetFullPath($_.ModuleBase).TrimEnd(
                [System.IO.Path]::DirectorySeparatorChar,
                [System.IO.Path]::AltDirectorySeparatorChar
            ) + [System.IO.Path]::DirectorySeparatorChar
            $candidateBase.StartsWith($requiredRoot, [System.StringComparison]::OrdinalIgnoreCase)
        })

    if ($exactCandidates.Count -ne 1) {
        throw "Expected exactly one staged '$moduleName' $requiredVersion module under '$RequiredModulesRoot'; found $($exactCandidates.Count)."
    }

    $acceptableCandidates = @(Get-Module -ListAvailable -FullyQualifiedName $requested |
        Where-Object {
            $_.Name -eq $moduleName -and
            $_.Version -eq $exactCandidates[0].Version -and
            [System.IO.Path]::GetFullPath($_.ModuleBase) -eq [System.IO.Path]::GetFullPath($exactCandidates[0].ModuleBase)
        })
    if ($acceptableCandidates.Count -ne 1) {
        throw "Staged '$moduleName' $requiredVersion does not satisfy its parent module's RequiredModules constraint."
    }

    Assert-PulseStagedModuleDigest `
        -ModuleName $moduleName `
        -Version $requiredVersion `
        -ModuleBase $exactCandidates[0].ModuleBase `
        -ExpectedDigests $ExpectedDigests

    $exactCandidates[0]
}

function Get-PulseStagedModuleManifest {
    param([Parameter(Mandatory)] [System.Management.Automation.PSModuleInfo] $Module)

    $transportWrappers = @(
        (Join-Path $Module.ModuleBase '[Content_Types].xml'),
        (Join-Path $Module.ModuleBase '_rels'),
        (Join-Path $Module.ModuleBase 'package'),
        (Join-Path $Module.ModuleBase "$($Module.Name).nuspec")
    )
    $presentWrappers = @($transportWrappers | Where-Object { Test-Path -LiteralPath $_ })
    if ($presentWrappers.Count -gt 0) {
        throw (
            "Staged module '$($Module.Name)' $($Module.Version) contains NuGet transport wrapper content: {0}. " +
            'Stage installed module files, not a raw whole-package extraction.' -f
            ($presentWrappers -join ', ')
        )
    }

    $manifestPath = Join-Path $Module.ModuleBase "$($Module.Name).psd1"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Staged module '$($Module.Name)' $($Module.Version) has no manifest at '$manifestPath'."
    }

    Import-PowerShellDataFile -LiteralPath $manifestPath
}

# Synopsis: Stage hard transitive runtime dependencies for Sampler's local package feed.
task Stage_Transitive_Runtime_Dependencies {
    . Set-SamplerTaskVariable

    if (-not $BuiltModuleManifest) {
        throw 'Stage_Transitive_Runtime_Dependencies requires a built module manifest. Run build first.'
    }

    $restorePinPath = Join-Path $ProjectPath 'RequiredModules.psd1'
    if (-not (Test-Path -LiteralPath $restorePinPath -PathType Leaf)) {
        throw "Restore pin file not found at '$restorePinPath'."
    }

    $restorePins = Import-PowerShellDataFile -LiteralPath $restorePinPath
    $dependencyDigestPath = Join-Path $PSScriptRoot 'RuntimeDependencyDigests.psd1'
    if (-not (Test-Path -LiteralPath $dependencyDigestPath -PathType Leaf)) {
        throw "Runtime dependency digest map not found at '$dependencyDigestPath'."
    }
    $expectedDigests = Import-PowerShellDataFile -LiteralPath $dependencyDigestPath
    $builtManifest = Import-PowerShellDataFile -LiteralPath $BuiltModuleManifest
    $requiredModulesRoot = [string] $RequiredModulesDirectory
    if ([string]::IsNullOrWhiteSpace($requiredModulesRoot)) {
        $requiredModulesRoot = Join-Path $OutputDirectory 'RequiredModules'
    }

    # Sampler itself uses the repository name 'output' and unconditionally unregisters
    # that name before packaging. Reuse the same convention here. This also recovers from
    # a prior failed Sampler pack, whose task can exit before reaching its unregister call;
    # PowerShellGet otherwise refuses to register the same local path under a second name.
    $repositoryName = 'output'
    $published = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $visiting = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Publish-PulseModuleChildren {
        param([Parameter(Mandatory)] [System.Management.Automation.PSModuleInfo] $ParentModule)

        $parentKey = "$($ParentModule.Name)|$($ParentModule.Version)"
        if (-not $visiting.Add($parentKey)) {
            throw "Circular hard runtime dependency detected while staging '$parentKey'."
        }

        try {
            $parentManifest = Get-PulseStagedModuleManifest -Module $ParentModule
            $externalNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($externalName in @(Get-PulseExternalModuleDependencyNames -Manifest $parentManifest)) {
                $null = $externalNames.Add($externalName)
            }

            # @($null) contains one element in PowerShell. Filter the optional manifest
            # field before iterating so a dependency leaf is genuinely an empty walk.
            foreach ($childSpecification in @($parentManifest.RequiredModules | Where-Object { $null -ne $_ })) {
                $childName = Get-PulseModuleSpecificationName -Specification $childSpecification
                if ($externalNames.Contains($childName)) {
                    continue
                }

                $childModule = Resolve-PulsePinnedStagedModule `
                    -Specification $childSpecification `
                    -RestorePins $restorePins `
                    -RequiredModulesRoot $requiredModulesRoot `
                    -ExpectedDigests $expectedDigests
                $childKey = "$($childModule.Name)|$($childModule.Version)"
                if ($published.Contains($childKey)) {
                    continue
                }

                Publish-PulseModuleChildren -ParentModule $childModule

                Write-Build Yellow (
                    "  Staging transitive runtime dependency {0} v{1} from '{2}'" -f
                    $childModule.Name,
                    $childModule.Version,
                    $childModule.ModuleBase
                )
                Publish-Module -Repository $repositoryName -Path $childModule.ModuleBase -ErrorAction Stop

                $publishedModule = Find-Module `
                    -Repository $repositoryName `
                    -Name $childModule.Name `
                    -RequiredVersion $childModule.Version `
                    -ErrorAction Stop
                if (-not $publishedModule) {
                    throw "Local build feed did not resolve '$childKey' after Publish-Module completed."
                }
                $null = $published.Add($childKey)
            }
        }
        finally {
            $null = $visiting.Remove($parentKey)
        }
    }

    try {
        Unregister-PSRepository -Name $repositoryName -ErrorAction SilentlyContinue
        Register-PSRepository `
            -Name $repositoryName `
            -SourceLocation $OutputDirectory `
            -PublishLocation $OutputDirectory `
            -InstallationPolicy Trusted `
            -ErrorAction Stop

        foreach ($directSpecification in @($builtManifest.RequiredModules | Where-Object { $null -ne $_ })) {
            $directModule = Resolve-PulsePinnedStagedModule `
                -Specification $directSpecification `
                -RestorePins $restorePins `
                -RequiredModulesRoot $requiredModulesRoot `
                -ExpectedDigests $expectedDigests
            Publish-PulseModuleChildren -ParentModule $directModule
        }
    }
    finally {
        Unregister-PSRepository -Name $repositoryName -ErrorAction SilentlyContinue
    }
}
