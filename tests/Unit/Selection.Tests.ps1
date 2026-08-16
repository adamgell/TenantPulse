BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Invoke-GraphOperation { param() }
        function Get-GraphOperation { param() }
    }

    function script:New-TestSelectionCheck {
        param(
            [string] $Id,
            [string] $Category
        )
        [pscustomobject]@{
            PSTypeName = 'TenantPulse.CheckDescriptor'
            Id         = $Id
            Category   = $Category
        }
    }

    $script:caCheck = New-TestSelectionCheck -Id 'TP.ENT.0001' -Category 'Entra.ConditionalAccess'
    $script:identityCheck = New-TestSelectionCheck -Id 'TP.ENT.0002' -Category 'Entra.Identity'
    $script:complianceCheck = New-TestSelectionCheck -Id 'TP.INT.0003' -Category 'Intune.Compliance'
    $script:entraFooCheck = New-TestSelectionCheck -Id 'TP.ENT.0004' -Category 'EntraFoo.Bogus'
}

Describe 'Select-PulseCheck' {
    It 'IncludeCategory prefix-matches the whole dotted subtree, not just an exact category' {
        $catalog = @($script:caCheck, $script:identityCheck, $script:complianceCheck, $script:entraFooCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -IncludeCategory 'Entra'
        }

        @($result.Id) | Should -Contain 'TP.ENT.0001'
        @($result.Id) | Should -Contain 'TP.ENT.0002'
        @($result.Id) | Should -Not -Contain 'TP.INT.0003'
        # 'EntraFoo.Bogus' must NOT match the 'Entra' prefix - only a full path-segment
        # prefix (an exact match, or the token followed by '.') counts.
        @($result.Id) | Should -Not -Contain 'TP.ENT.0004'
    }

    It 'IncludeCategory exact match still works (a leaf category with no further subtree)' {
        $catalog = @($script:caCheck, $script:identityCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -IncludeCategory 'Entra.ConditionalAccess'
        }

        @($result.Id) | Should -Be @('TP.ENT.0001')
    }

    It 'ExcludeCheck wins over IncludeCategory for the same check' {
        $catalog = @($script:caCheck, $script:identityCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -IncludeCategory 'Entra' -ExcludeCheck 'TP.ENT.0001'
        }

        @($result.Id) | Should -Be @('TP.ENT.0002')
    }

    It 'ExcludeCategory wins over IncludeCheck for the same check' {
        $catalog = @($script:caCheck, $script:identityCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -IncludeCheck 'TP.ENT.0001' -ExcludeCategory 'Entra.ConditionalAccess'
        }

        @($result).Count | Should -Be 0
    }

    It 'the generic -Exclude (profile vocabulary) wins over the generic -Include for the same check' {
        $catalog = @($script:caCheck, $script:identityCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -Include 'Entra' -Exclude 'TP.ENT.0001'
        }

        @($result.Id) | Should -Be @('TP.ENT.0002')
    }

    It '-Include matches either a category prefix or an exact check id' {
        $catalog = @($script:caCheck, $script:identityCheck, $script:complianceCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -Include @('Entra.ConditionalAccess', 'TP.INT.0003')
        }

        @($result.Id) | Should -Be @('TP.ENT.0001', 'TP.INT.0003')
    }

    It 'an unbound filter axis matches everything (no narrowing)' {
        $catalog = @($script:caCheck, $script:identityCheck, $script:complianceCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog
        }

        @($result.Id) | Should -Be @($catalog.Id)
    }

    It 'preserves the original relative order of the input checks' {
        $catalog = @($script:complianceCheck, $script:caCheck, $script:identityCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -IncludeCategory @('Intune', 'Entra')
        }

        @($result.Id) | Should -Be @('TP.INT.0003', 'TP.ENT.0001', 'TP.ENT.0002')
    }

    It 'every supplied axis narrows further (AND across axes)' {
        $catalog = @($script:caCheck, $script:identityCheck)

        $result = InModuleScope TenantPulse -ArgumentList (, $catalog) {
            param($catalog)
            Select-PulseCheck -Checks $catalog -IncludeCategory 'Entra' -IncludeCheck 'TP.ENT.0002'
        }

        @($result.Id) | Should -Be @('TP.ENT.0002')
    }
}

Describe 'Get-PulseTenantSnapshot -AssessmentProfile precedence' {
    BeforeEach {
        $script:snapshotRoot = Join-Path (Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())) 'snapshot'
    }

    AfterEach {
        if (Test-Path -LiteralPath (Split-Path -Path $script:snapshotRoot -Parent)) {
            Remove-Item -LiteralPath (Split-Path -Path $script:snapshotRoot -Parent) -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'an explicit -IncludeCategory wins over the profile Include, even as an empty array' {
        $inScope = [pscustomobject]@{ PSTypeName = 'TenantPulse.CheckDescriptor'; Id = 'TP.ENT.0001'; Category = 'Entra.ConditionalAccess'; Data = [pscustomobject]@{ Datasets = @('conditionalAccessPolicies') } }
        $outOfScope = [pscustomobject]@{ PSTypeName = 'TenantPulse.CheckDescriptor'; Id = 'TP.INT.0002'; Category = 'Intune.Compliance'; Data = [pscustomobject]@{ Datasets = @('deviceCompliancePolicies') } }

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($inScope, $outOfScope) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $profilePath = Join-Path ([System.IO.Path]::GetTempPath()) "$([Guid]::NewGuid().ToString()).psd1"
        Set-Content -LiteralPath $profilePath -Value "@{ Include = @('Intune'); Exclude = @() }" -NoNewline

        try {
            $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot, $profilePath {
                param($snapshotRoot, $profilePath)
                Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot -AssessmentProfile $profilePath -IncludeCategory @('Entra.ConditionalAccess')
            }

            $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
            $manifest.datasets.PSObject.Properties.Name | Should -Contain 'conditionalAccessPolicies'
            $manifest.datasets.PSObject.Properties.Name | Should -Not -Contain 'deviceCompliancePolicies'
        } finally {
            Remove-Item -LiteralPath $profilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'the profile Include applies when no CLI selection parameter is bound' {
        $inScope = [pscustomobject]@{ PSTypeName = 'TenantPulse.CheckDescriptor'; Id = 'TP.ENT.0001'; Category = 'Entra.ConditionalAccess'; Data = [pscustomobject]@{ Datasets = @('conditionalAccessPolicies') } }
        $outOfScope = [pscustomobject]@{ PSTypeName = 'TenantPulse.CheckDescriptor'; Id = 'TP.INT.0002'; Category = 'Intune.Compliance'; Data = [pscustomobject]@{ Datasets = @('deviceCompliancePolicies') } }

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($inScope, $outOfScope) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $profilePath = Join-Path ([System.IO.Path]::GetTempPath()) "$([Guid]::NewGuid().ToString()).psd1"
        Set-Content -LiteralPath $profilePath -Value "@{ Include = @('Entra.ConditionalAccess'); Exclude = @() }" -NoNewline

        try {
            $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot, $profilePath {
                param($snapshotRoot, $profilePath)
                Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot -AssessmentProfile $profilePath
            }

            $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
            $manifest.datasets.PSObject.Properties.Name | Should -Contain 'conditionalAccessPolicies'
            $manifest.datasets.PSObject.Properties.Name | Should -Not -Contain 'deviceCompliancePolicies'
        } finally {
            Remove-Item -LiteralPath $profilePath -Force -ErrorAction SilentlyContinue
        }
    }
}
