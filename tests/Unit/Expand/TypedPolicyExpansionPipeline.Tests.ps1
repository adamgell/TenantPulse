BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphObject { param() }
    }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
}

Describe 'Invoke-PulseTypedPolicyExpansionPipeline' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid'; ProfileId = 'contoso-lab' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes both families NotExpanded with a reason when neither raw dataset was ever collected, makes NO Graph call' {
        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'NotExpanded'
        $manifest.expansions.compliance.reason | Should -Match 'deviceCompliancePolicies unavailable'
        $manifest.expansions.deviceConfiguration.status | Should -Be 'NotExpanded'
        $manifest.expansions.deviceConfiguration.reason | Should -Match 'deviceConfigurations unavailable'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'a Collected deviceCompliancePolicies dataset expands compliance independently of a missing deviceConfigurations dataset' {
        $policy = [pscustomobject]@{ id = 'p1'; displayName = 'Win'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; bitLockerEnabled = $true }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicyAssignment' } { @() }

        InModuleScope TenantPulse -ArgumentList $script:store, $policy {
            param($store, $policy)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'Expanded'
        $manifest.expansions.deviceConfiguration.status | Should -Be 'NotExpanded'
        $manifest.expansions.deviceConfiguration.reason | Should -Match 'deviceConfigurations unavailable'
    }
}
