BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
    $script:graphEnvelopeHelperPath = Join-Path $script:repoRoot 'tests/Helpers/New-PulseTestGraphEnvelope.ps1'
    . $script:graphEnvelopeHelperPath

    InModuleScope TenantPulse {
        function Get-GraphObject { param() }
    }
    InModuleScope TenantPulse -ArgumentList $script:graphEnvelopeHelperPath {
        param($helperPath)
        . $helperPath
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
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicyAssignment' } { New-PulseTestGraphEnvelope }

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

    It 'persists the global authentication failure when one family aborts authentication and then throws' {
        $policy = [pscustomobject]@{
            id = 'p1'; displayName = 'Win'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
            bitLockerEnabled = $true
        }
        InModuleScope TenantPulse -ArgumentList $script:store, $policy {
            param($store, $policy)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) `
                -ApiVersion 'v1.0' -Status 'Collected'
        }

        $privateMarker = 'PRIVATE' + '-POST-AUTH-TYPED-THROW'
        $script:typedPostAuthThrowMarker = $privateMarker
        Mock Invoke-PulseTypedPolicyExpansion -ModuleName TenantPulse {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
            throw $script:typedPostAuthThrowMarker
        }
        $state = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $state {
            param($store, $context, $state)
            Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context `
                -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123' -NetworkAbortState $state
        }

        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifest = $manifestText | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'Failed'
        $manifest.expansions.deviceConfiguration.status | Should -Be 'NotExpanded'
        $manifest.collectionFailure | Should -Not -BeNullOrEmpty
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
        $state.AuthenticationAborted | Should -BeTrue
        Should-Invoke Invoke-PulseTypedPolicyExpansion -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}
