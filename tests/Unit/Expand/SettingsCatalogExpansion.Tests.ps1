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

    function New-TestPolicy {
        param([string] $Id, [string] $Name = 'Test Policy', [string] $TemplateFamily = 'none', [string] $TemplateId = '')
        return [pscustomobject]@{
            id               = $Id
            name             = $Name
            templateReference = [pscustomobject]@{ templateId = $TemplateId; templateFamily = $TemplateFamily }
        }
    }

    function New-TestDefinitionIndex {
        return [ordered]@{
            'setting-a' = [ordered]@{ Name = 'a'; DisplayName = 'Setting A'; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false }
        }
    }

    function New-TestSettingsResponse {
        param([string] $DefinitionId = 'setting-a', [string] $Value = 'v1', [string] $RootId = '0')
        return @(
            [pscustomobject]@{
                id             = $RootId
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = $DefinitionId
                    simpleSettingValue   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = $Value }
                }
            }
        )
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion' {
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

    It 'writes NotExpanded with reason "definitions corpus unavailable" and makes NO Graph call when -DefinitionIndex is null' {
        $policy = New-TestPolicy -Id 'policy-1'

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy {
            param($store, $context, $policy)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $null -Sequential
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'definitions corpus unavailable'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'expands a single clean policy end to end: Expanded status, one jsonl line, correct sha256, raw payload dataset persisted' {
        $policy = New-TestPolicy -Id 'policy-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'hello-world'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index -Sequential
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 1
        $summary.RowCount | Should -Be 1

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $manifest.expansions.settingsCatalog.rowCount | Should -Be 1
        $manifest.expansions.settingsCatalog.policyCount | Should -Be 1
        $manifest.expansions.settingsCatalog.sha256 | Should -Not -BeNullOrEmpty

        $jsonlPath = Join-Path $script:store.ExpandedPath 'settingsCatalog.jsonl'
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        $lines = @(Get-Content -LiteralPath $jsonlPath)
        $lines.Count | Should -Be 1
        ($lines[0] | ConvertFrom-Json).value | Should -Be 'hello-world'

        # verify recorded sha256 actually matches the file's bytes
        $bytes = [System.IO.File]::ReadAllBytes($jsonlPath)
        $hash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes)) -replace '-', '').ToLowerInvariant()
        $hash | Should -Be $manifest.expansions.settingsCatalog.sha256

        # raw payload dataset persisted
        $manifest.datasets.'configurationPolicySettings-policy-1'.status | Should -Be 'Collected'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-1.json') -PathType Leaf | Should -BeTrue
    }

    It 'a policy fetch failure yields Partial status with a {policyId;reason} gap, other policies still succeed' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $badPolicy = New-TestPolicy -Id 'policy-bad'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'policy-good' } { $settingsResponse }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'policy-bad' } { throw 'simulated Graph failure' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $badPolicy, $index {
            param($store, $context, $goodPolicy, $badPolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $badPolicy) -DefinitionIndex $index -Sequential
        }

        $summary.Status | Should -Be 'Partial'
        $summary.RowCount | Should -Be 1
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-bad'
        $summary.Gaps[0].reason | Should -Match 'fetch-failed'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Partial'
        $manifest.expansions.settingsCatalog.gaps.Count | Should -Be 1
    }

    It 'planted secret value never appears in the raw persisted dataset or the final jsonl' {
        $policy = New-TestPolicy -Id 'policy-secret'
        $index = New-TestDefinitionIndex
        $plantedSecret = 'PLANTED-SECRET-VALUE-zzz999'
        $settingsResponse = @(
            [pscustomobject]@{
                id             = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-secret'
                    simpleSettingValue   = [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'
                        value         = $plantedSecret
                        valueState    = 'notEncrypted'
                    }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index -Sequential
        }

        $rawDatasetContent = Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-secret.json') -Raw
        $rawDatasetContent | Should -Not -Match ([regex]::Escape($plantedSecret))

        $jsonlContent = Get-Content -LiteralPath (Join-Path $script:store.ExpandedPath 'settingsCatalog.jsonl') -Raw
        $jsonlContent | Should -Not -Match ([regex]::Escape($plantedSecret))

        $manifestContent = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifestContent | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'merge determinism: processing the same two policies in reversed order produces a byte-identical jsonl file' {
        $policyA = New-TestPolicy -Id 'aaaaaaaa-0000-0000-0000-000000000001'
        $policyB = New-TestPolicy -Id 'bbbbbbbb-0000-0000-0000-000000000002'
        $index = New-TestDefinitionIndex
        $responseA = New-TestSettingsResponse -Value 'value-a'
        $responseB = New-TestSettingsResponse -Value 'value-b'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq $policyA.id } { $responseA }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq $policyB.id } { $responseB }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyA, $policyB, $index {
            param($store, $context, $policyA, $policyB, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyA, $policyB) -DefinitionIndex $index -Sequential
        }
        $forwardBytes = [System.IO.File]::ReadAllBytes((Join-Path $script:store.ExpandedPath 'settingsCatalog.jsonl'))

        $storeRoot2 = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store2 = InModuleScope TenantPulse -ArgumentList $storeRoot2 { param($storeRoot2) New-PulseSnapshotStore -Path $storeRoot2 }
        try {
            InModuleScope TenantPulse -ArgumentList $store2, $script:context, $policyA, $policyB, $index {
                param($store2, $context, $policyA, $policyB, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store2 -Context $context -Policies @($policyB, $policyA) -DefinitionIndex $index -Sequential
            }
            $reversedBytes = [System.IO.File]::ReadAllBytes((Join-Path $store2.ExpandedPath 'settingsCatalog.jsonl'))

            [System.Convert]::ToBase64String($forwardBytes) | Should -Be ([System.Convert]::ToBase64String($reversedBytes))
        } finally {
            Remove-Item -LiteralPath $storeRoot2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It '-FromCapturedPayloads re-expands from the persisted raw dataset with NO Graph call' {
        $policy = New-TestPolicy -Id 'policy-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'captured-value'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index -Sequential
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'must not be called on -FromCapturedPayloads' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $index {
            param($store, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -Sequential -FromCapturedPayloads
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.RowCount | Should -Be 1
        $lines = @(Get-Content -LiteralPath (Join-Path $script:store.ExpandedPath 'settingsCatalog.jsonl'))
        ($lines[0] | ConvertFrom-Json).value | Should -Be 'captured-value'
    }

    It 'zero policies: Expanded with rowCount 0 and policyCount 0, an empty but hash-verified jsonl file' {
        $index = New-TestDefinitionIndex

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $index {
            param($store, $context, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @() -DefinitionIndex $index -Sequential
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 0
        $summary.RowCount | Should -Be 0
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly

        $jsonlPath = Join-Path $script:store.ExpandedPath 'settingsCatalog.jsonl'
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -BeNullOrEmpty
    }
}
