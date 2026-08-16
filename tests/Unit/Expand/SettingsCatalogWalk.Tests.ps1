BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $script:fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalog'

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function Get-Fixture {
        param([string] $Name)
        $path = Join-Path $script:fixturesPath "$Name.json"
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 64
    }
}

Describe 'ConvertTo-PulseSettingRows' {
    It 'walks a golden choice-01 fixture (a SimpleSettingCollectionInstance root) into one root row with schema v1 fields' {
        $fixture = Get-Fixture -Name 'choice-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -PolicyType 'settingsCatalog' `
                -PolicyName $fixture.Policy.name -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $result.Rows.Count | Should -Be 1
        $row = $result.Rows[0]
        $row.schemaVersion | Should -Be '1'
        $row.policyId | Should -Be $fixture.Policy.id
        $row.instanceId | Should -Be '0'
        $row.settingDefinitionId | Should -Be $fixture.Settings.settingInstance.settingDefinitionId
        $row.settingPath | Should -Be $fixture.Settings.settingInstance.settingDefinitionId
        , $row.value | Should -Not -BeNullOrEmpty
        $row.redacted | Should -BeFalse
        $row.assignments | Should -BeNullOrEmpty
    }

    It 'walks a golden simple-01 fixture (a ChoiceSettingInstance root with children) into a root row carrying the choice value' {
        $fixture = Get-Fixture -Name 'simple-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $root = $result.Rows | Where-Object { $_.settingDefinitionId -eq $fixture.Settings.settingInstance.settingDefinitionId }
        $root.value | Should -Be $fixture.Settings.settingInstance.choiceSettingValue.value
        $root.redacted | Should -BeFalse
    }

    It 'walks a golden simplecollection-01 fixture into one row whose value is an array' {
        $fixture = Get-Fixture -Name 'simplecollection-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Rows.Count | Should -Be 1
        , $result.Rows[0].value | Should -Not -BeNullOrEmpty
        $result.Rows[0].value.Count | Should -Be 1
        $result.Rows[0].value[0] | Should -Be $fixture.Settings.settingInstance.simpleSettingCollectionValue[0].value
    }

    It 'walks a golden choicecollection-01 fixture, nested children get synthetic instance ids under the collection row' {
        $fixture = Get-Fixture -Name 'choicecollection-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $result.Rows.Count | Should -BeGreaterThan 1
        $rootRow = $result.Rows | Where-Object { $_.instanceId -eq '0' }
        $rootRow | Should -Not -BeNullOrEmpty
        # every non-root row's instanceId must be synthetic and reference an ancestor
        ($result.Rows | Where-Object { $_.instanceId -ne '0' } | ForEach-Object { $_.instanceId }) |
            ForEach-Object { $_ | Should -Match '^0(/|.*#\d+)' }
    }

    It 'walks the richly-nested groupcollection-02-nested fixture without gaps and produces multiple rows' {
        $fixture = Get-Fixture -Name 'groupcollection-02-nested'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $result.Rows.Count | Should -BeGreaterThan 5
        # a group row itself carries no value
        $groupRows = $result.Rows | Where-Object { $_.settingDefinitionId -eq 'com.apple.servicemanagement_com.apple.servicemanagement' }
        $groupRows.Count | Should -Be 1
        $groupRows[0].value | Should -BeNullOrEmpty
    }

    It 'resolves settingName and valueLabel from a supplied DefinitionIndex' {
        $fixture = Get-Fixture -Name 'simple-01'
        $definitionId = $fixture.Settings.settingInstance.settingDefinitionId
        $value = $fixture.Settings.settingInstance.choiceSettingValue.value

        $index = [ordered]@{
            $definitionId = [ordered]@{
                Name             = 'raw_name'
                DisplayName      = 'Friendly Display Name'
                RootDefinitionId = $null
                OptionLabels     = [ordered]@{ $value = 'Friendly Option Label' }
                Applicability    = $null
                IsSecretCapable  = $false
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $fixture, $index {
            param($fixture, $index)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings -DefinitionIndex $index
        }

        $row = $result.Rows[0]
        $row.settingName | Should -Be 'Friendly Display Name'
        $row.nameResolved | Should -BeTrue
        $row.valueLabel | Should -Be 'Friendly Option Label'
        $row.labelResolved | Should -BeTrue
    }

    It 'leaves settingName/valueLabel null and *Resolved false with no DefinitionIndex supplied' {
        $fixture = Get-Fixture -Name 'choice-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $row = $result.Rows[0]
        $row.settingName | Should -BeNullOrEmpty
        $row.nameResolved | Should -BeFalse
        $row.valueLabel | Should -BeNullOrEmpty
        $row.labelResolved | Should -BeFalse
    }

    It 'redacts a secret SimpleSettingInstance: value is null, redacted true, valueState carried, the planted secret never appears anywhere in the row' {
        $plantedSecret = 'sw0rdfish-do-not-leak-1234567890'
        $settingsPayload = [pscustomobject]@{
            id             = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'device_vendor_msft_policy_config_example_secret'
                simpleSettingValue  = [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'
                    value         = $plantedSecret
                    valueState    = 'encryptedValueToken'
                }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-secret-1' -SettingsPayload $settingsPayload
        }

        $result.Rows.Count | Should -Be 1
        $row = $result.Rows[0]
        $row.redacted | Should -BeTrue
        $row.value | Should -BeNullOrEmpty
        $row.valueState | Should -Be 'encryptedValueToken'

        $serialized = $row | ConvertTo-Json -Depth 20 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'redacts a SimpleSettingCollectionInstance when any element is secret-typed (fail-closed: whole row null)' {
        $plantedSecret = 'another-planted-secret-value'
        $settingsPayload = [pscustomobject]@{
            id             = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'                 = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                settingDefinitionId          = 'device_vendor_msft_policy_config_example_secret_collection'
                simpleSettingCollectionValue = @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'ordinary' }
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'; value = $plantedSecret; valueState = 'notEncrypted' }
                )
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-secret-2' -SettingsPayload $settingsPayload
        }

        $row = $result.Rows[0]
        $row.redacted | Should -BeTrue
        $row.value | Should -BeNullOrEmpty
        $row.valueState | Should -Be 'notEncrypted'

        $serialized = $row | ConvertTo-Json -Depth 20 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'reports a gap for an unknown @odata.type and skips only that node, continuing the walk' {
        $settingsPayload = @(
            [pscustomobject]@{
                id             = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationFutureUnknownInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_future'
                }
            }
            [pscustomobject]@{
                id             = '1'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_known'
                    simpleSettingValue   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'known-value' }
                }
            }
        )

        $result = InModuleScope TenantPulse -ArgumentList (, $settingsPayload) {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-unknown-1' -SettingsPayload $settingsPayload
        }

        $result.Gaps.Count | Should -Be 1
        $result.Gaps[0] | Should -Match 'unknown-instance-type'
        $result.Rows.Count | Should -Be 1
        $result.Rows[0].settingDefinitionId | Should -Be 'device_vendor_msft_policy_config_known'
    }

    It 'assigns synthetic instance ids per the frozen scheme when the raw payload carries no native id' {
        $settingsPayload = [pscustomobject]@{
            settingInstance = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'device_vendor_msft_policy_config_noid'
                simpleSettingValue   = [pscustomobject]@{ value = 'v' }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-noid-1' -SettingsPayload $settingsPayload
        }

        $result.Rows[0].instanceId | Should -Be 'policy-noid-1/device_vendor_msft_policy_config_noid#0'
    }

    It 'escapes a "/" inside a settingDefinitionId as ~s in settingPath' {
        $settingsPayload = [pscustomobject]@{
            id             = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'weird/definition/id'
                simpleSettingValue   = [pscustomobject]@{ value = 'v' }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-escape-1' -SettingsPayload $settingsPayload
        }

        $result.Rows[0].settingPath | Should -Be 'weird~sdefinition~sid'
    }

    It 'reports a depth-budget gap rather than throwing for a pathologically deep choice-child chain' {
        $leaf = [pscustomobject]@{
            '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = 'leaf'
            simpleSettingValue   = [pscustomobject]@{ value = 'v' }
        }
        $current = $leaf
        for ($i = 0; $i -lt 70; $i++) {
            $current = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = "level$i"
                choiceSettingValue   = [pscustomobject]@{ value = 'v'; children = @($current) }
            }
        }
        $settingsPayload = [pscustomobject]@{ id = '0'; settingInstance = $current }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-deep-1' -SettingsPayload $settingsPayload -MaxDepth 64
        }

        $result.Gaps | Where-Object { $_ -match 'depth-budget-exceeded' } | Should -Not -BeNullOrEmpty
    }

    It 'always emits assignments:null on every row (assignments-deferred, G-gate sequencing amendment)' {
        $fixture = Get-Fixture -Name 'groupcollection-02-nested'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Rows | ForEach-Object { $_.assignments | Should -BeNullOrEmpty }
    }
}
