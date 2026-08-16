BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Resolve-PulseSettingsCatalogValueClassification (P0-2 shared classifier)' {
    It 'classifies a real secret-typed value as secret, with no gap-worthy unknown shape' {
        $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'; value = 'x'; valueState = 'notEncrypted' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeTrue
        $result.IsSecretByType | Should -BeTrue
        $result.ValueState | Should -Be 'notEncrypted'
    }

    It 'classifies a known-safe StringSettingValue as not secret' {
        $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeFalse
        $result.IsKnownSafeShape | Should -BeTrue
    }

    It 'classifies a known-safe IntegerSettingValue as not secret' {
        $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'; value = 42 }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeFalse
    }

    It 'FAIL CLOSED: a value with NO @odata.type at all (PSObject shape) is treated as secret, unknown shape' {
        $value = [pscustomobject]@{ value = 'plaintext' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeTrue
        $result.IsSecretByType | Should -BeFalse
        $result.IsKnownSafeShape | Should -BeFalse
        $result.HasDiscriminator | Should -BeFalse
    }

    It 'FAIL CLOSED: a dictionary/hashtable-shaped value with no @odata.type is treated as secret (the reproduced bypass shape)' {
        $value = @{ value = 'plaintext' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeTrue
        $result.HasDiscriminator | Should -BeFalse
    }

    It 'FAIL CLOSED: an unrecognized/future @odata.type is treated as secret (unknown shape, not known-safe)' {
        $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationFutureExoticSettingValue'; value = 'x' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeTrue
        $result.IsSecretByType | Should -BeFalse
        $result.IsKnownSafeShape | Should -BeFalse
    }

    It 'FAIL CLOSED: a $null value is treated as secret (nothing to classify safe)' {
        $result = InModuleScope TenantPulse { Resolve-PulseSettingsCatalogValueClassification -SettingValue $null }

        $result.IsSecret | Should -BeTrue
        $result.HasDiscriminator | Should -BeFalse
    }

    It 'a definition-level IsSecretCapable flag forces secret even for an otherwise known-safe shape' {
        $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v -DefinitionIsSecretCapable $true }

        $result.IsSecret | Should -BeTrue
        $result.IsKnownSafeShape | Should -BeTrue
        $result.IsSecretByType | Should -BeFalse
    }

    It 'VALUESTATE VALIDATION: an unrecognized valueState value is discarded, never passed through verbatim' {
        $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'; value = 'x'; valueState = 'attacker-controlled-arbitrary-string' }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.ValueState | Should -BeNullOrEmpty
    }

    It 'accepts every one of the three known valueState values verbatim' {
        foreach ($state in @('notEncrypted', 'encryptedValueToken', 'invalidValueState')) {
            $value = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'; value = 'x'; valueState = $state }
            $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }
            $result.ValueState | Should -Be $state
        }
    }

    It 'SUFFIX-BYPASS (re-review round 2, reproduced): an @odata.type that merely ENDS in "...IntegerSettingValue" but is NOT the real fully-qualified type fails closed - no plaintext leak' {
        $plantedSecret = 'PLANTED-plaintext-suffix-bypass-zzz777'
        # Same textual SUFFIX as the real known-safe type ('...IntegerSettingValue'), but a
        # DIFFERENT, unrecognized fully-qualified type - the exact shape a suffix-regex
        # whitelist would have wrongly classified safe.
        $value = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationFutureIntegerSettingValue'
            value         = $plantedSecret
        }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeTrue -Because 'a suffix-only match must not satisfy the known-safe whitelist'
        $result.IsKnownSafeShape | Should -BeFalse
        $result.IsSecretByType | Should -BeFalse

        $serialized = $result | ConvertTo-Json -Depth 10 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'SUFFIX-BYPASS (re-review round 2, reproduced): the same trap for "...StringSettingValue" also fails closed' {
        $plantedSecret = 'PLANTED-plaintext-string-suffix-bypass-qqq888'
        $value = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationLegacyStringSettingValue'
            value         = $plantedSecret
        }
        $result = InModuleScope TenantPulse -ArgumentList $value { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $result.IsSecret | Should -BeTrue
        $result.IsKnownSafeShape | Should -BeFalse
    }

    It 'the REAL fully-qualified StringSettingValue/IntegerSettingValue types (exact match) still classify safe' {
        $stringValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'ok' }
        $integerValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'; value = 1 }

        $stringResult = InModuleScope TenantPulse -ArgumentList $stringValue { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }
        $integerResult = InModuleScope TenantPulse -ArgumentList $integerValue { param($v) Resolve-PulseSettingsCatalogValueClassification -SettingValue $v }

        $stringResult.IsKnownSafeShape | Should -BeTrue
        $stringResult.IsSecret | Should -BeFalse
        $integerResult.IsKnownSafeShape | Should -BeTrue
        $integerResult.IsSecret | Should -BeFalse
    }

    It 'END-TO-END SUFFIX-BYPASS: the walker never emits plaintext for a suffix-bypass-shaped simpleSettingValue' {
        $plantedSecret = 'PLANTED-walker-suffix-bypass-yyy999'
        $settingsPayload = [pscustomobject]@{
            id              = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'setting-suffix-bypass'
                simpleSettingValue  = [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationFutureIntegerSettingValue'
                    value         = $plantedSecret
                }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-suffix-bypass-1' -SettingsPayload $settingsPayload
        }

        $row = $result.Rows[0]
        $row.redacted | Should -BeTrue
        $row.value | Should -BeNullOrEmpty

        $serialized = $row | ConvertTo-Json -Depth 20 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }
}
