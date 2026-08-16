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
}
