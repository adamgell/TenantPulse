BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

    $script:rawFido2Hashtable = @{
        '@odata.type'            = '#microsoft.graph.fido2AuthenticationMethodConfiguration'
        id                       = 'Fido2'
        state                    = 'enabled'
        isAttestationEnforced    = $true
        isSelfServiceRegistrationAllowed = $true
        keyRestrictions          = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() }
        includeTargets           = @(
            @{ id = 'all_users'; targetType = 'group'; isRegistrationRequired = $false }
        )
        excludeTargets           = @()
    }

    $script:rawSmsHashtable = @{
        '@odata.type'  = '#microsoft.graph.smsAuthenticationMethodConfiguration'
        id             = 'Sms'
        state          = 'enabled'
        includeTargets = @(
            @{ id = 'grp-1'; targetType = 'group'; isUsableForSignIn = $true }
            @{ id = 'grp-2'; targetType = 'group'; isUsableForSignIn = $false }
        )
    }
}

Describe 'ConvertTo-PulseAuthMethodView' {
    It 'normalizes methodId and state (hashtable-shaped input)' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawFido2Hashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.methodId | Should -Be 'Fido2'
        $result.state | Should -Be 'enabled'
    }

    It 'normalizes methodId and state (PSObject-shaped input)' {
        $pso = ConvertTo-PSObjectShape -Value $script:rawFido2Hashtable

        $result = InModuleScope TenantPulse -ArgumentList $pso {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.methodId | Should -Be 'Fido2'
        $result.state | Should -Be 'enabled'
    }

    It 'throws when state is absent entirely (field-absence lens)' {
        $raw = @{ id = 'Fido2' }

        {
            InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }
        } | Should -Throw
    }

    It 'throws on a state value that is neither enabled nor disabled' {
        $raw = $script:rawFido2Hashtable.Clone()
        $raw.state = 'somethingElse'

        {
            InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }
        } | Should -Throw
    }

    It 'folds every non-well-known top-level property into -settings, keyed by its raw name' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawFido2Hashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.settings['isAttestationEnforced'] | Should -BeTrue
        $result.settings['isSelfServiceRegistrationAllowed'] | Should -BeTrue
        $result.settings.Contains('id') | Should -BeFalse
        $result.settings.Contains('state') | Should -BeFalse
        $result.settings.Contains('includeTargets') | Should -BeFalse
        $result.settings.Contains('@odata.type') | Should -BeFalse
    }

    It 'normalizes includeTargets entries, preserving per-target isUsableForSignIn (TP.ENT.0009 shape)' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawSmsHashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        @($result.includeTargets).Count | Should -Be 2
        ($result.includeTargets | Where-Object { $_.id -eq 'grp-1' }).isUsableForSignIn | Should -BeTrue
        ($result.includeTargets | Where-Object { $_.id -eq 'grp-2' }).isUsableForSignIn | Should -BeFalse
    }

    It 'excludeTargets defaults to an empty array when absent, without throwing' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawSmsHashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        @($result.excludeTargets).Count | Should -Be 0
    }

    It 'accepts an array via pipeline and returns one view per method configuration' {
        $results = InModuleScope TenantPulse -ArgumentList (, @($script:rawFido2Hashtable, $script:rawSmsHashtable)) {
            param($raws)
            $raws | ConvertTo-PulseAuthMethodView
        }

        @($results).Count | Should -Be 2
        ($results | Where-Object { $_.methodId -eq 'Sms' }) | Should -Not -BeNullOrEmpty
    }
}
