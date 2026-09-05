BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:disabledPolicy = @{
        id            = 'disabled-predecessor'
        displayName   = 'Disabled predecessor'
        state         = 'disabled'
        conditions    = @{}
        grantControls = @{}
    }
}

Describe 'Conditional Access policy evidence identity fallback' {
    It 'uses the original collection ordinal for a blank-id all-users MFA witness' {
        $policy = @{
            id            = ''
            displayName   = 'All users MFA'
            state         = 'enabled'
            conditions    = @{
                users          = @{ includeUsers = @('All') }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }

        $finding = InModuleScope TenantPulse -ArgumentList $script:disabledPolicy, $policy {
            param($disabledPolicy, $policy)
            Test-PulseAllUsersMfaEnforced -Datasets @{ conditionalAccessPolicies = @($disabledPolicy, $policy) }
        }

        $finding.Status | Should -Be 'Pass'
        $finding.Evidence[0].Identity | Should -Be 'conditional-access-policy:1'
    }

    It 'uses the original collection ordinal for a blank-id admin MFA witness' {
        $policy = @{
            id            = ''
            displayName   = 'All admins MFA'
            state         = 'enabled'
            conditions    = @{
                users          = @{ includeUsers = @('All') }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }

        $finding = InModuleScope TenantPulse -ArgumentList $script:disabledPolicy, $policy {
            param($disabledPolicy, $policy)
            Test-PulseAdminMfaEnforced -Datasets @{ conditionalAccessPolicies = @($disabledPolicy, $policy) }
        }

        $finding.Status | Should -Be 'Pass'
        $finding.Evidence[0].Identity | Should -Be 'conditional-access-policy:1'
    }

    It 'uses the original collection ordinal for a blank-id legacy-auth block witness' {
        $policy = @{
            id            = ''
            displayName   = 'Block legacy authentication'
            state         = 'enabled'
            conditions    = @{
                users          = @{ includeUsers = @('All') }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
            }
            grantControls = @{ builtInControls = @('block') }
        }

        $finding = InModuleScope TenantPulse -ArgumentList $script:disabledPolicy, $policy {
            param($disabledPolicy, $policy)
            Test-PulseLegacyAuthBlocked -Datasets @{ conditionalAccessPolicies = @($disabledPolicy, $policy) }
        }

        $finding.Status | Should -Be 'Pass'
        $finding.Evidence[0].Identity | Should -Be 'conditional-access-policy:1'
    }

    It 'uses the original collection ordinal for a blank-id workload-identity policy' {
        $policy = @{
            id            = ''
            displayName   = 'Workload identity policy'
            state         = 'enabled'
            conditions    = @{
                clientApplications = @{ includeServicePrincipals = @('ServicePrincipalsInMyTenant') }
            }
            grantControls = @{ builtInControls = @('block') }
        }

        $finding = InModuleScope TenantPulse -ArgumentList $script:disabledPolicy, $policy {
            param($disabledPolicy, $policy)
            Test-PulseWorkloadIdentityCaCoverage -Datasets @{ conditionalAccessPolicies = @($disabledPolicy, $policy) }
        }

        $finding.Status | Should -Be 'Pass'
        $finding.Evidence[0].Identity | Should -Be 'conditional-access-policy:1'
    }
}
