BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Get-PulseCaExclusionContext' {
    It 'returns empty lists when neither -Context nor -Datasets carry anything' {
        $result = InModuleScope TenantPulse {
            Get-PulseCaExclusionContext
        }

        @($result.BreakGlassAccounts).Count | Should -Be 0
        @($result.ServiceAccounts).Count | Should -Be 0
        @($result.PermanentGlobalAdmins).Count | Should -Be 0
        @($result.ExcludedIdentifiers).Count | Should -Be 0
    }

    It 'carries BreakGlassAccounts and ServiceAccounts straight through into ExcludedIdentifiers' {
        $context = @{ BreakGlassAccounts = @('bg1@contoso.com'); ServiceAccounts = @('svc1@contoso.com') }

        $result = InModuleScope TenantPulse -ArgumentList $context {
            param($context)
            Get-PulseCaExclusionContext -Context $context
        }

        $result.BreakGlassAccounts | Should -Contain 'bg1@contoso.com'
        $result.ServiceAccounts | Should -Contain 'svc1@contoso.com'
        $result.ExcludedIdentifiers | Should -Contain 'bg1@contoso.com'
        $result.ExcludedIdentifiers | Should -Contain 'svc1@contoso.com'
    }

    It 'finds a permanent Global Administrator by well-known template id when directoryRoleDefinitions is absent' {
        $datasets = @{
            directoryRoleAssignments = @(
                @{ id = 'ra1'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'ga-user-1' }
                @{ id = 'ra2'; roleDefinitionId = 'some-other-role-id'; principalId = 'not-ga-user' }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseCaExclusionContext -Datasets $datasets
        }

        $result.PermanentGlobalAdmins | Should -Be @('ga-user-1')
        $result.ExcludedIdentifiers | Should -Contain 'ga-user-1'
        $result.ExcludedIdentifiers | Should -Not -Contain 'not-ga-user'
    }

    It 'resolves Global Administrator via a directoryRoleDefinitions displayName join when the role definition id differs from the well-known template id' {
        $datasets = @{
            directoryRoleDefinitions = @(
                @{ id = 'custom-def-id'; displayName = 'Global Administrator'; templateId = '62e90394-69f5-4237-9190-012177145e10' }
            )
            directoryRoleAssignments = @(
                @{ id = 'ra1'; roleDefinitionId = 'custom-def-id'; principalId = 'ga-user-2' }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseCaExclusionContext -Datasets $datasets
        }

        $result.PermanentGlobalAdmins | Should -Be @('ga-user-2')
    }

    It 'de-duplicates a principal that is both an operator-declared break-glass account and a permanent Global Administrator' {
        $context = @{ BreakGlassAccounts = @('ga-user-1') }
        $datasets = @{
            directoryRoleAssignments = @(
                @{ id = 'ra1'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'ga-user-1' }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $context, $datasets {
            param($context, $datasets)
            Get-PulseCaExclusionContext -Context $context -Datasets $datasets
        }

        @($result.ExcludedIdentifiers | Where-Object { $_ -eq 'ga-user-1' }).Count | Should -Be 1
    }

    It 'never throws and yields zero PermanentGlobalAdmins when directoryRoleAssignments was not collected' {
        $result = InModuleScope TenantPulse {
            Get-PulseCaExclusionContext -Datasets @{}
        }

        @($result.PermanentGlobalAdmins).Count | Should -Be 0
    }

    It 'returns ExcludedIdentifiers ordinally sorted' {
        $context = @{ BreakGlassAccounts = @('zeta@contoso.com', 'alpha@contoso.com') }

        $result = InModuleScope TenantPulse -ArgumentList $context {
            param($context)
            Get-PulseCaExclusionContext -Context $context
        }

        $result.ExcludedIdentifiers[0] | Should -Be 'alpha@contoso.com'
        $result.ExcludedIdentifiers[1] | Should -Be 'zeta@contoso.com'
    }
}
