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
        @($result.ActiveGlobalAdmins).Count | Should -Be 0
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

        $result.ActiveGlobalAdmins | Should -Be @('ga-user-1')
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

        $result.ActiveGlobalAdmins | Should -Be @('ga-user-2')
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

    It 'never throws and yields zero ActiveGlobalAdmins when directoryRoleAssignments was not collected' {
        $result = InModuleScope TenantPulse {
            Get-PulseCaExclusionContext -Datasets @{}
        }

        @($result.ActiveGlobalAdmins).Count | Should -Be 0
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

    # ---- Task 4.1: GUID contract on declared accounts (classify, don't filter) ----

    It 'MalformedDeclaredAccounts is empty and ExcludedIdentifiers still contains a GUID-shaped declared account' {
        $context = @{ BreakGlassAccounts = @('11111111-1111-1111-1111-111111111111') }

        $result = InModuleScope TenantPulse -ArgumentList $context {
            param($context)
            Get-PulseCaExclusionContext -Context $context
        }

        @($result.MalformedDeclaredAccounts).Count | Should -Be 0
        $result.ExcludedIdentifiers | Should -Contain '11111111-1111-1111-1111-111111111111'
    }

    It 'flags a non-GUID BreakGlassAccounts entry as malformed but still carries it through ExcludedIdentifiers unchanged (Task 1.9 contract preserved)' {
        $context = @{ BreakGlassAccounts = @('breakglass@contoso.onmicrosoft.com') }

        $result = InModuleScope TenantPulse -ArgumentList $context {
            param($context)
            Get-PulseCaExclusionContext -Context $context
        }

        $result.MalformedDeclaredAccounts | Should -Contain 'breakglass@contoso.onmicrosoft.com'
        $result.ExcludedIdentifiers | Should -Contain 'breakglass@contoso.onmicrosoft.com'
    }

    It 'flags a non-GUID ServiceAccounts entry as malformed too (not only BreakGlassAccounts)' {
        $context = @{ ServiceAccounts = @('svc-not-a-guid') }

        $result = InModuleScope TenantPulse -ArgumentList $context {
            param($context)
            Get-PulseCaExclusionContext -Context $context
        }

        $result.MalformedDeclaredAccounts | Should -Contain 'svc-not-a-guid'
    }

    It 'de-duplicates the same malformed identifier declared as both BreakGlassAccounts and ServiceAccounts' {
        $context = @{ BreakGlassAccounts = @('dup-not-a-guid'); ServiceAccounts = @('dup-not-a-guid') }

        $result = InModuleScope TenantPulse -ArgumentList $context {
            param($context)
            Get-PulseCaExclusionContext -Context $context
        }

        @($result.MalformedDeclaredAccounts | Where-Object { $_ -eq 'dup-not-a-guid' }).Count | Should -Be 1
    }

    # ---- Task 4.1: resolved group exclusions (honest limitation, not silent) ----

    It 'GroupExclusionsResolved is $false and GroupExclusionNote is non-null when no groupMembers dataset was collected' {
        $result = InModuleScope TenantPulse {
            Get-PulseCaExclusionContext
        }

        $result.GroupExclusionsResolved | Should -BeFalse
        $result.GroupExclusionNote | Should -Not -BeNullOrEmpty
        @($result.ResolvedGroupExclusions).Count | Should -Be 0
    }

    It 'resolves group exclusions into ExcludedIdentifiers when a groupMembers dataset is present' {
        $datasets = @{
            conditionalAccessPolicies = @(
                [pscustomobject]@{
                    state      = 'enabled'
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ excludeGroups = @('grp-1') } }
                }
            )
            groupMembers              = @{ 'grp-1' = @('member-guid-1', 'member-guid-2') }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseCaExclusionContext -Datasets $datasets
        }

        $result.GroupExclusionsResolved | Should -BeTrue
        $result.GroupExclusionNote | Should -BeNullOrEmpty
        $result.ResolvedGroupExclusions | Should -Contain 'member-guid-1'
        $result.ResolvedGroupExclusions | Should -Contain 'member-guid-2'
        $result.ExcludedIdentifiers | Should -Contain 'member-guid-1'
    }

    It 'ignores excludeGroups on a disabled policy when resolving group exclusions' {
        $datasets = @{
            conditionalAccessPolicies = @(
                [pscustomobject]@{
                    state      = 'disabled'
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ excludeGroups = @('grp-1') } }
                }
            )
            groupMembers              = @{ 'grp-1' = @('member-guid-1') }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseCaExclusionContext -Datasets $datasets
        }

        @($result.ReportOnlyExclusions).Count | Should -Be 0

        @($result.ResolvedGroupExclusions).Count | Should -Be 0
    }

    # ---- Task 4.1 post-review, Finding 2 (High): report-only group exclusions are kept
    # in their own field, never merged into the enforced-only exclusion set ----

    It 'resolves a report-only policy''s excludeGroups into ReportOnlyExclusions, NOT into ResolvedGroupExclusions or ExcludedIdentifiers' {
        $datasets = @{
            conditionalAccessPolicies = @(
                [pscustomobject]@{
                    state      = 'enabledForReportingButNotEnforced'
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ excludeGroups = @('grp-report-only') } }
                }
            )
            groupMembers              = @{ 'grp-report-only' = @('member-report-1') }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseCaExclusionContext -Datasets $datasets
        }

        $result.ReportOnlyExclusions | Should -Contain 'member-report-1'
        $result.ResolvedGroupExclusions | Should -Not -Contain 'member-report-1'
        $result.ExcludedIdentifiers | Should -Not -Contain 'member-report-1'
    }

    It 'resolves BOTH ResolvedGroupExclusions (enabled) and ReportOnlyExclusions (report-only) independently, with no cross-contamination' {
        $datasets = @{
            conditionalAccessPolicies = @(
                [pscustomobject]@{
                    state      = 'enabled'
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ excludeGroups = @('grp-enforced') } }
                }
                [pscustomobject]@{
                    state      = 'enabledForReportingButNotEnforced'
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ excludeGroups = @('grp-report-only') } }
                }
            )
            groupMembers              = @{
                'grp-enforced'    = @('member-enforced-1')
                'grp-report-only' = @('member-report-1')
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseCaExclusionContext -Datasets $datasets
        }

        $result.ResolvedGroupExclusions | Should -Contain 'member-enforced-1'
        $result.ResolvedGroupExclusions | Should -Not -Contain 'member-report-1'
        $result.ReportOnlyExclusions | Should -Contain 'member-report-1'
        $result.ReportOnlyExclusions | Should -Not -Contain 'member-enforced-1'
        $result.ExcludedIdentifiers | Should -Contain 'member-enforced-1'
        $result.ExcludedIdentifiers | Should -Not -Contain 'member-report-1'
    }

    It 'ReportOnlyExclusions is always an empty array (never $null) when GroupExclusionsResolved is $false' {
        $result = InModuleScope TenantPulse {
            Get-PulseCaExclusionContext
        }

        @($result.ReportOnlyExclusions).Count | Should -Be 0
        $result.ReportOnlyExclusions.GetType().IsArray | Should -BeTrue
    }

    # ---- Task 3.5: contract direction TP.ENT.0004/0005 rely on - only
    # conditionalAccessPolicies is ever present in -Datasets for those two checks
    # (directoryRoleAssignments is not in either check's own Data.Datasets), so this shape
    # must resolve BreakGlassAccounts/ServiceAccounts into ExcludedIdentifiers correctly with
    # ActiveGlobalAdmins gracefully empty - the exact call shape Test-PulseLegacyAuthBlocked
    # and Test-PulseAdminMfaEnforced make. ----

    It 'resolves declared exclusions into ExcludedIdentifiers with ActiveGlobalAdmins empty when -Datasets only carries conditionalAccessPolicies (TP.ENT.0004/0005 shape)' {
        $context = @{ BreakGlassAccounts = @('11111111-1111-1111-1111-111111111111'); ServiceAccounts = @('22222222-2222-2222-2222-222222222222') }
        $datasets = @{ conditionalAccessPolicies = @() }

        $result = InModuleScope TenantPulse -ArgumentList $context, $datasets {
            param($context, $datasets)
            Get-PulseCaExclusionContext -Context $context -Datasets $datasets
        }

        @($result.ActiveGlobalAdmins).Count | Should -Be 0
        $result.ExcludedIdentifiers | Should -Contain '11111111-1111-1111-1111-111111111111'
        $result.ExcludedIdentifiers | Should -Contain '22222222-2222-2222-2222-222222222222'
    }

    It 'ExcludedIdentifiers is queryable by -contains against a policy excludeUsers entry - the exact match TP.ENT.0004/0005 evidence performs' {
        $guid = '33333333-3333-3333-3333-333333333333'
        $result = InModuleScope TenantPulse -ArgumentList $guid {
            param($guid)
            Get-PulseCaExclusionContext -Context @{ BreakGlassAccounts = @($guid) } -Datasets @{ conditionalAccessPolicies = @() }
        }

        $policyExcludeUsers = @($guid, 'some-other-guid')
        ($policyExcludeUsers -contains $result.ExcludedIdentifiers[0]) | Should -BeTrue
    }
}
