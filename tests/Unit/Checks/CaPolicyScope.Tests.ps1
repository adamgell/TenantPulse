BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Conditional Access effective-scope classifiers' {
    BeforeEach {
        $script:policy = @{
            id            = 'ca-scope-fixture'
            displayName   = 'Scope fixture'
            state         = 'enabled'
            conditions    = @{
                users        = @{ includeUsers = @('All'); excludeUsers = @(); excludeGroups = @(); excludeRoles = @() }
                applications = @{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
    }

    It 'classifies an explicit All resource target with no exclusions or filter as AllResources' {
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            $view = @($policy | ConvertTo-PulseCaPolicyView)[0]
            Get-PulseCaApplicationScope -PolicyView $view
        }

        $result.State | Should -Be 'AllResources'
        $result.Complete | Should -BeTrue
    }

    It 'classifies one included application as known Narrow scope' {
        $script:policy.conditions.applications.includeApplications = @('application-1')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Narrow'
        $result.Complete | Should -BeTrue
    }

    It 'classifies an authentication-context-only resource target as known Narrow scope' {
        $script:policy.conditions.applications.includeApplications = @()
        $script:policy.conditions.applications.includeAuthenticationContextClassReferences = @('c1')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Narrow'
        $result.Complete | Should -BeTrue
        $result.CouldBeAllResources | Should -BeFalse
        $result.IncludedAuthenticationContextCount | Should -Be 1
    }

    It 'retains a valid authentication-context lower bound beside a blank sibling' {
        $script:policy.conditions.applications.includeApplications = @()
        $script:policy.conditions.applications.includeAuthenticationContextClassReferences = @('c1', '')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'blank-application-scope-value'
        $result.CouldBeAllResources | Should -BeFalse
        $result.IncludedAuthenticationContextCount | Should -Be 2
    }

    It 'classifies All with an excluded application as known Narrow scope' {
        $script:policy.conditions.applications.excludeApplications = @('application-excluded')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Narrow'
        $result.ExcludedApplicationCount | Should -Be 1
    }

    It 'preserves and classifies a valid application filter as known Narrow scope' {
        $script:policy.conditions.applications.applicationFilter = @{
            mode = 'exclude'
            rule = 'CustomSecurityAttribute.Apps_Project -eq "Legacy"'
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            $view = @($policy | ConvertTo-PulseCaPolicyView)[0]
            [pscustomobject]@{
                Scope  = Get-PulseCaApplicationScope -PolicyView $view
                Filter = $view.conditions.apps.applicationFilter
            }
        }

        $result.Scope.State | Should -Be 'Narrow'
        $result.Scope.HasApplicationFilter | Should -BeTrue
        $result.Filter.mode | Should -Be 'exclude'
        $result.Filter.rule | Should -Match 'Apps_Project'
    }

    It 'classifies a missing applications node as Incomplete rather than all-resource coverage' {
        $script:policy.conditions.Remove('applications')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Incomplete'
        $result.Complete | Should -BeFalse
    }

    It 'classifies an unrecognized application-filter mode as Incomplete' {
        $script:policy.conditions.applications.applicationFilter = @{ mode = 'futureMode'; rule = 'x' }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Incomplete'
        $result.Complete | Should -BeFalse
    }

    It 'retains a known resource-scope lower bound when a specific include has an invalid filter sibling' {
        $applicationId = [guid]::ParseExact(('6' * 32), 'N').ToString('D')
        $script:policy.conditions.applications.includeApplications = @($applicationId)
        $script:policy.conditions.applications.applicationFilter = @{ mode = 'futureMode'; rule = 'x' }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaApplicationScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'invalid-application-filter'
        $result.PSObject.Properties.Name | Should -Contain 'CouldBeAllResources'
        $result.CouldBeAllResources | Should -BeFalse
        $result.IncludedApplicationCount | Should -Be 1
    }

    It 'classifies All users with no exclusions as AllIntendedUsers' {
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @()
        }

        $result.State | Should -Be 'AllIntendedUsers'
    }

    It 'classifies All mixed with another includeUsers entry as incomplete contradictory scope' {
        $syntheticUserId = [guid]::ParseExact(('3' * 32), 'N').ToString('D')
        $script:policy.conditions.users.includeUsers = @('All', $syntheticUserId)
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            $view = @($policy | ConvertTo-PulseCaPolicyView)[0]
            Get-PulseCaAllUsersScope -PolicyView $view
        }
        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'contradictory-all-user-scope'
    }

    It 'retains a known user-scope lower bound when a specific include has a blank exclusion sibling' {
        $userId = [guid]::ParseExact(('7' * 32), 'N').ToString('D')
        $script:policy.conditions.users.includeUsers = @($userId)
        $script:policy.conditions.users.excludeUsers = @('')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'blank-user-scope-value'
        $result.PSObject.Properties.Name | Should -Contain 'CouldBeAllUsers'
        $result.CouldBeAllUsers | Should -BeFalse
    }

    It 'accepts an explicitly declared excluded user as an intended exception' {
        $accepted = [guid]::ParseExact(('4' * 32), 'N').ToString('D')
        $script:policy.conditions.users.excludeUsers = @($accepted)
        $result = InModuleScope TenantPulse -ArgumentList $script:policy, $accepted {
            param($policy, $accepted)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @($accepted)
        }

        $result.State | Should -Be 'AllIntendedUsers'
        $result.AcceptedExcludedUserCount | Should -Be 1
    }

    It 'classifies an undeclared excluded user as known Narrow scope' {
        $syntheticUserId = [guid]::ParseExact(('5' * 32), 'N').ToString('D')
        $script:policy.conditions.users.excludeUsers = @($syntheticUserId)
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @()
        }

        $result.State | Should -Be 'Narrow'
        $result.UnacceptedExcludedUserCount | Should -Be 1
    }

    It 'classifies a group or role exclusion as known Narrow scope' {
        $script:policy.conditions.users.excludeGroups = @('group-1')
        $script:policy.conditions.users.excludeRoles = @('role-1')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @()
        }

        $result.State | Should -Be 'Narrow'
        $result.ExcludedGroupCount | Should -Be 1
        $result.ExcludedRoleCount | Should -Be 1
    }

    It 'classifies a guests-or-external-users exclusion as known Narrow scope' {
        $script:policy.conditions.users.excludeGuestsOrExternalUsers = @{
            guestOrExternalUserTypes = 'b2bCollaborationGuest'
            externalTenants = @{ membershipKind = 'all' }
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @()
        }

        $result.State | Should -Be 'Narrow'
        $result.HasExcludedGuestsOrExternalUsers | Should -BeTrue
    }

    It 'classifies a guests-only include as known Narrow rather than an empty unknown scope' {
        $script:policy.conditions.users.includeUsers = @()
        $script:policy.conditions.users.includeGuestsOrExternalUsers = @{
            guestOrExternalUserTypes = 'b2bCollaborationGuest'
            externalTenants = @{ membershipKind = 'all' }
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @()
        }

        $result.State | Should -Be 'Narrow'
        $result.Complete | Should -BeTrue
    }

    It 'classifies a missing users node as Incomplete' {
        $script:policy.conditions.Remove('users')
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -AcceptedExcludedIdentifiers @()
        }

        $result.State | Should -Be 'Incomplete'
        $result.Complete | Should -BeFalse
    }

    It 'keeps an empty include-user scope from possibly covering users already known excluded' {
        $excludedGroupId = [guid]::ParseExact(('8' * 32), 'N').ToString('D')
        $script:policy.conditions.users = @{
            includeUsers  = @()
            excludeGroups = @($excludedGroupId)
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy {
            param($policy)
            Get-PulseCaAllUsersScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0]
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'empty-user-scope'
        $result.CouldBeAllUsers | Should -BeFalse
    }

    It 'keeps only well-formed matching roles possible when an included role id is malformed' {
        $requiredRoles = @(
            [guid]::ParseExact(('1' * 32), 'N').ToString('D')
            [guid]::ParseExact(('2' * 32), 'N').ToString('D')
        )
        $script:policy.conditions.users = @{
            includeRoles = @($requiredRoles[0], 'not-a-guid')
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy, $requiredRoles {
            param($policy, $requiredRoles)
            Get-PulseCaAdminRoleScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -RequiredRoleIds $requiredRoles
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'invalid-included-role-id'
        @($result.PossibleRoleIds) | Should -Be @($requiredRoles[0])
    }

    It 'subtracts known excluded roles from an otherwise empty admin-role scope lower bound' {
        $requiredRoles = @(
            [guid]::ParseExact(('1' * 32), 'N').ToString('D')
            [guid]::ParseExact(('2' * 32), 'N').ToString('D')
        )
        $script:policy.conditions.users = @{
            includeUsers = @()
            includeGroups = @()
            includeRoles = @()
            excludeRoles = @($requiredRoles[0])
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy, $requiredRoles {
            param($policy, $requiredRoles)
            Get-PulseCaAdminRoleScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -RequiredRoleIds $requiredRoles
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'empty-user-role-scope'
        @($result.PossibleRoleIds) | Should -Be @($requiredRoles[1])
    }

    It 'marks an unaccepted canonical direct-user exclusion Incomplete without losing possible roles' {
        $requiredRoles = @(
            [guid]::ParseExact(('1' * 32), 'N').ToString('D')
            [guid]::ParseExact(('2' * 32), 'N').ToString('D')
        )
        $script:policy.conditions.users = @{
            includeRoles = $requiredRoles
            excludeUsers = @('33333333-3333-3333-3333-333333333333')
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy, $requiredRoles {
            param($policy, $requiredRoles)
            Get-PulseCaAdminRoleScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -RequiredRoleIds $requiredRoles
        }

        $result.State | Should -Be 'Incomplete'
        $result.Complete | Should -BeFalse
        $result.ReasonCode | Should -Be 'unaccepted-excluded-user-id'
        $result.AcceptedExcludedUserCount | Should -Be 0
        $result.UnacceptedExcludedUserCount | Should -Be 1
        @($result.PossibleRoleIds) | Should -Be $requiredRoles
    }

    It 'marks an excluded group Incomplete because role membership cannot be bounded from policy shape alone' {
        $requiredRoles = @([guid]::ParseExact(('1' * 32), 'N').ToString('D'))
        $script:policy.conditions.users = @{
            includeRoles  = $requiredRoles
            excludeGroups = @([guid]::ParseExact(('4' * 32), 'N').ToString('D'))
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy, $requiredRoles {
            param($policy, $requiredRoles)
            Get-PulseCaAdminRoleScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -RequiredRoleIds $requiredRoles
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'excluded-group-membership-unresolved'
        $result.ExcludedGroupCount | Should -Be 1
        @($result.PossibleRoleIds) | Should -Be $requiredRoles
    }

    It 'marks a guest or external-user carve-out Incomplete' {
        $requiredRoles = @([guid]::ParseExact(('1' * 32), 'N').ToString('D'))
        $script:policy.conditions.users = @{
            includeRoles = $requiredRoles
            excludeGuestsOrExternalUsers = @{
                guestOrExternalUserTypes = 'b2bCollaborationGuest'
                externalTenants          = @{ membershipKind = 'all' }
            }
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:policy, $requiredRoles {
            param($policy, $requiredRoles)
            Get-PulseCaAdminRoleScope -PolicyView @($policy | ConvertTo-PulseCaPolicyView)[0] -RequiredRoleIds $requiredRoles
        }

        $result.State | Should -Be 'Incomplete'
        $result.ReasonCode | Should -Be 'excluded-guests-or-external-users'
        $result.HasExcludedGuestsOrExternalUsers | Should -BeTrue
        @($result.PossibleRoleIds) | Should -Be $requiredRoles
    }
}
