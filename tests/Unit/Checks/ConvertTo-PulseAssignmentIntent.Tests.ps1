BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'ConvertTo-PulseAssignmentIntent' {
    It 'classifies null assignments as Unknown and not assigned' {
        $result = InModuleScope TenantPulse { ConvertTo-PulseAssignmentIntent -Assignments $null }
        $result.State | Should -Be 'Unknown'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
    }

    It 'classifies an authoritative empty array as Empty' {
        $result = InModuleScope TenantPulse { ConvertTo-PulseAssignmentIntent -Assignments @() }
        $result.State | Should -Be 'Empty'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeTrue
    }

    It 'classifies an include group target as Include' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-include' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IsAssigned | Should -BeTrue
        $result.IncludeGroupIds | Should -Contain 'grp-include'
        $result.IncludeKinds | Should -Contain 'Group'
    }

    It 'classifies exclude-only group targets as ExcludeOnly, not assigned' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'grp-ex' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'ExcludeOnly'
        $result.IsAssigned | Should -BeFalse
        $result.ExcludeGroupIds | Should -Contain 'grp-ex'
    }

    It 'records a filter id without treating a filter as assignment by itself' {
        $assignments = @(
            @{
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = 'grp-include'
                    deviceAndAppManagementAssignmentFilterId = 'filter-1'
                    deviceAndAppManagementAssignmentFilterType = 'include'
                }
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.HasFilter | Should -BeTrue
        $result.FilterIds | Should -Contain 'filter-1'
        $result.IsAssigned | Should -BeTrue
    }

    It 'classifies all-users and all-devices typed include intents' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
            @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Include'
        $result.IncludeKinds | Should -Be @('AllDevices', 'AllUsers')
    }

    It 'classifies a missing target type as Malformed' {
        $assignments = @(
            @{ target = @{ groupId = 'grp-1' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Malformed'
        $result.IsAssigned | Should -BeFalse
        $result.Complete | Should -BeFalse
        $result.MalformedReasons | Should -Contain 'missing-target-type'
    }

    It 'classifies a group target with no groupId as Malformed' {
        $assignments = @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget' } }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'Malformed'
        $result.MalformedReasons | Should -Contain 'missing-group-id'
    }

    It 'treats settings-catalog intent=exclude as exclude-only' {
        $assignments = @(
            @{
                intent = 'exclude'
                target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'grp-ex' }
            }
        )
        $result = InModuleScope TenantPulse -ArgumentList @(, $assignments) {
            param($assignments)
            ConvertTo-PulseAssignmentIntent -Assignments $assignments
        }
        $result.State | Should -Be 'ExcludeOnly'
        $result.IsAssigned | Should -BeFalse
    }
}
