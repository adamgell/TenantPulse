BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:privRole = 'role-ga'
}

Describe 'Get-PulseRoleAssignmentClosure' {
    It 'counts unique effective principals through group membership, not the group row' {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
                @{ id = 'ra-u'; roleDefinitionId = $script:privRole; principalId = 'user-direct' }
            )
            groupMembers = @{
                'grp-admins' = @('user-a', 'user-b', 'user-direct')
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.DirectActiveCount | Should -Be 2
        $result.UniqueEffectiveActiveCount | Should -Be 3
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a', 'user-b', 'user-direct')
        $result.Incomplete | Should -BeFalse
    }

    It 'expands permanent-active PIM assignments through a group and keeps exempt principals separate' {
        $bg = '44444444-4444-4444-4444-444444444444'
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            roleAssignmentScheduleInstances = @(
                @{ id = 'i-g'; principalId = 'grp-admins'; roleDefinitionId = $script:privRole; assignmentType = 'Assigned'; endDateTime = $null }
            )
            groupMembers = @{ 'grp-admins' = @($bg, 'user-standing') }
        }
        $context = @{ BreakGlassAccounts = @($bg) }

        $result = InModuleScope TenantPulse -ArgumentList $datasets, $context {
            param($datasets, $context)
            Get-PulseRoleAssignmentClosure -Datasets $datasets -Context $context
        }

        $result.PermanentOffendingPrincipals | Should -Be @('user-standing')
        $result.PermanentExemptPrincipals | Should -Be @($bg)
        $result.EligibilityAvailable | Should -BeFalse
        $result.ScheduleAvailable | Should -BeTrue
    }

    It 'consumes eligible instances without requiring them for permanent-active evaluation' {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            roleAssignmentScheduleInstances = @()
            roleEligibilityScheduleInstances = @(
                @{ id = 'el-1'; principalId = 'user-eligible'; roleDefinitionId = $script:privRole }
            )
            directoryRoleAssignments = @()
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.EligibilityAvailable | Should -BeTrue
        $result.UniqueEffectiveEligiblePrincipals | Should -Be @('user-eligible')
        $result.PermanentOffendingPrincipals.Count | Should -Be 0
    }

    It 'marks Incomplete when group closure is truncated so callers cannot Pass' {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = @(
                [pscustomobject]@{
                    groupId   = 'grp-admins'
                    memberIds = @('user-a')
                    truncated = $true
                    complete  = $false
                    sampled   = $true
                    caps      = @{ MaxMembersPerGroup = 1 }
                }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.Incomplete | Should -BeTrue
        $result.Sampled | Should -BeTrue
        $result.UniqueEffectiveActiveCount | Should -Be 1
    }
}
