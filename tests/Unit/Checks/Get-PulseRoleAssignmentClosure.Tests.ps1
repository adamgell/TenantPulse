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
        $normalized = InModuleScope TenantPulse -ArgumentList (, $datasets.groupMembers) {
            param($groupMembers)
            ConvertTo-PulseGroupMemberMap -GroupMembers $groupMembers
        }

        $result.Incomplete | Should -BeTrue
        $result.Sampled | Should -BeTrue
        $result.UniqueEffectiveActiveCount | Should -Be 1
        $normalized.TruncatedGroupIds | Should -Be @('grp-admins')
    }

    It 'marks Incomplete when group closure contains an unusable <Shape> row' -ForEach @(
        @{ Shape = 'null'; UnusableRow = $null }
        @{
            Shape       = 'blank-group-id'
            UnusableRow = [pscustomobject]@{
                groupId   = '   '
                memberIds = @('unattributed-member')
                complete  = $true
            }
        }
        @{
            Shape       = 'non-native-complete-metadata'
            UnusableRow = [pscustomobject]@{
                groupId   = 'malformed-metadata'
                memberIds = @()
                truncated = $false
                complete  = 'false'
                sampled   = $false
            }
        }
        @{
            Shape       = 'missing-memberIds'
            UnusableRow = [pscustomobject]@{
                groupId  = 'missing-members'
                truncated = $false
                complete = $true
                sampled = $false
            }
        }
        @{
            Shape       = 'missing-truncated'
            UnusableRow = [pscustomobject]@{
                groupId   = 'missing-truncated'
                memberIds = @()
                complete  = $true
                sampled   = $false
            }
        }
        @{
            Shape       = 'missing-complete'
            UnusableRow = [pscustomobject]@{
                groupId   = 'missing-complete'
                memberIds = @()
                truncated = $false
                sampled   = $false
            }
        }
        @{
            Shape       = 'missing-sampled'
            UnusableRow = [pscustomobject]@{
                groupId   = 'missing-sampled'
                memberIds = @()
                truncated = $false
                complete  = $true
            }
        }
    ) {
        $validRow = [pscustomobject]@{
            groupId   = 'grp-admins'
            memberIds = @('user-a')
            truncated = $false
            complete  = $true
            sampled   = $false
        }
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = [object[]] @($UnusableRow, $validRow)
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }
        $normalized = InModuleScope TenantPulse -ArgumentList (, $datasets.groupMembers) {
            param($groupMembers)
            ConvertTo-PulseGroupMemberMap -GroupMembers $groupMembers
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeTrue
        $result.Sampled | Should -BeFalse
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a')
        @($normalized.TruncatedGroupIds).Count | Should -Be 0
    }

    It 'keeps an explicit empty memberIds array complete' {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-empty' }
            )
            groupMembers = @(
                [pscustomobject]@{
                    groupId   = 'grp-empty'
                    memberIds = @()
                    truncated = $false
                    complete  = $true
                    sampled   = $false
                }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeFalse
        $result.UniqueEffectiveActivePrincipals | Should -Be @()
    }

    It 'marks Incomplete when the compatibility dictionary contains a blank group id without losing valid closure' {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = [ordered]@{
                '   '        = @('unattributed-member')
                'grp-admins' = @('user-a')
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeTrue
        $result.Sampled | Should -BeFalse
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a')
    }

    It 'marks non-native Boolean metadata in the compatibility dictionary Incomplete' {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = [ordered]@{
                'grp-admins' = @('user-a')
                Complete     = 'false'
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeTrue
        $result.Sampled | Should -BeFalse
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a')
    }

    It 'treats a compatibility dictionary <Shape> group value as <Completeness>' -ForEach @(
        @{
            Shape              = 'null'
            Completeness       = 'incomplete'
            MemberValue        = $null
            ExpectedIncomplete = $true
        }
        @{
            Shape              = 'explicit-empty-array'
            Completeness       = 'complete'
            MemberValue        = [object[]] @()
            ExpectedIncomplete = $false
        }
    ) {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-empty' }
            )
            groupMembers = [ordered]@{
                'grp-empty' = $MemberValue
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -Be $ExpectedIncomplete
        $result.UniqueEffectiveActivePrincipals | Should -Be @()
    }

    It 'marks duplicate array group ids Incomplete and deterministically unions usable membership <Order>' -ForEach @(
        @{
            Order          = 'lowercase-first'
            FirstGroupId   = 'grp-admins'
            FirstMemberId  = 'user-b'
            SecondGroupId  = 'GRP-ADMINS'
            SecondMemberId = 'user-a'
        }
        @{
            Order          = 'uppercase-first'
            FirstGroupId   = 'GRP-ADMINS'
            FirstMemberId  = 'user-a'
            SecondGroupId  = 'grp-admins'
            SecondMemberId = 'user-b'
        }
    ) {
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = @(
                [pscustomobject]@{
                    groupId   = $FirstGroupId
                    memberIds = @($FirstMemberId)
                    truncated = $false
                    complete  = $true
                    sampled   = $false
                }
                [pscustomobject]@{
                    groupId   = $SecondGroupId
                    memberIds = @($SecondMemberId)
                    truncated = $false
                    complete  = $true
                    sampled   = $false
                }
            )
        }

        $normalized = InModuleScope TenantPulse -ArgumentList (, $datasets.groupMembers) {
            param($groupMembers)
            ConvertTo-PulseGroupMemberMap -GroupMembers $groupMembers
        }
        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $normalized.Complete | Should -BeFalse
        @($normalized.Map.Keys) | Should -Be @($FirstGroupId)
        @($normalized.Map[$FirstGroupId]) | Should -Be @('user-a', 'user-b')
        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeTrue
        $result.Sampled | Should -BeFalse
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a', 'user-b')
    }

    It 'accepts a generic Dictionary string-object compatibility map without relying on Contains' {
        $groupMembers = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        $groupMembers.Add('grp-admins', [object[]] @('user-a'))
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = $groupMembers
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeFalse
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a')
    }

    It 'marks duplicate compatibility dictionary group ids Incomplete and preserves their deterministic union <Order>' -ForEach @(
        @{
            Order          = 'lowercase-first'
            FirstGroupId   = 'grp-admins'
            FirstMemberId  = 'user-b'
            SecondGroupId  = 'GRP-ADMINS'
            SecondMemberId = 'user-a'
        }
        @{
            Order          = 'uppercase-first'
            FirstGroupId   = 'GRP-ADMINS'
            FirstMemberId  = 'user-a'
            SecondGroupId  = 'grp-admins'
            SecondMemberId = 'user-b'
        }
    ) {
        $groupMembers = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        $groupMembers.Add($FirstGroupId, [object[]] @($FirstMemberId))
        $groupMembers.Add($SecondGroupId, [object[]] @($SecondMemberId))
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = $groupMembers
        }

        $normalized = InModuleScope TenantPulse -ArgumentList $groupMembers {
            param($groupMembers)
            ConvertTo-PulseGroupMemberMap -GroupMembers $groupMembers
        }
        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $normalized.Complete | Should -BeFalse
        @($normalized.Map.Keys) | Should -Be @($FirstGroupId)
        @($normalized.Map[$FirstGroupId]) | Should -Be @('user-a', 'user-b')
        $result.Incomplete | Should -BeTrue
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a', 'user-b')
    }

    It 'rejects non-string <Identifier> identifiers in <Shape> closure while retaining usable membership' -ForEach @(
        @{ Shape = 'compatibility-dictionary'; Identifier = 'group' }
        @{ Shape = 'compatibility-dictionary'; Identifier = 'member' }
        @{ Shape = 'array-row'; Identifier = 'group' }
        @{ Shape = 'array-row'; Identifier = 'member' }
    ) {
        $validRow = [pscustomobject]@{
            groupId   = 'grp-admins'
            memberIds = @('user-a')
            truncated = $false
            complete  = $true
            sampled   = $false
        }
        if ($Shape -eq 'compatibility-dictionary' -and $Identifier -eq 'group') {
            $groupMembers = @{}
            $groupMembers[42] = @('numeric-group-member')
            $groupMembers[[pscustomobject]@{ kind = 'object-group' }] = @('object-group-member')
            $groupMembers['grp-admins'] = @('user-a')
        } elseif ($Shape -eq 'compatibility-dictionary') {
            $groupMembers = [ordered]@{
                'grp-admins' = @('user-a', 42, [pscustomobject]@{ kind = 'object-member' })
            }
        } elseif ($Identifier -eq 'group') {
            $groupMembers = @(
                [pscustomobject]@{ groupId = 42; memberIds = @('numeric-group-member'); truncated = $false; complete = $true; sampled = $false }
                [pscustomobject]@{ groupId = [pscustomobject]@{ kind = 'object-group' }; memberIds = @('object-group-member'); truncated = $false; complete = $true; sampled = $false }
                $validRow
            )
        } else {
            $groupMembers = @(
                [pscustomobject]@{
                    groupId   = 'grp-admins'
                    memberIds = @('user-a', 42, [pscustomobject]@{ kind = 'object-member' })
                    truncated = $false
                    complete  = $true
                    sampled   = $false
                }
            )
        }
        $datasets = @{
            directoryRoleDefinitions = @(@{ id = $script:privRole; displayName = 'Global Administrator'; isPrivileged = $true })
            directoryRoleAssignments = @(
                @{ id = 'ra-g'; roleDefinitionId = $script:privRole; principalId = 'grp-admins' }
            )
            groupMembers = $groupMembers
        }

        $result = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            Get-PulseRoleAssignmentClosure -Datasets $datasets
        }

        $result.GroupMembersPresent | Should -BeTrue
        $result.Incomplete | Should -BeTrue
        $result.UniqueEffectiveActivePrincipals | Should -Be @('user-a')
    }
}
