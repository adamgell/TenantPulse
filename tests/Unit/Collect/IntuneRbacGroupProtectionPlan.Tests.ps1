BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
    function script:Invoke-RbacPlanFixture {
        param(
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RoleDefinitions,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RoleAssignments,
            [Parameter(Mandatory)] [hashtable] $Groups,
            [Parameter()] [hashtable] $GroupErrors = @{}
        )

        $fixture = @{
            RoleDefinitions = $RoleDefinitions
            RoleAssignments = $RoleAssignments
            Groups          = $Groups
            GroupErrors     = $GroupErrors
        }
        InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            $script:RbacFixture = $fixture
            $script:RbacCalls = [System.Collections.Generic.List[object]]::new()
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                param($Type, $Operation, $ApiVersion)
                $script:RbacCalls.Add([pscustomobject]@{
                    Kind       = 'Descriptor'
                    Type       = $Type
                    Operation  = $Operation
                    ApiVersion = $ApiVersion
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                $script:RbacCalls.Add([pscustomobject]@{
                    Kind       = 'Graph'
                    Type       = $Type
                    Operation  = $Operation
                    Id         = if ($null -ne $Parameters) { [string] $Parameters.id } else { $null }
                })

                if ($Type -eq 'DeviceManagementRoleDefinition') {
                    return @($script:RbacFixture.RoleDefinitions)
                }
                if ($Type -eq 'DeviceManagementRoleAssignment') {
                    return @($script:RbacFixture.RoleAssignments)
                }
                if ($Type -eq 'Group') {
                    $groupId = [string] $Parameters.id
                    if ($script:RbacFixture.GroupErrors.ContainsKey($groupId)) {
                        throw $script:RbacFixture.GroupErrors[$groupId]
                    }
                    return $script:RbacFixture.Groups[$groupId]
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            $outcome = Invoke-PulseIntuneRbacGroupProtectionPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'intuneRbacGroupProtection' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Type = 'IntuneRbacGroupProtectionWalk'; Operation = 'Walk' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'

            [pscustomobject]@{
                Outcome = $outcome
                Calls   = @($script:RbacCalls)
            }
        }
    }
}

Describe 'Invoke-PulseIntuneRbacGroupProtectionPlan' {
    It 'emits compact deterministic rows for protected and unprotected groups' {
        $result = Invoke-RbacPlanFixture `
            -RoleDefinitions @(
                [pscustomobject]@{ id = 'role-b'; displayName = 'School Administrator' }
                [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
            ) `
            -RoleAssignments @(
                [pscustomobject]@{ id = 'assignment-b'; roleDefinitionId = 'role-b'; members = @('group-b', 'group-a') }
                [pscustomobject]@{ id = 'assignment-a'; roleDefinitionId = 'role-a'; members = @('group-a') }
            ) `
            -Groups @{
                'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
                'group-b' = [pscustomobject]@{ id = 'group-b'; displayName = 'School Admins'; isManagementRestricted = $true; isAssignableToRole = $false }
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        @($result.Outcome.Rows | ForEach-Object groupId) | Should -Be @('group-a', 'group-b')
        $result.Outcome.Rows[0].roleDefinitionName | Should -Be 'App Manager, School Administrator'
        $result.Outcome.Rows[0].groupDisplayName | Should -Be 'App Admins'
        $result.Outcome.Rows[1].isManagementRestricted | Should -BeTrue
        @($result.Outcome.Gaps).Count | Should -Be 0
    }

    It 'deduplicates repeated group references while preserving every role name' {
        $result = Invoke-RbacPlanFixture `
            -RoleDefinitions @([pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }) `
            -RoleAssignments @(
                [pscustomobject]@{ id = 'assignment-a'; roleDefinitionId = 'role-a'; members = @('group-a', 'group-a') }
                [pscustomobject]@{ id = 'assignment-b'; roleDefinitionId = 'role-a'; members = @('group-a') }
            ) `
            -Groups @{ 'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true } }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].roleDefinitionName | Should -Be 'App Manager'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 1
    }

    It 'returns an authoritative empty collection only after a successful assignment read with no group-backed assignments' {
        $result = Invoke-RbacPlanFixture `
            -RoleDefinitions @([pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }) `
            -RoleAssignments @([pscustomobject]@{ id = 'assignment-a'; roleDefinitionId = 'role-a'; members = @() }) `
            -Groups @{}

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 0
    }

    It 'retains a missing group protection flag as a structured child gap instead of emitting an unreadable row' {
        $result = Invoke-RbacPlanFixture `
            -RoleDefinitions @([pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }) `
            -RoleAssignments @([pscustomobject]@{ id = 'assignment-a'; roleDefinitionId = 'role-a'; members = @('group-a') }) `
            -Groups @{ 'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false } }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'group:group-a'
        $result.Outcome.Gaps[0].Operation | Should -Be 'Get'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'retains a failed child group lookup as a gap with the group scope and operation' {
        $result = Invoke-RbacPlanFixture `
            -RoleDefinitions @([pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }) `
            -RoleAssignments @([pscustomobject]@{ id = 'assignment-a'; roleDefinitionId = 'role-a'; members = @('group-a', 'group-b') }) `
            -Groups @{
                'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
                'group-b' = [pscustomobject]@{ id = 'group-b'; displayName = 'School Admins'; isManagementRestricted = $true; isAssignableToRole = $false }
            } `
            -GroupErrors @{ 'group-b' = '403 Forbidden while reading group-b' }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].groupId | Should -Be 'group-a'
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'group:group-b'
        $result.Outcome.Gaps[0].Operation | Should -Be 'Get'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'PermissionDenied'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'permission-denied'
    }

    It 'validates all released descriptors before making any Graph call' {
        $result = Invoke-RbacPlanFixture `
            -RoleDefinitions @() `
            -RoleAssignments @() `
            -Groups @{}

        $descriptorCalls = @($result.Calls | Where-Object Kind -eq 'Descriptor')
        $descriptorCalls.Count | Should -Be 3
        @($descriptorCalls | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.ApiVersion)" }) | Should -Be @(
            'DeviceManagementRoleDefinition/List/v1.0'
            'DeviceManagementRoleAssignment/List/v1.0'
            'Group/Get/v1.0'
        )
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 2
    }
}
