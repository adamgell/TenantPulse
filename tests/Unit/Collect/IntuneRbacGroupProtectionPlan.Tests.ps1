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
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RoleAssignments,
            [Parameter(Mandatory)] [hashtable] $Groups,
            [Parameter()] [hashtable] $GroupErrors = @{}
        )

        $fixture = @{
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

                if ($Type -eq 'DeviceManagementUnifiedRoleAssignment' -and $Operation -eq 'ListBeta') {
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
            -RoleAssignments @(
                [pscustomobject]@{
                    id             = 'assignment-b'
                    roleDefinition = [pscustomobject]@{ id = 'role-b'; displayName = 'School Administrator' }
                    principals     = @(
                        [pscustomobject]@{ id = 'group-b'; displayName = 'School Admins'; '@odata.type' = '#microsoft.graph.group' }
                        [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; '@odata.type' = '#microsoft.graph.group' }
                    )
                }
                [pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; '@odata.type' = '#microsoft.graph.group' })
                }
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

    It 'normalizes present-null Graph group protection flags to native false values' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @(
                [pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' })
                }
            ) `
            -Groups @{
                'group-a' = [pscustomobject]@{
                    id                     = 'group-a'
                    displayName            = 'App Admins'
                    isManagementRestricted = $null
                    isAssignableToRole     = $null
                }
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].isManagementRestricted | Should -BeFalse
        $result.Outcome.Rows[0].isAssignableToRole | Should -BeFalse
        $result.Outcome.Rows[0].isManagementRestricted.GetType().FullName | Should -Be 'System.Boolean'
        $result.Outcome.Rows[0].isAssignableToRole.GetType().FullName | Should -Be 'System.Boolean'
        @($result.Outcome.Gaps).Count | Should -Be 0
    }

    It 'deduplicates repeated group references while preserving every role name' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @(
                [pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @(
                        [pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' }
                        [pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' }
                    )
                }
                [pscustomobject]@{
                    id             = 'assignment-b'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' })
                }
            ) `
            -Groups @{ 'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true } }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].roleDefinitionName | Should -Be 'App Manager'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 1
    }

    It 'ignores known non-group principals and reads only expanded group principals' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @(
                        [pscustomobject]@{ id = 'user-a'; displayName = 'Direct Admin'; '@odata.type' = '#microsoft.graph.user' }
                        [pscustomobject]@{ id = 'service-a'; displayName = 'Automation'; '@odata.type' = '#microsoft.graph.servicePrincipal' }
                        [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; '@odata.type' = '#microsoft.graph.group' }
                    )
                }) `
            -Groups @{
                'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true }
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].groupId | Should -Be 'group-a'
        @($result.Outcome.Gaps).Count | Should -Be 0
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group' | ForEach-Object Id) | Should -Be @('group-a')
    }

    It 'gaps a principal with no type discriminator without attempting Group.Get' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = 'unknown-a'; displayName = 'Unknown principal' })
                }) `
            -Groups @{
                'unknown-a' = [pscustomobject]@{ id = 'unknown-a'; displayName = 'Must not be read'; isManagementRestricted = $true; isAssignableToRole = $true }
            }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'assignment:assignment-a'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 0
    }

    It 'fails closed for a lone <PrincipalType> principal discriminator' -ForEach @(
        @{ PrincipalType = '#microsoft.graph.directoryObject'; PrincipalId = 'directory-object-a' }
        @{ PrincipalType = '#microsoft.graph.futurePrincipal'; PrincipalId = 'future-principal-a' }
    ) {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = $PrincipalId; '@odata.type' = $PrincipalType })
                }) `
            -Groups @{}

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'assignment:assignment-a'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'invalid-provider-data'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 0
    }

    It 'returns an authoritative empty collection only after a successful empty expanded-assignment read' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @() `
            -Groups @{}

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 0
    }

    It 'retains a missing group protection flag as a structured child gap instead of emitting an unreadable row' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' })
                }) `
            -Groups @{ 'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false } }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'group:group-a'
        $result.Outcome.Gaps[0].Operation | Should -Be 'Get'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'rejects string-valued group protection flags instead of publishing check input' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @([pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' })
                }) `
            -Groups @{
                'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = 'false'; isAssignableToRole = 'false' }
            }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'group:group-a'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'retains a failed child group lookup as a gap with the group scope and operation' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @(
                        [pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' }
                        [pscustomobject]@{ id = 'group-b'; '@odata.type' = '#microsoft.graph.group' }
                    )
                }) `
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

    It 'propagates uniform child permission failures to the failed top-level outcome' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @(
                        [pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' }
                        [pscustomobject]@{ id = 'group-b'; '@odata.type' = '#microsoft.graph.group' }
                    )
                }) `
            -Groups @{} `
            -GroupErrors @{
                'group-a' = '403 Forbidden while reading group-a'
                'group-b' = '403 Forbidden while reading group-b'
            }

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -Be 'PermissionDenied'
        $result.Outcome.ReasonCode | Should -Be 'permission-denied'
        @($result.Outcome.Gaps).Count | Should -Be 2
        @($result.Outcome.Gaps.FailureClass | Sort-Object -Unique) | Should -Be @('PermissionDenied')
    }

    It 'propagates uniform child authentication failures to the failed top-level outcome' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                    principals     = @(
                        [pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' }
                        [pscustomobject]@{ id = 'group-b'; '@odata.type' = '#microsoft.graph.group' }
                    )
                }) `
            -Groups @{} `
            -GroupErrors @{
                'group-a' = 'AADSTS700016: application not found while reading group-a'
                'group-b' = 'AADSTS700016: application not found while reading group-b'
            }

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -Be 'AuthenticationFailed'
        $result.Outcome.ReasonCode | Should -Be 'authentication-failed'
        @($result.Outcome.Gaps).Count | Should -Be 2
        @($result.Outcome.Gaps.FailureClass | Sort-Object -Unique) | Should -Be @('AuthenticationFailed')
    }

    It 'records a missing role-definition relation as an assignment gap instead of an unknown-role row' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id         = 'assignment-a'
                    displayName = 'HD Team'
                    principals = @([pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' })
                }) `
            -Groups @{ 'group-a' = [pscustomobject]@{ id = 'group-a'; displayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false } }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'assignment:assignment-a'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ListBeta'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'invalid-provider-data'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 0
    }

    It 'records a missing principals expansion as an assignment gap instead of an authoritative empty collection' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @([pscustomobject]@{
                    id             = 'assignment-a'
                    roleDefinition = [pscustomobject]@{ id = 'role-a'; displayName = 'App Manager' }
                }) `
            -Groups @{}

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'assignment:assignment-a'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ListBeta'
        $result.Outcome.Gaps[0].ApiVersion | Should -Be 'beta'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        @($result.Calls | Where-Object Kind -eq 'Graph' | Where-Object Type -eq 'Group').Count | Should -Be 0
    }

    It 'validates all released descriptors before making any Graph call' {
        $result = Invoke-RbacPlanFixture `
            -RoleAssignments @() `
            -Groups @{}

        $descriptorCalls = @($result.Calls | Where-Object Kind -eq 'Descriptor')
        $descriptorCalls.Count | Should -Be 2
        @($descriptorCalls | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.ApiVersion)" }) | Should -Be @(
            'DeviceManagementUnifiedRoleAssignment/ListBeta/beta'
            'Group/Get/v1.0'
        )
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 1
    }
}
