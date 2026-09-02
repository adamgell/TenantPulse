BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulseDirectoryMember {
        param([string] $Id, [string] $Type)
        [pscustomobject]@{
            id           = $Id
            '@odata.type' = "#microsoft.graph.$Type"
        }
    }

    function script:New-PulseTruncatedEnvelope {
        param([object[]] $Data)
        [pscustomobject]@{
            Outcome   = 'Succeeded'
            Certainty = 'Indeterminate'
            Truncated = $true
            Data      = @($Data)
        }
    }

    function script:Invoke-GroupClosureFixture {
        param(
            [Parameter()] [AllowEmptyCollection()] [string[]] $SeedGroupIds = @(),
            [Parameter(Mandatory)] [hashtable] $MembersByGroup,
            [Parameter()] [hashtable] $GroupErrors = @{},
            [Parameter()] [hashtable] $EnvelopesByGroup = @{},
            [Parameter()] [int] $MaxDepth = 8,
            [Parameter()] [int] $MaxGroups = 256,
            [Parameter()] [int] $MaxMembersPerGroup = 2000,
            [Parameter()] [int] $MaxTotalMembers = 20000
        )

        $fixture = @{
            SeedGroupIds        = @($SeedGroupIds)
            MembersByGroup      = $MembersByGroup
            GroupErrors         = $GroupErrors
            EnvelopesByGroup    = $EnvelopesByGroup
            MaxDepth            = $MaxDepth
            MaxGroups           = $MaxGroups
            MaxMembersPerGroup  = $MaxMembersPerGroup
            MaxTotalMembers     = $MaxTotalMembers
        }

        InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            $script:ClosureFixture = $fixture
            $script:ClosureCalls = [System.Collections.Generic.List[object]]::new()

            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                param($Type, $Operation, $ApiVersion)
                $script:ClosureCalls.Add([pscustomobject]@{
                    Kind       = 'Descriptor'
                    Type       = $Type
                    Operation  = $Operation
                    ApiVersion = $ApiVersion
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters, $PassThruResult, $PageCap)
                $groupId = if ($null -ne $Parameters) { [string] $Parameters.id } else { $null }
                $script:ClosureCalls.Add([pscustomobject]@{
                    Kind      = 'Graph'
                    Type      = $Type
                    Operation = $Operation
                    Id        = $groupId
                    PageCap   = $PageCap
                })
                if ($Type -ne 'GroupMember') {
                    throw "Unexpected Graph call '$Type/$Operation'."
                }
                if ($script:ClosureFixture.GroupErrors.ContainsKey($groupId)) {
                    throw $script:ClosureFixture.GroupErrors[$groupId]
                }
                if ($script:ClosureFixture.EnvelopesByGroup.ContainsKey($groupId)) {
                    return $script:ClosureFixture.EnvelopesByGroup[$groupId]
                }
                if ($script:ClosureFixture.MembersByGroup.ContainsKey($groupId)) {
                    return @($script:ClosureFixture.MembersByGroup[$groupId])
                }
                return @()
            }

            $manifest = [pscustomobject]@{
                Dataset            = 'groupClosure'
                ApiVersion         = 'v1.0'
                Type               = 'GroupClosureWalk'
                Operation          = 'Walk'
                SeedGroupIds       = @($fixture.SeedGroupIds)
                MaxDepth           = $fixture.MaxDepth
                MaxGroups          = $fixture.MaxGroups
                MaxMembersPerGroup = $fixture.MaxMembersPerGroup
                MaxTotalMembers    = $fixture.MaxTotalMembers
            }

            $outcome = Invoke-PulseGroupClosurePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'groupClosure' `
                -ManifestEntry $manifest `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'

            [pscustomobject]@{
                Outcome = $outcome
                Calls   = @($script:ClosureCalls)
            }
        }
    }
}

Describe 'Invoke-PulseGroupClosurePlan' {
    It 'walks nested groups into a deterministic transitive member set' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-b', 'grp-a') `
            -MembersByGroup @{
                'grp-a' = @(
                    (New-PulseDirectoryMember -Id 'user-z' -Type 'user')
                    (New-PulseDirectoryMember -Id 'grp-b' -Type 'group')
                )
                'grp-b' = @(
                    (New-PulseDirectoryMember -Id 'user-a' -Type 'user')
                )
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Gaps).Count | Should -Be 0
        $groupA = @($result.Outcome.Rows | Where-Object groupId -eq 'grp-a')[0]
        $groupA.memberIds | Should -Be @('user-a', 'user-z')
        $groupA.nestedGroupIds | Should -Be @('grp-b')
        $result.Outcome.Rows.groupId | Should -Be @('grp-a', 'grp-b')
        $result.Outcome.Detail.caps.MaxDepth | Should -Be 8
    }

    It 'closes a cycle without looping and still returns both groups' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-a') `
            -MembersByGroup @{
                'grp-a' = @((New-PulseDirectoryMember -Id 'grp-b' -Type 'group'), (New-PulseDirectoryMember -Id 'user-1' -Type 'user'))
                'grp-b' = @((New-PulseDirectoryMember -Id 'grp-a' -Type 'group'), (New-PulseDirectoryMember -Id 'user-2' -Type 'user'))
            }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        $groupA = @($result.Outcome.Rows | Where-Object groupId -eq 'grp-a')[0]
        $groupA.cycleClosed | Should -BeTrue
        $groupA.memberIds | Should -Be @('user-1', 'user-2')
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 2
    }

    It 'deduplicates duplicate reachability of the same user' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-root') `
            -MembersByGroup @{
                'grp-root' = @(
                    (New-PulseDirectoryMember -Id 'grp-x' -Type 'group')
                    (New-PulseDirectoryMember -Id 'grp-y' -Type 'group')
                    (New-PulseDirectoryMember -Id 'user-dup' -Type 'user')
                )
                'grp-x' = @((New-PulseDirectoryMember -Id 'user-dup' -Type 'user'))
                'grp-y' = @((New-PulseDirectoryMember -Id 'user-dup' -Type 'user'))
            }

        $root = @($result.Outcome.Rows | Where-Object groupId -eq 'grp-root')[0]
        @($root.memberIds | Where-Object { $_ -eq 'user-dup' }).Count | Should -Be 1
        $root.memberIds | Should -Be @('user-dup')
    }

    It 'records a depth cap as Partial and never Collected' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-a') `
            -MaxDepth 1 `
            -MembersByGroup @{
                'grp-a' = @((New-PulseDirectoryMember -Id 'grp-b' -Type 'group'), (New-PulseDirectoryMember -Id 'user-1' -Type 'user'))
                'grp-b' = @((New-PulseDirectoryMember -Id 'user-2' -Type 'user'))
            }

        $result.Outcome.Status | Should -Be 'Partial'
        $result.Outcome.Detail.sampled | Should -BeTrue
        $result.Outcome.Gaps.ReasonCode | Should -Contain 'depth-cap'
        $root = @($result.Outcome.Rows | Where-Object groupId -eq 'grp-a')[0]
        $root.truncated | Should -BeTrue
        $root.complete | Should -BeFalse
        $root.caps.MaxDepth | Should -Be 1
    }

    It 'records a per-group member cap as Partial with visible caps' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-a') `
            -MaxMembersPerGroup 1 `
            -MembersByGroup @{
                'grp-a' = @(
                    (New-PulseDirectoryMember -Id 'user-1' -Type 'user')
                    (New-PulseDirectoryMember -Id 'user-2' -Type 'user')
                )
            }

        $result.Outcome.Status | Should -Be 'Partial'
        $result.Outcome.Gaps.ReasonCode | Should -Contain 'member-cap'
        $row = $result.Outcome.Rows[0]
        $row.truncated | Should -BeTrue
        $row.memberCount | Should -Be 1
    }

    It 'treats a truncated GraphKit page as sampled Partial, never Collected' {
        $envelope = New-PulseTruncatedEnvelope -Data @(
            (New-PulseDirectoryMember -Id 'user-1' -Type 'user')
        )
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-a') `
            -MembersByGroup @{} `
            -EnvelopesByGroup @{ 'grp-a' = $envelope }

        $result.Outcome.Status | Should -Be 'Partial'
        $result.Outcome.Gaps.ReasonCode | Should -Contain 'page-cap'
        $result.Outcome.Detail.sampled | Should -BeTrue
        $result.Outcome.Rows[0].memberIds | Should -Be @('user-1')
        $result.Outcome.Rows[0].complete | Should -BeFalse
    }

    It 'keeps usable rows and a scoped gap when one nested group page is unavailable' {
        $denied = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('Graph provider response contained permission denied'),
            'GraphKit.OperationFailed.403',
            [System.Management.Automation.ErrorCategory]::PermissionDenied,
            [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Failed'; Certainty = 'Known'; Telemetry = @([pscustomobject]@{ Attempt = 1; StatusCode = 403 }) }
        )
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-a') `
            -MembersByGroup @{
                'grp-a' = @((New-PulseDirectoryMember -Id 'grp-b' -Type 'group'), (New-PulseDirectoryMember -Id 'user-1' -Type 'user'))
            } `
            -GroupErrors @{ 'grp-b' = $denied }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows | Where-Object groupId -eq 'grp-a').Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'group:grp-b'
        $result.Outcome.Rows[0].complete | Should -BeFalse
    }

    It 'emits rows in ordinal groupId order regardless of seed order' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-z', 'grp-a') `
            -MembersByGroup @{
                'grp-z' = @((New-PulseDirectoryMember -Id 'user-z' -Type 'user'))
                'grp-a' = @((New-PulseDirectoryMember -Id 'user-a' -Type 'user'))
            }

        $result.Outcome.Rows.groupId | Should -Be @('grp-a', 'grp-z')
        $result.Outcome.Rows[0].memberIds | Should -Be @('user-a')
    }

    It 'returns Collected empty when seeds resolve to no groups' {
        $result = Invoke-GroupClosureFixture -SeedGroupIds @() -MembersByGroup @{}
        $result.Outcome.Status | Should -Be 'Collected'
        $result.Outcome.ReasonCode | Should -Be 'no-seed-groups'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 0
    }

    It 'asserts GroupMember.List before any member read' {
        $result = Invoke-GroupClosureFixture `
            -SeedGroupIds @('grp-a') `
            -MembersByGroup @{
                'grp-a' = @((New-PulseDirectoryMember -Id 'user-1' -Type 'user'))
            }

        $result.Calls[0].Kind | Should -Be 'Descriptor'
        $result.Calls[0].Type | Should -Be 'GroupMember'
        $result.Calls[0].Operation | Should -Be 'List'
        $result.Calls[1].Kind | Should -Be 'Graph'
    }
}
