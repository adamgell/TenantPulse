BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
    $script:graphEnvelopeHelperPath = Join-Path $script:repoRoot 'tests/Helpers/New-PulseTestGraphEnvelope.ps1'
    . $script:graphEnvelopeHelperPath
    InModuleScope TenantPulse -ArgumentList $script:graphEnvelopeHelperPath {
        param($helperPath)
        . $helperPath
    }

    function script:Invoke-PolicyAssignmentFixture {
        param(
            [Parameter(Mandatory)] [string] $Dataset,
            [Parameter(Mandatory)] [AllowNull()] $RootResult,
            [Parameter()] [hashtable] $AssignmentsById = @{},
            [Parameter()] [hashtable] $ErrorsById = @{},
            [Parameter()] [switch] $InitiallyAborted
        )

        $fixture = @{
            Dataset         = $Dataset
            RootResult      = $RootResult
            AssignmentsById = $AssignmentsById
            ErrorsById      = $ErrorsById
            InitiallyAborted = [bool] $InitiallyAborted
        }
        InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            $script:PolicyAssignmentFixture = $fixture
            $script:PolicyAssignmentCalls = [System.Collections.Generic.List[object]]::new()

            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse { }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                $id = if ($null -ne $Parameters) { [string] $Parameters.id } else { '' }
                $script:PolicyAssignmentCalls.Add([pscustomobject]@{
                        Type = $Type; Operation = $Operation; Id = $id
                    }) | Out-Null
                if ($Type -notmatch 'Assignment$') {
                    return $script:PolicyAssignmentFixture.RootResult
                }
                if ($script:PolicyAssignmentFixture.ErrorsById.ContainsKey($id)) {
                    throw $script:PolicyAssignmentFixture.ErrorsById[$id]
                }
                if (-not $script:PolicyAssignmentFixture.AssignmentsById.ContainsKey($id)) {
                    throw "fixture has no assignment response for '$id'"
                }
                return $script:PolicyAssignmentFixture.AssignmentsById[$id]
            }

            $abort = [pscustomobject]@{
                AuthenticationAborted = $script:PolicyAssignmentFixture.InitiallyAborted
                Reason = if ($script:PolicyAssignmentFixture.InitiallyAborted) { 'authentication-failed: collection aborted' } else { $null }
            }
            $datasetApiVersion = if ($fixture.Dataset -eq 'deviceCompliancePolicies') { 'beta' } else { 'v1.0' }
            $result = Invoke-PulsePolicyAssignmentPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset $fixture.Dataset `
                -ManifestEntry ([pscustomobject]@{ Dataset = $fixture.Dataset; Provider = 'TenantPulse'; Plan = 'Invoke-PulsePolicyAssignmentPlan'; ApiVersion = $datasetApiVersion }) `
                -ProfileId 'fixture' -TenantPseudonym 'tp-fixture' -NetworkAbortState $abort

            [pscustomobject]@{
                Outcome = $result
                Calls   = @($script:PolicyAssignmentCalls)
                Abort   = $abort
            }
        }
    }
}

Describe 'Invoke-PulsePolicyAssignmentPlan' {
    It 'collects each policy family through its exact root and child operations with stable joined rows' -ForEach @(
        @{
            Dataset = 'deviceCompliancePolicies'
            RootType = 'DeviceCompliancePolicy'
            RootOperation = 'ListBeta'
            RootApiVersion = 'beta'
            DatasetApiVersion = 'beta'
            ChildType = 'DeviceCompliancePolicyAssignment'
        }
        @{
            Dataset = 'deviceConfigurations'
            RootType = 'DeviceConfiguration'
            RootOperation = 'List'
            RootApiVersion = 'v1.0'
            DatasetApiVersion = 'v1.0'
            ChildType = 'DeviceConfigurationAssignment'
        }
    ) {
        $root = New-PulseTestGraphEnvelope -Data @(
            [pscustomobject]@{ id = 'policy-b'; displayName = 'B' }
            [pscustomobject]@{ id = 'policy-a'; displayName = 'A' }
        )
        $includeA = [pscustomobject]@{ id = 'assignment-z'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        $includeB = [pscustomobject]@{ id = 'assignment-a'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-a' } }
        $fixture = Invoke-PolicyAssignmentFixture -Dataset $Dataset -RootResult $root -AssignmentsById @{
            'policy-a' = (New-PulseTestGraphEnvelope -Data @($includeA, $includeB))
            'policy-b' = (New-PulseTestGraphEnvelope -Data @())
        }

        $fixture.Outcome.Status | Should -Be 'Collected'
        $fixture.Outcome.Provider | Should -Be 'TenantPulse'
        $fixture.Outcome.ApiVersion | Should -BeExactly $DatasetApiVersion
        @($fixture.Outcome.Operations) | Should -Be @("$RootType.$RootOperation", "$ChildType.List")
        @($fixture.Outcome.Rows.id) | Should -Be @('policy-a', 'policy-b')
        @($fixture.Outcome.Rows[0].assignments.id) | Should -Be @('assignment-a', 'assignment-z')
        @($fixture.Outcome.Rows[1].assignments).Count | Should -Be 0
        @($fixture.Calls | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.Id)" }) | Should -Be @(
            "$RootType/$RootOperation/"
            "$ChildType/List/policy-a"
            "$ChildType/List/policy-b"
        )
        Should-Invoke Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Type -eq $RootType -and $Operation -eq $RootOperation -and $ApiVersion -eq $RootApiVersion
        }
        Should-Invoke Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Type -eq $ChildType -and $Operation -eq 'List' -and $ApiVersion -eq 'v1.0'
        }
    }

    It 'retains valid parents but gaps missing and duplicate IDs without issuing ambiguous child reads' {
        $root = New-PulseTestGraphEnvelope -Data @(
            [pscustomobject]@{ id = ''; displayName = 'Missing' }
            [pscustomobject]@{ id = 'duplicate'; displayName = 'First' }
            [pscustomobject]@{ id = 'valid'; displayName = 'Valid' }
            [pscustomobject]@{ id = 'duplicate'; displayName = 'Second' }
        )
        $fixture = Invoke-PolicyAssignmentFixture -Dataset 'deviceConfigurations' -RootResult $root -AssignmentsById @{
            valid = (New-PulseTestGraphEnvelope -Data @())
        }

        $fixture.Outcome.Status | Should -Be 'Partial'
        @($fixture.Outcome.Rows.id) | Should -Be @('valid')
        @($fixture.Outcome.Gaps.ReasonCode) | Should -Contain 'missing-parent-id'
        @($fixture.Outcome.Gaps.ReasonCode) | Should -Contain 'duplicate-parent-id'
        @($fixture.Calls | Where-Object { $_.Type -eq 'DeviceConfigurationAssignment' }).Count | Should -Be 1
        @($fixture.Calls | Where-Object Id -EQ 'duplicate').Count | Should -Be 0
    }

    It 'retains known root rows from an incomplete envelope while preserving root and child uncertainty' {
        $root = New-PulseTestGraphEnvelope -Data @(
            [pscustomobject]@{ id = 'known-a'; displayName = 'Known A' }
            [pscustomobject]@{ id = 'known-b'; displayName = 'Known B' }
        ) -Truncated $true -PageCount 2
        $fixture = Invoke-PolicyAssignmentFixture -Dataset 'deviceCompliancePolicies' -RootResult $root -AssignmentsById @{
            'known-a' = (New-PulseTestGraphEnvelope -Data @())
            'known-b' = (New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'uncertain-child' }) -Certainty Indeterminate)
        }

        $fixture.Outcome.Status | Should -Be 'Partial'
        @($fixture.Outcome.Rows.id) | Should -Be @('known-a', 'known-b')
        @($fixture.Outcome.Rows[0].assignments).Count | Should -Be 0
        $fixture.Outcome.Rows[1].PSObject.Properties['assignments'] | Should -Not -BeNullOrEmpty
        $fixture.Outcome.Rows[1].assignments | Should -BeNullOrEmpty
        @($fixture.Outcome.Gaps.Scope) | Should -Contain 'dataset:deviceCompliancePolicies/root'
        @($fixture.Outcome.Gaps.Scope) | Should -Contain 'policy:known-b/assignments'
        ($fixture.Outcome.Gaps | Where-Object Scope -EQ 'dataset:deviceCompliancePolicies/root').ApiVersion | Should -BeExactly 'beta'
        ($fixture.Outcome.Gaps | Where-Object Scope -EQ 'policy:known-b/assignments').ApiVersion | Should -BeExactly 'v1.0'
    }

    It 'fails closed for a malformed root envelope and sends no child operations' {
        $fixture = Invoke-PolicyAssignmentFixture -Dataset 'deviceCompliancePolicies' -RootResult ([pscustomobject]@{ Data = @() })

        $fixture.Outcome.Status | Should -Be 'Failed'
        $fixture.Outcome.FailureClass | Should -Be 'InvalidProviderData'
        @($fixture.Outcome.Rows).Count | Should -Be 0
        @($fixture.Calls).Count | Should -Be 1
    }

    It 'performs no send when shared authentication state is already aborted' {
        $fixture = Invoke-PolicyAssignmentFixture -Dataset 'deviceCompliancePolicies' `
            -RootResult (New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'must-not-read' })) `
            -InitiallyAborted

        $fixture.Outcome.Status | Should -Be 'Failed'
        $fixture.Outcome.FailureClass | Should -Be 'AuthenticationFailed'
        $fixture.Outcome.ReasonCode | Should -Be 'authentication-failed'
        $fixture.Outcome.ApiVersion | Should -BeExactly 'beta'
        @($fixture.Outcome.Operations) | Should -Be @(
            'DeviceCompliancePolicy.ListBeta'
            'DeviceCompliancePolicyAssignment.List'
        )
        @($fixture.Calls).Count | Should -Be 0
    }

    It 'attaches explicit null assignment evidence and a scoped gap when a child request fails' {
        $root = New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'policy-a'; displayName = 'A' })
        $fixture = Invoke-PolicyAssignmentFixture -Dataset 'deviceConfigurations' -RootResult $root -ErrorsById @{
            'policy-a' = 'service unavailable'
        }

        $fixture.Outcome.Status | Should -Be 'Partial'
        $fixture.Outcome.Rows[0].PSObject.Properties['assignments'] | Should -Not -BeNullOrEmpty
        $fixture.Outcome.Rows[0].assignments | Should -BeNullOrEmpty
        $fixture.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-a/assignments'
        $fixture.Outcome.Gaps[0].Operation | Should -Be 'DeviceConfigurationAssignment.List'
    }

    It 'stops all remaining sends after an assignment authentication failure and marks every unattempted parent unknown' {
        $root = New-PulseTestGraphEnvelope -Data @(
            [pscustomobject]@{ id = 'policy-c' }
            [pscustomobject]@{ id = 'policy-a' }
            [pscustomobject]@{ id = 'policy-b' }
        )
        $fixture = Invoke-PolicyAssignmentFixture -Dataset 'deviceCompliancePolicies' -RootResult $root -ErrorsById @{
            'policy-a' = 'AADSTS700016: application not found'
        }

        $fixture.Outcome.Status | Should -Be 'Partial'
        $fixture.Abort.AuthenticationAborted | Should -BeTrue
        @($fixture.Calls).Count | Should -Be 2
        @($fixture.Calls | Select-Object -ExpandProperty Id) | Should -Be @('', 'policy-a')
        @($fixture.Outcome.Rows.id) | Should -Be @('policy-a', 'policy-b', 'policy-c')
        @($fixture.Outcome.Rows | Where-Object { $null -ne $_.assignments }).Count | Should -Be 0
        @($fixture.Outcome.Gaps.ReasonCode) | Should -Contain 'authentication-failed'
        @($fixture.Outcome.Gaps.ReasonCode | Where-Object { $_ -eq 'not-attempted-after-authentication-failure' }).Count | Should -Be 2
    }

    It 'persists joined rows and embedded raw assignments through collection plus typed expansion without a duplicate Graph read' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $policy = [pscustomobject]@{
                id = 'policy-one'; displayName = 'Windows baseline'
                '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
                bitLockerEnabled = $true
            }
            $assignment = [pscustomobject]@{
                id = 'assignment-one'
                target = [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = 'group-one'
                }
            }
            $result = InModuleScope TenantPulse -ArgumentList $tempRoot, $policy, $assignment {
                param($tempRoot, $policy, $assignment)
                $script:IntegrationGraphCalls = [System.Collections.Generic.List[string]]::new()
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse { }
                Mock Get-GraphObject -ModuleName TenantPulse {
                    param($Type, $Operation, $Parameters)
                    $id = if ($null -ne $Parameters) { [string] $Parameters.id } else { '' }
                    $script:IntegrationGraphCalls.Add("$Type/$Operation/$id") | Out-Null
                    if ($Type -eq 'DeviceCompliancePolicy') {
                        return New-PulseTestGraphEnvelope -Data @($policy)
                    }
                    if ($Type -eq 'DeviceCompliancePolicyAssignment') {
                        return New-PulseTestGraphEnvelope -Data @($assignment)
                    }
                    throw "unexpected Graph call $Type/$Operation"
                }

                $store = New-PulseSnapshotStore -Path $tempRoot -Tenant 'tp-fixture'
                $registry = Resolve-PulseProviderPlanRegistry
                $decisions = [ordered]@{}
                foreach ($operation in @($registry.deviceCompliancePolicies.Operations)) {
                    $key = Get-PulsePermissionOperationKey -Type $operation.Type -Operation $operation.Operation
                    $decisions[$key] = New-PulsePermissionOperationDecision -Type $operation.Type -Operation $operation.Operation `
                        -ApiVersion $operation.ApiVersion -Decision Granted -ReasonCode granted
                }
                $authorization = New-PulsePermissionPreflightResult -TargetAppId ([guid]::NewGuid()) `
                    -Decision Granted -ReasonCode granted -Decisions $decisions
                $manifest = @([pscustomobject]@{
                        Dataset = 'deviceCompliancePolicies'; Provider = 'TenantPulse'
                        Plan = 'Invoke-PulsePolicyAssignmentPlan'; ApiVersion = 'beta'; Pending = $false
                    })
                $context = [pscustomobject]@{ TenantId = 'tenant'; ProfileId = 'fixture' }

                Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'fixture' `
                    -TenantPseudonym 'tp-fixture' -ProviderPlanRegistry $registry -AuthorizationDecision $authorization
                Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId 'fixture' `
                    -TenantPseudonym 'tp-fixture'

                [pscustomobject]@{
                    Joined   = Read-PulseDataset -Store $store -Name 'deviceCompliancePolicies'
                    Raw      = Read-PulseDataset -Store $store -Name 'complianceAssignments-policy-one'
                    Manifest = Get-PulseSnapshotManifest -Store $store
                    Calls    = @($script:IntegrationGraphCalls)
                }
            }

            @($result.Calls) | Should -Be @(
                'DeviceCompliancePolicy/ListBeta/'
                'DeviceCompliancePolicyAssignment/List/policy-one'
            )
            @($result.Joined).Count | Should -Be 1
            $result.Joined[0].assignments[0].id | Should -Be 'assignment-one'
            @($result.Raw).Count | Should -Be 1
            $result.Raw[0].target.groupId | Should -Be 'group-one'
            $result.Manifest.datasets.deviceCompliancePolicies.provider | Should -Be 'TenantPulse'
            $result.Manifest.datasets.deviceCompliancePolicies.apiVersion | Should -BeExactly 'beta'
            $result.Manifest.datasets.'complianceAssignments-policy-one'.status | Should -Be 'Collected'
            $result.Manifest.expansions.compliance.status | Should -Be 'Expanded'
        } finally {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'persists a partial joined dataset with explicit null child evidence and its scoped gap' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $policy = [pscustomobject]@{ id = 'policy-partial'; displayName = 'Partial' }
            $result = InModuleScope TenantPulse -ArgumentList $tempRoot, $policy {
                param($tempRoot, $policy)
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse { }
                Mock Get-GraphObject -ModuleName TenantPulse {
                    param($Type)
                    if ($Type -eq 'DeviceConfiguration') {
                        return New-PulseTestGraphEnvelope -Data @($policy)
                    }
                    if ($Type -eq 'DeviceConfigurationAssignment') {
                        return [pscustomobject]@{ Data = @() }
                    }
                    throw "unexpected Graph call $Type"
                }

                $store = New-PulseSnapshotStore -Path $tempRoot -Tenant 'tp-fixture'
                $registry = Resolve-PulseProviderPlanRegistry
                $decisions = [ordered]@{}
                foreach ($operation in @($registry.deviceConfigurations.Operations)) {
                    $key = Get-PulsePermissionOperationKey -Type $operation.Type -Operation $operation.Operation
                    $decisions[$key] = New-PulsePermissionOperationDecision -Type $operation.Type -Operation $operation.Operation `
                        -ApiVersion $operation.ApiVersion -Decision Granted -ReasonCode granted
                }
                $authorization = New-PulsePermissionPreflightResult -TargetAppId ([guid]::NewGuid()) `
                    -Decision Granted -ReasonCode granted -Decisions $decisions
                $manifest = @([pscustomobject]@{
                        Dataset = 'deviceConfigurations'; Provider = 'TenantPulse'
                        Plan = 'Invoke-PulsePolicyAssignmentPlan'; ApiVersion = 'v1.0'; Pending = $false
                    })
                Invoke-PulseCollection -Store $store -Manifest $manifest `
                    -Context ([pscustomobject]@{ TenantId = 'tenant'; ProfileId = 'fixture' }) `
                    -ProfileId 'fixture' -TenantPseudonym 'tp-fixture' `
                    -ProviderPlanRegistry $registry -AuthorizationDecision $authorization

                [pscustomobject]@{
                    Rows     = Read-PulseDataset -Store $store -Name 'deviceConfigurations'
                    Manifest = Get-PulseSnapshotManifest -Store $store
                }
            }

            $persistedManifest = Get-Content -LiteralPath (Join-Path $tempRoot 'manifest.json') -Raw | ConvertFrom-Json
            $persistedManifest.datasets.deviceConfigurations.status | Should -Be 'Partial'
            $persistedManifest.datasets.deviceConfigurations.gaps[0].scope | Should -Be 'policy:policy-partial/assignments'
            $persistedManifest.datasets.deviceConfigurations.gaps[0].failureClass | Should -Be 'InvalidProviderData'
            $result.Rows[0].PSObject.Properties['assignments'] | Should -Not -BeNullOrEmpty
            $result.Rows[0].assignments | Should -BeNullOrEmpty
        } finally {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
