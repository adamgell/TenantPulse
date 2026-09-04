BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphObject { param() }
        function Get-GraphOperation { param() }
    }

    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must be mocked in this test.' }

    function New-ProviderPlanGraphErrorRecord {
        param(
            [Parameter(Mandatory)]
            [int] $StatusCode,

            [Parameter(Mandatory)]
            [System.Management.Automation.ErrorCategory] $Category,

            [Parameter(Mandatory)]
            [string] $PrivateMarker
        )

        $target = [pscustomobject][ordered]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Failed'
            Certainty  = 'Known'
            Telemetry  = @([pscustomobject]@{ Attempt = 1; StatusCode = $StatusCode })
        }
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Graph provider response contained $PrivateMarker"),
            "GraphKit.OperationFailed.$StatusCode",
            $Category,
            $target)
    }
}

Describe 'Invoke-PulseCollection provider plans' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($path)
            New-PulseSnapshotStore -Path $path -Tenant 'tp-test'
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-1'; ProfileId = 'profile-1' }
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:storeRoot) {
            Remove-Item -LiteralPath $script:storeRoot -Recurse -Force
        }
    }

    It 'dispatches a dataset-keyed plan and preserves successful rows plus a failed child gap' {
        $planRegistry = InModuleScope TenantPulse {
            @{
                compositeDataset = {
                    param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
                    $gap = New-PulseCollectionGap -Scope 'policy-2/settings' -FailureClass 'ProviderFailed' `
                        -ReasonCode 'child-failed' -Detail @{ child = 'policy-2' } `
                        -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta'
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Partial `
                        -Rows @([pscustomobject]@{ policyId = 'policy-1'; enabled = $true }) -Gaps @($gap) `
                        -ReasonCode 'partial' -Detail @{ childCount = 2 } -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('ConfigurationPolicy.ListBeta', 'ConfigurationPolicySetting.ListBeta')
                }
            }
        }
        $manifest = @([pscustomobject]@{ Dataset = 'compositeDataset'; Type = 'NotAReleasedDescriptor'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true })

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.compositeDataset.status | Should -Be 'Partial'
        $saved.datasets.compositeDataset.operations | Should -Be @(
            'ConfigurationPolicy.ListBeta'
            'ConfigurationPolicySetting.ListBeta'
        )
        $saved.datasets.compositeDataset.gaps[0].scope | Should -Be 'policy-2/settings'
        $saved.datasets.compositeDataset.gaps[0].operation | Should -Be 'ConfigurationPolicySetting.ListBeta'
        $rows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'compositeDataset'
        }
        $rows.Count | Should -Be 1
    }
    
    It 'rejects a dependency cycle before a provider plan can dispatch' {
        $checks = @([pscustomobject]@{ Id = 'TP.INT.TEST'; Data = [pscustomobject]@{ Datasets = @('compositeA') } })
        $map = @{
            compositeA = @{ Type = 'Synthetic'; Operation = 'Walk'; ApiVersion = 'beta'; Plan = 'compositeA'; IdFromDataset = 'compositeB' }
            compositeB = @{ Type = 'Synthetic'; Operation = 'Walk'; ApiVersion = 'beta'; Plan = 'compositeB'; IdFromDataset = 'compositeA' }
        }

        {
            InModuleScope TenantPulse -ArgumentList $checks, $map {
                param($checks, $map)
                Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
            }
        } | Should -Throw -ExpectedMessage '*cycle*'
    }

    It 'distinguishes authoritative empty plans from zero-row failed plans' {
        $planRegistry = InModuleScope TenantPulse {
            @{
                authoritativeEmpty = {
                    param($Context, $Dataset)
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected -Rows @() -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' -Operations @('ListBeta')
                }
                unresolvedEmpty = {
                    param($Context, $Dataset)
                    $gap = New-PulseCollectionGap -Scope 'policy-1/settings' -FailureClass 'ProviderFailed' `
                        -ReasonCode 'child-failed' -Detail $null -Operation 'ListBeta' -ApiVersion 'beta'
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @($gap) `
                        -FailureClass 'ProviderFailed' -ReasonCode 'provider-failed' -Detail @{} -Provider 'GraphKit' `
                        -ApiVersion 'beta' -Operations @('ListBeta', 'ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'authoritativeEmpty'; Type = 'Synthetic'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'unresolvedEmpty'; Type = 'Synthetic'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.authoritativeEmpty.status | Should -Be 'Collected'
        $saved.datasets.unresolvedEmpty.status | Should -Be 'Failed'
        $saved.datasets.unresolvedEmpty.failureClass | Should -Be 'ProviderFailed'
        $saved.datasets.unresolvedEmpty.reasonCode | Should -Be 'provider-failed'
        $saved.datasets.unresolvedEmpty.gaps[0].scope | Should -Be 'policy-1/settings'
        $emptyRows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            (Read-PulseDataset -Store $store -Name 'authoritativeEmpty').Count
        }
        $emptyRows | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'unresolvedEmpty.json') | Should -BeFalse
    }
    It 'normalizes a zero-row Partial plan to Failed while retaining structured gaps and operations' {
        $planRegistry = InModuleScope TenantPulse {
            @{
                unresolvedPartial = {
                    param($Context, $Dataset)
                    $gap = New-PulseCollectionGap -Scope 'policy-1/settings' -FailureClass 'ProviderFailed' `
                        -ReasonCode 'child-failed' -Detail @{ child = 'policy-1' } -Operation 'ListBeta' -ApiVersion 'beta'
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Partial -Rows @() -Gaps @($gap) `
                        -ReasonCode 'partial' -Detail @{ childCount = 1 } -Provider 'GraphKit' `
                        -ApiVersion 'beta' -Operations @('ListBeta')
                }
            }
        }
        $manifest = @([pscustomobject]@{
            Dataset = 'unresolvedPartial'; Type = 'Synthetic'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $true
        })

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.unresolvedPartial.status | Should -Be 'Failed'
        $saved.datasets.unresolvedPartial.status | Should -Not -Be 'Partial'
        $saved.datasets.unresolvedPartial.status | Should -Not -Be 'Collected'
        $saved.datasets.unresolvedPartial.failureClass | Should -Be 'ProviderFailed'
        $saved.datasets.unresolvedPartial.gaps[0].scope | Should -Be 'policy-1/settings'
        $saved.datasets.unresolvedPartial.gaps[0].failureClass | Should -Be 'ProviderFailed'
        $saved.datasets.unresolvedPartial.operations | Should -Be @('ListBeta')
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'unresolvedPartial.json') | Should -BeFalse
    }

    It 'aborts later network-backed plans when a provider plan returns AuthenticationFailed' {
        $planRegistry = InModuleScope TenantPulse {
            $script:secondPlanCalls = 0
            @{
                firstPlan = {
                    param($Context, $Dataset)
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @() `
                        -FailureClass 'AuthenticationFailed' -ReasonCode 'authentication-failed' `
                        -Detail @{ stage = 'first' } -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('First.ListBeta')
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:secondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'must-not-be-collected' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'First.ListBeta'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.ListBeta'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.firstPlan.status | Should -Be 'Failed'
        $saved.datasets.firstPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.firstPlan.reasonCode | Should -Be 'authentication-failed'
        $saved.datasets.secondPlan.status | Should -Be 'Failed'
        $saved.datasets.secondPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.secondPlan.reasonCode | Should -Be 'authentication-failed'
        $saved.collectionFailure | Should -Not -BeNullOrEmpty
        InModuleScope TenantPulse { $script:secondPlanCalls } | Should -Be 0
    }

    It 'preserves a message-only authentication classification and aborts later network-backed plans' {
        $planRegistry = InModuleScope TenantPulse {
            $script:messageOnlySecondPlanCalls = 0
            @{
                firstPlan = {
                    throw 'AADSTS700016: token acquisition failed'
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:messageOnlySecondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'must-not-be-collected' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'First.ListBeta'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.ListBeta'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.firstPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.firstPlan.reasonCode | Should -Be 'authentication-failed'
        $saved.datasets.secondPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.collectionFailure | Should -Not -BeNullOrEmpty
        InModuleScope TenantPulse { $script:messageOnlySecondPlanCalls } | Should -Be 0
    }

    It 'preserves a message-only permission classification without aborting later network-backed plans' {
        $planRegistry = InModuleScope TenantPulse {
            $script:messageOnlyPermissionSecondPlanCalls = 0
            @{
                firstPlan = {
                    throw '403 Forbidden'
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:messageOnlyPermissionSecondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'collected-after-permission-denial' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'First.ListBeta'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.ListBeta'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.firstPlan.failureClass | Should -Be 'PermissionDenied'
        $saved.datasets.firstPlan.reasonCode | Should -Be 'permission-denied'
        $saved.datasets.secondPlan.status | Should -Be 'Collected'
        $saved.collectionFailure | Should -BeNullOrEmpty
        InModuleScope TenantPulse { $script:messageOnlyPermissionSecondPlanCalls } | Should -Be 1
    }

    It 'does not abort later network-backed plans for a non-authentication provider-plan failure' {
        $planRegistry = InModuleScope TenantPulse {
            $script:secondPlanCalls = 0
            @{
                firstPlan = {
                    param($Context, $Dataset)
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @() `
                        -FailureClass 'DeadlineExpired' -ReasonCode 'deadline-expired' `
                        -Detail @{ stage = 'first' } -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('First.ListBeta')
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:secondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'collected-after-isolated-failure' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'First.ListBeta'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.ListBeta'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.firstPlan.failureClass | Should -Be 'DeadlineExpired'
        $saved.datasets.secondPlan.status | Should -Be 'Collected'
        $saved.collectionFailure | Should -BeNullOrEmpty
        InModuleScope TenantPulse { $script:secondPlanCalls } | Should -Be 1
    }

    It 'aborts later network-backed plans when a Partial provider outcome contains an AuthenticationFailed gap' {
        $planRegistry = InModuleScope TenantPulse {
            $script:secondPlanCalls = 0
            @{
                firstPlan = {
                    param($Context, $Dataset)
                    $gap = New-PulseCollectionGap -Scope 'child:one' -FailureClass 'AuthenticationFailed' `
                        -ReasonCode 'authentication-failed' -Detail @{} -Operation 'Child.Get' -ApiVersion 'beta'
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Partial `
                        -Rows @([pscustomobject]@{ id = 'usable-before-auth-failure' }) -Gaps @($gap) `
                        -ReasonCode 'partial' -Detail @{ gapCount = 1 } -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Parent.List', 'Child.Get')
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:secondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'must-not-be-collected' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.List')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'Parent.List'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.List'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.firstPlan.status | Should -Be 'Partial'
        $saved.datasets.firstPlan.gaps[0].failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.secondPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.collectionFailure | Should -Not -BeNullOrEmpty
        InModuleScope TenantPulse { $script:secondPlanCalls } | Should -Be 0
    }

    It 'does not abort later network-backed plans for a non-authentication Partial gap' {
        $planRegistry = InModuleScope TenantPulse {
            $script:secondPlanCalls = 0
            @{
                firstPlan = {
                    param($Context, $Dataset)
                    $gap = New-PulseCollectionGap -Scope 'child:one' -FailureClass 'DeadlineExpired' `
                        -ReasonCode 'deadline-expired' -Detail @{} -Operation 'Child.Get' -ApiVersion 'beta'
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Partial `
                        -Rows @([pscustomobject]@{ id = 'usable-before-deadline' }) -Gaps @($gap) `
                        -ReasonCode 'partial' -Detail @{ gapCount = 1 } -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Parent.List', 'Child.Get')
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:secondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'collected-after-isolated-gap' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.List')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'Parent.List'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.List'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.firstPlan.status | Should -Be 'Partial'
        $saved.datasets.firstPlan.gaps[0].failureClass | Should -Be 'DeadlineExpired'
        $saved.datasets.secondPlan.status | Should -Be 'Collected'
        $saved.collectionFailure | Should -BeNullOrEmpty
        InModuleScope TenantPulse { $script:secondPlanCalls } | Should -Be 1
    }

    It 'maps a thrown GraphKit authentication record and gives every later network-backed plan the canonical authentication-failed reason' {
        $privateMarker = 'PRIVATE' + '-PLAN-AUTH-BODY'
        $record = New-ProviderPlanGraphErrorRecord -StatusCode 401 `
            -Category ([System.Management.Automation.ErrorCategory]::AuthenticationError) `
            -PrivateMarker $privateMarker
        $planRegistry = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:providerPlanRecord = $record
            $script:secondPlanCalls = 0
            @{
                firstPlan = {
                    throw $script:providerPlanRecord
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:secondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'must-not-be-collected' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'First.ListBeta'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.ListBeta'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $saved = $manifestText | ConvertFrom-Json
        $saved.datasets.firstPlan.status | Should -Be 'Failed'
        $saved.datasets.firstPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.firstPlan.reasonCode | Should -Be 'authentication-failed'
        $saved.datasets.firstPlan.reason | Should -Be 'graph-request-failed: failureClass=AuthenticationFailed; reasonCode=authentication-failed; statusCode=401'
        $saved.datasets.secondPlan.status | Should -Be 'Failed'
        $saved.datasets.secondPlan.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.secondPlan.reasonCode | Should -Be 'authentication-failed'
        $saved.datasets.secondPlan.reason | Should -Be 'authentication-failed: collection aborted'
        $saved.collectionFailure | Should -Be 'authentication-failed'
        InModuleScope TenantPulse { $script:secondPlanCalls } | Should -Be 0
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
    }

    It 'isolates a thrown structured non-authentication provider failure and persists no provider text' {
        $privateMarker = 'PRIVATE' + '-PLAN-PROVIDER-BODY'
        $record = New-ProviderPlanGraphErrorRecord -StatusCode 503 `
            -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable) `
            -PrivateMarker $privateMarker
        $planRegistry = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:providerPlanRecord = $record
            $script:secondPlanCalls = 0
            @{
                firstPlan = {
                    throw $script:providerPlanRecord
                }
                secondPlan = {
                    param($Context, $Dataset)
                    $script:secondPlanCalls++
                    New-PulseCollectionOutcome -Dataset $Dataset -Status Collected `
                        -Rows @([pscustomobject]@{ id = 'collected-after-isolated-failure' }) -Gaps @() `
                        -ReasonCode 'collected' -Detail @{} -Provider 'GraphKit' -ApiVersion 'beta' `
                        -Operations @('Second.ListBeta')
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'firstPlan'; Type = 'Synthetic'; Operation = 'First.ListBeta'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'secondPlan'; Type = 'Synthetic'; Operation = 'Second.ListBeta'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $saved = $manifestText | ConvertFrom-Json
        $saved.datasets.firstPlan.status | Should -Be 'Failed'
        $saved.datasets.firstPlan.failureClass | Should -Be 'ProviderFailed'
        $saved.datasets.firstPlan.reasonCode | Should -Be 'provider-failed'
        $saved.datasets.firstPlan.reason | Should -Be 'graph-request-failed: failureClass=ProviderFailed; reasonCode=provider-failed; statusCode=503'
        $saved.datasets.secondPlan.status | Should -Be 'Collected'
        $saved.collectionFailure | Should -BeNullOrEmpty
        InModuleScope TenantPulse { $script:secondPlanCalls } | Should -Be 1
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
    }

    It 'never persists arbitrary exception text when a provider plan throws' {
        $privateMarker = 'PRIVATE' + '-PLAN-BODY'
        $planRegistry = InModuleScope TenantPulse -ArgumentList $privateMarker {
            param($marker)
            @{
                throwingPlan = [scriptblock]::Create("throw 'provider plan response contained $marker'")
            }
        }
        $manifest = @([pscustomobject]@{
            Dataset = 'throwingPlan'; Type = 'Synthetic'; Operation = 'List'; ApiVersion = 'beta'; Pending = $true
        })

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $saved = $manifestText | ConvertFrom-Json
        $saved.datasets.throwingPlan.reason | Should -Be 'provider-plan-failed: execution or validation error'
        $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
    }

    It 'preserves a built-in no-network plan after auth abort while failing network-backed plans without another Graph call' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @() }
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw 'Get-GraphObject failed: AADSTS700016: Application not found in the directory.'
        }

        $planRegistry = InModuleScope TenantPulse { Resolve-PulseProviderPlanRegistry }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'; Type = 'DataProcessorServiceForWindowsFeaturesOnboarding'; Operation = 'Get'; ApiVersion = 'beta'; Pending = $true }
            [pscustomobject]@{ Dataset = 'subscribedSkus'; Type = 'SubscribedSku'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.conditionalAccessPolicies.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.status | Should -Be 'Skipped'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.failureClass | Should -Be 'PlatformUnavailable'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.reasonCode | Should -Be 'platform-unavailable'
        $saved.datasets.subscribedSkus.status | Should -Be 'Failed'
        $saved.datasets.subscribedSkus.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.subscribedSkus.reasonCode | Should -Be 'authentication-failed'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'treats a caller override for the built-in no-network dataset as networked after auth abort' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @() }
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw 'Get-GraphObject failed: AADSTS700016: Application not found in the directory.'
        }

        $planRegistry = InModuleScope TenantPulse {
            Resolve-PulseProviderPlanRegistry -Overrides @{
                dataProcessorServiceForWindowsFeaturesOnboarding = {
                    throw 'caller override must not run after authentication has failed'
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'; Type = 'DataProcessorServiceForWindowsFeaturesOnboarding'; Operation = 'Get'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.status | Should -Be 'Failed'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.reasonCode | Should -Be 'authentication-failed'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'treats a registration-shaped caller override claiming no network as networked after auth abort' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @() }
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw 'Get-GraphObject failed: AADSTS700016: Application not found in the directory.'
        }

        $planRegistry = InModuleScope TenantPulse {
            Resolve-PulseProviderPlanRegistry -Overrides @{
                dataProcessorServiceForWindowsFeaturesOnboarding = @{
                    Command = {
                        throw 'caller override claiming no network must not run after authentication has failed'
                    }
                    RequiresNetwork = $false
                }
            }
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'; Type = 'DataProcessorServiceForWindowsFeaturesOnboarding'; Operation = 'Get'; ApiVersion = 'beta'; Pending = $true }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $planRegistry {
            param($store, $manifest, $context, $registry)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-test' -ProviderPlanRegistry $registry
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.status | Should -Be 'Failed'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.failureClass | Should -Be 'AuthenticationFailed'
        $saved.datasets.dataProcessorServiceForWindowsFeaturesOnboarding.reasonCode | Should -Be 'authentication-failed'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'rejects a registration-shaped caller override with a null command' {
        {
            InModuleScope TenantPulse {
                Resolve-PulseProviderPlanRegistry -Overrides @{
                    dataProcessorServiceForWindowsFeaturesOnboarding = @{
                        Command         = $null
                        RequiresNetwork = $false
                    }
                }
            }
        } | Should -Throw -ExpectedMessage "ProviderPlanRegistry override for 'dataProcessorServiceForWindowsFeaturesOnboarding' command cannot be null."
    }


    It 'records a structured dependency failure instead of silently dropping the dependent dataset' {
        Mock Get-GraphOperation -ModuleName TenantPulse {
            @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'v1.0'; RequiredPermissions = @() }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'List' } {
            throw 'dependency provider failed'
        }
        $manifest = @(
            [pscustomobject]@{ Dataset = 'organization'; Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null }
            [pscustomobject]@{ Dataset = 'organizationMdmAuthority'; Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = 'organization' }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'profile-1' -TenantPseudonym 'tp-test'
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $saved.datasets.organizationMdmAuthority.status | Should -Be 'Failed'
        $saved.datasets.organizationMdmAuthority.failureClass | Should -Be 'DependencyUnavailable'
        $saved.datasets.organizationMdmAuthority.reasonCode | Should -Be 'dependency-unavailable'
        $saved.datasets.organizationMdmAuthority.operations | Should -Be @('GetMdmAuthority')
    }
}
