BeforeDiscovery {
    $failureCases = @(
        @{ Name = 'deadline'; Outcome = 'DeadlineExpired'; Certainty = 'Indeterminate'; StatusCode = 408; Category = [System.Management.Automation.ErrorCategory]::OperationTimeout; FailureClass = 'DeadlineExpired'; ReasonCode = 'deadline-expired'; SettingsCategory = 'DeadlineExpired'; AssignmentCategory = 'AssignmentDeadlineExpired'; Aborts = $false }
        @{ Name = 'cancellation'; Outcome = 'Cancelled'; Certainty = 'Known'; StatusCode = 0; Category = [System.Management.Automation.ErrorCategory]::OperationStopped; FailureClass = 'Cancelled'; ReasonCode = 'cancelled'; SettingsCategory = 'Cancelled'; AssignmentCategory = 'AssignmentCancelled'; Aborts = $false }
        @{ Name = 'indeterminate certainty'; Outcome = 'Failed'; Certainty = 'Indeterminate'; StatusCode = 500; Category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable; FailureClass = 'Indeterminate'; ReasonCode = 'indeterminate'; SettingsCategory = 'Indeterminate'; AssignmentCategory = 'AssignmentIndeterminate'; Aborts = $false }
        @{ Name = 'permission denial'; Outcome = 'Failed'; Certainty = 'Known'; StatusCode = 403; Category = [System.Management.Automation.ErrorCategory]::PermissionDenied; FailureClass = 'PermissionDenied'; ReasonCode = 'permission-denied'; SettingsCategory = 'PermissionDenied'; AssignmentCategory = 'AssignmentPermissionDenied'; Aborts = $false }
        @{ Name = 'authentication failure'; Outcome = 'Failed'; Certainty = 'Known'; StatusCode = 401; Category = [System.Management.Automation.ErrorCategory]::AuthenticationError; FailureClass = 'AuthenticationFailed'; ReasonCode = 'authentication-failed'; SettingsCategory = 'AuthFailure'; AssignmentCategory = 'AssignmentAuthFailure'; Aborts = $true }
        @{ Name = 'provider failure'; Outcome = 'Failed'; Certainty = 'Known'; StatusCode = 503; Category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable; FailureClass = 'ProviderFailed'; ReasonCode = 'provider-failed'; SettingsCategory = 'FetchFailed'; AssignmentCategory = 'AssignmentFetchFailed'; Aborts = $false }
    )
}

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function New-AdapterGraphErrorRecord {
        param($Outcome, $Certainty, $StatusCode, $Category)
        $target = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome = $Outcome
            Certainty = $Certainty
            Telemetry = @([pscustomobject]@{ Attempt = 1; StatusCode = $StatusCode })
        }
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Graph failure $Outcome/$Certainty HTTP $StatusCode"),
            "GraphKit.OperationFailed.$StatusCode",
            $Category,
            $target)
    }

    function New-AdapterStore {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store = InModuleScope TenantPulse -ArgumentList $root {
            param($root)
            New-PulseSnapshotStore -Path $root
        }
        [pscustomobject]@{ Root = $root; Store = $store }
    }
}

Describe 'Graph failure adapter contract' {
    It 'persists <Name> as Failed and aborts later network collection only for authentication' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $fixture = New-AdapterStore
        try {
            $manifest = @(
                [pscustomobject]@{ Dataset = 'firstDataset'; Type = 'FirstType'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null }
                [pscustomobject]@{ Dataset = 'secondDataset'; Type = 'SecondType'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null }
            )
            $context = [pscustomobject]@{ ProfileId = 'fixture' }
            InModuleScope TenantPulse -ArgumentList $fixture.Store, $manifest, $context, $record {
                param($store, $manifest, $context, $record)
                $script:AdapterRecord = $record
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
                Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'FirstType' } { throw $script:AdapterRecord }
                Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'SecondType' } { @([pscustomobject]@{ id = 'row-2' }) }
                Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                    -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
            }

            $saved = Get-Content -LiteralPath $fixture.Store.ManifestPath -Raw | ConvertFrom-Json
            $saved.datasets.firstDataset.status | Should -Be 'Failed'
            $saved.datasets.firstDataset.failureClass | Should -Be $FailureClass
            $saved.datasets.firstDataset.reasonCode | Should -Be $ReasonCode
            if ($Aborts) {
                $saved.datasets.secondDataset.status | Should -Be 'Failed'
                $saved.datasets.secondDataset.failureClass | Should -Be 'AuthenticationFailed'
            } else {
                $saved.datasets.secondDataset.status | Should -Be 'Collected'
            }
        } finally {
            Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'never persists arbitrary provider response text from a direct Graph failure' {
        $privateMarker = 'PRIVATE' + '-PROVIDER-BODY'
        $record = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("provider response contained $privateMarker"),
            'GraphKit.OperationFailed',
            [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
            $null)
        $fixture = New-AdapterStore
        try {
            $manifest = @([pscustomobject]@{
                Dataset = 'privateFailure'; Type = 'Synthetic'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null
            })
            $context = [pscustomobject]@{ ProfileId = 'fixture' }
            InModuleScope TenantPulse -ArgumentList $fixture.Store, $manifest, $context, $record {
                param($store, $manifest, $context, $record)
                $script:AdapterRecord = $record
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
                Mock Get-GraphObject -ModuleName TenantPulse { throw $script:AdapterRecord }
                Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                    -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
            }

            $manifestText = Get-Content -LiteralPath $fixture.Store.ManifestPath -Raw
            $saved = $manifestText | ConvertFrom-Json
            $saved.datasets.privateFailure.failureClass | Should -Be 'ProviderFailed'
            $saved.datasets.privateFailure.reasonCode | Should -Be 'provider-failed'
            $saved.datasets.privateFailure.reason | Should -Be 'graph-request-failed: failureClass=ProviderFailed; reasonCode=provider-failed; statusCode=unknown'
            $manifestText | Should -Not -Match ([regex]::Escape($privateMarker))
        } finally {
            Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'maps <Name> through the RBAC composite top-level read' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { throw $script:AdapterRecord }
            Invoke-PulseIntuneRbacGroupProtectionPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'intuneRbacGroupProtection' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
    }

    It 'promotes a uniform <Name> RBAC child-gap tuple to the failed parent' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceManagementUnifiedRoleAssignment' } {
                @([pscustomobject]@{
                    id = 'assignment-1'
                    roleDefinition = [pscustomobject]@{ displayName = 'Role' }
                    principals = @(
                        [pscustomobject]@{ id = 'group-a'; '@odata.type' = '#microsoft.graph.group' }
                        [pscustomobject]@{ id = 'group-b'; '@odata.type' = '#microsoft.graph.group' }
                    )
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } { throw $script:AdapterRecord }
            Invoke-PulseIntuneRbacGroupProtectionPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'intuneRbacGroupProtection' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
        @($outcome.Gaps.FailureClass | Sort-Object -Unique) | Should -Be @($FailureClass)
        @($outcome.Gaps.ReasonCode | Sort-Object -Unique) | Should -Be @($ReasonCode)
    }

    It 'maps <Name> through the Endpoint Security composite top-level read' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { throw $script:AdapterRecord }
            Invoke-PulseEndpointSecurityPolicyPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'endpointSecurityDiskEncryptionPolicies' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
    }

    It 'promotes a uniform <Name> Endpoint Security child-gap tuple to the failed parent' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } {
                @([pscustomobject]@{
                    id = 'policy-1'; name = 'Disk policy'
                    templateReference = [pscustomobject]@{ templateFamily = 'endpointSecurityDiskEncryption'; templateId = 'template-1' }
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw $script:AdapterRecord }
            Invoke-PulseEndpointSecurityPolicyPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'endpointSecurityDiskEncryptionPolicies' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
        $outcome.Gaps[0].FailureClass | Should -Be $FailureClass
        $outcome.Gaps[0].ReasonCode | Should -Be $ReasonCode
    }

    It 'maps <Name> through the security-baseline composite top-level read' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { throw $script:AdapterRecord }
            Invoke-PulseSecurityBaselinePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'securityBaselinesAssignedAndCurrent' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
    }

    It 'promotes a uniform <Name> security-baseline assignment gap to the failed parent' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceManagementTemplate' } { @() }
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceManagementConfigurationPolicyTemplate' } {
                @([pscustomobject]@{ id = 'template-1'; lifecycleState = 'active'; templateFamily = 'baseline' })
            }
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } {
                @([pscustomobject]@{ id = 'policy-1'; name = 'Baseline'; templateReference = [pscustomobject]@{ templateId = 'template-1'; templateFamily = 'baseline' } })
            }
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceManagementIntent' } { @() }
            Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicyAssignment' } { throw $script:AdapterRecord }
            Invoke-PulseSecurityBaselinePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'securityBaselinesAssignedAndCurrent' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
        $outcome.Gaps[0].FailureClass | Should -Be $FailureClass
        $outcome.Gaps[0].ReasonCode | Should -Be $ReasonCode
    }

    It 'maps <Name> through the subscribed-SKU provider plan' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $outcome = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            $script:AdapterRecord = $record
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { throw $script:AdapterRecord }
            Invoke-PulseSubscribedSkuLicensePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -Dataset 'subscribedSkus' `
                -ManifestEntry ([pscustomobject]@{ ApiVersion = 'beta' }) -ProfileId 'fixture' -TenantPseudonym 'tp-fixture'
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $FailureClass
        $outcome.ReasonCode | Should -Be $ReasonCode
    }

    It 'maps <Name> to the compatible Settings Catalog settings category' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $fixture = New-AdapterStore
        try {
            $result = InModuleScope TenantPulse -ArgumentList $fixture.Store, $record {
                param($store, $record)
                $script:AdapterRecord = $record
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
                Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw $script:AdapterRecord }
                Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicyAssignment' } { @() }
                Invoke-PulseSettingsCatalogPolicy -Store $store `
                    -Policy ([pscustomobject]@{ id = 'policy-1'; name = 'Policy'; templateReference = [pscustomobject]@{ templateFamily = 'none'; templateId = '' } }) `
                    -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -DefinitionIndex ([ordered]@{}) `
                    -FromCapturedPayloads $false -RawDatasetName 'raw-settings-policy-1' `
                    -RawAssignmentDatasetName 'raw-assignments-policy-1'
            }

            $result.Gap | Should -Be "category:$SettingsCategory;statusCode:$StatusCode"
        } finally {
            Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'maps <Name> to the compatible Settings Catalog assignment category' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $fixture = New-AdapterStore
        try {
            $result = InModuleScope TenantPulse -ArgumentList $fixture.Store, $record {
                param($store, $record)
                $script:AdapterRecord = $record
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
                Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { @() }
                Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicyAssignment' } { throw $script:AdapterRecord }
                Invoke-PulseSettingsCatalogPolicy -Store $store `
                    -Policy ([pscustomobject]@{ id = 'policy-1'; name = 'Policy'; templateReference = [pscustomobject]@{ templateFamily = 'none'; templateId = '' } }) `
                    -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -DefinitionIndex ([ordered]@{}) `
                    -FromCapturedPayloads $false -RawDatasetName 'raw-settings-policy-1' `
                    -RawAssignmentDatasetName 'raw-assignments-policy-1'
            }

            $result.Gap | Should -Be "category:$AssignmentCategory;statusCode:$StatusCode"
        } finally {
            Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'maps <Name> to the compatible typed-policy assignment category' -ForEach $failureCases {
        $record = New-AdapterGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $StatusCode -Category $Category
        $fixture = New-AdapterStore
        try {
            $summary = InModuleScope TenantPulse -ArgumentList $fixture.Store, $record {
                param($store, $record)
                $script:AdapterRecord = $record
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
                Mock Get-GraphObject -ModuleName TenantPulse { throw $script:AdapterRecord }
                Invoke-PulseTypedPolicyExpansion -Store $store -Context ([pscustomobject]@{ ProfileId = 'fixture' }) `
                    -Policies @([pscustomobject]@{ id = 'policy-1'; displayName = 'Policy'; '@odata.type' = '#microsoft.graph.testPolicy' }) `
                    -PolicyType compliance -TypeMap ([ordered]@{ '#microsoft.graph.testPolicy' = [ordered]@{} }) `
                    -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
            }

            @($summary.Gaps).Count | Should -Be 1
            $summary.Gaps[0].reason | Should -Be "category:$AssignmentCategory"
        } finally {
            Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not let Partial provider-plan rows satisfy an IdFromDataset dependency' {
        $fixture = New-AdapterStore
        try {
            $manifest = @(
                [pscustomobject]@{ Dataset = 'partialParent'; Type = 'Composite'; Operation = 'Walk'; ApiVersion = 'beta'; Pending = $false; IdFromDataset = $null }
                [pscustomobject]@{ Dataset = 'dependentChild'; Type = 'Child'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = 'partialParent' }
            )
            InModuleScope TenantPulse -ArgumentList $fixture.Store, $manifest {
                param($store, $manifest)
                Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
                Mock Get-GraphObject -ModuleName TenantPulse { throw 'dependent Graph call must not run' }
                $plan = {
                    param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
                    New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' `
                        -Rows @([pscustomobject]@{ id = 'must-not-satisfy-dependency' }) `
                        -Gaps @(
                            New-PulseCollectionGap -Scope 'child' -FailureClass 'ProviderFailed' `
                                -ReasonCode 'provider-failed' -Detail @{} -Operation 'Get' -ApiVersion 'beta'
                        ) -ReasonCode 'partial' -Detail @{ gapCount = 1 } -Provider 'GraphKit' `
                        -ApiVersion 'beta' -Operations @('Get')
                }
                Invoke-PulseCollection -Store $store -Manifest $manifest `
                    -Context ([pscustomobject]@{ ProfileId = 'fixture' }) -ProfileId 'fixture' `
                    -TenantPseudonym 'tp-fixture' -ProviderPlanRegistry @{ partialParent = $plan }

                Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
            }

            $saved = Get-Content -LiteralPath $fixture.Store.ManifestPath -Raw | ConvertFrom-Json
            $saved.datasets.partialParent.status | Should -Be 'Partial'
            $saved.datasets.dependentChild.status | Should -Be 'Failed'
            $saved.datasets.dependentChild.failureClass | Should -Be 'DependencyUnavailable'
            $saved.datasets.dependentChild.reasonCode | Should -Be 'dependency-unavailable'
        } finally {
            Remove-Item -LiteralPath $fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Canonical Graph failure interpreter source contract' {
    It 'rejects renamed signal interpreters and has none outside Resolve-PulseGraphFailure' {
        function Get-InterpreterViolations {
            param([string] $Text, [string] $Path)

            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, $Path, [ref] $tokens, [ref] $parseErrors)
            $result = [System.Collections.Generic.List[string]]::new()
            foreach ($parseError in @($parseErrors)) {
                $result.Add("${Path}: parse error: $($parseError.Message)") | Out-Null
            }

            $signalMembers = @('TargetObject', 'CategoryInfo', 'FullyQualifiedErrorId', 'Telemetry', 'Outcome', 'Certainty')
            foreach ($memberAst in $ast.FindAll({
                        param($node)
                        $node -is [System.Management.Automation.Language.MemberExpressionAst] -and
                        $node.Member.Value -in $signalMembers
                    }, $true)) {
                $result.Add("${Path}:$($memberAst.Extent.StartLineNumber): reads Graph error signal '$($memberAst.Member.Value)'") | Out-Null
            }

            foreach ($stringAst in $ast.FindAll({
                        param($node)
                        $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                        $node.Value -match '(?i)AADSTS\d+|token acquisition|\bunauthorized\b|\bforbidden\b|accessdenied'
                    }, $true)) {
                $result.Add("${Path}:$($stringAst.Extent.StartLineNumber): contains an inline auth/permission classifier token") | Out-Null
            }

            if ($Text -match 'Get-PulseFailureClass|Test-PulseErrorRecordHasStructuredSignal|Get-PulseGraphErrorStatusCode') {
                $result.Add("${Path}: contains a legacy classifier symbol") | Out-Null
            }
            return $result.ToArray()
        }

        $renamedInterpreter = @'
function Resolve-RenamedGraphProblem {
    param($Caught)
    if ($Caught.TargetObject.Outcome -eq 'Cancelled') { return 'Cancelled' }
    if ($Caught.Exception.Message -match 'AADSTS700016') { return 'AuthenticationFailed' }
}
'@
        @(Get-InterpreterViolations -Text $renamedInterpreter -Path 'synthetic-renamed-classifier.ps1').Count | Should -BeGreaterThan 0

        $violations = [System.Collections.Generic.List[string]]::new()
        foreach ($directory in @('source/Private/Collect', 'source/Private/Expand')) {
            foreach ($file in Get-ChildItem (Join-Path $script:repoRoot $directory) -Recurse -Filter '*.ps1') {
                if ($file.Name -eq 'Resolve-PulseGraphFailure.ps1') { continue }
                foreach ($violation in @(Get-InterpreterViolations -Text (Get-Content -LiteralPath $file.FullName -Raw) -Path $file.FullName)) {
                    $violations.Add($violation) | Out-Null
                }
            }
        }

        $violations.ToArray() | Should -BeNullOrEmpty
    }
}
