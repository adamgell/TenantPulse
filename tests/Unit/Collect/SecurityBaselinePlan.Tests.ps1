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

    function script:Invoke-SecurityBaselinePlanFixture {
        param(
            [Parameter()] [AllowEmptyCollection()] [object[]] $Templates = @(),
            [Parameter()] [AllowEmptyCollection()] [object[]] $CurrentTemplates = @(),
            [Parameter()] [AllowEmptyCollection()] [object[]] $Policies = @(),
            [Parameter()] [AllowEmptyCollection()] [object[]] $Intents = @(),
            [Parameter()] [hashtable] $Assignments = @{},
            [Parameter()] [AllowNull()] $TemplateError,
            [Parameter()] [AllowNull()] $CurrentTemplateError,
            [Parameter()] [AllowNull()] $PolicyError,
            [Parameter()] [AllowNull()] $IntentError,
            [Parameter()] [hashtable] $AssignmentErrors = @{}
        )

        $fixture = @{
            Templates       = $Templates
            CurrentTemplates = $CurrentTemplates
            Policies        = $Policies
            Intents         = $Intents
            Assignments     = $Assignments
            TemplateError   = $TemplateError
            CurrentTemplateError = $CurrentTemplateError
            PolicyError     = $PolicyError
            IntentError     = $IntentError
            AssignmentErrors = $AssignmentErrors
        }

        InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            $script:SecurityBaselineFixture = $fixture
            $script:SecurityBaselineCalls = [System.Collections.Generic.List[object]]::new()

            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                param($Type, $Operation, $ApiVersion)
                $script:SecurityBaselineCalls.Add([pscustomobject]@{
                    Kind       = 'Descriptor'
                    Type       = $Type
                    Operation  = $Operation
                    ApiVersion = $ApiVersion
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                $script:SecurityBaselineCalls.Add([pscustomobject]@{
                    Kind      = 'Graph'
                    Type      = $Type
                    Operation = $Operation
                    Id        = if ($null -ne $Parameters) { [string] $Parameters.id } else { $null }
                })

                if ($Type -eq 'DeviceManagementTemplate') {
                    if ($null -ne $script:SecurityBaselineFixture.TemplateError) {
                        throw $script:SecurityBaselineFixture.TemplateError
                    }
                    return New-PulseTestGraphEnvelope -Data @($script:SecurityBaselineFixture.Templates)
                }
                if ($Type -eq 'DeviceManagementConfigurationPolicyTemplate') {
                    if ($null -ne $script:SecurityBaselineFixture.CurrentTemplateError) {
                        throw $script:SecurityBaselineFixture.CurrentTemplateError
                    }
                    return New-PulseTestGraphEnvelope -Data @($script:SecurityBaselineFixture.CurrentTemplates)
                }
                if ($Type -eq 'DeviceManagementIntent') {
                    if ($null -ne $script:SecurityBaselineFixture.IntentError) {
                        throw $script:SecurityBaselineFixture.IntentError
                    }
                    return New-PulseTestGraphEnvelope -Data @($script:SecurityBaselineFixture.Intents)
                }
                if ($Type -eq 'ConfigurationPolicy') {
                    if ($null -ne $script:SecurityBaselineFixture.PolicyError) {
                        throw $script:SecurityBaselineFixture.PolicyError
                    }
                    return New-PulseTestGraphEnvelope -Data @($script:SecurityBaselineFixture.Policies)
                }
                if ($Type -eq 'ConfigurationPolicyAssignment') {
                    $id = [string] $Parameters.id
                    if ($script:SecurityBaselineFixture.AssignmentErrors.ContainsKey($id)) {
                        throw $script:SecurityBaselineFixture.AssignmentErrors[$id]
                    }
                    return New-PulseTestGraphEnvelope -Data @($script:SecurityBaselineFixture.Assignments[$id])
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            $outcome = Invoke-PulseSecurityBaselinePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'securityBaselinesAssignedAndCurrent' `
                -ManifestEntry ([pscustomobject]@{
                    Dataset    = 'securityBaselinesAssignedAndCurrent'
                    Type       = 'SecurityBaselineAssignedAndCurrentWalk'
                    Operation  = 'Walk'
                    ApiVersion = 'beta'
                }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'

            [pscustomobject]@{
                Outcome = $outcome
                Calls   = @($script:SecurityBaselineCalls)
            }
        }
    }

    function script:Invoke-SecurityBaselineCheckFixture {
        param([AllowEmptyCollection()] [object[]] $Rows)
        $rowsArgument = if ($null -eq $Rows) { [object[]]@() } else { [object[]]@($Rows) }
        InModuleScope TenantPulse -ArgumentList (,$rowsArgument) {
            param($Rows)
            $datasetRows = if ($null -eq $Rows) { [object[]]@() } else { [object[]]@($Rows) }
            Test-PulseSecurityBaselinesAssignedAndCurrent `
                -Datasets @{ securityBaselinesAssignedAndCurrent = $datasetRows } `
                -DatasetOutcomes @{ securityBaselinesAssignedAndCurrent = @{ Status = 'Collected' } }
        }
    }
}

Describe 'Invoke-PulseSecurityBaselinePlan' {
    It 'collects current configuration-policy baselines, assignments, and template disposition' {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; baseId = 'base-windows'; version = 2; displayName = 'Windows baseline'; displayVersion = '24H2'; lifecycleState = 'active'; templateFamily = 'baseline' }
            [pscustomobject]@{ id = 'template-old'; baseId = 'base-edge'; version = 1; displayName = 'Edge baseline'; displayVersion = 'v1'; lifecycleState = 'superseded'; templateFamily = 'baseline' }
            [pscustomobject]@{ id = 'template-other'; baseId = 'base-disk'; version = 1; displayName = 'Disk settings'; displayVersion = 'v1'; lifecycleState = 'active'; templateFamily = 'endpointSecurityDiskEncryption' }
        ) -Policies @(
            [pscustomobject]@{ id = 'policy-current'; name = 'Windows profile'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline'; templateDisplayName = 'Windows baseline'; templateDisplayVersion = '24H2' } }
            [pscustomobject]@{ id = 'policy-old'; name = 'Edge profile'; isAssigned = $false; templateReference = [pscustomobject]@{ templateId = 'template-old'; templateFamily = 'baseline'; templateDisplayName = 'Edge baseline'; templateDisplayVersion = 'v1' } }
            [pscustomobject]@{ id = 'policy-other'; name = 'Disk profile'; isAssigned = $false; templateReference = [pscustomobject]@{ templateId = 'template-other'; templateFamily = 'endpointSecurityDiskEncryption'; templateDisplayName = 'Disk settings'; templateDisplayVersion = 'v1' } }
        ) -Assignments @{
            'policy-current' = @([pscustomobject]@{ id = 'assignment-1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; deviceAndAppManagementAssignmentFilterType = 'none' }; source = 'direct'; sourceId = $null })
            'policy-old' = @()
        }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        @($result.Outcome.Gaps).Count | Should -Be 0
        $result.Outcome.Rows[0].id | Should -Be 'policy-current'
        $result.Outcome.Rows[0].templateFamily | Should -Be 'baseline'
        $result.Outcome.Rows[0].hasAssignment | Should -BeTrue
        $result.Outcome.Rows[0].isDeprecated | Should -BeFalse
        $result.Outcome.Rows[1].id | Should -Be 'policy-old'
        $result.Outcome.Rows[1].templateFamily | Should -Be 'baseline'
        $result.Outcome.Rows[1].hasAssignment | Should -BeFalse
        $result.Outcome.Rows[1].isDeprecated | Should -BeTrue
        @($result.Calls | Where-Object Kind -eq 'Descriptor' | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.ApiVersion)" }) | Should -Be @(
            'DeviceManagementTemplate/ListBeta/beta'
            'DeviceManagementConfigurationPolicyTemplate/ListBeta/beta'
            'ConfigurationPolicy/ListBeta/beta'
            'ConfigurationPolicyAssignment/ListBeta/beta'
            'DeviceManagementIntent/ListBeta/beta'
        )
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.Id)" }) | Should -Be @(
            'DeviceManagementTemplate/ListBeta/'
            'DeviceManagementConfigurationPolicyTemplate/ListBeta/'
            'ConfigurationPolicy/ListBeta/'
            'DeviceManagementIntent/ListBeta/'
            'ConfigurationPolicyAssignment/ListBeta/policy-current'
            'ConfigurationPolicyAssignment/ListBeta/policy-old'
        )
    }

    It 'keeps the current-baseline branch when the independent legacy template surface fails' {
        $result = Invoke-SecurityBaselinePlanFixture -TemplateError '503 Service Unavailable' -CurrentTemplates @(
            [pscustomobject]@{
                id = 'template-current'; lifecycleState = 'active'; templateFamily = 'baseline'
            }
        ) -Policies @(
            [pscustomobject]@{
                id = 'policy-current'; name = 'Current Windows baseline'
                templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline' }
            }
        ) -Assignments @{
            'policy-current' = @(
                [pscustomobject]@{
                    id = 'assignment-current'
                    target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
                }
            )
        }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Rows[0].id | Should -Be 'policy-current'
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'surface:deviceManagementTemplates'
        $result.Outcome.Gaps[0].Operation | Should -Be 'DeviceManagementTemplate.ListBeta'
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Contain 'DeviceManagementConfigurationPolicyTemplate/ListBeta'
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Contain 'ConfigurationPolicy/ListBeta'
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Contain 'ConfigurationPolicyAssignment/ListBeta'
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Not -Contain 'DeviceManagementIntent/ListBeta'
    }

    It 'also collects the four documented legacy intent families and normalizes their family names' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 't-win'; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 1 }
            [pscustomobject]@{ id = 't-defender'; templateType = 'advancedThreatProtectionSecurityBaseline'; isDeprecated = $false; intentCount = 1 }
            [pscustomobject]@{ id = 't-edge'; templateType = 'microsoftEdgeSecurityBaseline'; isDeprecated = $true; intentCount = 1 }
            [pscustomobject]@{ id = 't-cloud'; templateType = 'cloudPC'; isDeprecated = $false; intentCount = 1 }
            [pscustomobject]@{ id = 't-office'; templateType = 'microsoftOffice365ProPlusSecurityBaseline'; isDeprecated = $false; intentCount = 1 }
        ) -Intents @(
            [pscustomobject]@{ id = 'i-win'; displayName = 'Windows'; templateId = 't-win'; isAssigned = $true }
            [pscustomobject]@{ id = 'i-defender'; displayName = 'Defender'; templateId = 't-defender'; isAssigned = $true }
            [pscustomobject]@{ id = 'i-edge'; displayName = 'Edge'; templateId = 't-edge'; isAssigned = $false }
            [pscustomobject]@{ id = 'i-cloud'; displayName = 'Windows 365'; templateId = 't-cloud'; isAssigned = $true }
            [pscustomobject]@{ id = 'i-office'; displayName = 'Office'; templateId = 't-office'; isAssigned = $true }
        )

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 4
        @($result.Outcome.Rows.templateFamily) | Should -Be @(
            'baselineWindows365'
            'baselineDefenderForEndpoint'
            'baselineMicrosoftEdge'
            'baseline'
        )
        @($result.Outcome.Rows.id) | Should -Not -Contain 'i-office'
    }

    It 'returns an authoritative empty collection only when both current and legacy baseline surfaces are empty' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 0 }
        ) -Policies @() -Intents @()

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
    }

    It 'fails closed when a current baseline policy cannot join to template disposition metadata' {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @() -Policies @(
            [pscustomobject]@{ id = 'policy-unknown'; name = 'Unknown'; templateReference = [pscustomobject]@{ templateId = 'missing'; templateFamily = 'baseline' } }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'fails closed when a policy omits both template id and template family metadata' {
        $result = Invoke-SecurityBaselinePlanFixture -Policies @(
            [pscustomobject]@{ id = 'policy-unclassified'; name = 'Unclassified'; templateReference = [pscustomobject]@{} }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-unclassified'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicy.ListBeta'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].ReasonCode | Should -Be 'invalid-provider-data'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicyAssignment' }).Count | Should -Be 0
    }

    It 'skips an explicitly classified non-baseline policy without a template id' {
        $result = Invoke-SecurityBaselinePlanFixture -Policies @(
            [pscustomobject]@{
                id = 'policy-disk-encryption'
                name = 'Disk encryption'
                templateReference = [pscustomobject]@{ templateFamily = 'endpointSecurityDiskEncryption' }
            }
        )

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicyAssignment' }).Count | Should -Be 0
    }

    It 'fails closed when a tracked template reports legacy intents but the intent collection is empty' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 1 }
        ) -Intents @()

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'template:template-current'
    }

    It 'retains a scoped gap when a current baseline assignment read fails' {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; baseId = 'base-current'; version = 2; displayName = 'Windows baseline'; displayVersion = '24H2'; lifecycleState = 'active'; templateFamily = 'baseline' }
        ) -Policies @(
            [pscustomobject]@{ id = 'policy-current'; name = 'Windows'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline'; templateDisplayName = 'Windows baseline'; templateDisplayVersion = '24H2' } }
        ) -AssignmentErrors @{ 'policy-current' = '403 Forbidden' }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-current'
    }

    It 'sorts equivalent gaps independently of provider traversal order' {
        $templates = @(
            [pscustomobject]@{ id = 'template-current'; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 2 }
        )
        $first = Invoke-SecurityBaselinePlanFixture -Templates $templates -Intents @(
            [pscustomobject]@{ id = 'intent-z'; templateId = 'missing-z'; isAssigned = $true }
            [pscustomobject]@{ id = 'intent-a'; templateId = 'missing-a'; isAssigned = $true }
        )
        $second = Invoke-SecurityBaselinePlanFixture -Templates $templates -Intents @(
            [pscustomobject]@{ id = 'intent-a'; templateId = 'missing-a'; isAssigned = $true }
            [pscustomobject]@{ id = 'intent-z'; templateId = 'missing-z'; isAssigned = $true }
        )

        ($first.Outcome.Gaps | ConvertTo-Json -Depth 8 -Compress) | Should -Be `
            ($second.Outcome.Gaps | ConvertTo-Json -Depth 8 -Compress)
        @($first.Outcome.Gaps.Scope) | Should -Be @('intent:intent-a', 'intent:intent-z', 'template:template-current')
    }

    It 'preserves a legacy-template permission failure while still attempting the independent current profile surface' {
        $result = Invoke-SecurityBaselinePlanFixture -TemplateError ([System.UnauthorizedAccessException]::new('fixture permission denied'))

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -BeIn @('PermissionDenied', 'ProviderFailed')
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'surface:deviceManagementTemplates'
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Be @(
            'DeviceManagementTemplate/ListBeta'
            'DeviceManagementConfigurationPolicyTemplate/ListBeta'
            'ConfigurationPolicy/ListBeta'
        )
    }

    It 'preserves a sole profile-surface permission failure at the top level' {
        $result = Invoke-SecurityBaselinePlanFixture -PolicyError '403 Forbidden'

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -Be 'PermissionDenied'
        $result.Outcome.ReasonCode | Should -Be 'permission-denied'
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'PermissionDenied'
    }

    It 'still calls both profile surfaces when neither contains a tracked baseline' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @() -Policies @() -Intents @()

        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Be @(
            'DeviceManagementTemplate/ListBeta'
            'DeviceManagementConfigurationPolicyTemplate/ListBeta'
            'ConfigurationPolicy/ListBeta'
            'DeviceManagementIntent/ListBeta'
        )
    }

    It 'counts only well-formed positive current-policy assignment targets as assigned' {
        $templates = @(
            [pscustomobject]@{ id = 'template-current'; baseId = 'base-current'; version = 2; displayName = 'Windows baseline'; displayVersion = '24H2'; lifecycleState = 'active'; templateFamily = 'baseline' }
        )
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates $templates -Policies @(
            [pscustomobject]@{ id = 'policy-exclusion-only'; name = 'Excluded only'; isAssigned = $false; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline'; templateDisplayName = 'Windows baseline'; templateDisplayVersion = '24H2' } }
            [pscustomobject]@{ id = 'policy-positive'; name = 'Positive'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline'; templateDisplayName = 'Windows baseline'; templateDisplayVersion = '24H2' } }
        ) -Assignments @{
            'policy-exclusion-only' = @(
                [pscustomobject]@{ id = 'assignment-exclude'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'group-exclude'; deviceAndAppManagementAssignmentFilterType = 'none' }; source = 'direct'; sourceId = $null }
            )
            'policy-positive' = @(
                [pscustomobject]@{ id = 'assignment-include'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-include'; deviceAndAppManagementAssignmentFilterType = 'none' }; source = 'direct'; sourceId = $null }
            )
        }

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        ($result.Outcome.Rows | Where-Object id -eq 'policy-exclusion-only').hasAssignment | Should -BeFalse
        ($result.Outcome.Rows | Where-Object id -eq 'policy-positive').hasAssignment | Should -BeTrue
    }

    It 'gaps a malformed current-policy assignment instead of counting it as assigned' {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; baseId = 'base-current'; version = 2; displayName = 'Windows baseline'; displayVersion = '24H2'; lifecycleState = 'active'; templateFamily = 'baseline' }
        ) -Policies @(
            [pscustomobject]@{ id = 'policy-malformed'; name = 'Malformed'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline'; templateDisplayName = 'Windows baseline'; templateDisplayVersion = '24H2' } }
        ) -Assignments @{
            'policy-malformed' = @(
                [pscustomobject]@{ id = 'assignment-malformed'; target = $null; source = 'direct'; sourceId = $null }
            )
        }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-malformed'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'rejects <InvalidKind> before counting a positive current-policy assignment' -ForEach @(
        @{ InvalidKind = 'numeric assignment id'; AssignmentId = 42; GroupId = 'group-a' }
        @{ InvalidKind = 'object assignment id'; AssignmentId = [pscustomobject]@{ value = 'assignment-a' }; GroupId = 'group-a' }
        @{ InvalidKind = 'numeric group id'; AssignmentId = 'assignment-a'; GroupId = 42 }
        @{ InvalidKind = 'object group id'; AssignmentId = 'assignment-a'; GroupId = [pscustomobject]@{ value = 'group-a' } }
    ) {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; lifecycleState = 'active'; templateFamily = 'baseline' }
        ) -Policies @(
            [pscustomobject]@{
                id = 'policy-malformed-id'
                name = 'Malformed identifier'
                templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline' }
            }
        ) -Assignments @{
            'policy-malformed-id' = @(
                [pscustomobject]@{
                    id = $AssignmentId
                    target = [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId = $GroupId
                    }
                }
            )
        }

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-malformed-id'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].Detail.invalid | Should -Be 'assignment-target'
    }

    It 'gaps a tracked legacy template when intentCount is absent' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-missing-count'; templateType = 'securityBaseline'; isDeprecated = $false }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.Gaps[0].Scope | Should -Be 'template:template-missing-count'
        $result.Outcome.Gaps[0].Detail.invalid | Should -Be 'intentCount'
    }

    It 'gaps a tracked legacy template whose required id is missing' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = ''; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 0 }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.Gaps[0].Scope | Should -Be 'template:unknown'
        $result.Outcome.Gaps[0].Detail.missing | Should -Be 'id'
    }

    It 'emits one structured gap for a duplicate legacy template id even when no intent references it' {
        $templates = @(
            [pscustomobject]@{ id = 'template-duplicate'; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 0 }
            [pscustomobject]@{ id = 'template-duplicate'; templateType = 'securityBaseline'; isDeprecated = $true; intentCount = 1 }
        )

        $first = Invoke-SecurityBaselinePlanFixture -Templates $templates
        $second = Invoke-SecurityBaselinePlanFixture -Templates @($templates[1], $templates[0])

        $first.Outcome.Status | Should -Be 'Failed'
        @($first.Outcome.Rows).Count | Should -Be 0
        ($first.Outcome | ConvertTo-Json -Depth 8 -Compress) | Should -Be ($second.Outcome | ConvertTo-Json -Depth 8 -Compress)
        @($first.Outcome.Gaps).Count | Should -Be 1
        $first.Outcome.Gaps[0].Scope | Should -Be 'template:template-duplicate'
        $first.Outcome.Gaps[0].Operation | Should -Be 'DeviceManagementTemplate.ListBeta'
        $first.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $first.Outcome.Gaps[0].Detail.duplicateTemplateId | Should -Be 'template-duplicate'
    }

    It 'emits one structured gap for a duplicate current template id even when no policy references it' {
        $templates = @(
            [pscustomobject]@{ id = 'template-duplicate'; lifecycleState = 'active'; templateFamily = 'baseline' }
            [pscustomobject]@{ id = 'template-duplicate'; lifecycleState = 'superseded'; templateFamily = 'baseline' }
        )

        $first = Invoke-SecurityBaselinePlanFixture -CurrentTemplates $templates
        $second = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @($templates[1], $templates[0])

        $first.Outcome.Status | Should -Be 'Failed'
        @($first.Outcome.Rows).Count | Should -Be 0
        ($first.Outcome | ConvertTo-Json -Depth 8 -Compress) | Should -Be ($second.Outcome | ConvertTo-Json -Depth 8 -Compress)
        @($first.Outcome.Gaps).Count | Should -Be 1
        $first.Outcome.Gaps[0].Scope | Should -Be 'current-template:template-duplicate'
        $first.Outcome.Gaps[0].Operation | Should -Be 'DeviceManagementConfigurationPolicyTemplate.ListBeta'
        $first.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $first.Outcome.Gaps[0].Detail.duplicateTemplateId | Should -Be 'template-duplicate'
    }

    It 'fails closed when a joined baseline policy omits its policy-side template family' {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; lifecycleState = 'active'; templateFamily = 'baseline' }
        ) -Policies @(
            [pscustomobject]@{ id = 'policy-missing-family'; name = 'Missing family'; templateReference = [pscustomobject]@{ templateId = 'template-current' } }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-missing-family'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicy.ListBeta'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].Detail.invalid | Should -Be 'templateFamily'
        $result.Outcome.Gaps[0].Detail.policyTemplateFamily | Should -BeNullOrEmpty
        $result.Outcome.Gaps[0].Detail.joinedTemplateFamily | Should -Be 'baseline'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicyAssignment' }).Count | Should -Be 0
    }

    It 'fails closed when policy-side template family disagrees with its joined template metadata' {
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; lifecycleState = 'active'; templateFamily = 'baseline' }
        ) -Policies @(
            [pscustomobject]@{ id = 'policy-mismatched-family'; name = 'Mismatched family'; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'endpointSecurityDiskEncryption' } }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].Scope | Should -Be 'policy:policy-mismatched-family'
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicy.ListBeta'
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $result.Outcome.Gaps[0].Detail.invalid | Should -Be 'templateFamily'
        $result.Outcome.Gaps[0].Detail.policyTemplateFamily | Should -Be 'endpointSecurityDiskEncryption'
        $result.Outcome.Gaps[0].Detail.joinedTemplateFamily | Should -Be 'baseline'
        @($result.Calls | Where-Object { $_.Kind -eq 'Graph' -and $_.Type -eq 'ConfigurationPolicyAssignment' }).Count | Should -Be 0
    }

    It 'drops duplicate current-policy ids deterministically instead of retaining either row' {
        $templates = @(
            [pscustomobject]@{ id = 'template-active'; baseId = 'base'; version = 2; displayName = 'Active'; displayVersion = 'v2'; lifecycleState = 'active'; templateFamily = 'baseline' }
            [pscustomobject]@{ id = 'template-old'; baseId = 'base'; version = 1; displayName = 'Old'; displayVersion = 'v1'; lifecycleState = 'superseded'; templateFamily = 'baseline' }
        )
        $policies = @(
            [pscustomobject]@{ id = 'policy-duplicate'; name = 'Active profile'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-active'; templateFamily = 'baseline'; templateDisplayName = 'Active'; templateDisplayVersion = 'v2' } }
            [pscustomobject]@{ id = 'policy-duplicate'; name = 'Old profile'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-old'; templateFamily = 'baseline'; templateDisplayName = 'Old'; templateDisplayVersion = 'v1' } }
        )
        $assignments = @{ 'policy-duplicate' = @([pscustomobject]@{ id = 'assignment'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; deviceAndAppManagementAssignmentFilterType = 'none' }; source = 'direct'; sourceId = $null }) }

        $first = Invoke-SecurityBaselinePlanFixture -CurrentTemplates $templates -Policies $policies -Assignments $assignments
        $second = Invoke-SecurityBaselinePlanFixture -CurrentTemplates $templates -Policies @($policies[1], $policies[0]) -Assignments $assignments

        $first.Outcome.Status | Should -Be 'Failed'
        @($first.Outcome.Rows).Count | Should -Be 0
        ($first.Outcome | ConvertTo-Json -Depth 8 -Compress) | Should -Be ($second.Outcome | ConvertTo-Json -Depth 8 -Compress)
        @($first.Outcome.Gaps | Where-Object { $_.Detail.duplicatePolicyId -eq 'policy-duplicate' }).Count | Should -Be 1
    }

    It 'drops duplicate legacy-intent ids deterministically instead of retaining either row' {
        $templates = @(
            [pscustomobject]@{ id = 'template-active'; templateType = 'securityBaseline'; isDeprecated = $false; intentCount = 1 }
            [pscustomobject]@{ id = 'template-old'; templateType = 'securityBaseline'; isDeprecated = $true; intentCount = 1 }
        )
        $intents = @(
            [pscustomobject]@{ id = 'intent-duplicate'; displayName = 'Active'; templateId = 'template-active'; isAssigned = $true }
            [pscustomobject]@{ id = 'intent-duplicate'; displayName = 'Old'; templateId = 'template-old'; isAssigned = $false }
        )

        $first = Invoke-SecurityBaselinePlanFixture -Templates $templates -Intents $intents
        $second = Invoke-SecurityBaselinePlanFixture -Templates $templates -Intents @($intents[1], $intents[0])

        $first.Outcome.Status | Should -Be 'Failed'
        @($first.Outcome.Rows).Count | Should -Be 0
        ($first.Outcome | ConvertTo-Json -Depth 8 -Compress) | Should -Be ($second.Outcome | ConvertTo-Json -Depth 8 -Compress)
        @($first.Outcome.Gaps | Where-Object { $_.Detail.duplicateIntentId -eq 'intent-duplicate' }).Count | Should -Be 1
    }
}

Describe 'TP.INT.0029 security-baseline row fixtures' {
    It 'evaluates assigned/current rows as Pass' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b1'; name = 'Windows baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false }
        )
        $finding.Status | Should -Be 'Pass'
    }

    It 'evaluates unassigned/current rows as Fail' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b1'; name = 'Windows baseline'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
        )
        $finding.Status | Should -Be 'Fail'
    }

    It 'evaluates assigned/deprecated rows as Fail' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b1'; name = 'Windows baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $true }
        )
        $finding.Status | Should -Be 'Fail'
    }

    It 'fails mixed rows when any baseline is unassigned or deprecated' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b-current'; name = 'Current'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false }
            [pscustomobject]@{ id = 'b-unassigned'; name = 'Unassigned'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
            [pscustomobject]@{ id = 'b-deprecated'; name = 'Deprecated'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $true }
        )
        $finding.Status | Should -Be 'Fail'
        @($finding.Evidence).Count | Should -Be 2
    }

    It 'keeps zero baselines as the existing NotApplicable result' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @()
        $finding.Status | Should -Be 'NotApplicable'
    }

    It 'rejects non-Boolean provider values rather than coercing them' {
        {
            Invoke-SecurityBaselineCheckFixture -Rows @(
                [pscustomobject]@{ id = 'b1'; name = 'Invalid'; templateFamily = 'baseline'; hasAssignment = 'false'; isDeprecated = $false }
            )
        } | Should -Throw '*native boolean*'
    }

    It 'does not turn a malformed native assignment value into successful check input' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; displayName = 'Windows baseline'; templateType = 'securityBaseline'; versionInfo = '24H2'; isDeprecated = $false; intentCount = 1 }
        ) -Intents @(
            [pscustomobject]@{ id = 'intent-invalid'; displayName = 'Invalid'; templateId = 'template-current'; isAssigned = 'true' }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'classifies every enumerated baseline as Expanded, Partial, or NotExpanded with equal totals' {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('assignment failed'),
            'GraphKit.OperationFailed.500',
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $null)
        $result = Invoke-SecurityBaselinePlanFixture -CurrentTemplates @(
            [pscustomobject]@{ id = 'template-current'; baseId = 'base-windows'; version = 2; displayName = 'Windows baseline'; displayVersion = '24H2'; lifecycleState = 'active'; templateFamily = 'baseline' }
            [pscustomobject]@{ id = 'template-old'; baseId = 'base-edge'; version = 1; displayName = 'Edge baseline'; displayVersion = 'v1'; lifecycleState = 'superseded'; templateFamily = 'baseline' }
        ) -Policies @(
            [pscustomobject]@{ id = 'policy-current'; name = 'Windows profile'; isAssigned = $true; templateReference = [pscustomobject]@{ templateId = 'template-current'; templateFamily = 'baseline'; templateDisplayName = 'Windows baseline'; templateDisplayVersion = '24H2' } }
            [pscustomobject]@{ id = 'policy-old'; name = 'Edge profile'; isAssigned = $false; templateReference = [pscustomobject]@{ templateId = 'template-old'; templateFamily = 'baseline'; templateDisplayName = 'Edge baseline'; templateDisplayVersion = 'v1' } }
        ) -Assignments @{
            'policy-current' = @([pscustomobject]@{ id = 'assignment-1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; deviceAndAppManagementAssignmentFilterType = 'none' }; source = 'direct'; sourceId = $null })
        } -AssignmentErrors @{
            'policy-old' = $errorRecord
        }

        $result.Outcome.Status | Should -Be 'Partial'
        @($result.Outcome.Rows).Count | Should -Be 1
        $result.Outcome.Detail.enumeratedCount | Should -Be 2
        ($result.Outcome.Detail.expandedCount + $result.Outcome.Detail.partialCount + $result.Outcome.Detail.notExpandedCount) |
            Should -Be $result.Outcome.Detail.enumeratedCount
        $result.Outcome.Gaps[0].Operation | Should -Be 'ConfigurationPolicyAssignment.ListBeta'
        $result.Outcome.Gaps[0].ApiVersion | Should -Be 'beta'
        $result.Outcome.Operations | Should -Be @(
            'DeviceManagementTemplate.ListBeta'
            'DeviceManagementConfigurationPolicyTemplate.ListBeta'
            'ConfigurationPolicy.ListBeta'
            'ConfigurationPolicyAssignment.ListBeta'
            'DeviceManagementIntent.ListBeta'
        )
    }
}
