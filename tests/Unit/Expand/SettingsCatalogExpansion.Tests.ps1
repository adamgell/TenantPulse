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
        function Get-GraphObject { param() }
    }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
        $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
    } { New-PulseTestGraphEnvelope }

    function New-TestPolicy {
        param([string] $Id, [string] $Name = 'Test Policy', [string] $TemplateFamily = 'none', [string] $TemplateId = '')
        return [pscustomobject]@{
            id                = $Id
            name              = $Name
            templateReference = [pscustomobject]@{ templateId = $TemplateId; templateFamily = $TemplateFamily }
        }
    }

    function New-TestDefinitionIndex {
        return [ordered]@{
            'setting-a' = [ordered]@{ Name = 'a'; DisplayName = 'Setting A'; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false }
        }
    }

    function New-TestSettingsResponse {
        param([string] $DefinitionId = 'setting-a', [string] $Value = 'v1', [string] $RootId = '0')
        return @(
            [pscustomobject]@{
                id              = $RootId
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = $DefinitionId
                    simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = $Value }
                }
            }
        )
    }

    # P0-6: the published jsonl is now an IMMUTABLE, generation-named file
    # (expanded/<Name>.<sha256>.jsonl), not a fixed 'settingsCatalog.jsonl' - every test
    # that needs the actual file resolves its path from the manifest's own recorded `path`,
    # never a hardcoded filename.
    function Get-PulseExpandedJsonlPath {
        param($Store, [string] $Name = 'settingsCatalog')
        $manifest = Get-Content -LiteralPath $Store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.$Name
        if (-not $entry -or -not $entry.path) { return $null }
        return Join-Path $Store.Root $entry.path
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid'; ProfileId = 'contoso-lab' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes NotExpanded with reason "definitions corpus unavailable" and makes NO Graph call when -DefinitionIndex is null' {
        $policy = New-TestPolicy -Id 'policy-1'

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy {
            param($store, $context, $policy)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $null
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'definitions corpus unavailable'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'expands a single clean unassigned policy end to end with settings and assignment payloads persisted' {
        $policy = New-TestPolicy -Id 'policy-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'hello-world'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 1
        $summary.RowCount | Should -Be 1

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $manifest.expansions.settingsCatalog.rowCount | Should -Be 1
        $manifest.expansions.settingsCatalog.policyCount | Should -Be 1
        $manifest.expansions.settingsCatalog.sha256 | Should -Not -BeNullOrEmpty
        # P0-6: path is generation-named, embeds the recorded sha256.
        $manifest.expansions.settingsCatalog.path | Should -Match "settingsCatalog\.$($manifest.expansions.settingsCatalog.sha256)\.jsonl$"
        $manifest.expansions.settingsCatalog.reason | Should -BeNullOrEmpty

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        $lines = @(Get-Content -LiteralPath $jsonlPath)
        $lines.Count | Should -Be 1
        ($lines[0] | ConvertFrom-Json).value | Should -Be 'hello-world'

        # verify recorded sha256 actually matches the file's bytes
        $bytes = [System.IO.File]::ReadAllBytes($jsonlPath)
        $hash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes)) -replace '-', '').ToLowerInvariant()
        $hash | Should -Be $manifest.expansions.settingsCatalog.sha256

        # raw payload dataset persisted
        $manifest.datasets.'configurationPolicySettings-policy-1'.status | Should -Be 'Collected'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-1.json') -PathType Leaf | Should -BeTrue
        $manifest.datasets.'configurationPolicyAssignments-policy-1'.status | Should -Be 'Collected'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicyAssignments-policy-1.json') -PathType Leaf | Should -BeTrue

        # no orphaned .tmp file left behind
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter '*.tmp' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'collects and preserves Settings Catalog assignment targets and reports an unavailable assignment payload as a partial policy gap' {
        $assignedPolicy = New-TestPolicy -Id 'policy-assigned'
        $unavailablePolicy = New-TestPolicy -Id 'policy-assignment-unavailable'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta' -and $Parameters.id -eq 'policy-assigned'
        } {
            New-PulseTestGraphEnvelope -Data @(
                [ordered]@{
                    id     = 'assignment-include'
                    intent = 'include'
                    target = [ordered]@{
                        '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
                        groupId                                   = 'group-include'
                        deviceAndAppManagementAssignmentFilterId   = 'filter-include'
                        deviceAndAppManagementAssignmentFilterType = 'include'
                    }
                }
                [ordered]@{
                    id     = 'assignment-exclude'
                    intent = 'exclude'
                    target = [ordered]@{
                        '@odata.type'                              = '#microsoft.graph.exclusionGroupAssignmentTarget'
                        groupId                                   = 'group-exclude'
                        deviceAndAppManagementAssignmentFilterId   = $null
                        deviceAndAppManagementAssignmentFilterType = 'none'
                    }
                }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta' -and $Parameters.id -eq 'policy-assignment-unavailable'
        } { throw 'simulated assignment endpoint unavailable' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $assignedPolicy, $unavailablePolicy, $index {
            param($store, $context, $assignedPolicy, $unavailablePolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($assignedPolicy, $unavailablePolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        $summary.RowCount | Should -Be 1
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-assignment-unavailable'
        $summary.Gaps[0].reason | Should -Match 'category:AssignmentFetchFailed'

        $row = Get-Content -LiteralPath (Get-PulseExpandedJsonlPath -Store $script:store) | ConvertFrom-Json
        $row.assignments.Count | Should -Be 2
        $includeAssignment = $row.assignments | Where-Object groupId -EQ 'group-include'
        $includeAssignment.intent | Should -Be 'include'
        $includeAssignment.targetType | Should -Be 'group'
        $includeAssignment.filterId | Should -Be 'filter-include'
        $includeAssignment.filterType | Should -Be 'include'
        $excludeAssignment = $row.assignments | Where-Object groupId -EQ 'group-exclude'
        $excludeAssignment.intent | Should -Be 'exclude'
        $excludeAssignment.targetType | Should -Be 'exclusionGroup'
        $excludeAssignment.filterId | Should -BeNullOrEmpty
        $excludeAssignment.filterType | Should -Be 'none'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.'configurationPolicyAssignments-policy-assigned'.status | Should -Be 'Collected'

        $liveJsonl = Get-Content -LiteralPath (Get-PulseExpandedJsonlPath -Store $script:store) -Raw
        $capturedSummary = InModuleScope TenantPulse -ArgumentList $script:store, $assignedPolicy, $unavailablePolicy, $index {
            param($store, $assignedPolicy, $unavailablePolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($assignedPolicy, $unavailablePolicy) `
                -DefinitionIndex $index -FromCapturedPayloads
        }
        $capturedSummary.Status | Should -Be 'Partial'
        $capturedSummary.Gaps[0].reason | Should -Match 'category:AssignmentPayloadMissing'
        (Get-Content -LiteralPath (Get-PulseExpandedJsonlPath -Store $script:store) -Raw) | Should -Be $liveJsonl
    }

    It 'gaps a policy when an assignment target is missing, null, or not an object instead of publishing authoritative empty assignments' {
        $policies = @(
            (New-TestPolicy -Id 'policy-target-missing')
            (New-TestPolicy -Id 'policy-target-null')
            (New-TestPolicy -Id 'policy-target-scalar')
        )
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            $assignmentRows = switch ($Parameters.id) {
                'policy-target-missing' { @([ordered]@{ id = 'assignment-missing' }) }
                'policy-target-null' { @([ordered]@{ id = 'assignment-null'; target = $null }) }
                'policy-target-scalar' { @([ordered]@{ id = 'assignment-scalar'; target = 'not-an-object' }) }
            }
            New-PulseTestGraphEnvelope -Data @($assignmentRows)
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policies, $index {
            param($store, $context, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies $policies -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 3
        @($summary.Gaps | ForEach-Object reason | Sort-Object -Unique) | Should -Be @('category:InvalidAssignmentTarget')
        $summary.Gaps.policyId | Sort-Object | Should -Be @('policy-target-missing', 'policy-target-null', 'policy-target-scalar')
    }

    It 'gaps every policy whose assignment target cannot be represented by the supported Settings Catalog target schema' {
        $policies = @(
            (New-TestPolicy -Id 'target-empty-object')
            (New-TestPolicy -Id 'target-missing-discriminator')
            (New-TestPolicy -Id 'target-group-missing-id')
            (New-TestPolicy -Id 'target-exclusion-missing-id')
            (New-TestPolicy -Id 'target-group-numeric-id')
            (New-TestPolicy -Id 'target-exclusion-object-id')
            (New-TestPolicy -Id 'target-unsupported')
        )
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            $target = switch ($Parameters.id) {
                'target-empty-object' { [ordered]@{} }
                'target-missing-discriminator' { [ordered]@{ groupId = 'orphan-group' } }
                'target-group-missing-id' { [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget' } }
                'target-exclusion-missing-id' { [ordered]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget' } }
                'target-group-numeric-id' { [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 12345 } }
                'target-exclusion-object-id' { [ordered]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = [ordered]@{ value = 'group-object' } } }
                'target-unsupported' { [ordered]@{ '@odata.type' = '#microsoft.graph.scopeTagGroupAssignmentTarget' } }
            }
            New-PulseTestGraphEnvelope -Data @([ordered]@{ id = "assignment-$($Parameters.id)"; target = $target })
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policies, $index {
            param($store, $context, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies $policies -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 7
        @($summary.Gaps.reason | Sort-Object -Unique) | Should -Be @('category:InvalidAssignmentTarget')
        @($summary.Gaps.policyId | Sort-Object) | Should -Be @(
            'target-empty-object'
            'target-exclusion-missing-id'
            'target-exclusion-object-id'
            'target-group-missing-id'
            'target-group-numeric-id'
            'target-missing-discriminator'
            'target-unsupported'
        )
        Get-PulseExpandedJsonlPath -Store $script:store | Should -BeNullOrEmpty
    }

    It 'gaps allDevices and allLicensedUsers targets that supply any non-null groupId' {
        $caseIds = @(
            'target-all-devices-string-id'
            'target-all-devices-numeric-id'
            'target-all-licensed-users-string-id'
            'target-all-licensed-users-object-id'
        )
        $policies = @($caseIds | ForEach-Object { New-TestPolicy -Id $_ })
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            $target = switch ($Parameters.id) {
                'target-all-devices-string-id' {
                    [ordered]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; groupId = 'stray-group' }
                }
                'target-all-devices-numeric-id' {
                    [ordered]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; groupId = 12345 }
                }
                'target-all-licensed-users-string-id' {
                    [ordered]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget'; groupId = 'stray-group' }
                }
                'target-all-licensed-users-object-id' {
                    [ordered]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget'; groupId = [ordered]@{ value = 'stray-group' } }
                }
            }
            New-PulseTestGraphEnvelope -Data @([ordered]@{ id = "assignment-$($Parameters.id)"; target = $target })
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policies, $index {
            param($store, $context, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies $policies -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be $caseIds.Count
        @($summary.Gaps.reason | Sort-Object -Unique) | Should -Be @('category:InvalidAssignmentTarget')
        @($summary.Gaps.policyId | Sort-Object) | Should -Be @($caseIds | Sort-Object)
        Get-PulseExpandedJsonlPath -Store $script:store | Should -BeNullOrEmpty
    }

    It 'gaps policies whose supplied assignment intent is not the exact target-derived row-schema intent' {
        $caseIds = @(
            'intent-non-string'
            'intent-unknown'
            'intent-wrong-case'
            'intent-include-on-exclusion'
            'intent-exclude-on-group'
        )
        $policies = @($caseIds | ForEach-Object { New-TestPolicy -Id $_ })
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            $intent = switch ($Parameters.id) {
                'intent-non-string' { [ordered]@{ value = 'include' } }
                'intent-unknown' { 'futureValue' }
                'intent-wrong-case' { 'Include' }
                'intent-include-on-exclusion' { 'include' }
                'intent-exclude-on-group' { 'exclude' }
            }
            $targetType = if ($Parameters.id -eq 'intent-include-on-exclusion') {
                '#microsoft.graph.exclusionGroupAssignmentTarget'
            } else {
                '#microsoft.graph.groupAssignmentTarget'
            }
            New-PulseTestGraphEnvelope -Data @([ordered]@{
                    id = "assignment-$($Parameters.id)"
                    intent = $intent
                    target = [ordered]@{
                        '@odata.type' = $targetType
                        groupId = "group-$($Parameters.id)"
                    }
                })
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policies, $index {
            param($store, $context, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies $policies -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be $caseIds.Count
        @($summary.Gaps.reason | Sort-Object -Unique) | Should -Be @('category:InvalidAssignmentTarget')
        @($summary.Gaps.policyId | Sort-Object) | Should -Be @($caseIds | Sort-Object)
        Get-PulseExpandedJsonlPath -Store $script:store | Should -BeNullOrEmpty
    }

    It 'gaps a policy when its assignment filter id is not a string instead of stringifying it into authoritative metadata' {
        $policy = New-TestPolicy -Id 'policy-filter-id-invalid'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            New-PulseTestGraphEnvelope -Data @([ordered]@{
                    id = 'assignment-filter-id-invalid'
                    target = [ordered]@{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId = 'group-valid'
                        deviceAndAppManagementAssignmentFilterId = 12345
                        deviceAndAppManagementAssignmentFilterType = 'include'
                    }
                })
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-filter-id-invalid'
        $summary.Gaps[0].reason | Should -Be 'category:InvalidAssignmentTarget'
        Get-PulseExpandedJsonlPath -Store $script:store | Should -BeNullOrEmpty
    }

    It 'gaps a policy when its assignment filter type is not a string instead of stringifying it into authoritative metadata' {
        $policy = New-TestPolicy -Id 'policy-filter-type-invalid'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            New-PulseTestGraphEnvelope -Data @([ordered]@{
                    id = 'assignment-filter-type-invalid'
                    target = [ordered]@{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId = 'group-valid'
                        deviceAndAppManagementAssignmentFilterId = 'filter-valid'
                        deviceAndAppManagementAssignmentFilterType = [ordered]@{ value = 'include' }
                    }
                })
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-filter-type-invalid'
        $summary.Gaps[0].reason | Should -Be 'category:InvalidAssignmentTarget'
        Get-PulseExpandedJsonlPath -Store $script:store | Should -BeNullOrEmpty
    }

    It 'gaps policies whose assignment filter enum or id/type pairing violates the Graph contract' {
        $caseIds = @(
            'filter-type-unknown'
            'filter-type-wrong-case'
            'filter-include-missing-id'
            'filter-include-blank-id'
            'filter-exclude-null-id'
            'filter-exclude-whitespace-id'
            'filter-none-with-id'
            'filter-none-with-blank-id'
            'filter-null-type-with-id'
        )
        $policies = @($caseIds | ForEach-Object { New-TestPolicy -Id $_ })
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            $target = [ordered]@{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                groupId = 'group-valid'
            }
            switch ($Parameters.id) {
                'filter-type-unknown' {
                    $target.deviceAndAppManagementAssignmentFilterId = 'filter-valid'
                    $target.deviceAndAppManagementAssignmentFilterType = 'unknownFutureValue'
                }
                'filter-type-wrong-case' {
                    $target.deviceAndAppManagementAssignmentFilterId = 'filter-valid'
                    $target.deviceAndAppManagementAssignmentFilterType = 'Include'
                }
                'filter-include-missing-id' {
                    $target.deviceAndAppManagementAssignmentFilterType = 'include'
                }
                'filter-include-blank-id' {
                    $target.deviceAndAppManagementAssignmentFilterId = ''
                    $target.deviceAndAppManagementAssignmentFilterType = 'include'
                }
                'filter-exclude-null-id' {
                    $target.deviceAndAppManagementAssignmentFilterId = $null
                    $target.deviceAndAppManagementAssignmentFilterType = 'exclude'
                }
                'filter-exclude-whitespace-id' {
                    $target.deviceAndAppManagementAssignmentFilterId = '   '
                    $target.deviceAndAppManagementAssignmentFilterType = 'exclude'
                }
                'filter-none-with-id' {
                    $target.deviceAndAppManagementAssignmentFilterId = 'filter-contradiction'
                    $target.deviceAndAppManagementAssignmentFilterType = 'none'
                }
                'filter-none-with-blank-id' {
                    $target.deviceAndAppManagementAssignmentFilterId = ''
                    $target.deviceAndAppManagementAssignmentFilterType = 'none'
                }
                'filter-null-type-with-id' {
                    $target.deviceAndAppManagementAssignmentFilterId = 'filter-orphaned'
                    $target.deviceAndAppManagementAssignmentFilterType = $null
                }
            }
            New-PulseTestGraphEnvelope -Data @([ordered]@{ id = "assignment-$($Parameters.id)"; target = $target })
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policies, $index {
            param($store, $context, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies $policies -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be $caseIds.Count
        @($summary.Gaps.reason | Sort-Object -Unique) | Should -Be @('category:InvalidAssignmentTarget')
        @($summary.Gaps.policyId | Sort-Object) | Should -Be @($caseIds | Sort-Object)
        Get-PulseExpandedJsonlPath -Store $script:store | Should -BeNullOrEmpty
    }

    It 'preserves unfiltered assignments when Graph omits both filter fields or returns null and none' {
        $policy = New-TestPolicy -Id 'policy-valid-unfiltered-shapes'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            New-PulseTestGraphEnvelope -Data @(
                [ordered]@{
                    id = 'assignment-fields-omitted'
                    target = [ordered]@{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId = 'group-fields-omitted'
                    }
                }
                [ordered]@{
                    id = 'assignment-explicit-null'
                    target = [ordered]@{
                        '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'
                        groupId = $null
                        deviceAndAppManagementAssignmentFilterId = $null
                        deviceAndAppManagementAssignmentFilterType = $null
                    }
                }
                [ordered]@{
                    id = 'assignment-none'
                    target = [ordered]@{
                        '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget'
                        deviceAndAppManagementAssignmentFilterId = $null
                        deviceAndAppManagementAssignmentFilterType = 'none'
                    }
                }
            )
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.Gaps.Count | Should -Be 0
        $row = Get-Content -LiteralPath (Get-PulseExpandedJsonlPath -Store $script:store) | ConvertFrom-Json
        $row.assignments.Count | Should -Be 3

        $omitted = $row.assignments | Where-Object groupId -EQ 'group-fields-omitted'
        $omitted.filterId | Should -BeNullOrEmpty
        $omitted.filterType | Should -BeNullOrEmpty

        $explicitNull = $row.assignments | Where-Object targetType -EQ 'allDevices'
        $explicitNull.groupId | Should -BeNullOrEmpty
        $explicitNull.filterId | Should -BeNullOrEmpty
        $explicitNull.filterType | Should -BeNullOrEmpty

        $none = $row.assignments | Where-Object targetType -EQ 'allLicensedUsers'
        $none.groupId | Should -BeNullOrEmpty
        $none.filterId | Should -BeNullOrEmpty
        $none.filterType | Should -Be 'none'
    }

    It 'preserves a rejected policy as uncertainty in both derived artifacts when another policy expands successfully' {
        $validPolicy = New-TestPolicy -Id 'policy-valid-assignment'
        $invalidPolicy = New-TestPolicy -Id 'policy-invalid-assignment'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            if ($Parameters.id -eq 'policy-valid-assignment') {
                return New-PulseTestGraphEnvelope -Data @([ordered]@{
                        id = 'assignment-valid'
                        target = [ordered]@{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId = 'group-valid'
                        }
                    })
            }
            return New-PulseTestGraphEnvelope -Data @([ordered]@{
                    id = 'assignment-invalid'
                    target = [ordered]@{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId = 12345
                    }
                })
        }

        $summaries = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $validPolicy, $invalidPolicy, $index {
            param($store, $context, $validPolicy, $invalidPolicy, $index)
            $settings = Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context `
                -Policies @($validPolicy, $invalidPolicy) -DefinitionIndex $index
            $conflicts = Invoke-PulseConflictDetection -Store $store
            $presence = Invoke-PulseSettingPresenceIndexBuild -Store $store
            [pscustomobject]@{ Settings = $settings; Conflicts = $conflicts; Presence = $presence }
        }

        $summaries.Settings.Status | Should -Be 'Partial'
        $summaries.Settings.RowCount | Should -Be 1
        $summaries.Settings.Gaps.Count | Should -Be 1

        foreach ($derived in @($summaries.Conflicts, $summaries.Presence)) {
            $derived.Status | Should -Be 'Partial'
            $derived.Gaps.Count | Should -Be 1
            $derived.Gaps[0].policyId | Should -Be 'policy-invalid-assignment'
            $derived.Gaps[0].reason | Should -Be 'category:InvalidAssignmentTarget'
        }

        $artifacts = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            [pscustomobject]@{
                Conflicts = Get-PulseConflictArtifact -Store $store
                Presence = Get-PulseSettingPresenceIndex -Store $store
            }
        }
        $artifacts.Conflicts.Status | Should -Be 'Available'
        $artifacts.Conflicts.Conflicts.Count | Should -Be 0
        $artifacts.Conflicts.Gaps.Count | Should -Be 1
        $artifacts.Presence.Status | Should -Be 'Available'
        $artifacts.Presence.Gaps.Count | Should -Be 1
    }

    It 'a policy fetch failure yields Partial status with a STRUCTURED {policyId;reason} gap (P0-3: no raw exception text), other policies still succeed' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $badPolicy = New-TestPolicy -Id 'policy-bad'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        $plantedSecretInException = 'PLANTED-EXCEPTION-SECRET-abc123'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq 'policy-good'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq 'policy-bad'
        } { throw "simulated Graph failure carrying $plantedSecretInException" }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $badPolicy, $index {
            param($store, $context, $goodPolicy, $badPolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $badPolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        $summary.RowCount | Should -Be 1
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-bad'
        $summary.Gaps[0].reason | Should -Match 'category:FetchFailed'
        $summary.Gaps[0].reason | Should -Not -Match ([regex]::Escape($plantedSecretInException))

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Partial'
        $manifest.expansions.settingsCatalog.gaps.Count | Should -Be 1
        $manifest.expansions.settingsCatalog.gaps[0].reason | Should -Not -Match ([regex]::Escape($plantedSecretInException))
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecretInException))
    }

    It 'stops Settings Catalog fan-out immediately after first or middle authentication failure, but isolates a non-auth child failure' -ForEach @(
        @{
            Name = 'first settings auth'; FailId = 'policy-1'; FailType = 'ConfigurationPolicySetting'; Status = 401
            ExpectedSettings = 1; ExpectedAssignments = 0; ExpectedStatus = 'NotExpanded'
            ExpectedGapIds = @('policy-1', 'policy-2', 'policy-3'); ExpectedNotAttempted = @('policy-2', 'policy-3')
        }
        @{
            Name = 'middle assignment auth'; FailId = 'policy-2'; FailType = 'ConfigurationPolicyAssignment'; Status = 401
            ExpectedSettings = 2; ExpectedAssignments = 2; ExpectedStatus = 'Partial'
            ExpectedGapIds = @('policy-2', 'policy-3'); ExpectedNotAttempted = @('policy-3')
        }
        @{
            Name = 'first settings provider'; FailId = 'policy-1'; FailType = 'ConfigurationPolicySetting'; Status = 503
            ExpectedSettings = 3; ExpectedAssignments = 2; ExpectedStatus = 'Partial'
            ExpectedGapIds = @('policy-1'); ExpectedNotAttempted = @()
        }
    ) {
        $policies = 1..3 | ForEach-Object { New-TestPolicy -Id "policy-$_" }
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        $target = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Failed'; Certainty = 'Known'
            Telemetry = @([pscustomobject]@{ Attempt = 1; StatusCode = $Status })
        }
        $category = if ($Status -eq 401) {
            [System.Management.Automation.ErrorCategory]::AuthenticationError
        } else {
            [System.Management.Automation.ErrorCategory]::ResourceUnavailable
        }
        $record = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('planted provider response'),
            "GraphKit.OperationFailed.$Status", $category, $target)

        $script:settingsCalls = 0
        $script:assignmentCalls = 0
        $script:fanoutRecord = $record
        $script:fanoutFailId = $FailId
        $script:fanoutFailType = $FailType
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            $script:settingsCalls++
            if ($script:fanoutFailType -eq $Type -and $Parameters.id -eq $script:fanoutFailId) { throw $script:fanoutRecord }
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicyAssignment' } {
            $script:assignmentCalls++
            if ($script:fanoutFailType -eq $Type -and $Parameters.id -eq $script:fanoutFailId) { throw $script:fanoutRecord }
            New-PulseTestGraphEnvelope
        }

        $state = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policies, $index, $state {
            param($store, $context, $policies, $index, $state)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies $policies `
                -DefinitionIndex $index -NetworkAbortState $state
        }

        $script:settingsCalls | Should -Be $ExpectedSettings
        $script:assignmentCalls | Should -Be $ExpectedAssignments
        $state.AuthenticationAborted | Should -Be ($Status -eq 401)
        $summary.Status | Should -Be $ExpectedStatus
        @($summary.Gaps.policyId) | Should -Be $ExpectedGapIds
        @($summary.Gaps | Where-Object reason -eq 'category:NotAttemptedAfterAuthenticationFailure' | ForEach-Object policyId) |
            Should -Be $ExpectedNotAttempted

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be $ExpectedStatus
        @($manifest.expansions.settingsCatalog.gaps.policyId) | Should -Be $ExpectedGapIds
    }

    It 'planted secret value never appears in the raw persisted dataset, the final jsonl, or the manifest' {
        $policy = New-TestPolicy -Id 'policy-secret'
        $index = New-TestDefinitionIndex
        $plantedSecret = 'PLANTED-SECRET-VALUE-zzz999'
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-secret'
                    simpleSettingValue  = [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'
                        value         = $plantedSecret
                        valueState    = 'notEncrypted'
                    }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $rawDatasetContent = Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-secret.json') -Raw
        $rawDatasetContent | Should -Not -Match ([regex]::Escape($plantedSecret))

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecret))

        $manifestContent = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifestContent | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'T2.7 LIVE-GATE REGRESSION: a raw tenant id appearing as an ordinary (non-secret) admin-configured setting VALUE is redacted to its pseudonym in the published jsonl' {
        # Reproduced live on Ivy24: a real Settings Catalog policy's own OneDrive
        # Known-Folder-Move opt-in value legitimately carries the tenant's own GUID as
        # admin-entered configuration data - not a secret-typed value at all, so the
        # secret-contract redaction path never touches it, yet the raw tenant id still
        # reached the published jsonl before this fix (Protect-PulseGraphRowTenantId was
        # never wired into this pipeline - only into T1.11's raw-dataset writes).
        $policy = New-TestPolicy -Id 'policy-tenant-id-value'
        $index = New-TestDefinitionIndex
        $tenantId = 'tenant-guid'
        $pseudonym = 'tp-deadbeefdeadbeef'
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_onedrivengsc_kfmoptinnowizard'
                    simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = $tenantId }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index, $tenantId, $pseudonym {
            param($store, $context, $policy, $index, $tenantId, $pseudonym)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index `
                -TenantId $tenantId -Pseudonym $pseudonym
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $jsonlContent = Get-Content -LiteralPath $jsonlPath -Raw
        $jsonlContent | Should -Not -Match ([regex]::Escape($tenantId))
        $jsonlContent | Should -Match ([regex]::Escape($pseudonym))
    }

    It 'SECRET-MARKER-LOSS: a no-discriminator (dictionary-shaped) settingValue still redacts fail-closed and never leaks the planted plaintext' {
        $policy = New-TestPolicy -Id 'policy-no-discriminator'
        $index = New-TestDefinitionIndex
        $plantedSecret = 'PLANTED-NO-DISCRIMINATOR-VALUE'
        # No `@odata.type` at all on the settingValue - the exact reproduced bypass shape.
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-a'
                    simpleSettingValue  = @{ value = $plantedSecret }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        # unknown shape -> redacted AND a gap (Partial), per the shared classifier's
        # contract.
        $summary.Status | Should -Be 'Partial'
        $summary.RedactedSecretCount | Should -Be 1

        $rawDatasetContent = Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-no-discriminator.json') -Raw
        $rawDatasetContent | Should -Not -Match ([regex]::Escape($plantedSecret))

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'DUPLICATE-ID: two policies sharing the same id - only the first is fetched, the duplicate gaps immediately, one raw-dataset owner' {
        $policyA = New-TestPolicy -Id 'shared-id'
        $policyB = New-TestPolicy -Id 'shared-id'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'owner-value'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq 'shared-id'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyA, $policyB, $index {
            param($store, $context, $policyA, $policyB, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyA, $policyB) -DefinitionIndex $index
        }

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Parameters.id -eq 'shared-id' -and $Type -eq 'ConfigurationPolicySetting'
        }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Parameters.id -eq 'shared-id' -and $Type -eq 'ConfigurationPolicyAssignment'
        }
        $summary.Status | Should -Be 'Partial'
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'shared-id'
        $summary.Gaps[0].reason | Should -Match 'category:DuplicatePolicyId'
        $summary.RowCount | Should -Be 1
    }

    It 'EMPTY-ID: a policy with no id gaps immediately and is never fetched' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $emptyPolicy = New-TestPolicy -Id ''
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq 'policy-good'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $emptyPolicy, $index {
            param($store, $context, $goodPolicy, $emptyPolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $emptyPolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        ($summary.Gaps | Where-Object { $_.reason -match 'category:EmptyPolicyId' }).Count | Should -Be 1
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 2 -Exactly
    }

    It 'WHITESPACE-ID (re-review fix): a policy whose id is whitespace-only gaps immediately, prevalidation rejects it, and it is never fetched' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $whitespacePolicy = New-TestPolicy -Id '   '
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq 'policy-good'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $whitespacePolicy, $index {
            param($store, $context, $goodPolicy, $whitespacePolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $whitespacePolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        ($summary.Gaps | Where-Object { $_.reason -match 'category:EmptyPolicyId' }).Count | Should -Be 1
        # zero Graph calls for the whitespace-id policy - only the good policy is fetched
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 2 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Parameters.id -match '^\s+$' }
    }

    It 'PATH-COLLISION (P1-8): two definitionId chains that would collide under a single-pass escape produce distinct settingPaths' {
        $policy = New-TestPolicy -Id 'policy-path-collision'
        $index = New-TestDefinitionIndex
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'a~sb'
                    simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $row = Get-Content -LiteralPath $jsonlPath -Raw | ConvertFrom-Json
        $row.settingPath | Should -Be 'a~tsb'
        $row.settingPath | Should -Not -Be 'a~sb'
    }

    It 'merge determinism: processing the same two policies in reversed order produces a byte-identical jsonl file' {
        $policyA = New-TestPolicy -Id 'aaaaaaaa-0000-0000-0000-000000000001'
        $policyB = New-TestPolicy -Id 'bbbbbbbb-0000-0000-0000-000000000002'
        $index = New-TestDefinitionIndex
        $responseA = New-TestSettingsResponse -Value 'value-a'
        $responseB = New-TestSettingsResponse -Value 'value-b'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq $policyA.id
        } { New-PulseTestGraphEnvelope -Data @($responseA) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Parameters.id -eq $policyB.id
        } { New-PulseTestGraphEnvelope -Data @($responseB) }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyA, $policyB, $index {
            param($store, $context, $policyA, $policyB, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyA, $policyB) -DefinitionIndex $index
        }
        $forwardBytes = [System.IO.File]::ReadAllBytes((Get-PulseExpandedJsonlPath -Store $script:store))

        $storeRoot2 = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store2 = InModuleScope TenantPulse -ArgumentList $storeRoot2 { param($storeRoot2) New-PulseSnapshotStore -Path $storeRoot2 }
        try {
            InModuleScope TenantPulse -ArgumentList $store2, $script:context, $policyA, $policyB, $index {
                param($store2, $context, $policyA, $policyB, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store2 -Context $context -Policies @($policyB, $policyA) -DefinitionIndex $index
            }
            $reversedBytes = [System.IO.File]::ReadAllBytes((Get-PulseExpandedJsonlPath -Store $store2))

            [System.Convert]::ToBase64String($forwardBytes) | Should -Be ([System.Convert]::ToBase64String($reversedBytes))
        } finally {
            Remove-Item -LiteralPath $storeRoot2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'assignment normalization is byte-identical when Graph returns the same complete assignment tuples in reverse order' {
        $policy = New-TestPolicy -Id 'policy-assignment-order'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        $assignments = @(
            [ordered]@{
                id = 'assignment-exclude'
                target = [ordered]@{
                    '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'
                    groupId = 'group-z'
                    deviceAndAppManagementAssignmentFilterId = 'filter-z'
                    deviceAndAppManagementAssignmentFilterType = 'exclude'
                }
            }
            [ordered]@{
                id = 'assignment-include-filtered'
                target = [ordered]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = 'group-a'
                    deviceAndAppManagementAssignmentFilterId = 'filter-a'
                    deviceAndAppManagementAssignmentFilterType = 'include'
                }
            }
            [ordered]@{
                id = 'assignment-include-unfiltered'
                target = [ordered]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = 'group-a'
                    deviceAndAppManagementAssignmentFilterId = $null
                    deviceAndAppManagementAssignmentFilterType = 'none'
                }
            }
        )
        $script:assignmentFetchCount = 0

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta'
        } { New-PulseTestGraphEnvelope -Data @($settingsResponse) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ConfigurationPolicyAssignment' -and $Operation -eq 'ListBeta'
        } {
            $script:assignmentFetchCount++
            if ($script:assignmentFetchCount -eq 1) {
                return New-PulseTestGraphEnvelope -Data @($assignments)
            }
            return New-PulseTestGraphEnvelope -Data @($assignments[2], $assignments[1], $assignments[0])
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }
        $forwardBytes = [System.IO.File]::ReadAllBytes((Get-PulseExpandedJsonlPath -Store $script:store))

        $storeRoot2 = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store2 = InModuleScope TenantPulse -ArgumentList $storeRoot2 { param($storeRoot2) New-PulseSnapshotStore -Path $storeRoot2 }
        try {
            InModuleScope TenantPulse -ArgumentList $store2, $script:context, $policy, $index {
                param($store2, $context, $policy, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store2 -Context $context -Policies @($policy) -DefinitionIndex $index
            }
            $reversedBytes = [System.IO.File]::ReadAllBytes((Get-PulseExpandedJsonlPath -Store $store2))

            [System.Convert]::ToBase64String($forwardBytes) | Should -Be ([System.Convert]::ToBase64String($reversedBytes))
        } finally {
            Remove-Item -LiteralPath $storeRoot2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It '-FromCapturedPayloads re-expands from the persisted raw dataset with NO Graph call' {
        $policy = New-TestPolicy -Id 'policy-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'captured-value'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'must not be called on -FromCapturedPayloads' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $index {
            param($store, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.RowCount | Should -Be 1
        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $lines = @(Get-Content -LiteralPath $jsonlPath)
        ($lines[0] | ConvertFrom-Json).value | Should -Be 'captured-value'
    }

    It 'zero policies: Expanded with rowCount 0 and policyCount 0, an empty but hash-verified generation-named jsonl file' {
        $index = New-TestDefinitionIndex

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $index {
            param($store, $context, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @() -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 0
        $summary.RowCount | Should -Be 0
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -BeNullOrEmpty
    }

    It 'GAPS SORTED ORDINALLY on (policyId, reason) regardless of input/failure order' {
        $policyZ = New-TestPolicy -Id 'zzz-policy'
        $policyA = New-TestPolicy -Id 'aaa-policy'
        $index = New-TestDefinitionIndex
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'zzz-policy' } { throw 'z fails' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'aaa-policy' } { throw 'a fails' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyZ, $policyA, $index {
            param($store, $context, $policyZ, $policyA, $index)
            # deliberately supplied in Z-then-A order
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyZ, $policyA) -DefinitionIndex $index
        }

        $summary.Gaps.Count | Should -Be 2
        $summary.Gaps[0].policyId | Should -Be 'aaa-policy'
        $summary.Gaps[1].policyId | Should -Be 'zzz-policy'
    }

    It 'PUBLICATION FAULT INJECTION: the expanded/ directory disappearing mid-staging leaves no orphaned .tmp file, disposes the hash, and does not publish a corrupt artifact' {
        $policy = New-TestPolicy -Id 'policy-fault'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'x'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        # Fault injection: the expanded/ directory itself is removed right before the
        # driver runs, so [System.IO.File]::Open for the staging temp file fails partway
        # through the staging sequence (after the IncrementalHash has already been
        # created) - a real, reproducible I/O fault, not a synthetic unreachable shape.
        Remove-Item -LiteralPath $script:store.ExpandedPath -Recurse -Force

        {
            InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
                param($store, $context, $policy, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
            }
        } | Should -Throw

        # no expansion entry was ever written for a corrupt/incomplete artifact
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingsCatalog') | Should -BeFalse
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion - sequential-only (Part D, T3.4: RunspacePool -MaxParallel path deleted)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # RETIRED (Part D, T3.4 - ledger record): two multi-worker byte-identity tests used to
    # live here -
    #   'a real -MaxParallel 4 run over captured payloads is byte-identical to -Sequential'
    #   'T2.7: -MaxParallel 4 against the driver directly (bypassing the pipeline''s forced
    #    -Sequential) stays byte-identical to -Sequential over 24 captured-payload policies'
    # - both asserting a real RunspacePool worker-pool run produced byte-identical output to
    # a sequential run over the same captured-payload corpus. Both are deleted, not
    # skipped: the RunspacePool path they exercised no longer exists in the product code
    # (see Invoke-PulseSettingsCatalogExpansion's own docstring for the measured deletion
    # rationale - per-runspace ~20s token acquisition, a runspace-local throttle
    # coordinator, and an Import-Module table race that only survived 2 of 6 concurrent
    # pooled runspace opens even with -Force), so there is no second code path left for
    # either test to compare against; a sequential-vs-sequential "byte-identity" assertion
    # would prove nothing these tests' many sibling sequential-path Its don't already
    # cover. The test BELOW this comment (WORKER-FAILURE CLASSIFICATION) covered real
    # behavior beyond byte-identity - gap classification for one missing captured payload
    # among several policies - so it is KEPT, converted to the sequential call every other
    # test in this file already uses, rather than deleted.
    It 'WORKER-FAILURE CLASSIFICATION: a missing captured payload for one policy (of several) gaps only that policy' {
        $index = New-TestDefinitionIndex
        $goodIds = 1..3 | ForEach-Object { "22222222-2222-2222-2222-{0:D12}" -f $_ }
        $missingId = '22222222-2222-2222-2222-999999999999'
        $policies = @($goodIds | ForEach-Object { New-TestPolicy -Id $_ }) + @(New-TestPolicy -Id $missingId)

        foreach ($id in $goodIds) {
            $response = New-TestSettingsResponse -Value "value-$id" -DefinitionId 'setting-a'
            InModuleScope TenantPulse -ArgumentList $script:store, $id, $response {
                param($store, $id, $response)
                Write-PulseDataset -Store $store -Name "configurationPolicySettings-$id" -Data $response -ApiVersion 'beta' -Status 'Collected'
                Write-PulseDataset -Store $store -Name "configurationPolicyAssignments-$id" -Data @() -ApiVersion 'beta' -Status 'Collected'
            }
        }
        # $missingId is intentionally never written - Read-PulseDataset will fail for it.

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policies, $index {
            param($store, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies $policies -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.Status | Should -Be 'Partial'
        $summary.RowCount | Should -Be 3
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be $missingId
        $summary.Gaps[0].reason | Should -Match 'category:CapturedPayload'
    }

    It 'ALL-POLICIES-FAILED: every eligible policy failing yields NotExpanded (not Partial with an empty artifact), no jsonl is written' {
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-all-fail-1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'simulated Graph failure' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-all-fail-1'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'all 1 policy'
        # NotExpanded per Set-PulseExpansionEntry's own contract does not require/publish a
        # Path - no jsonl artifact should exist under expanded/ for this run at all.
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'a legitimately empty policy (walks cleanly, zero settings, zero gaps) stays Expanded with a valid empty artifact - not misclassified as ALL-POLICIES-FAILED' {
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-empty-1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 0

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
    }

    It 'READ-ONLY ENFORCEMENT: a Write-class/Unsafe ConfigurationPolicySetting descriptor aborts (fatal, matching Assert-PulseReadOnlyDescriptor''s own contract) before any Graph call' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } {
            [pscustomobject]@{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ThrottleClass = 'Write'; ReplayPolicy = 'Unsafe'; ApiVersion = 'beta' }
        }
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-readonly-1'

        {
            InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
                param($store, $context, $policy, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
            }
        } | Should -Throw '*not a read-only descriptor*'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' }
    }

    It 'READ-ONLY ENFORCEMENT: a descriptor-version-drift downgrades to NotExpanded (not fatal), no Graph call' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } {
            [pscustomobject]@{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'v1.0' }
        }
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-drift-1'

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' }
    }

    It '-FromCapturedPayloads skips the read-only assertion entirely (no Graph call is ever made on this path, so no descriptor needs resolving)' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'Get-GraphOperation must not be called on -FromCapturedPayloads' }
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-captured-readonly-1'

        # No captured dataset exists for this policy - expect a CapturedPayloadMissing gap,
        # not a Get-GraphOperation-related failure.
        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $index {
            param($store, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.Gaps[0].reason | Should -Match 'CapturedPayloadMissing'
    }

    It 'DEPTH BUDGET ALIGNMENT: a chain exactly at the walker''s own 64-level budget (worst-case 4x GroupSettingCollection nesting) does not spuriously fail redaction/fetch' {
        # Build a GroupSettingCollectionInstance chain 64 levels deep - the worst-case shape
        # for the redactor's own per-raw-node depth counting (see ConvertTo-PulseSettingRows.ps1's
        # $script:PulseSettingsCatalogWalkerMaxDepth docstring: 4 raw levels per walker level).
        # A walker-valid chain at exactly this budget must not throw inside
        # Protect-PulseSettingsCatalogSecretPayload and get misclassified as a fetch failure.
        $leafDefId = 'leaf-setting'
        $current = [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = $leafDefId
            simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'v' }
        }
        for ($i = 0; $i -lt 63; $i++) {
            $current = [pscustomobject]@{
                '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                settingDefinitionId          = "level-$i"
                groupSettingCollectionValue  = @([pscustomobject]@{ children = @($current) })
            }
        }
        $settingsResponse = @([pscustomobject]@{ id = '0'; settingInstance = $current })

        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-deep-1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        # A depth-budget-exceeded gap (from the WALKER itself) is fine at exactly the
        # boundary either way (off-by-one at the edge is not what this test is pinning) -
        # what this test forbids is a redaction-triggered 'category:FetchFailed' gap, which
        # would mean the redactor's own budget was smaller than the walker's and a VALID
        # chain got misclassified as a fetch failure purely due to raw-node overcounting.
        $summary.Gaps | Where-Object { $_.reason -match 'category:FetchFailed' } | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion - Task 2.5 endpoint security / baseline instances' {
    <#
        Endpoint security policies live in the SAME configurationPolicies dataset T2.2
        already fans out over - templateFamily/isBaseline are frozen row schema v1 fields
        T2.2 already populates from -Policy's own templateReference (no new fetch here, per
        the plan). This block pins the ONE thing T2.5 actually changes: isBaseline must be
        true ONLY for the 'baseline' template family (Security Baselines), never for every
        OTHER template-bearing family (ordinary endpoint security profiles - antivirus,
        disk encryption, firewall, ... - are template-bearing too, but are not baselines).
    #>
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid'; ProfileId = 'contoso-lab' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'a security-baseline policy (templateFamily "baseline") walks with isBaseline:true on every row' {
        $policy = New-TestPolicy -Id 'policy-baseline' -TemplateFamily 'baseline' -TemplateId 'tpl-baseline-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'baseline'
            $_.isBaseline | Should -BeTrue
        }
    }

    It 'GOLDEN (real fixture): an endpointSecurityAccountProtection policy (choicecollection-01, real Ivy24 templateFamily) walks with isBaseline:false' {
        $fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalog'
        $fixture = Get-Content -LiteralPath (Join-Path $fixturesPath 'choicecollection-01.json') -Raw | ConvertFrom-Json -Depth 64
        $fixture.Policy.templateReference.templateFamily | Should -Be 'endpointSecurityAccountProtection'

        $index = New-TestDefinitionIndex
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($fixture.Settings)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $fixture.Policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'endpointSecurityAccountProtection'
            $_.isBaseline | Should -BeFalse
        }
    }

    It 'GOLDEN (real fixture): an endpointSecurityAttackSurfaceReduction policy (choicecollection-02, real Ivy24 templateFamily) walks with isBaseline:false' {
        $fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalog'
        $fixture = Get-Content -LiteralPath (Join-Path $fixturesPath 'choicecollection-02.json') -Raw | ConvertFrom-Json -Depth 64
        $fixture.Policy.templateReference.templateFamily | Should -Be 'endpointSecurityAttackSurfaceReduction'

        $index = New-TestDefinitionIndex
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($fixture.Settings)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $fixture.Policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'endpointSecurityAttackSurfaceReduction'
            $_.isBaseline | Should -BeFalse
        }
    }

    It 'an ordinary, non-template Settings Catalog policy (templateFamily "none", no templateId) walks with isBaseline:false' {
        $policy = New-TestPolicy -Id 'policy-plain'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'none'
            $_.isBaseline | Should -BeFalse
        }
    }

    It 'a policy whose templateFamily merely starts with "baseline" (future variant) still classifies isBaseline:true (prefix match, not exact)' {
        $policy = New-TestPolicy -Id 'policy-baseline-variant' -TemplateFamily 'baselineWindows10MdmSecurity' -TemplateId 'tpl-baseline-2'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } {
            New-PulseTestGraphEnvelope -Data @($settingsResponse)
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows | ForEach-Object { $_.isBaseline | Should -BeTrue }
    }
}
