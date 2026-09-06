BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Get-GraphOperation { param() }
        function Test-GraphPermission { param() }
    }

    function script:New-AuditReportStore {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [hashtable] $Datasets,
            [hashtable] $Statuses = @{}
        )

        InModuleScope TenantPulse -ArgumentList $Root, $Datasets, $Statuses {
            param($storeRoot, $sourceDatasets, $sourceStatuses)
            $store = New-PulseSnapshotStore -Path $storeRoot -Tenant 'tp-fixture'
            foreach ($name in @($sourceDatasets.Keys | Sort-Object)) {
                $status = if ($sourceStatuses.ContainsKey($name)) { [string] $sourceStatuses[$name] } else { 'Collected' }
                $write = @{
                    Store        = $store
                    Name         = $name
                    Data         = @($sourceDatasets[$name])
                    ApiVersion   = 'beta'
                    Status       = $status
                    Provider     = 'GraphKit'
                    Operations   = @('List')
                    ReasonCode   = $(if ($status -eq 'Partial') { 'page-cap-reached' } else { 'collected' })
                    FailureClass = $null
                    Gaps         = @()
                }
                Write-PulseDataset @write
            }
            return $store
        }
    }
}

Describe 'TenantPulse snapshot-only audit report contract' {
    BeforeEach {
        $script:roots = [System.Collections.Generic.List[string]]::new()
    }

    AfterEach {
        foreach ($root in $script:roots) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'exposes Reports and All only on fresh-collection surfaces' {
        $snapshotParameter = (Get-Command Get-PulseTenantSnapshot).Parameters['ReportData']
        $assessmentParameter = (Get-Command Invoke-PulseAssessment).Parameters['ReportData']
        foreach ($value in @('Reports', 'All')) {
            @($snapshotParameter.Attributes.ValidValues) | Should -Contain $value
            @($assessmentParameter.Attributes.ValidValues) | Should -Contain $value
        }
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Contain 'Collect'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Not -Contain 'FromSnapshot'
    }

    It 'deduplicates the Reports source set inside All and marks every artifact when authentication fails' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'fixture profile unavailable' }

        $store = Get-PulseTenantSnapshot -ProfileId fixture -OutputPath $root -ReportData All
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $expectedDatasets = @(
            'androidEnrollmentProfiles', 'appProtectionPolicies', 'authenticationMethodsPolicy',
            'conditionalAccessPolicies', 'depOnboardingSettings', 'deviceCategories',
            'deviceCompliancePolicies', 'deviceConfigurations', 'deviceEnrollmentConfigurations',
            'deviceManagementScripts', 'deviceManagementSettings', 'directoryRoleAssignments',
            'directoryRoleDefinitions', 'domainConnectors', 'domains', 'groups',
            'managedDeviceCleanupRules', 'managedDevices', 'mobileAppCategories',
            'mobileAppConfigurations', 'ndesConnectors', 'roleAssignmentScheduleInstances',
            'roleEligibilityScheduleInstances', 'subscribedSkus', 'vppTokens',
            'windowsAutopilotDeviceIdentities', 'windowsUpdateCatalogItems'
        ) | Sort-Object
        $datasetNames = @($manifest.datasets.PSObject.Properties.Name | Sort-Object)
        $datasetNames | Should -Be $expectedDatasets
        @($datasetNames | Select-Object -Unique).Count | Should -Be 27
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'compliance-policy-assignments'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'conditional-access-policies'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'connectors-and-tokens'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'directory-role-summary'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'groups-inventory'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'application-assignments'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'app-install-errors'
        @($manifest.expansions.PSObject.Properties.Name) | Should -Contain 'managed-device-inventory'
        foreach ($entry in @($manifest.expansions.PSObject.Properties.Value)) {
            $entry.status | Should -Be 'NotExpanded'
        }
    }

    It 'selects the exact report source datasets once independently of checks' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $script:capturedManifest = @()
        $tenantId = @('00000000', '1111', '2222', '3333', '444444444444') -join '-'
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse {
            [pscustomobject]@{ ProfileId = 'fixture'; TenantId = $tenantId; ClientId = [guid]::Empty }
        }
        Mock Invoke-PulsePermissionPreflight -ModuleName TenantPulse {
            [pscustomobject]@{ Operations = @(); Findings = @(); Decisions = @() }
        }
        Mock Invoke-PulseCollection -ModuleName TenantPulse { $script:capturedManifest = @($Manifest) }
        Mock Invoke-PulseAuditReportCollection -ModuleName TenantPulse { [pscustomobject]@{} }

        $null = Get-PulseTenantSnapshot -ProfileId fixture -OutputPath $root -ReportData Reports
        $expected = @(
            'conditionalAccessPolicies', 'depOnboardingSettings', 'deviceCompliancePolicies',
            'directoryRoleAssignments', 'directoryRoleDefinitions', 'domainConnectors', 'groups',
            'ndesConnectors', 'roleAssignmentScheduleInstances',
            'roleEligibilityScheduleInstances', 'vppTokens'
        ) | Sort-Object
        @($script:capturedManifest.Dataset) | Should -Be $expected
        @($script:capturedManifest.Dataset | Select-Object -Unique).Count | Should -Be 11
        Should-Invoke Invoke-PulseCollection -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Invoke-PulseAuditReportCollection -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'projects compliance policy assignments without flattening assignment evidence' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $policy = [pscustomobject]@{
            id = 'compliance-1'; displayName = 'Windows baseline'
            '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
            passwordRequired = $true; passwordMinimumLength = 14; storageRequireEncryption = $true
            assignments = @([pscustomobject]@{ id = 'assignment-1'; target = [pscustomobject]@{ groupId = 'group-1' } })
            futureField = 'preserved'
        }
        $threatOnlyPolicy = [pscustomobject]@{
            id = 'compliance-2'; displayName = 'Threat protection only'
            '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
            deviceThreatProtectionEnabled = $true
            assignments = @()
        }
        $store = New-AuditReportStore -Root $root -Datasets @{ deviceCompliancePolicies = @($policy, $threatOnlyPolicy) }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseComplianceReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Expanded'
        $reportRows = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'compliance-policy-assignments')
        }
        $row = @($reportRows | Where-Object policyId -EQ 'compliance-1')[0]
        $row.platform | Should -Be 'Windows'
        $row.assignmentCount | Should -Be 1
        $row.assignments[0].target.groupId | Should -Be 'group-1'
        $row.passcodeRequired | Should -BeTrue
        $row.minimumPasscodeLength | Should -Be 14
        $row.encryptionRequired | Should -BeTrue
        $row.sourceColumns.futureField | Should -Be 'preserved'
        @($row.PSObject.Properties.Name) | Should -Not -Contain 'severity'
        $threatOnlyRow = @($reportRows | Where-Object policyId -EQ 'compliance-2')[0]
        $threatOnlyRow.encryptionRequired | Should -BeNullOrEmpty
    }

    It 'publishes normalized Conditional Access overview fields and gaps unrecognized state' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $policies = @(
            [pscustomobject]@{
                id = 'ca-1'; displayName = 'Require MFA'; state = 'enabled'
                createdDateTime = '2026-01-01T00:00:00Z'; modifiedDateTime = '2026-02-01T00:00:00Z'
                conditions = [pscustomobject]@{
                    users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @('breakglass'); includeGroups = @('group-a'); excludeGroups = @('group-b') }
                    applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @('app-x') }
                    clientAppTypes = @('browser')
                }
                grantControls = [pscustomobject]@{ operator = 'AND'; builtInControls = @('mfa') }
            }
            [pscustomobject]@{ id = 'ca-bad'; displayName = 'Future'; state = 'futureValue' }
        )
        $store = New-AuditReportStore -Root $root -Datasets @{ conditionalAccessPolicies = $policies }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseConditionalAccessReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Partial'
        $result.RowCount | Should -Be 1
        @($result.Gaps.reason) | Should -Contain 'category:invalid-provider-data;dataset:conditionalAccessPolicies;detail:normalization-failed'
        $row = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'conditional-access-policies')[0]
        }
        $row.state | Should -Be 'enforced'
        $row.accessType | Should -Be 'Grant'
        $row.usersIncluded | Should -Be @('All')
        $row.usersExcluded | Should -Be @('breakglass')
        $row.groupsIncluded | Should -Be @('group-a')
        $row.applicationsIncluded | Should -Be @('All')
        $row.grantControls.builtInControls | Should -Be @('mfa')
    }

    It 'unions connector and token rows while preserving unavailable sources as certainty gaps' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $store = New-AuditReportStore -Root $root -Datasets @{
            ndesConnectors = @([pscustomobject]@{ id = 'ndes-1'; displayName = 'NDES'; state = 'active'; connectorVersion = '6.0'; machineName = 'srv-1' })
            vppTokens = @([pscustomobject]@{ tokenName = 'VPP'; expirationDateTime = '2027-01-01T00:00:00Z'; appleId = 'admin@example.test' })
        }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseConnectorReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Partial'
        $result.RowCount | Should -Be 2
        @($result.Gaps.policyId) | Should -Contain 'domainConnectors'
        @($result.Gaps.policyId) | Should -Contain 'depOnboardingSettings'
        $rows = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'connectors-and-tokens')
        }
        @($rows.recordType) | Should -Contain 'CertificateConnector'
        @($rows.recordType) | Should -Contain 'AppleVppToken'
        @($rows | Where-Object recordType -EQ 'AppleVppToken')[0].recordId |
            Should -Match '^vppTokens-[0-9a-f]{64}$'
        foreach ($row in $rows) {
            @($row.PSObject.Properties.Name) | Should -Not -Contain 'daysUntilExpiration'
            @($row.PSObject.Properties.Name) | Should -Not -Contain 'severity'
        }
    }

    It 'joins role definitions to permanent, active, and eligible assignment evidence by id' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $store = New-AuditReportStore -Root $root -Datasets @{
            directoryRoleDefinitions = @([pscustomobject]@{ id = 'role-1'; displayName = 'Security Administrator'; description = 'Security'; isBuiltIn = $true; isPrivileged = $true })
            directoryRoleAssignments = @([pscustomobject]@{ id = 'perm-1'; roleDefinitionId = 'role-1'; principalId = 'principal-1' })
            roleAssignmentScheduleInstances = @([pscustomobject]@{ id = 'active-1'; roleDefinitionId = 'role-1'; principalId = 'principal-2' })
            roleEligibilityScheduleInstances = @([pscustomobject]@{ id = 'eligible-1'; roleDefinitionId = 'role-1'; principalId = 'principal-3' })
        }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseDirectoryRoleReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Expanded'
        $row = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'directory-role-summary')[0]
        }
        $row.roleName | Should -Be 'Security Administrator'
        $row.permanentAssignmentCount | Should -Be 1
        $row.activeAssignmentCount | Should -Be 1
        $row.eligibleAssignmentCount | Should -Be 1
        $row.principalIds | Should -Be @('principal-1')
        $row.activeScheduleInstances[0].principalId | Should -Be 'principal-2'
    }

    It 'projects the complete legacy group inventory surface and source columns' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $group = [pscustomobject]@{
            id = 'group-1'; displayName = 'Dynamic Windows'; description = 'Devices'; groupTypes = @('DynamicMembership')
            mail = $null; mailEnabled = $false; mailNickname = 'dynamicwindows'; securityEnabled = $true; visibility = 'Private'
            membershipRule = '(device.deviceOSType -eq "Windows")'; membershipRuleProcessingState = 'On'
            createdDateTime = '2025-01-01T00:00:00Z'; renewedDateTime = '2026-01-01T00:00:00Z'; expirationDateTime = $null
            futureGroupField = 'preserved'
        }
        $store = New-AuditReportStore -Root $root -Datasets @{ groups = @($group, [pscustomobject]@{ description = 'invalid' }) }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseGroupReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Partial'
        $result.RowCount | Should -Be 1
        $row = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'groups-inventory')[0]
        }
        $row.groupId | Should -Be 'group-1'
        $row.groupTypes | Should -Be @('DynamicMembership')
        $row.membershipRuleProcessingState | Should -Be 'On'
        $row.sourceColumns.futureGroupField | Should -Be 'preserved'
    }

    It 'marks a report NotExpanded when its only authoritative source is unavailable' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $store = InModuleScope TenantPulse -ArgumentList $root {
            param($storeRoot)
            $snapshotStore = New-PulseSnapshotStore -Path $storeRoot -Tenant 'tp-fixture'
            Write-PulseDataset -Store $snapshotStore -Name groups -ApiVersion beta -Status Failed `
                -Reason 'permission-denied' -ReasonCode 'permission-denied' -FailureClass PermissionDenied `
                -Provider GraphKit -Operations @('List')
            return $snapshotStore
        }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseGroupReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'NotExpanded'
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        [string] $manifest.expansions.'groups-inventory'.path | Should -BeNullOrEmpty
    }

    It 'is byte-deterministic across dataset and row order and recursively scrubs tenant ids' {
        $rootA = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $rootB = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($rootA)
        $script:roots.Add($rootB)
        $tenantId = @('00000000', '1111', '2222', '3333', '444444444444') -join '-'
        $rows = @(
            [pscustomobject]@{ id = 'group-b'; displayName = 'Bravo'; nested = [pscustomobject]@{ tenant = $tenantId } }
            [pscustomobject]@{ id = 'group-a'; displayName = 'Alpha' }
        )
        $storeA = New-AuditReportStore -Root $rootA -Datasets @{ groups = $rows }
        $storeB = New-AuditReportStore -Root $rootB -Datasets @{ groups = @($rows[1], $rows[0]) }

        InModuleScope TenantPulse -ArgumentList $storeA, $tenantId {
            param($s, $tid)
            Invoke-PulseGroupReportCollection -Store $s -TenantId $tid -Pseudonym 'tp-redacted' | Out-Null
        }
        InModuleScope TenantPulse -ArgumentList $storeB, $tenantId {
            param($s, $tid)
            Invoke-PulseGroupReportCollection -Store $s -TenantId $tid -Pseudonym 'tp-redacted' | Out-Null
        }
        $manifestA = Get-Content -LiteralPath $storeA.ManifestPath -Raw | ConvertFrom-Json
        $manifestB = Get-Content -LiteralPath $storeB.ManifestPath -Raw | ConvertFrom-Json
        $manifestA.expansions.'groups-inventory'.sha256 | Should -Be $manifestB.expansions.'groups-inventory'.sha256
        $artifactText = Get-Content -LiteralPath (Join-Path $storeA.Root $manifestA.expansions.'groups-inventory'.path) -Raw
        $artifactText | Should -Not -Match ([regex]::Escape($tenantId))
        $artifactText | Should -Match 'tp-redacted'
    }
}
