BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    . (Join-Path $script:repoRoot 'tests/Helpers/New-PulseTestGraphEnvelope.ps1')

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

    Mock Get-GraphContext -ModuleName TenantPulse { throw 'Get-GraphContext must be mocked in this test.' }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Get-GraphOperation -ModuleName TenantPulse {
        @{
            Type          = $Type
            Operation     = $Operation
            ApiVersion    = $(if ($Operation -eq 'ListBeta' -or $Type -eq 'AppInstallSummaryReport') { 'beta' } else { 'v1.0' })
            ThrottleClass = 'Read'
            ReplayPolicy  = 'Safe'
        }
    }
    Mock Test-GraphPermission -ModuleName TenantPulse { throw 'Test-GraphPermission must be mocked in this test.' }

    function script:New-TestAuthorizationDecision {
        param(
            [string[]] $Denied = @(),
            [string[]] $Unknown = @()
        )

        $operations = InModuleScope TenantPulse { @(Get-PulseApplicationReportOperations) }
        $decisions = [ordered]@{}
        foreach ($operation in $operations) {
            $key = '{0}/{1}' -f $operation.Type, $operation.Operation
            $decision = if ($Denied -contains $key) { 'Denied' } elseif ($Unknown -contains $key) { 'Unknown' } else { 'Granted' }
            $decisions[$key] = [pscustomobject]@{
                Type       = $operation.Type
                Operation  = $operation.Operation
                ApiVersion = $operation.ApiVersion
                Decision   = $decision
                ReasonCode = $(if ($decision -eq 'Granted') { 'granted' } elseif ($decision -eq 'Denied') { 'missing-grant' } else { 'descriptor-unresolved' })
            }
        }

        [pscustomobject]@{
            Decision   = $(if ($Denied.Count -gt 0) { 'Denied' } elseif ($Unknown.Count -gt 0) { 'Unknown' } else { 'Granted' })
            ReasonCode = $(if ($Denied.Count -gt 0) { 'missing-grant' } elseif ($Unknown.Count -gt 0) { 'permission-unknown' } else { 'granted' })
            Decisions  = $decisions
        }
    }
}

Describe 'TenantPulse application report-data contract' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($root)
            New-PulseSnapshotStore -Path $root -Tenant 'tp-fixture'
        }
        $script:context = [pscustomobject]@{
            ProfileId = 'fixture'
            TenantId  = '11111111-1111-1111-1111-111111111111'
            ClientId  = '22222222-2222-2222-2222-222222222222'
        }
        $script:authorization = New-TestAuthorizationDecision
        $script:abortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'declares the exact read-only GraphKit operation union independently of check selection' {
        $operations = InModuleScope TenantPulse { @(Get-PulseApplicationReportOperations) }
        @($operations).Count | Should -Be 5
        @($operations | ForEach-Object { '{0}/{1}/{2}' -f $_.Type, $_.Operation, $_.ApiVersion }) | Should -Be @(
            'AppInstallSummaryReport/Get/beta'
            'Group/Get/v1.0'
            'GroupMember/List/v1.0'
            'MobileApp/ListBeta/beta'
            'MobileAppAssignment/List/v1.0'
        )
    }

    It 'wires Applications through the public snapshot controller, preflights once, and returns one store object' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse { $script:context }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            @($Baseline).Count | Should -Be 5
            @($Baseline | ForEach-Object { '{0}/{1}' -f $_.Type, $_.Operation }) | Should -Contain 'MobileApp/ListBeta'
            @(
                [pscustomobject]@{ Finding = 'Configured'; Value = 'Unknown' }
                [pscustomobject]@{ Finding = 'Granted'; Value = 'Yes' }
                [pscustomobject]@{ Finding = 'MissingGrant'; Value = 'None' }
                [pscustomobject]@{ Finding = 'ExcessGranted'; Value = 'None' }
                [pscustomobject]@{ Finding = 'AuthenticationCompatible'; Value = 'Yes' }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse { New-PulseTestGraphEnvelope }

        $publicRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $stores = @(Get-PulseTenantSnapshot -ProfileId 'fixture' -OutputPath $publicRoot -ReportData Applications)
            $stores.Count | Should -Be 1
            $manifest = Get-Content -LiteralPath $stores[0].ManifestPath -Raw | ConvertFrom-Json
            $manifest.expansions.'application-assignments'.status | Should -Be 'Expanded'
            $manifest.expansions.'app-install-errors'.status | Should -Be 'Expanded'
            Should-Invoke Test-GraphPermission -ModuleName TenantPulse -Times 1 -Exactly
        } finally {
            Remove-Item -LiteralPath $publicRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'exposes the same Applications report-data profile on the assessment collection surface only' {
        $snapshotParameter = (Get-Command Get-PulseTenantSnapshot).Parameters['ReportData']
        $assessmentParameter = (Get-Command Invoke-PulseAssessment).Parameters['ReportData']
        $snapshotParameter | Should -Not -BeNullOrEmpty
        $assessmentParameter | Should -Not -BeNullOrEmpty
        @($snapshotParameter.Attributes.ValidValues) | Should -Contain 'Applications'
        @($assessmentParameter.Attributes.ValidValues) | Should -Contain 'Applications'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Contain 'Collect'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Not -Contain 'FromSnapshot'
    }

    It 'forwards the selected report-data profile through Invoke-PulseAssessment' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseTenantSnapshot -ModuleName TenantPulse {
            @($ReportData) | Should -Be @('Applications')
            return $script:store
        }

        $assessmentRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $summary = Invoke-PulseAssessment -ProfileId 'fixture' -OutputPath $assessmentRoot -ReportData Applications
            $summary.SnapshotPath | Should -Be $script:store.Root
            Test-Path -LiteralPath $summary.FindingsPath -PathType Leaf | Should -BeTrue
            Should-Invoke Get-PulseTenantSnapshot -ModuleName TenantPulse -ParameterFilter {
                @($ReportData).Count -eq 1 -and $ReportData[0] -eq 'Applications'
            } -Times 1 -Exactly
        } finally {
            Remove-Item -LiteralPath $assessmentRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'records both requested artifacts as NotExpanded when context resolution fails before a request' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'fixture profile unavailable' }

        $failedRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $store = Get-PulseTenantSnapshot -ProfileId 'fixture' -OutputPath $failedRoot -ReportData Applications
            $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
            $manifest.collectionFailure | Should -Match 'authentication-failed'
            $manifest.expansions.'application-assignments'.status | Should -Be 'NotExpanded'
            $manifest.expansions.'app-install-errors'.status | Should -Be 'NotExpanded'
            Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
        } finally {
            Remove-Item -LiteralPath $failedRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'collects schema-v1 assignment and install-error artifacts, resolves every target type, and caches shared groups' {
        $apps = @(
            [pscustomobject]@{ id = 'app-b'; displayName = 'Beta'; publisher = 'Pub B'; '@odata.type' = '#microsoft.graph.win32LobApp'; isFeatured = $true; createdDateTime = '2026-01-02T00:00:00Z'; lastModifiedDateTime = '2026-02-02T00:00:00Z' }
            [pscustomobject]@{ id = 'app-a'; displayName = 'Alpha'; publisher = 'Pub A'; '@odata.type' = '#microsoft.graph.microsoftStoreForBusinessApp'; isFeatured = $false; createdDateTime = '2026-01-01T00:00:00Z'; lastModifiedDateTime = '2026-02-01T00:00:00Z' }
        )
        $assignments = @(
            [pscustomobject]@{ id = 'z-exclude'; intent = 'uninstall'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'group-1'; deviceAndAppManagementAssignmentFilterId = 'filter-1'; deviceAndAppManagementAssignmentFilterType = 'exclude' }; settings = [ordered]@{ vpnConfigurationId = 'cfg-1'; notifications = 'showAll' } }
            [pscustomobject]@{ id = 'a-group'; intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' }; settings = [ordered]@{ notifications = 'hideAll' } }
            [pscustomobject]@{ id = 'm-devices'; intent = 'available'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }; settings = $null }
            [pscustomobject]@{ id = 'n-users'; intent = 'available'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }; settings = $null }
            [pscustomobject]@{ id = 'o-filter'; intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceAndAppManagementAssignmentTarget'; deviceAndAppManagementAssignmentFilterId = 'filter-2'; deviceAndAppManagementAssignmentFilterType = 'include' }; settings = $null }
        )
        $reportPayload = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'AppName' }
                [pscustomobject]@{ Column = 'AppId' }
                [pscustomobject]@{ Column = 'ErrorCode' }
                [pscustomobject]@{ Column = 'DeviceCount' }
                [pscustomobject]@{ Column = 'UserCount' }
            )
            Values = @(
                @('Beta', 'app-b', '0x87D13B64', 7, 3)
            )
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            $PassThruResult | Should -BeTrue
            New-PulseTestGraphEnvelope -Data $apps
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-a' } {
            New-PulseTestGraphEnvelope
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-b' } {
            New-PulseTestGraphEnvelope -Data $assignments
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'group-1'; displayName = 'Pilot Users'; description = 'Pilot ring' })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'm-1' }, [pscustomobject]@{ id = 'm-2' })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $Parameters.Body.filter | Should -Be ''
            New-PulseTestGraphEnvelope -Data @($reportPayload)
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'Expanded'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'application-assignments'.schemaVersion | Should -Be '1'
        $manifest.expansions.'application-assignments'.rowCount | Should -Be 6
        $manifest.expansions.'app-install-errors'.schemaVersion | Should -Be '1'
        $manifest.expansions.'app-install-errors'.rowCount | Should -Be 1

        $assignmentRows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'application-assignments')
        }
        $assignmentRows[0].appId | Should -Be 'app-a'
        $assignmentRows[0].assignmentResolutionState | Should -Be 'NoAssignments'
        @($assignmentRows | ForEach-Object targetType) | Should -Contain 'groupAssignmentTarget'
        @($assignmentRows | ForEach-Object targetType) | Should -Contain 'exclusionGroupAssignmentTarget'
        @($assignmentRows | ForEach-Object targetType) | Should -Contain 'allDevicesAssignmentTarget'
        @($assignmentRows | ForEach-Object targetType) | Should -Contain 'allLicensedUsersAssignmentTarget'
        @($assignmentRows | ForEach-Object targetType) | Should -Contain 'deviceAndAppManagementAssignmentTarget'

        $groupRow = $assignmentRows | Where-Object assignmentId -eq 'a-group'
        $groupRow.groupName | Should -Be 'Pilot Users'
        $groupRow.groupDescription | Should -Be 'Pilot ring'
        $groupRow.groupMemberCount | Should -Be 2
        $groupRow.groupResolutionState | Should -Be 'Resolved'
        $groupRow.memberResolutionState | Should -Be 'Complete'
        $groupRow.settings.notifications | Should -Be 'hideAll'

        $exclusionRow = $assignmentRows | Where-Object assignmentId -eq 'z-exclude'
        $exclusionRow.isExclusion | Should -BeTrue
        $exclusionRow.targetDisplayName | Should -Be 'Exclude: Pilot Users'
        $exclusionRow.filterId | Should -Be 'filter-1'
        $exclusionRow.filterType | Should -Be 'exclude'

        $installRows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'app-install-errors')
        }
        $installRows[0].schemaVersion | Should -Be '1'
        $installRows[0].appName | Should -Be 'Beta'
        $installRows[0].appId | Should -Be 'app-b'
        $installRows[0].errorCode | Should -Be '0x87D13B64'
        $installRows[0].deviceCount | Should -Be 7
        $installRows[0].userCount | Should -Be 3
        $installRows[0].PSObject.Properties.Name | Should -Not -Contain 'severity'
        $installRows[0].PSObject.Properties.Name | Should -Not -Contain 'failureRate'
        $installRows[0].sourceColumns.ErrorCode | Should -Be '0x87D13B64'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { -not $PassThruResult } -Times 0 -Exactly
    }

    It 'blocks only the artifact whose required operation is denied and sends no blocked request' {
        $authorization = New-TestAuthorizationDecision -Denied @('Group/Get', 'AppInstallSummaryReport/Get')

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'NotExpanded'
        $result.AppInstallErrors.Status | Should -Be 'NotExpanded'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'application-assignments'.reason | Should -Match 'permission-preflight'
        $manifest.expansions.'app-install-errors'.reason | Should -Match 'permission-preflight'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'retains partial assignment and member evidence with explicit gaps instead of claiming completeness' {
        $app = [pscustomobject]@{ id = 'app-1'; displayName = 'Partial App'; publisher = 'Vendor'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignment = [pscustomobject]@{ id = 'assignment-1'; intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' }; settings = $null }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope -Data @($app)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } {
            New-PulseTestGraphEnvelope -Data @($assignment) -Truncated $true -PageCount 2
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'group-1'; displayName = 'Known Group'; description = $null })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'member-1' }) -Truncated $true -PageCount 2
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Partial'
        $rows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'application-assignments')
        }
        $rows.Count | Should -Be 1
        $rows[0].assignmentResolutionState | Should -Be 'Partial'
        $rows[0].groupMemberCount | Should -Be 1
        $rows[0].memberResolutionState | Should -Be 'Partial'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps).Count | Should -BeGreaterOrEqual 2
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:page-cap;operation:MobileAppAssignment.List'
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:page-cap;operation:GroupMember.List'
    }

    It 'continues after a per-app 403 and retains an unresolved group id with independently known member count' {
        $apps = @(
            [pscustomobject]@{ id = 'app-group'; displayName = 'Group App'; publisher = 'Vendor'; '@odata.type' = '#microsoft.graph.win32LobApp' }
            [pscustomobject]@{ id = 'app-denied'; displayName = 'Denied App'; publisher = 'Vendor'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        )
        $groupAssignment = [pscustomobject]@{
            id = 'assignment-group'; intent = 'required'
            target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'missing-group' }
            settings = $null
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope -Data $apps
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-group' } {
            New-PulseTestGraphEnvelope -Data @($groupAssignment)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-denied' } {
            throw '403 Forbidden'
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'known-member' })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Partial'
        $rows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'application-assignments')
        }
        ($rows | Where-Object appId -eq 'app-denied').assignmentResolutionState | Should -Be 'Failed'
        $unresolved = $rows | Where-Object appId -eq 'app-group'
        $unresolved.groupId | Should -Be 'missing-group'
        $unresolved.groupName | Should -BeNullOrEmpty
        $unresolved.groupResolutionState | Should -Be 'Failed'
        $unresolved.groupMemberCount | Should -Be 1
        $unresolved.memberResolutionState | Should -Be 'Complete'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:permission-denied;operation:MobileAppAssignment.List'
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:invalid-provider-data;operation:Group.Get'
    }

    It 'normalizes direct named install records while retaining every source column unchanged' {
        $named = [pscustomobject][ordered]@{
            AppDisplayName   = 'Named App'
            ApplicationId    = 'app-named'
            HexErrorCode     = '0x80070005'
            FailedDeviceCount = 11
            FailedUserCount  = 4
            CustomDimension  = 'preserve-me'
        }

        $converted = InModuleScope TenantPulse -ArgumentList (, @($named)) {
            param($rows)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows $rows
        }

        @($converted.Gaps).Count | Should -Be 0
        @($converted.Rows).Count | Should -Be 1
        $converted.Rows[0].appName | Should -Be 'Named App'
        $converted.Rows[0].appId | Should -Be 'app-named'
        $converted.Rows[0].errorCode | Should -Be '0x80070005'
        $converted.Rows[0].deviceCount | Should -Be 11
        $converted.Rows[0].userCount | Should -Be 4
        $converted.Rows[0].sourceColumns.CustomDimension | Should -Be 'preserve-me'
    }

    It 'treats a report matrix with a valid schema and zero values as authoritative empty data' {
        $payload = [pscustomobject]@{
            Schema = @([pscustomobject]@{ Column = 'AppName' }, [pscustomobject]@{ Column = 'ErrorCode' })
            Values = @()
        }

        $converted = InModuleScope TenantPulse -ArgumentList (, @($payload)) {
            param($rows)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows $rows
        }

        @($converted.Rows).Count | Should -Be 0
        @($converted.Gaps).Count | Should -Be 0
    }

    It 'rejects malformed install-report payloads rather than publishing empty success' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ unexpected = 'shape' })
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'NotExpanded'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'app-install-errors'.reason | Should -Match 'invalid-provider-data'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'app-install-errors*.jsonl').Count | Should -Be 0
    }

    It 'publishes byte-identical report rows regardless of input order' {
        $secondRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $secondStore = InModuleScope TenantPulse -ArgumentList $secondRoot {
                param($root)
                New-PulseSnapshotStore -Path $root -Tenant 'tp-fixture'
            }
            $rows = @(
                [pscustomobject][ordered]@{ schemaVersion = '1'; appId = 'b'; assignmentId = '2'; targetType = 'groupAssignmentTarget'; groupId = 'g2' }
                [pscustomobject][ordered]@{ schemaVersion = '1'; appId = 'a'; assignmentId = '1'; targetType = 'allDevicesAssignmentTarget'; groupId = $null }
            )

            InModuleScope TenantPulse -ArgumentList $script:store, $rows {
                param($store, $rows)
                Publish-PulseReportDataRows -Store $store -Name 'application-assignments' -Rows $rows -Gaps @() -SourceCount 2 | Out-Null
            }
            InModuleScope TenantPulse -ArgumentList $secondStore, @($rows[1], $rows[0]) {
                param($store, $rows)
                Publish-PulseReportDataRows -Store $store -Name 'application-assignments' -Rows $rows -Gaps @() -SourceCount 2 | Out-Null
            }

            $firstManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
            $secondManifest = Get-Content -LiteralPath $secondStore.ManifestPath -Raw | ConvertFrom-Json
            $firstPath = Join-Path $script:store.Root $firstManifest.expansions.'application-assignments'.path
            $secondPath = Join-Path $secondStore.Root $secondManifest.expansions.'application-assignments'.path
            [Convert]::ToHexString([IO.File]::ReadAllBytes($firstPath)) | Should -Be ([Convert]::ToHexString([IO.File]::ReadAllBytes($secondPath)))
            $firstManifest.expansions.'application-assignments'.sha256 | Should -Be $secondManifest.expansions.'application-assignments'.sha256
        } finally {
            Remove-Item -LiteralPath $secondRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'aborts later report Graph work after an authentication failure' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            throw 'AADSTS700016: fixture authentication failure'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $script:abortState.AuthenticationAborted | Should -BeTrue
        $result.ApplicationAssignments.Status | Should -Be 'NotExpanded'
        $result.AppInstallErrors.Status | Should -Be 'NotExpanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 0 -Exactly
    }
}
