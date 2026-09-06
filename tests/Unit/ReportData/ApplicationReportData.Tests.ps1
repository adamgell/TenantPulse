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
            PagingStrategy = $(if ($Type -in @('AppInstallSummaryReport', 'Group')) { 'None' } else { 'NextLink' })
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

    function script:New-PulseTestEmptyAppInstallEnvelope {
        New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                Schema = @(
                    [pscustomobject]@{ Column = 'ApplicationId' }
                    [pscustomobject]@{ Column = 'FailedDeviceCount' }
                )
                Values = @()
                TotalRowCount = 0
            })
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
        @($operations | ForEach-Object { '{0}/{1}/{2}' -f $_.Type, $_.Operation, $_.PagingStrategy }) | Should -Be @(
            'AppInstallSummaryReport/Get/None'
            'Group/Get/None'
            'GroupMember/List/NextLink'
            'MobileApp/ListBeta/NextLink'
            'MobileAppAssignment/List/NextLink'
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
        Mock Get-GraphObject -ModuleName TenantPulse {
            if ($Type -eq 'AppInstallSummaryReport') { return New-PulseTestEmptyAppInstallEnvelope }
            New-PulseTestGraphEnvelope
        }

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
            TotalRowCount = 1
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

    It 'request-body pages the real app-install summary shape through TotalRowCount' {
        $script:installReportSchema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
            [pscustomobject]@{ Column = 'FailedUserCount' }
            [pscustomobject]@{ Column = 'PendingInstallDeviceCount' }
        )
        $firstValues = [object[]]::new(2)
        $firstValues[0] = [object[]]@('app-1', 'Alpha', 3, 1, 2)
        $firstValues[1] = [object[]]@('app-2', 'Beta', 0, 0, 4)
        $secondValues = [object[]]::new(1)
        $secondValues[0] = [object[]]@('app-3', 'Gamma', 7, 2, 0)
        $script:installReportBodies = [System.Collections.Generic.List[object]]::new()
        $script:installReportPages = @{
            0 = [pscustomobject]@{ Schema = $script:installReportSchema; Values = $firstValues; TotalRowCount = 3; SessionId = 'session-stable' }
            2 = [pscustomobject]@{ Schema = $script:installReportSchema; Values = $secondValues; TotalRowCount = 3; SessionId = 'session-stable' }
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $script:installReportBodies.Add($Parameters.Body) | Out-Null
            $Parameters.Body.top | Should -Be 200
            @($Parameters.Body.orderBy) | Should -Be @('ApplicationId asc')
            @($Parameters.Body.select).Count | Should -Be 0
            New-PulseTestGraphEnvelope -Data @($script:installReportPages[[int] $Parameters.Body.skip])
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.RowCount | Should -Be 3
        $rows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'app-install-errors')
        }
        @($rows | ForEach-Object appName) | Should -Be @('Alpha', 'Beta', 'Gamma')
        ($rows | Where-Object appId -eq 'app-3').deviceCount | Should -Be 7
        ($rows | Where-Object appId -eq 'app-3').userCount | Should -Be 2
        ($rows | Where-Object appId -eq 'app-1').sourceColumns.PendingInstallDeviceCount | Should -Be 2
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $artifactPath = Join-Path $script:store.Root $manifest.expansions.'app-install-errors'.path
        [IO.File]::ReadAllText($artifactPath) | Should -Not -Match ([regex]::Escape('session-stable'))
        $script:installReportBodies[0].Contains('sessionId') | Should -BeFalse
        $script:installReportBodies[1].sessionId | Should -BeExactly 'session-stable'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 2 -Exactly
    }

    It 'advances request-body paging by the rows actually returned from a short page' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-1', 'Alpha', 1)
        $secondValues = [object[]]::new(1)
        $secondValues[0] = [object[]]@('app-2', 'Beta', 2)
        $script:shortPageBodies = [System.Collections.Generic.List[object]]::new()
        $script:shortPages = @{
            0 = [pscustomobject]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 2; SessionId = 'session-short' }
            1 = [pscustomobject]@{ Schema = $schema; Values = $secondValues; TotalRowCount = 2; SessionId = 'session-short' }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $script:shortPageBodies.Add($Parameters.Body) | Out-Null
            New-PulseTestGraphEnvelope -Data @($script:shortPages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.CollectedRowCount | Should -Be 2
        @($outcome.PayloadRows).Count | Should -Be 2
        @($script:shortPageBodies | ForEach-Object { [int] $_.skip }) | Should -Be @(0, 1)
        foreach ($body in $script:shortPageBodies) {
            $body.top | Should -Be 200
            @($body.orderBy) | Should -Be @('ApplicationId asc')
        }
        $script:shortPageBodies[0].Contains('sessionId') | Should -BeFalse
        $script:shortPageBodies[1].sessionId | Should -BeExactly 'session-short'
    }

    It 'stops Partial before continuing when the first report paging session is <Shape>' -ForEach @(
        @{ Shape = 'missing'; IncludeSession = $false; Session = $null }
        @{ Shape = 'null'; IncludeSession = $true; Session = $null }
        @{ Shape = 'blank'; IncludeSession = $true; Session = '   ' }
        @{ Shape = 'array'; IncludeSession = $true; Session = [object[]] @('session-coercible') }
        @{ Shape = 'numeric'; IncludeSession = $true; Session = 42 }
        @{ Shape = 'boolean'; IncludeSession = $true; Session = $true }
    ) {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-a', 'Alpha', 1)
        $secondValues = [object[]]::new(1)
        $secondValues[0] = [object[]]@('app-b', 'Beta', 2)
        $firstPage = [ordered]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 2 }
        if ($IncludeSession) { $firstPage.SessionId = $Session }
        $script:invalidSessionPages = @{
            0 = [pscustomobject] $firstPage
            1 = [pscustomobject]@{ Schema = $schema; Values = $secondValues; TotalRowCount = 2; SessionId = $Session }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:invalidSessionPages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 1
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain 'category:paging-session-missing;operation:AppInstallSummaryReport.Get'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 1 -Exactly
    }

    It 'discards a later page when its paging session is <Shape>' -ForEach @(
        @{ Shape = 'missing'; IncludeSession = $false; Session = $null; ExpectedReason = 'paging-session-missing' }
        @{ Shape = 'changed'; IncludeSession = $true; Session = 'session-two'; ExpectedReason = 'paging-session-mismatch' }
    ) {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(2)
        $firstValues[0] = [object[]]@('app-a', 'Alpha', 1)
        $firstValues[1] = [object[]]@('app-b', 'Beta', 2)
        $secondValues = [object[]]::new(2)
        $secondValues[0] = [object[]]@('app-d', 'Delta', 3)
        $secondValues[1] = [object[]]@('app-e', 'Echo', 4)
        $secondPage = [ordered]@{ Schema = $schema; Values = $secondValues; TotalRowCount = 4 }
        if ($IncludeSession) { $secondPage.SessionId = $Session }
        $script:shiftedSessionBodies = [System.Collections.Generic.List[object]]::new()
        $script:shiftedSessionPages = @{
            0 = [pscustomobject]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 4; SessionId = 'session-one' }
            2 = [pscustomobject] $secondPage
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $script:shiftedSessionBodies.Add($Parameters.Body) | Out-Null
            New-PulseTestGraphEnvelope -Data @($script:shiftedSessionPages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 2
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain "category:$ExpectedReason;operation:AppInstallSummaryReport.Get"
        $script:shiftedSessionBodies[0].Contains('sessionId') | Should -BeFalse
        $script:shiftedSessionBodies[1].sessionId | Should -BeExactly 'session-one'
    }

    It 'discards a direct named-record response returned as a matrix continuation' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-a', 'Alpha', 1)
        $script:mixedShapeBodies = [System.Collections.Generic.List[object]]::new()
        $script:mixedShapePages = @{
            0 = [pscustomobject]@{
                Schema = $schema; Values = $firstValues; TotalRowCount = 2; SessionId = 'session-mixed-shape'
            }
            1 = [pscustomobject]@{
                ApplicationId = 'app-b'; DisplayName = 'Beta'; FailedDeviceCount = 2; SessionId = 'session-mixed-shape'
            }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $script:mixedShapeBodies.Add($Parameters.Body) | Out-Null
            New-PulseTestGraphEnvelope -Data @($script:mixedShapePages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 1
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps).Count | Should -Be 1
        $outcome.Gaps[0].reason | Should -BeExactly 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get'
        $script:mixedShapeBodies[0].Contains('sessionId') | Should -BeFalse
        $script:mixedShapeBodies[1].sessionId | Should -BeExactly 'session-mixed-shape'
    }

    It 'discards a multi-row matrix continuation containing missing and mismatched paging sessions' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-a', 'Alpha', 1)
        $missingSessionValues = [object[]]::new(1)
        $missingSessionValues[0] = [object[]]@('app-b', 'Beta', 2)
        $mismatchedSessionValues = [object[]]::new(1)
        $mismatchedSessionValues[0] = [object[]]@('app-c', 'Charlie', 3)
        $script:multiRowSessionPages = @{
            0 = @([pscustomobject]@{
                    Schema = $schema; Values = $firstValues; TotalRowCount = 3; SessionId = 'session-one'
                })
            1 = @(
                [pscustomobject]@{
                    Schema = $schema; Values = $missingSessionValues; TotalRowCount = 3
                }
                [pscustomobject]@{
                    Schema = $schema; Values = $mismatchedSessionValues; TotalRowCount = 3; SessionId = 'session-two'
                }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data $script:multiRowSessionPages[[int] $Parameters.Body.skip]
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 1
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get'
    }

    It 'discards a mixed direct-and-matrix multi-row continuation as one unverified response' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-a', 'Alpha', 1)
        $matrixContinuationValues = [object[]]::new(1)
        $matrixContinuationValues[0] = [object[]]@('app-b', 'Beta', 2)
        $script:mixedMultiRowPages = @{
            0 = @([pscustomobject]@{
                    Schema = $schema; Values = $firstValues; TotalRowCount = 3; SessionId = 'session-mixed-multi'
                })
            1 = @(
                [pscustomobject]@{
                    Schema = $schema; Values = $matrixContinuationValues; TotalRowCount = 3; SessionId = 'session-mixed-multi'
                }
                [pscustomobject]@{
                    ApplicationId = 'app-c'; DisplayName = 'Charlie'; FailedDeviceCount = 3; SessionId = 'session-mixed-multi'
                }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data $script:mixedMultiRowPages[[int] $Parameters.Body.skip]
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 1
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get'
    }

    It 'rejects an ambiguous multi-row matrix first response without retaining any payload' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-a', 'Alpha', 1)
        $secondValues = [object[]]::new(1)
        $secondValues[0] = [object[]]@('app-b', 'Beta', 2)
        $script:ambiguousFirstResponse = @(
            [pscustomobject]@{
                Schema = $schema; Values = $firstValues; TotalRowCount = 2; SessionId = 'session-ambiguous'
            }
            [pscustomobject]@{
                Schema = $schema; Values = $secondValues; TotalRowCount = 2; SessionId = 'session-ambiguous'
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data $script:ambiguousFirstResponse
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.CollectedRowCount | Should -Be 0
        @($outcome.PayloadRows).Count | Should -Be 0
        @($outcome.Gaps.reason) | Should -Contain 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get'
    }

    It 'fails closed when reordered report pages overlap on application identity' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-same', 'Before reorder', 1)
        $overlapValues = [object[]]::new(1)
        $overlapValues[0] = [object[]]@('app-same', 'After reorder', 2)
        $script:overlapBodies = [System.Collections.Generic.List[object]]::new()
        $script:overlapPages = @{
            0 = [pscustomobject]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 2; SessionId = 'session-overlap' }
            1 = [pscustomobject]@{ Schema = $schema; Values = $overlapValues; TotalRowCount = 2; SessionId = 'session-overlap' }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $script:overlapBodies.Add($Parameters.Body) | Out-Null
            New-PulseTestGraphEnvelope -Data @($script:overlapPages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 1
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain 'category:overlapping-page;operation:AppInstallSummaryReport.Get'
        @($script:overlapBodies | ForEach-Object { [int] $_.skip }) | Should -Be @(0, 1)
        foreach ($body in $script:overlapBodies) {
            @($body.orderBy) | Should -Be @('ApplicationId asc')
        }
    }

    It 'discards an overlapping later page before retaining its rows when TotalRowCount is missing' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-same', 'Before reorder', 1)
        $overlapValues = [object[]]::new(1)
        $overlapValues[0] = [object[]]@('app-same', 'After reorder', 2)
        $script:missingTotalOverlapPages = @{
            0 = [pscustomobject]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 3; SessionId = 'session-missing-total' }
            1 = [pscustomobject]@{ Schema = $schema; Values = $overlapValues; SessionId = 'session-missing-total' }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:missingTotalOverlapPages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 1
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain 'category:overlapping-page;operation:AppInstallSummaryReport.Get'
    }

    It 'refuses a first page containing duplicate application identities as unusable' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $values = [object[]]::new(2)
        $values[0] = [object[]]@('app-same', 'First copy', 1)
        $values[1] = [object[]]@('APP-SAME', 'Second copy', 2)
        $script:duplicateIdentityPage = [pscustomobject]@{ Schema = $schema; Values = $values; TotalRowCount = 2 }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:duplicateIdentityPage)
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.CollectedRowCount | Should -Be 0
        @($outcome.PayloadRows).Count | Should -Be 0
        @($outcome.Gaps.reason) | Should -Contain 'category:overlapping-page;operation:AppInstallSummaryReport.Get'
    }

    It 'retains a valid later page as Partial when TotalRowCount changes between requests' {
        $schema = @(
            [pscustomobject]@{ Column = 'ApplicationId' }
            [pscustomobject]@{ Column = 'DisplayName' }
            [pscustomobject]@{ Column = 'FailedDeviceCount' }
        )
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-1', 'Alpha', 1)
        $secondValues = [object[]]::new(1)
        $secondValues[0] = [object[]]@('app-2', 'Beta', 2)
        $script:changingTotalPages = @{
            0 = [pscustomobject]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 2; SessionId = 'session-total' }
            1 = [pscustomobject]@{ Schema = $schema; Values = $secondValues; TotalRowCount = 3; SessionId = 'session-total' }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:changingTotalPages[[int] $Parameters.Body.skip])
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.CollectedRowCount | Should -Be 2
        @($outcome.PayloadRows).Count | Should -Be 2
        @($outcome.Gaps.reason) | Should -Contain 'category:total-row-count-mismatch;operation:AppInstallSummaryReport.Get'
    }

    It 'retains earlier install-summary pages as Partial when a declared total cannot be reached' {
        $schema = @([pscustomobject]@{ Column = 'ApplicationId' }, [pscustomobject]@{ Column = 'DisplayName' }, [pscustomobject]@{ Column = 'FailedDeviceCount' })
        $firstValues = [object[]]::new(1)
        $firstValues[0] = [object[]]@('app-1', 'Alpha', 3)
        $script:incompleteReportPages = @{
            0 = [pscustomobject]@{ Schema = $schema; Values = $firstValues; TotalRowCount = 3; SessionId = 'session-incomplete' }
            1 = [pscustomobject]@{ Schema = $schema; Values = @(); TotalRowCount = 3; SessionId = 'session-incomplete' }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:incompleteReportPages[[int] $Parameters.Body.skip])
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'Partial'
        $result.AppInstallErrors.RowCount | Should -Be 1
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'app-install-errors'.gaps.reason) | Should -Contain 'category:total-row-count-mismatch;operation:AppInstallSummaryReport.Get'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 2 -Exactly
    }

    It 'retains earlier install-summary pages as Partial when a later page fails' {
        $values = [object[]]::new(1)
        $values[0] = [object[]]@('app-1', 'Alpha', 3)
        $firstPage = [pscustomobject]@{
            Schema = @([pscustomobject]@{ Column = 'ApplicationId' }, [pscustomobject]@{ Column = 'DisplayName' }, [pscustomobject]@{ Column = 'FailedDeviceCount' })
            Values = $values
            TotalRowCount = 2
            SessionId = 'session-later-failure'
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' -and $Parameters.Body.skip -eq 0 } {
            New-PulseTestGraphEnvelope -Data @($firstPage)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' -and $Parameters.Body.skip -eq 1 } {
            throw '503 Service Unavailable'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'Partial'
        $result.AppInstallErrors.RowCount | Should -Be 1
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'app-install-errors'.gaps.reason) | Should -Contain 'category:provider-failed;operation:AppInstallSummaryReport.Get'
    }

    It 'marks a populated report page Partial when TotalRowCount is missing' {
        $values = [object[]]::new(1)
        $values[0] = [object[]]@('app-1', 'Alpha', 3)
        $page = [pscustomobject]@{
            Schema = @([pscustomobject]@{ Column = 'ApplicationId' }, [pscustomobject]@{ Column = 'DisplayName' }, [pscustomobject]@{ Column = 'FailedDeviceCount' })
            Values = $values
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } { New-PulseTestGraphEnvelope -Data @($page) }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'Partial'
        $result.AppInstallErrors.RowCount | Should -Be 1
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'app-install-errors'.gaps.reason) | Should -Contain 'category:total-row-count-missing;operation:AppInstallSummaryReport.Get'
    }

    It 'bounds request-body paging when the declared total remains unreachable' {
        $script:boundedReportPage = 0
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            $script:boundedReportPage++
            $values = [object[]]::new(1)
            $values[0] = [object[]]@("app-$($script:boundedReportPage)", "App $($script:boundedReportPage)", 1)
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                    Schema = @(
                        [pscustomobject]@{ Column = 'ApplicationId' }
                        [pscustomobject]@{ Column = 'DisplayName' }
                        [pscustomobject]@{ Column = 'FailedDeviceCount' }
                    )
                    Values = $values
                    TotalRowCount = 1000
                    SessionId = 'session-bounded'
                })
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec -MaxPages 2
        }

        $outcome.Status | Should -Be 'Partial'
        @($outcome.PayloadRows).Count | Should -Be 2
        @($outcome.Gaps.reason) | Should -Contain 'category:page-cap;operation:AppInstallSummaryReport.Get'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 2 -Exactly
    }

    It 'stops on a repeated request-body page instead of counting duplicates toward completeness' {
        $values = [object[]]::new(1)
        $values[0] = [object[]]@('app-repeat', 'Repeated App', 1)
        $script:repeatedReportPage = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'DisplayName' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
            )
            Values = $values
            TotalRowCount = 2
            SessionId = 'session-repeat'
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:repeatedReportPage)
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Partial'
        @($outcome.PayloadRows).Count | Should -Be 1
        @($outcome.Gaps.reason) | Should -Contain 'category:repeated-page;operation:AppInstallSummaryReport.Get'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 2 -Exactly
    }

    It 'does not treat an absent first report payload as authoritative empty data' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } { New-PulseTestGraphEnvelope }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'NotExpanded'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'app-install-errors'.reason | Should -Match 'invalid-provider-data'
    }

    It 'accepts a complete direct named-record response without a matrix wrapper' {
        $script:namedReportRows = @(
            [pscustomobject]@{
                ApplicationId = 'app-1'; DisplayName = 'First'; FailedDeviceCount = 0; FailedUserCount = 0
                SessionId = 'session-pscustom-canary'; CustomDimension = 'preserve-first'
            }
            [ordered]@{
                ApplicationId = 'app-2'; DisplayName = 'Second'; FailedDeviceCount = 3; FailedUserCount = 1
                sEsSiOnId = 'session-dictionary-canary'; CustomDimension = 'preserve-second'
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data $script:namedReportRows
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.RowCount | Should -Be 2
        $rows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'app-install-errors')
        }
        @($rows | ForEach-Object appId) | Should -Be @('app-1', 'app-2')
        @($rows | ForEach-Object { $_.sourceColumns.CustomDimension }) | Should -Be @('preserve-first', 'preserve-second')
        foreach ($row in $rows) {
            @($row.sourceColumns.PSObject.Properties.Name | Where-Object {
                    [string]::Equals([string] $_, 'SessionId', [System.StringComparison]::OrdinalIgnoreCase)
                }).Count | Should -Be 0
        }
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $artifactPath = Join-Path $script:store.Root $manifest.expansions.'app-install-errors'.path
        $artifactText = [IO.File]::ReadAllText($artifactPath)
        $artifactText | Should -Not -Match ([regex]::Escape('session-pscustom-canary'))
        $artifactText | Should -Not -Match ([regex]::Escape('session-dictionary-canary'))
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 1 -Exactly
    }

    It 'excludes a case-insensitive SessionId matrix column from persisted report rows' {
        $script:matrixSessionColumnCanary = 'session-matrix-column-canary'
        $matrixValues = [object[]]::new(1)
        $matrixValues[0] = [object[]]@('app-matrix', 'Matrix App', 11, $script:matrixSessionColumnCanary, 'preserve-me')
        $script:matrixSessionColumnPayload = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'DisplayName' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
                [pscustomobject]@{ Column = 'SeSsIoNiD' }
                [pscustomobject]@{ Column = 'CustomDimension' }
            )
            Values = $matrixValues
            TotalRowCount = 1
            SessionId = 'session-page-metadata-canary'
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($script:matrixSessionColumnPayload)
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.AppInstallErrors.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.RowCount | Should -Be 1
        $rows = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            @(Get-PulseExpansionRows -Store $store -Name 'app-install-errors')
        }
        $rows[0].appId | Should -Be 'app-matrix'
        $rows[0].deviceCount | Should -Be 11
        $rows[0].sourceColumns.CustomDimension | Should -Be 'preserve-me'
        @($rows[0].sourceColumns.PSObject.Properties.Name | Where-Object {
                [string]::Equals([string] $_, 'SessionId', [System.StringComparison]::OrdinalIgnoreCase)
            }).Count | Should -Be 0
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $artifactPath = Join-Path $script:store.Root $manifest.expansions.'app-install-errors'.path
        $artifactText = [IO.File]::ReadAllText($artifactPath)
        $artifactText | Should -Not -Match ([regex]::Escape($script:matrixSessionColumnCanary))
        $artifactText | Should -Not -Match ([regex]::Escape('session-page-metadata-canary'))
    }

    It 'reports the terminal row count for a complete direct named-record response' {
        $script:directNamedRows = @(
            [pscustomobject]@{ ApplicationId = 'app-1'; DisplayName = 'First'; FailedDeviceCount = 0 }
            [pscustomobject]@{ ApplicationId = 'app-2'; DisplayName = 'Second'; FailedDeviceCount = 3 }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data $script:directNamedRows
        }
        $spec = InModuleScope TenantPulse {
            @(Get-PulseApplicationReportOperations | Where-Object Type -eq 'AppInstallSummaryReport')[0]
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $script:context, $spec {
            param($context, $operationSpec)
            Invoke-PulseAppInstallReportPages -Context $context -Spec $operationSpec
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.CollectedRowCount | Should -Be 2
        @($outcome.PayloadRows).Count | Should -Be 2
    }

    It 'scrubs the tenant id recursively from settings, descriptions, names, and source columns before publication' {
        $tenantId = [string] $script:context.TenantId
        $app = [pscustomobject]@{ id = 'app-1'; displayName = "App $tenantId"; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignment = [pscustomobject]@{
            id = 'assignment-1'; intent = 'required'
            target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' }
            settings = [ordered]@{ nested = [ordered]@{ tenantReference = "https://example.invalid/$tenantId/value" } }
        }
        $values = [object[]]::new(1)
        $values[0] = [object[]]@('app-1', "Summary $tenantId", 1, "custom-$tenantId")
        $report = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'DisplayName' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
                [pscustomobject]@{ Column = 'CustomDimension' }
            )
            Values = $values
            TotalRowCount = 1
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data @($app) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } { New-PulseTestGraphEnvelope -Data @($assignment) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'group-1'; displayName = 'Group'; description = "Description $tenantId" })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } { New-PulseTestGraphEnvelope -Data @($report) }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-report-redacted' | Out-Null
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        foreach ($name in @('application-assignments', 'app-install-errors')) {
            $path = Join-Path $script:store.Root $manifest.expansions.$name.path
            $raw = [IO.File]::ReadAllText($path)
            $raw | Should -Not -Match ([regex]::Escape($tenantId))
            $raw | Should -Match 'tp-report-redacted'
        }
        $assignmentRows = InModuleScope TenantPulse -ArgumentList $script:store { param($store) @(Get-PulseExpansionRows -Store $store -Name 'application-assignments') }
        $installRows = InModuleScope TenantPulse -ArgumentList $script:store { param($store) @(Get-PulseExpansionRows -Store $store -Name 'app-install-errors') }
        $assignmentRows[0].settings.nested.tenantReference | Should -Be 'https://example.invalid/tp-report-redacted/value'
        $assignmentRows[0].groupDescription | Should -Be 'Description tp-report-redacted'
        $installRows[0].sourceColumns.CustomDimension | Should -Be 'custom-tp-report-redacted'
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

    It 'isolates an install-report denial while still collecting application assignments' {
        $authorization = New-TestAuthorizationDecision -Denied @('AppInstallSummaryReport/Get')
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'NotExpanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 0 -Exactly
    }

    It 'isolates an assignment-operation denial while still collecting the install report' {
        $authorization = New-TestAuthorizationDecision -Denied @('Group/Get')
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestEmptyAppInstallEnvelope
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'NotExpanded'
        $result.AppInstallErrors.Status | Should -Be 'Expanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } -Times 0 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 1 -Exactly
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
            New-PulseTestEmptyAppInstallEnvelope
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

    It 'does not count a member row without identity as complete membership evidence' {
        $app = [pscustomobject]@{
            id = 'app-1'; displayName = 'Malformed Member App'; publisher = 'Vendor'
            '@odata.type' = '#microsoft.graph.win32LobApp'
        }
        $assignment = [pscustomobject]@{
            id = 'assignment-1'; intent = 'required'
            target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' }
            settings = $null
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope -Data @($app)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } {
            New-PulseTestGraphEnvelope -Data @($assignment)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'group-1'; displayName = 'Known Group'; description = $null })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } {
            New-PulseTestGraphEnvelope -Data @(
                [pscustomobject]@{ id = 'member-1' }
                [pscustomobject]@{ displayName = 'Missing identity' }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestEmptyAppInstallEnvelope
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
        $rows[0].groupMemberCount | Should -Be 1
        $rows[0].memberResolutionState | Should -Be 'Partial'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps.reason) |
            Should -Contain 'category:invalid-provider-data;operation:GroupMember.List'
    }

    It 'records a usable indeterminate non-paged Group.Get response as partial evidence with an explicit gap' {
        $app = [pscustomobject]@{ id = 'app-1'; displayName = 'Partial Group App'; publisher = 'Vendor'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignment = [pscustomobject]@{ id = 'assignment-1'; intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' }; settings = $null }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope -Data @($app)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } {
            New-PulseTestGraphEnvelope -Data @($assignment)
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            [pscustomobject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Outcome    = 'Succeeded'
                Certainty  = 'Indeterminate'
                Data       = @([pscustomobject]@{ id = 'group-1'; displayName = 'Known Group'; description = 'Partial metadata' })
                Telemetry  = @()
                Provenance = @{}
            }
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'member-1' })
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
        $rows[0].groupResolutionState | Should -Be 'Partial'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:indeterminate;operation:Group.Get'
    }

    It 'rejects mismatched group metadata identity while retaining independently known membership' {
        $app = [pscustomobject]@{ id = 'app-1'; displayName = 'Identity App'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignment = [pscustomobject]@{ id = 'assignment-1'; intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-requested' } }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data @($app) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } { New-PulseTestGraphEnvelope -Data @($assignment) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'group-other'; displayName = 'Wrong Group'; description = 'Wrong object' })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'member-1' })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } { New-PulseTestGraphEnvelope }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Partial'
        $rows = InModuleScope TenantPulse -ArgumentList $script:store { param($store) @(Get-PulseExpansionRows -Store $store -Name 'application-assignments') }
        $rows[0].groupId | Should -Be 'group-requested'
        $rows[0].groupName | Should -BeNullOrEmpty
        $rows[0].groupDescription | Should -BeNullOrEmpty
        $rows[0].groupResolutionState | Should -Be 'Failed'
        $rows[0].groupMemberCount | Should -Be 1
        $rows[0].memberResolutionState | Should -Be 'Complete'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:invalid-provider-data;operation:Group.Get'
    }

    It 'marks an assignment without its own identity malformed' {
        $app = [pscustomobject]@{ id = 'app-1'; displayName = 'Malformed Assignment App'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignment = [pscustomobject]@{ intent = 'required'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data @($app) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } { New-PulseTestGraphEnvelope -Data @($assignment) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } { New-PulseTestGraphEnvelope }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Partial'
        $rows = InModuleScope TenantPulse -ArgumentList $script:store { param($store) @(Get-PulseExpansionRows -Store $store -Name 'application-assignments') }
        $rows[0].assignmentId | Should -BeNullOrEmpty
        $rows[0].assignmentResolutionState | Should -Be 'Malformed'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Contain 'category:invalid-provider-data;operation:MobileAppAssignment.List'
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

    It 'excludes reserved paging metadata from <Shape> direct records while retaining report columns' -ForEach @(
        @{
            Shape = 'PSCustomObject mixed-case SessionId'
            SessionCanary = 'session-converter-pscustom'
            Record = [pscustomobject][ordered]@{
                AppDisplayName = 'Named App'; ApplicationId = 'app-named'; FailedDeviceCount = 11
                SeSsIoNiD = 'session-converter-pscustom'; CustomDimension = 'preserve-me'
            }
        }
        @{
            Shape = 'IDictionary upper-case SessionId'
            SessionCanary = 'session-converter-dictionary'
            Record = [ordered]@{
                AppDisplayName = 'Named App'; ApplicationId = 'app-named'; FailedDeviceCount = 11
                SESSIONID = 'session-converter-dictionary'; CustomDimension = 'preserve-me'
            }
        }
    ) {
        $converted = InModuleScope TenantPulse -ArgumentList (, @($Record)) {
            param($rows)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows $rows
        }

        @($converted.Gaps).Count | Should -Be 0
        @($converted.Rows).Count | Should -Be 1
        $converted.Rows[0].appName | Should -Be 'Named App'
        $converted.Rows[0].appId | Should -Be 'app-named'
        $converted.Rows[0].deviceCount | Should -Be 11
        $converted.Rows[0].sourceColumns.CustomDimension | Should -Be 'preserve-me'
        @($converted.Rows[0].sourceColumns.Keys | Where-Object {
                [string]::Equals([string] $_, 'SessionId', [System.StringComparison]::OrdinalIgnoreCase)
            }).Count | Should -Be 0
        ($converted.Rows[0] | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($SessionCanary))
    }

    It 'normalizes direct named install records while retaining every report source column unchanged' {
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

        $converted = InModuleScope TenantPulse -ArgumentList $payload {
            param($reportPayload)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows @($reportPayload)
        }

        @($converted.Rows).Count | Should -Be 0
        @($converted.Gaps).Count | Should -Be 0
    }

    It 'rejects an unknown-only report matrix instead of publishing an all-null normalized row' {
        $payload = [pscustomobject]@{
            Schema = @([pscustomobject]@{ Column = 'Foo' }, [pscustomobject]@{ Column = 'Bar' })
            Values = @(@('x', 'y'))
        }

        $converted = InModuleScope TenantPulse -ArgumentList (, @($payload)) {
            param($rows)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows $rows
        }

        @($converted.Rows).Count | Should -Be 0
        @($converted.Gaps).Count | Should -Be 1
        $converted.Gaps[0].reason | Should -Match 'invalid-provider-data'
    }

    It 'rejects recognized report columns whose identity and signal values are empty' {
        $values = [object[]]::new(1)
        $values[0] = [object[]]@($null, '', $null)
        $payload = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'DisplayName' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
            )
            Values = $values
        }

        $converted = InModuleScope TenantPulse -ArgumentList $payload {
            param($reportPayload)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows @($reportPayload)
        }

        @($converted.Rows).Count | Should -Be 0
        @($converted.Gaps).Count | Should -Be 1
        $converted.Gaps[0].reason | Should -Match 'invalid-provider-data'
    }

    It 'preserves numeric zero as a meaningful report signal value' {
        $values = [object[]]::new(1)
        $values[0] = [object[]]@('app-zero', 'Zero App', 0)
        $payload = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'DisplayName' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
            )
            Values = $values
        }

        $converted = InModuleScope TenantPulse -ArgumentList $payload {
            param($reportPayload)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows @($reportPayload)
        }

        @($converted.Gaps).Count | Should -Be 0
        @($converted.Rows).Count | Should -Be 1
        $converted.Rows[0].appId | Should -Be 'app-zero'
        $converted.Rows[0].deviceCount | Should -Be 0
    }

    It 'rejects duplicate normalized report columns and a direct status without application identity' {
        $duplicatePayload = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'application-id' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
            )
            Values = @(@('app-1', 'app-1', 1))
        }
        $statusOnly = [pscustomobject]@{ Status = 'Failed' }

        $converted = InModuleScope TenantPulse -ArgumentList (, @($duplicatePayload, $statusOnly)) {
            param($rows)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows $rows
        }

        @($converted.Rows).Count | Should -Be 0
        @($converted.Gaps).Count | Should -Be 2
        @($converted.Gaps.reason | Where-Object { $_ -match 'invalid-provider-data' }).Count | Should -Be 2
    }

    It 'rejects direct named records whose distinct source keys normalize to the same key' {
        $collision = [pscustomobject][ordered]@{
            ApplicationId    = 'app-original'
            'application-id' = 'app-shadow'
            FailedDeviceCount = 1
        }

        $converted = InModuleScope TenantPulse -ArgumentList $collision {
            param($row)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows @($row)
        }

        @($converted.Rows).Count | Should -Be 0
        @($converted.Gaps).Count | Should -Be 1
        $converted.Gaps[0].reason | Should -Match 'invalid-provider-data'
    }

    It 'retains valid matrix rows and custom columns while isolating a malformed row' {
        $valueRows = [object[]]::new(3)
        $valueRows[0] = [object[]]@('Alpha', '0x1', 'first')
        $valueRows[1] = [object[]]@('short', '0x2')
        $valueRows[2] = [object[]]@('Beta', '0x3', 'second')
        $payload = [pscustomobject]@{
            Schema = @(
                [pscustomobject]@{ Column = 'AppName' }
                [pscustomobject]@{ Column = 'ErrorCode' }
                [pscustomobject]@{ Column = 'CustomDimension' }
            )
            Values = $valueRows
        }

        $converted = InModuleScope TenantPulse -ArgumentList $payload {
            param($reportPayload)
            ConvertTo-PulseAppInstallErrorRows -PayloadRows @($reportPayload)
        }

        @($converted.Rows).Count | Should -Be 2
        @($converted.Gaps).Count | Should -Be 1
        $converted.Gaps[0].policyId | Should -Be 'report-1-row-2'
        $converted.Rows[0].sourceColumns.CustomDimension | Should -Be 'first'
        $converted.Rows[1].sourceColumns.CustomDimension | Should -Be 'second'
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

    It 'publishes byte-identical report rows regardless of input order or duplicate primary sort keys' {
        $secondRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $secondStore = InModuleScope TenantPulse -ArgumentList $secondRoot {
                param($root)
                New-PulseSnapshotStore -Path $root -Tenant 'tp-fixture'
            }
            $assignmentRows = @(
                [pscustomobject][ordered]@{ schemaVersion = '1'; appId = 'same'; assignmentId = 'same'; targetType = 'groupAssignmentTarget'; groupId = 'same'; intent = 'required'; settings = [ordered]@{ notifications = 'hideAll' } }
                [pscustomobject][ordered]@{ schemaVersion = '1'; appId = 'same'; assignmentId = 'same'; targetType = 'groupAssignmentTarget'; groupId = 'same'; intent = 'available'; settings = [ordered]@{ notifications = 'showAll' } }
            )
            $installRows = @(
                [pscustomobject][ordered]@{ schemaVersion = '1'; appName = 'same'; appId = 'same'; errorCode = 'same'; installStatus = 'same'; platform = 'same'; errorMessage = 'first'; sourceColumns = [ordered]@{ Custom = 'a' } }
                [pscustomobject][ordered]@{ schemaVersion = '1'; appName = 'same'; appId = 'same'; errorCode = 'same'; installStatus = 'same'; platform = 'same'; errorMessage = 'second'; sourceColumns = [ordered]@{ Custom = 'b' } }
            )

            InModuleScope TenantPulse -ArgumentList $script:store, $assignmentRows, $installRows {
                param($store, $assignmentRows, $installRows)
                Publish-PulseReportDataRows -Store $store -Name 'application-assignments' -Rows $assignmentRows -Gaps @() -SourceCount 2 | Out-Null
                Publish-PulseReportDataRows -Store $store -Name 'app-install-errors' -Rows $installRows -Gaps @() -SourceCount 2 | Out-Null
            }
            InModuleScope TenantPulse -ArgumentList $secondStore, @($assignmentRows[1], $assignmentRows[0]), @($installRows[1], $installRows[0]) {
                param($store, $assignmentRows, $installRows)
                Publish-PulseReportDataRows -Store $store -Name 'application-assignments' -Rows $assignmentRows -Gaps @() -SourceCount 2 | Out-Null
                Publish-PulseReportDataRows -Store $store -Name 'app-install-errors' -Rows $installRows -Gaps @() -SourceCount 2 | Out-Null
            }

            $firstManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
            $secondManifest = Get-Content -LiteralPath $secondStore.ManifestPath -Raw | ConvertFrom-Json
            foreach ($name in @('application-assignments', 'app-install-errors')) {
                $firstPath = Join-Path $script:store.Root $firstManifest.expansions.$name.path
                $secondPath = Join-Path $secondStore.Root $secondManifest.expansions.$name.path
                [Convert]::ToHexString([IO.File]::ReadAllBytes($firstPath)) | Should -Be ([Convert]::ToHexString([IO.File]::ReadAllBytes($secondPath)))
                $firstManifest.expansions.$name.sha256 | Should -Be $secondManifest.expansions.$name.sha256
            }
        } finally {
            Remove-Item -LiteralPath $secondRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'publishes authoritative empty report artifacts with verified empty-file hashes' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestEmptyAppInstallEnvelope
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'Expanded'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        foreach ($name in @('application-assignments', 'app-install-errors')) {
            $entry = $manifest.expansions.$name
            $entry.status | Should -Be 'Expanded'
            $entry.format | Should -Be 'jsonl'
            $entry.schemaVersion | Should -Be '1'
            $entry.policyCount | Should -Be $(if ($name -eq 'app-install-errors') { 1 } else { 0 })
            $entry.rowCount | Should -Be 0
            $entry.sha256 | Should -Be 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            @($entry.gaps).Count | Should -Be 0
            $entry.reason | Should -BeNullOrEmpty
            $path = Join-Path $script:store.Root $entry.path
            Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $entry.sha256
            $readRows = InModuleScope TenantPulse -ArgumentList $script:store, $name {
                param($store, $artifactName)
                @(Get-PulseExpansionRows -Store $store -Name $artifactName)
            }
            @($readRows).Count | Should -Be 0
        }
    }

    It 'records an assignment artifact redaction failure and still publishes the independent install report' {
        $cycle = [ordered]@{ label = 'assignment-cycle' }
        $cycle.self = $cycle
        $app = [pscustomobject]@{ id = 'app-1'; displayName = 'Cycle App'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignment = [pscustomobject]@{
            id = 'assignment-1'; intent = 'required'
            target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
            settings = $cycle
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data @($app) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } { New-PulseTestGraphEnvelope -Data @($assignment) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } { New-PulseTestEmptyAppInstallEnvelope }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Failed'
        $result.AppInstallErrors.Status | Should -Be 'Expanded'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'application-assignments'.status | Should -Be 'Failed'
        $manifest.expansions.'application-assignments'.reason | Should -Be 'artifact-publication-failed'
        $manifest.expansions.'app-install-errors'.status | Should -Be 'Expanded'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'application-assignments*.jsonl').Count | Should -Be 0
    }

    It 'records an install artifact redaction failure without regressing the published assignment artifact' {
        $cycle = [ordered]@{
            ApplicationId     = 'app-cycle'
            DisplayName       = 'Cycle App'
            FailedDeviceCount = 1
        }
        $cycle.self = $cycle
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($cycle)
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'Failed'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'application-assignments'.status | Should -Be 'Expanded'
        $manifest.expansions.'app-install-errors'.status | Should -Be 'Failed'
        $manifest.expansions.'app-install-errors'.reason | Should -Be 'artifact-publication-failed'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'app-install-errors*.jsonl').Count | Should -Be 0
    }

    It 'contains an install matrix fingerprint failure without regressing the published assignment artifact' {
        $values = [object[]]::new(1)
        $values[0] = [object[]]@('app-cycle', 1)
        $cycle = [ordered]@{
            Schema = @(
                [pscustomobject]@{ Column = 'ApplicationId' }
                [pscustomobject]@{ Column = 'FailedDeviceCount' }
            )
            Values = $values
            TotalRowCount = 1
        }
        $cycle.self = $cycle

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } {
            New-PulseTestGraphEnvelope
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            New-PulseTestGraphEnvelope -Data @($cycle)
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'Failed'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'application-assignments'.status | Should -Be 'Expanded'
        $manifest.expansions.'app-install-errors'.status | Should -Be 'Failed'
        $manifest.expansions.'app-install-errors'.reason | Should -Be 'artifact-publication-failed'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'app-install-errors*.jsonl').Count | Should -Be 0
    }

    It 'aborts all later report reads after Group.Get authentication failure' {
        $apps = @(
            [pscustomobject]@{ id = 'app-1'; displayName = 'First'; '@odata.type' = '#microsoft.graph.win32LobApp' }
            [pscustomobject]@{ id = 'app-2'; displayName = 'Second'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        )
        $assignments = @(
            [pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' } }
            [pscustomobject]@{ id = 'a2'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-2' } }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data $apps }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-1' } { New-PulseTestGraphEnvelope -Data $assignments }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-2' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' -and $Parameters.id -eq 'group-1' } { throw 'AADSTS700016: fixture authentication failure' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' -and $Parameters.id -eq 'group-2' } { New-PulseTestGraphEnvelope }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture' | Out-Null
        }

        $script:abortState.AuthenticationAborted | Should -BeTrue
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json).collectionFailure | Should -Match 'authentication-failed'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } -Times 0 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 0 -Exactly
    }

    It 'preserves fetched assignment truth when child authentication abort suppresses later group resolution' {
        $app = [pscustomobject]@{ id = 'app-1'; displayName = 'Fetched Assignments'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        $assignments = @(
            [pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' } }
            [pscustomobject]@{ id = 'a2'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-2' } }
            [pscustomobject]@{ id = 'a3'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data @($app) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } { New-PulseTestGraphEnvelope -Data $assignments }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' -and $Parameters.id -eq 'group-1' } {
            throw 'AADSTS700016: fixture authentication failure'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Partial'
        $rows = InModuleScope TenantPulse -ArgumentList $script:store { param($store) @(Get-PulseExpansionRows -Store $store -Name 'application-assignments') }
        @($rows).Count | Should -Be 3
        @($rows | ForEach-Object assignmentResolutionState) | Should -Be @('Resolved', 'Resolved', 'Resolved')
        ($rows | Where-Object assignmentId -eq 'a1').groupResolutionState | Should -Be 'Failed'
        ($rows | Where-Object assignmentId -eq 'a2').groupResolutionState | Should -Be 'NotEvaluated'
        ($rows | Where-Object assignmentId -eq 'a2').memberResolutionState | Should -Be 'NotEvaluated'
        ($rows | Where-Object assignmentId -eq 'a3').groupResolutionState | Should -Be 'NotApplicable'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifest.expansions.'application-assignments'.gaps | Where-Object policyId -eq 'group-2').reason |
            Should -Contain 'category:authentication-failed;operation:Group.Get'
        @($manifest.expansions.'application-assignments'.gaps.reason) | Should -Not -Contain 'category:authentication-failed;operation:MobileAppAssignment.List'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } -Times 0 -Exactly
    }

    It 'aborts all later report reads after GroupMember.List authentication failure' {
        $apps = @(
            [pscustomobject]@{ id = 'app-1'; displayName = 'First'; '@odata.type' = '#microsoft.graph.win32LobApp' }
            [pscustomobject]@{ id = 'app-2'; displayName = 'Second'; '@odata.type' = '#microsoft.graph.win32LobApp' }
        )
        $assignments = @(
            [pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-1' } }
            [pscustomobject]@{ id = 'a2'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'group-2' } }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope -Data $apps }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-1' } { New-PulseTestGraphEnvelope -Data $assignments }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' -and $Parameters.id -eq 'app-2' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } {
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = $Parameters.id; displayName = $Parameters.id; description = $null })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' -and $Parameters.id -eq 'group-1' } { throw 'AADSTS700016: fixture authentication failure' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' -and $Parameters.id -eq 'group-2' } { New-PulseTestGraphEnvelope }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture' | Out-Null
        }

        $script:abortState.AuthenticationAborted | Should -BeTrue
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json).collectionFailure | Should -Match 'authentication-failed'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'Group' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'GroupMember' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileAppAssignment' } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 0 -Exactly
    }

    It 'sets the top-level collection failure when install-report authentication fails' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'MobileApp' } { New-PulseTestGraphEnvelope }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } {
            throw 'AADSTS700016: fixture authentication failure'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:authorization, $script:abortState {
            param($store, $context, $authorization, $abortState)
            Invoke-PulseApplicationReportCollection -Store $store -Context $context -AuthorizationDecision $authorization `
                -NetworkAbortState $abortState -ProfileId 'fixture' -Pseudonym 'tp-fixture'
        }

        $result.ApplicationAssignments.Status | Should -Be 'Expanded'
        $result.AppInstallErrors.Status | Should -Be 'NotExpanded'
        $script:abortState.AuthenticationAborted | Should -BeTrue
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json).collectionFailure | Should -Match 'authentication-failed'
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
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json).collectionFailure | Should -Match 'authentication-failed'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'AppInstallSummaryReport' } -Times 0 -Exactly
    }
}
