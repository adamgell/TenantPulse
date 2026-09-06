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
            Type           = $Type
            Operation      = $Operation
            ApiVersion     = $(if ($Operation -eq 'GetBeta') { 'beta' } else { 'v1.0' })
            PagingStrategy = $(if ($Operation -eq 'GetBeta') { 'None' } else { 'NextLink' })
            ThrottleClass  = 'Read'
            ReplayPolicy   = 'Safe'
            RequiredPermissions = @([pscustomobject]@{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' })
        }
    }
    Mock Test-GraphPermission -ModuleName TenantPulse { throw 'Test-GraphPermission must be mocked in this test.' }

    function script:New-DeviceReportStore {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [object[]] $Rows,
            [ValidateSet('Collected', 'Partial')] [string] $Status = 'Collected',
            [object[]] $Gaps = @()
        )

        InModuleScope TenantPulse -ArgumentList $Root, $Rows, $Status, $Gaps {
            param($storeRoot, $deviceRows, $datasetStatus, $datasetGaps)
            $store = New-PulseSnapshotStore -Path $storeRoot -Tenant 'tp-fixture'
            $write = @{
                Store       = $store
                Name        = 'managedDevices'
                Data        = @($deviceRows)
                ApiVersion  = 'v1.0'
                Status      = $datasetStatus
                Provider    = 'GraphKit'
                Operations  = @('List')
                ReasonCode  = $(if ($datasetStatus -eq 'Partial') { 'page-cap-reached' } else { 'collected' })
                FailureClass = $null
                Gaps        = @($datasetGaps)
            }
            Write-PulseDataset @write
            return $store
        }
    }
}

Describe 'TenantPulse managed-device report-data contract' {
    BeforeEach {
        $script:roots = [System.Collections.Generic.List[string]]::new()
    }

    AfterEach {
        foreach ($root in $script:roots) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'declares the exact beta singleton used for authoritative Windows hardware detail' {
        $operations = InModuleScope TenantPulse { @(Get-PulseManagedDeviceReportOperations) }
        $operations.Count | Should -Be 1
        $operations[0].Type | Should -Be 'ManagedDevice'
        $operations[0].Operation | Should -Be 'GetBeta'
        $operations[0].ApiVersion | Should -Be 'beta'
        $operations[0].PagingStrategy | Should -Be 'None'
    }

    It 'exposes Devices on both collection surfaces without adding it to FromSnapshot' {
        $snapshotParameter = (Get-Command Get-PulseTenantSnapshot).Parameters['ReportData']
        $assessmentParameter = (Get-Command Invoke-PulseAssessment).Parameters['ReportData']
        @($snapshotParameter.Attributes.ValidValues) | Should -Contain 'Devices'
        @($assessmentParameter.Attributes.ValidValues) | Should -Contain 'Devices'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Contain 'Collect'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Not -Contain 'FromSnapshot'
    }

    It 'collects managedDevices once even when check selection is empty and publishes the artifact' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $tenantId = @('00000000', '1111', '2222', '3333', '444444444444') -join '-'
        $context = [pscustomobject]@{
            ProfileId = 'fixture'
            TenantId  = $tenantId
            ClientId  = [guid] '22222222-2222-2222-2222-222222222222'
        }
        $devices = @(
            [pscustomobject]@{ id = 'device-b'; deviceName = 'Bravo'; operatingSystem = 'Windows'; isEncrypted = $false; complianceState = 'noncompliant' }
            [pscustomobject]@{ id = 'device-a'; deviceName = 'Alpha'; operatingSystem = 'Windows'; isEncrypted = $true; complianceState = 'compliant' }
        )

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse { $context }
        Mock Test-GraphPermission -ModuleName TenantPulse {
            @($Baseline).Count | Should -Be 2
            @($Baseline | ForEach-Object { '{0}/{1}' -f $_.Type, $_.Operation }) |
                Should -Be @('ManagedDevice/GetBeta', 'ManagedDevice/List')
            @(
                [pscustomobject]@{ Finding = 'Configured'; Value = 'Unknown' }
                [pscustomobject]@{ Finding = 'Granted'; Value = 'Yes' }
                [pscustomobject]@{ Finding = 'MissingGrant'; Value = 'None' }
                [pscustomobject]@{ Finding = 'ExcessGranted'; Value = 'None' }
                [pscustomobject]@{ Finding = 'AuthenticationCompatible'; Value = 'Yes' }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ManagedDevice' -and $Operation -eq 'List' } {
            New-PulseTestGraphEnvelope -Data $devices
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ManagedDevice' -and $Operation -eq 'GetBeta' } {
            $base = @($devices | Where-Object id -EQ $Parameters.id)[0]
            New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                    id = $base.id
                    hardwareInformation = [pscustomobject]@{ tpmVersion = '2.0'; totalStorageSpace = 1024 }
                    deviceHealthAttestationState = [pscustomobject]@{ secureBoot = 'enabled'; tpmVersion = '2.0' }
                    physicalMemoryInBytes = 8589934592
                    processorArchitecture = 'x64'
                })
        }

        $store = Get-PulseTenantSnapshot -ProfileId fixture -OutputPath $root -ReportData Devices
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.managedDevices.status | Should -Be 'Collected'
        $manifest.expansions.'managed-device-inventory'.status | Should -Be 'Expanded'
        $manifest.expansions.'managed-device-inventory'.rowCount | Should -Be 2

        $rows = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'managed-device-inventory')
        }
        @($rows.deviceId) | Should -Be @('device-a', 'device-b')
        @($rows.detailResolutionState) | Should -Be @('Resolved', 'Resolved')
        @($rows.tpmVersion) | Should -Be @('2.0', '2.0')
        @($rows.hardwareInformation.totalStorageSpace) | Should -Be @(1024, 1024)
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ManagedDevice' -and $Operation -eq 'List'
        } -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter {
            $Type -eq 'ManagedDevice' -and $Operation -eq 'GetBeta'
        } -Times 2 -Exactly
        Should-Invoke Test-GraphPermission -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'projects all IHA device-report fields without inventing TPM evidence or severity' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $source = [pscustomobject]@{
            id = 'device-1'; azureADDeviceId = 'entra-1'; deviceName = 'Device 1'
            userPrincipalName = 'user@example.test'; userId = 'user-1'; operatingSystem = 'Windows'
            osVersion = '10.0.26100'; manufacturer = 'Contoso'; model = 'Model'; serialNumber = 'SERIAL'
            physicalMemoryInBytes = 17179869184; isEncrypted = $false; complianceState = 'noncompliant'
            lastSyncDateTime = '2026-09-01T12:00:00Z'; enrolledDateTime = '2026-01-01T12:00:00Z'
            managementAgent = 'mdm'; managedDeviceOwnerType = 'company'; deviceCategoryDisplayName = 'Corporate'
            futureGraphField = 'preserved'
        }
        $store = New-DeviceReportStore -Root $root -Rows @($source)

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseDeviceReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Expanded'

        $row = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'managed-device-inventory')[0]
        }
        $row.schemaVersion | Should -Be '1'
        $row.deviceId | Should -Be 'device-1'
        $row.isEncrypted | Should -BeFalse
        $row.complianceState | Should -Be 'noncompliant'
        $row.sourceColumns.futureGraphField | Should -Be 'preserved'
        @($row.PSObject.Properties.Name) | Should -Not -Contain 'tpmStatus'
        @($row.PSObject.Properties.Name) | Should -Not -Contain 'severity'
    }

    It 'keeps base rows partial and stops later detail reads after an authentication failure' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $store = New-DeviceReportStore -Root $root -Rows @(
            [pscustomobject]@{ id = 'device-a'; deviceName = 'Alpha'; operatingSystem = 'Windows' }
            [pscustomobject]@{ id = 'device-b'; deviceName = 'Bravo'; operatingSystem = 'Windows' }
        )
        $context = [pscustomobject]@{ TenantId = '11111111-1111-1111-1111-111111111111' }
        $authorization = [pscustomobject]@{
            Decisions = [ordered]@{
                'ManagedDevice/GetBeta' = [pscustomobject]@{ Decision = 'Granted'; ReasonCode = 'granted' }
            }
        }
        $abort = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
        Mock Invoke-PulseReportGraphOperation -ModuleName TenantPulse {
            [pscustomobject]@{
                Status = 'Failed'; FailureClass = 'AuthenticationFailed'
                ReasonCode = 'authentication-failed'; Rows = @()
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $store, $context, $authorization, $abort {
            param($snapshotStore, $ctx, $auth, $abortState)
            Invoke-PulseDeviceReportCollection -Store $snapshotStore -Context $ctx `
                -AuthorizationDecision $auth -NetworkAbortState $abortState `
                -ProfileId fixture -Pseudonym tp-fixture
        }
        $result.Status | Should -Be 'Partial'
        $result.RowCount | Should -Be 2
        $abort.AuthenticationAborted | Should -BeTrue
        $rows = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'managed-device-inventory')
        }
        @($rows.detailResolutionState) | Should -Be @('Failed', 'NotEvaluated')
        Should-Invoke Invoke-PulseReportGraphOperation -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'is byte-deterministic across source order' {
        $rootA = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $rootB = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($rootA)
        $script:roots.Add($rootB)
        $rows = @(
            [pscustomobject]@{ id = 'b'; deviceName = 'Bravo'; operatingSystem = 'Windows' }
            [pscustomobject]@{ id = 'a'; deviceName = 'Alpha'; operatingSystem = 'macOS' }
        )
        $storeA = New-DeviceReportStore -Root $rootA -Rows $rows
        $storeB = New-DeviceReportStore -Root $rootB -Rows @($rows[1], $rows[0])

        InModuleScope TenantPulse -ArgumentList $storeA { param($s) Invoke-PulseDeviceReportCollection -Store $s | Out-Null }
        InModuleScope TenantPulse -ArgumentList $storeB { param($s) Invoke-PulseDeviceReportCollection -Store $s | Out-Null }
        $manifestA = Get-Content -LiteralPath $storeA.ManifestPath -Raw | ConvertFrom-Json
        $manifestB = Get-Content -LiteralPath $storeB.ManifestPath -Raw | ConvertFrom-Json
        $manifestA.expansions.'managed-device-inventory'.sha256 |
            Should -Be $manifestB.expansions.'managed-device-inventory'.sha256
    }

    It 'preserves a partial source as a partial artifact with an explicit source gap' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $sourceGap = [pscustomobject]@{
            Scope        = 'page'
            FailureClass = 'Indeterminate'
            ReasonCode   = 'page-cap-reached'
            Detail       = @{ pageCount = 100 }
            Operation    = 'ManagedDevice.List'
            ApiVersion   = 'v1.0'
        }
        $store = New-DeviceReportStore -Root $root -Rows @([pscustomobject]@{ id = 'device-1'; deviceName = 'Partial' }) `
            -Status Partial -Gaps @($sourceGap)

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseDeviceReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'Partial'
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'managed-device-inventory'.status | Should -Be 'Partial'
        @($manifest.expansions.'managed-device-inventory'.gaps.reason) |
            Should -Contain 'category:source-dataset-partial;dataset:managedDevices'
    }

    It 'does not publish an authoritative empty artifact from a failed source dataset' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $store = InModuleScope TenantPulse -ArgumentList $root {
            param($storeRoot)
            $snapshotStore = New-PulseSnapshotStore -Path $storeRoot -Tenant 'tp-fixture'
            Write-PulseDataset -Store $snapshotStore -Name managedDevices -ApiVersion v1.0 -Status Failed `
                -Reason 'permission-denied' -ReasonCode 'permission-denied' -FailureClass PermissionDenied `
                -Provider GraphKit -Operations @('List')
            return $snapshotStore
        }

        $result = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            Invoke-PulseDeviceReportCollection -Store $snapshotStore
        }
        $result.Status | Should -Be 'NotExpanded'
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.'managed-device-inventory'.status | Should -Be 'NotExpanded'
        [string] $manifest.expansions.'managed-device-inventory'.path | Should -BeNullOrEmpty
    }

    It 'gaps unusable rows and recursively pseudonymizes the tenant id before publication' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        $tenantId = @('00000000', '1111', '2222', '3333', '444444444444') -join '-'
        $store = New-DeviceReportStore -Root $root -Rows @(
            [pscustomobject]@{ id = 'device-1'; deviceName = 'Good'; nested = [pscustomobject]@{ tenant = $tenantId } }
            [pscustomobject]@{ operatingSystem = 'Windows' }
            $null
        )

        $result = InModuleScope TenantPulse -ArgumentList $store, $tenantId {
            param($snapshotStore, $rawTenantId)
            Invoke-PulseDeviceReportCollection -Store $snapshotStore -TenantId $rawTenantId -Pseudonym 'tp-redacted'
        }
        $result.Status | Should -Be 'Partial'
        $result.RowCount | Should -Be 1
        @($result.Gaps).Count | Should -Be 2
        $artifactPath = (Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json).expansions.'managed-device-inventory'.path
        $artifactText = Get-Content -LiteralPath (Join-Path $store.Root $artifactPath) -Raw
        $artifactText | Should -Not -Match ([regex]::Escape($tenantId))
        $artifactText | Should -Match 'tp-redacted'
    }

    It 'records the device artifact as NotExpanded when context resolution fails' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots.Add($root)
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'fixture profile unavailable' }

        $store = Get-PulseTenantSnapshot -ProfileId fixture -OutputPath $root -ReportData Devices
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.collectionFailure | Should -Match 'authentication-failed'
        $manifest.expansions.'managed-device-inventory'.status | Should -Be 'NotExpanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}
