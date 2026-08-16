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
    }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }

    $script:typedPolicyMaps = Import-PowerShellDataFile -LiteralPath (Join-Path $built.FullName 'Data/TypedPolicyMaps.psd1')

    function New-TestCompliancePolicy {
        param([string] $Id, [string] $Name = 'Test Compliance', [string] $ODataType = '#microsoft.graph.windows10CompliancePolicy')
        return [pscustomobject]@{ id = $Id; displayName = $Name; '@odata.type' = $ODataType; bitLockerEnabled = $true }
    }

    function New-TestAssignmentResponse {
        param([string] $GroupId = 'group-1')
        return @([pscustomobject]@{ id = "a-$GroupId"; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId } })
    }

    function Get-PulseExpandedJsonlPath {
        param($Store, [string] $Name)
        $manifest = Get-Content -LiteralPath $Store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.$Name
        if (-not $entry -or -not $entry.path) { return $null }
        return Join-Path $Store.Root $entry.path
    }
}

Describe 'Invoke-PulseTypedPolicyExpansion' {
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

    It 'expands one mapped compliance policy end to end: Expanded status, real assignment fan-out attached to every row, generation-named jsonl' {
        $policy = New-TestCompliancePolicy -Id 'p1'
        $assignmentResponse = New-TestAssignmentResponse -GroupId 'g1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicyAssignment' -and $Parameters.id -eq 'p1' } { $assignmentResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $script:typedPolicyMaps.compliance {
            param($store, $context, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @($policy) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 1
        $summary.Gaps.Count | Should -Be 0

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'Expanded'
        $manifest.expansions.compliance.path | Should -Match "compliance\.$($manifest.expansions.compliance.sha256)\.jsonl$"

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store -Name 'compliance'
        $lines = @(Get-Content -LiteralPath $jsonlPath)
        $lines.Count | Should -BeGreaterThan 0
        $rows = $lines | ForEach-Object { $_ | ConvertFrom-Json }
        $rows | ForEach-Object { $_.policyType | Should -Be 'compliance' }
        $rows | ForEach-Object { $_.assignments[0].groupId | Should -Be 'g1' }

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'DeviceCompliancePolicyAssignment' }
    }

    It 'an unmapped @odata.type is gapped with "collected, not setting-expanded: no property map for <type>", never fetches assignments for it, other policies still expand (Partial)' {
        $mapped = New-TestCompliancePolicy -Id 'mapped-1'
        $unmapped = [pscustomobject]@{ id = 'unmapped-1'; displayName = 'Legacy'; version = 1 }
        $assignmentResponse = New-TestAssignmentResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'mapped-1' } { $assignmentResponse }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'unmapped-1' } { throw 'must never be called for an unmapped type' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $mapped, $unmapped, $script:typedPolicyMaps.compliance {
            param($store, $context, $mapped, $unmapped, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @($mapped, $unmapped) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
        }

        $summary.Status | Should -Be 'Partial'
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'unmapped-1'
        $summary.Gaps[0].reason | Should -Match 'collected, not setting-expanded: no property map for'
        $summary.Gaps[0].reason | Should -Match '\(no @odata\.type\)'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Parameters.id -eq 'unmapped-1' }
    }

    It 'exact-match dispatch: a type that merely ENDS WITH a known suffix is never treated as a match (never a suffix/contains bypass)' {
        $spoofed = [pscustomobject]@{ id = 'spoof-1'; displayName = 'Spoofed'; '@odata.type' = '#microsoft.graph.futureWindows10CompliancePolicy' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $spoofed, $script:typedPolicyMaps.compliance {
            param($store, $context, $spoofed, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @($spoofed) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
        }

        $summary.Gaps[0].policyId | Should -Be 'spoof-1'
        $summary.Gaps[0].reason | Should -Match 'no property map for'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'an assignment fetch failure gaps the WHOLE policy (category:AssignmentFetchFailed), never emits rows with a fabricated assignments shape' {
        $policy = New-TestCompliancePolicy -Id 'p-bad'
        $plantedSecretInException = 'PLANTED-EXCEPTION-SECRET-abc123'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'p-bad' } { throw "simulated failure carrying $plantedSecretInException" }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $script:typedPolicyMaps.compliance {
            param($store, $context, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @($policy) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.Gaps[0].reason | Should -Match 'category:AssignmentFetchFailed'
        $summary.Gaps[0].reason | Should -Not -Match ([regex]::Escape($plantedSecretInException))

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecretInException))
    }

    It 'planted Sensitive property value never appears in the manifest or the jsonl artifact' {
        $entry = $script:typedPolicyMaps.deviceConfiguration.'#microsoft.graph.windows10CustomConfiguration'
        $plantedSecret = 'PLANTED-TYPED-SECRET-qqq777'
        $policy = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'c1'
            displayName   = 'Custom'
            omaSettings   = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './x'; value = $plantedSecret })
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'c1' } { @() }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $script:typedPolicyMaps.deviceConfiguration {
            param($store, $context, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @($policy) -PolicyType 'deviceConfiguration' `
                -TypeMap $typeMap -AssignmentType 'DeviceConfigurationAssignment' -Name 'deviceConfiguration'
        }

        $summary.Status | Should -Be 'Expanded'
        $manifestText = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifestText | Should -Not -Match ([regex]::Escape($plantedSecret))

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store -Name 'deviceConfiguration'
        $jsonlText = Get-Content -LiteralPath $jsonlPath -Raw
        $jsonlText | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'an empty -Policies array publishes a valid, empty, Expanded artifact' {
        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $script:typedPolicyMaps.compliance {
            param($store, $context, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @() -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.RowCount | Should -Be 0
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'persists the raw fetched assignment payload as its own hash-verified dataset (complianceAssignments-<policyId>)' {
        $policy = New-TestCompliancePolicy -Id 'p1'
        $assignmentResponse = New-TestAssignmentResponse -GroupId 'g1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicyAssignment' -and $Parameters.id -eq 'p1' } { $assignmentResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $script:typedPolicyMaps.compliance {
            param($store, $context, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $context -Policies @($policy) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.'complianceAssignments-p1'.status | Should -Be 'Collected'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'complianceAssignments-p1.json') -PathType Leaf | Should -BeTrue
    }

    It '-FromCapturedPayloads re-expands from the already-persisted raw assignment dataset, makes NO Graph call at all' {
        $policy = New-TestCompliancePolicy -Id 'p1'
        $assignmentResponse = New-TestAssignmentResponse -GroupId 'g1'

        InModuleScope TenantPulse -ArgumentList $script:store, $assignmentResponse {
            param($store, $assignmentResponse)
            Write-PulseDataset -Store $store -Name 'complianceAssignments-p1' -Data $assignmentResponse -ApiVersion 'v1.0' -Status 'Collected'
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $script:typedPolicyMaps.compliance {
            param($store, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $null -Policies @($policy) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance' -FromCapturedPayloads $true
        }

        $summary.Status | Should -Be 'Expanded'
        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store -Name 'compliance'
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows[0].assignments[0].groupId | Should -Be 'g1'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It '-FromCapturedPayloads with no persisted assignment dataset gaps that ONE policy (AssignmentPayloadMissing), makes NO Graph call' {
        $policy = New-TestCompliancePolicy -Id 'p1'

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $script:typedPolicyMaps.compliance {
            param($store, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Context $null -Policies @($policy) -PolicyType 'compliance' `
                -TypeMap $typeMap -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance' -FromCapturedPayloads $true
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.Gaps[0].reason | Should -Match 'category:AssignmentPayloadMissing'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}
