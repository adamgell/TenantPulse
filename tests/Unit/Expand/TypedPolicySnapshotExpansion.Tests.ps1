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
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must never be called by Resolve-PulseTypedPolicySnapshotExpansion (never Graph).' }

    function New-TestCompliancePolicyForSnapshot {
        param([string] $Id)
        return [pscustomobject]@{ id = $Id; displayName = 'P'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; bitLockerEnabled = $true }
    }
}

Describe 'Resolve-PulseTypedPolicySnapshotExpansion' {
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

    It 'no-op for both families when neither raw dataset was ever collected' {
        { InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store } } | Should -Not -Throw

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'compliance') | Should -BeFalse
        ($manifest.expansions.PSObject.Properties.Name -contains 'deviceConfiguration') | Should -BeFalse
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'VERIFIED branch: a hash-valid existing compliance expansion is left untouched' {
        $policy = New-TestCompliancePolicyForSnapshot -Id 'p1'
        $assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } })

        $typeMap = InModuleScope TenantPulse { $moduleBase = (Get-Module TenantPulse).ModuleBase; (Import-PowerShellDataFile -LiteralPath (Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1')).compliance }
        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $assignments {
            param($store, $policy, $assignments)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'complianceAssignments-p1' -Data $assignments -ApiVersion 'v1.0' -Status 'Collected'
        }
        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $typeMap {
            param($store, $policy, $typeMap)
            Invoke-PulseTypedPolicyExpansion -Store $store -Policies @($policy) -PolicyType 'compliance' -TypeMap $typeMap `
                -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance' -FromCapturedPayloads $true
        }

        $beforeManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store }
        $afterManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw

        $afterManifest | Should -Be $beforeManifest
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'ABSENT branch: no compliance expansion entry yet - re-expands via captured payloads, never Graph' {
        $policy = New-TestCompliancePolicyForSnapshot -Id 'p2'
        $assignments = @([pscustomobject]@{ id = 'a2'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g2' } })

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $assignments {
            param($store, $policy, $assignments)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'complianceAssignments-p2' -Data $assignments -ApiVersion 'v1.0' -Status 'Collected'
        }

        $beforeManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($beforeManifest.expansions.PSObject.Properties.Name -contains 'compliance') | Should -BeFalse

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store }

        $afterManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $afterManifest.expansions.compliance.status | Should -Be 'Expanded'
        $afterManifest.expansions.compliance.rowCount | Should -BeGreaterThan 0
        ($afterManifest.expansions.PSObject.Properties.Name -contains 'deviceConfiguration') | Should -BeFalse

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'INVALID (hash-mismatch) branch: a tampered compliance expansion file is re-derived, never trusted as-is' {
        $policy = New-TestCompliancePolicyForSnapshot -Id 'p3'
        $assignments = @([pscustomobject]@{ id = 'a3'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g3' } })
        $typeMap = InModuleScope TenantPulse { $moduleBase = (Get-Module TenantPulse).ModuleBase; (Import-PowerShellDataFile -LiteralPath (Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1')).compliance }

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $assignments, $typeMap {
            param($store, $policy, $assignments, $typeMap)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'complianceAssignments-p3' -Data $assignments -ApiVersion 'v1.0' -Status 'Collected'
            Invoke-PulseTypedPolicyExpansion -Store $store -Policies @($policy) -PolicyType 'compliance' -TypeMap $typeMap `
                -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance' -FromCapturedPayloads $true
        }

        $manifestBefore = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $expandedFilePath = Join-Path $script:store.Root $manifestBefore.expansions.compliance.path
        Add-Content -LiteralPath $expandedFilePath -Value 'TAMPERED' -NoNewline

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store }

        $manifestAfter = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $newFilePath = Join-Path $script:store.Root $manifestAfter.expansions.compliance.path
        $actualBytes = [System.IO.File]::ReadAllBytes($newFilePath)
        $actualHash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($actualBytes)) -replace '-', '').ToLowerInvariant()
        $actualHash | Should -Be $manifestAfter.expansions.compliance.sha256

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'a missing per-policy assignment payload gaps that policy on re-derivation rather than throwing' {
        $policy = New-TestCompliancePolicyForSnapshot -Id 'p4'
        # Deliberately no 'complianceAssignments-p4' dataset written.
        InModuleScope TenantPulse -ArgumentList $script:store, $policy {
            param($store, $policy)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
        }

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'NotExpanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}
