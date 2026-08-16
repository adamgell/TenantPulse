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

    # Rider fix (a): when NO policy in the family has ANY captured per-policy assignment
    # payload (a fully virgin family - expansion was never attempted, nothing was ever
    # captured for it), re-derivation is a guaranteed-futile attempt (every policy would
    # gap) - skipped cleanly, no manifest entry written at all, instead of the OLD
    # behavior of attempting anyway and recording NotExpanded. See this file's own
    # docstring rider fix (a) section.
    It 'NEVER-EXPANDED, NO CAPTURED PAYLOADS (rider fix a): skips re-derivation cleanly when zero policies in the family have any captured payload' {
        $policy = New-TestCompliancePolicyForSnapshot -Id 'p4'
        # Deliberately no 'complianceAssignments-p4' dataset written, and no OTHER
        # compliance policy's assignment payload exists either - the whole family is
        # virgin.
        InModuleScope TenantPulse -ArgumentList $script:store, $policy {
            param($store, $policy)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
        }
        Mock Invoke-PulseTypedPolicyExpansion -ModuleName TenantPulse { throw 'Invoke-PulseTypedPolicyExpansion must never be called - this is the skip-cleanly branch (rider fix a).' }

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'compliance') | Should -BeFalse
        Should-Invoke Invoke-PulseTypedPolicyExpansion -ModuleName TenantPulse -Times 0 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    # Distinguishes rider fix (a)'s "whole family virgin" skip from an ordinary per-policy
    # gap: as long as AT LEAST ONE policy in the family has a captured payload, this is not
    # a virgin family, and a re-derivation attempt IS made - a policy lacking its own
    # payload still gaps individually, exactly like a live fetch failure would.
    It 'a captured payload for at least one OTHER policy in the family still triggers re-derivation, gapping the one policy lacking its own payload' {
        $policyWithPayload = New-TestCompliancePolicyForSnapshot -Id 'p5'
        $policyWithoutPayload = New-TestCompliancePolicyForSnapshot -Id 'p6'
        $assignments = @([pscustomobject]@{ id = 'a5'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g5' } })

        InModuleScope TenantPulse -ArgumentList $script:store, $policyWithPayload, $policyWithoutPayload, $assignments {
            param($store, $policyWithPayload, $policyWithoutPayload, $assignments)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policyWithPayload, $policyWithoutPayload) -ApiVersion 'v1.0' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'complianceAssignments-p5' -Data $assignments -ApiVersion 'v1.0' -Status 'Collected'
            # Deliberately no 'complianceAssignments-p6' dataset.
        }

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'Partial'
        $manifest.expansions.compliance.gaps.policyId | Should -Contain 'p6'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    # Rider fix (b): an existing Expanded entry for one family that fails hash
    # verification is tracked as stale; if the re-derivation attempted to replace it then
    # throws, the stale entry must not survive claiming 'Expanded' for a file already
    # proven untrustworthy.
    It 'STALE-ENTRY FAILURE (rider fix b): a hash-invalid Expanded compliance entry whose re-derivation then throws is overwritten to Failed' {
        $policy = New-TestCompliancePolicyForSnapshot -Id 'p7'
        $assignments = @([pscustomobject]@{ id = 'a7'; target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g7' } })
        $typeMap = InModuleScope TenantPulse { $moduleBase = (Get-Module TenantPulse).ModuleBase; (Import-PowerShellDataFile -LiteralPath (Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1')).compliance }

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $assignments, $typeMap {
            param($store, $policy, $assignments, $typeMap)
            Write-PulseDataset -Store $store -Name 'deviceCompliancePolicies' -Data @($policy) -ApiVersion 'v1.0' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'complianceAssignments-p7' -Data $assignments -ApiVersion 'v1.0' -Status 'Collected'
            Invoke-PulseTypedPolicyExpansion -Store $store -Policies @($policy) -PolicyType 'compliance' -TypeMap $typeMap `
                -AssignmentType 'DeviceCompliancePolicyAssignment' -Name 'compliance' -FromCapturedPayloads $true
        }

        $manifestBefore = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifestBefore.expansions.compliance.status | Should -Be 'Expanded'
        $expandedFilePath = Join-Path $script:store.Root $manifestBefore.expansions.compliance.path
        Add-Content -LiteralPath $expandedFilePath -Value 'TAMPERED' -NoNewline

        Mock Invoke-PulseTypedPolicyExpansion -ModuleName TenantPulse { throw 'simulated re-derivation failure' }

        { InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseTypedPolicySnapshotExpansion -Store $store } } | Should -Not -Throw

        $manifestAfter = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifestAfter.expansions.compliance.status | Should -Be 'Failed'
        $manifestAfter.expansions.compliance.reason | Should -Match 'simulated re-derivation failure'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}
