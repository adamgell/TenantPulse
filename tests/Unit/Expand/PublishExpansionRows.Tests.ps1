BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

# Task 4: an explicit UNIT-level test of the shared Publish-PulseExpansionRows helper's own
# ALL-POLICIES-FAILED early exit (see that file's own docstring) - PolicyCount > 0, an
# empty -Rows, and a non-empty -Gaps must yield NotExpanded (never a Partial with an empty
# artifact), with NO jsonl written under expanded/. This behavior is DUAL-OWNED: both
# Invoke-PulseSettingsCatalogExpansion.ps1 (T2.2) and Invoke-PulseTypedPolicyExpansion.ps1
# (T2.3) call this exact function with these exact semantics (see each file's own call
# site) - a change to this early exit affects both callers identically, so it is asserted
# here once, directly against the shared function, in each caller's own idiom (-Name
# 'settingsCatalog' vs. a typed-policy family name like 'compliance'/'deviceConfiguration')
# rather than only indirectly through each caller's own higher-level pipeline tests
# (SettingsCatalogExpansion.Tests.ps1's own ALL-POLICIES-FAILED test, TypedPolicyExpansion.
# Tests.ps1's own NotExpanded coverage) - those exercise the SAME early exit, but only as
# one path through a much larger driver; this file pins the shared contract on its own.
Describe 'Publish-PulseExpansionRows: ALL-POLICIES-FAILED early exit (dual-owned by settingsCatalog and typed-policy callers)' {
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

    It 'settingsCatalog caller idiom: PolicyCount>0, zero rows, gaps>0 yields NotExpanded with no jsonl written' {
        $gaps = @([pscustomobject]@{ policyId = 'policy-a'; reason = 'category:WorkerException' })

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $gaps {
            param($store, $gaps)
            Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows @() -Gaps $gaps -PolicyCount 1
        }

        $result.Status | Should -Be 'NotExpanded'
        $result.PolicyCount | Should -Be 1
        $result.RowCount | Should -Be 0
        $result.Gaps.Count | Should -Be 1

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'all 1 policy'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'settingsCatalog.*.jsonl' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'typed-policy caller idiom (compliance family): PolicyCount>0, zero rows, gaps>0 yields NotExpanded with no jsonl written' {
        $gaps = @(
            [pscustomobject]@{ policyId = 'policy-b'; reason = 'category:AssignmentFetchFailed' }
            [pscustomobject]@{ policyId = 'policy-c'; reason = 'category:AssignmentFetchFailed' }
        )

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $gaps {
            param($store, $gaps)
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows @() -Gaps $gaps -PolicyCount 2
        }

        $result.Status | Should -Be 'NotExpanded'
        $result.PolicyCount | Should -Be 2
        $result.RowCount | Should -Be 0
        $result.Gaps.Count | Should -Be 2

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.compliance.status | Should -Be 'NotExpanded'
        $manifest.expansions.compliance.reason | Should -Match 'all 2 policy'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'compliance.*.jsonl' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'typed-policy caller idiom (deviceConfiguration family): PolicyCount>0, zero rows, gaps>0 yields NotExpanded with no jsonl written' {
        $gaps = @([pscustomobject]@{ policyId = 'policy-d'; reason = 'category:AssignmentFetchFailed' })

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $gaps {
            param($store, $gaps)
            Publish-PulseExpansionRows -Store $store -Name 'deviceConfiguration' -Rows @() -Gaps $gaps -PolicyCount 1
        }

        $result.Status | Should -Be 'NotExpanded'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.deviceConfiguration.status | Should -Be 'NotExpanded'
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter 'deviceConfiguration.*.jsonl' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
}
