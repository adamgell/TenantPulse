BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Invoke-PulseExpansionSummary' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($path)
            New-PulseSnapshotStore -Path $path -Tenant 'tp-test'
        }
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:storeRoot) {
            Remove-Item -LiteralPath $script:storeRoot -Recurse -Force
        }
    }

    It 'returns honest NotExpanded DependencyUnavailable when expansion is opted out' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Invoke-PulseExpansionSummary -Store $store -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
        }

        $result.Status | Should -Be 'NotExpanded'
        $result.FailureClass | Should -Be 'DependencyUnavailable'
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.expansionSummary.status | Should -Be 'NotExpanded'
        $manifest.expansions.expansionSummary.reason | Should -Match 'dependency-unavailable'
    }

    It 'publishes one content-addressed summary of counts, statuses, gaps, caps, and hashes' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $null = Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows @() -Gaps @() -PolicyCount 0
            $gap = [pscustomobject]@{ policyId = 'p-1'; reason = 'category:FetchFailed' }
            $null = Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows @() -Gaps @($gap) -PolicyCount 1
            Invoke-PulseExpansionSummary -Store $store -Requested -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
        }

        $result.Status | Should -Be 'Partial'
        $result.Counts.families | Should -Be 2
        $result.Counts.expanded + $result.Counts.partial + $result.Counts.notExpanded + $result.Counts.failed |
            Should -Be $result.Counts.families
        $result.Statuses.settingsCatalog | Should -Be 'Expanded'
        $result.Statuses.compliance | Should -Be 'NotExpanded'
        $result.Caps.reasonCharacters | Should -Be 500
        $result.Hashes.settingsCatalog | Should -Match '^[0-9a-f]{64}$'
        $result.Gaps.Count | Should -BeGreaterThan 0

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.expansionSummary.status | Should -Be 'Partial'
        $manifest.expansions.expansionSummary.format | Should -Be 'json'
        $manifest.expansions.expansionSummary.sha256 | Should -Match '^[0-9a-f]{64}$'
        $path = Join-Path $script:store.Root $manifest.expansions.expansionSummary.path
        Test-Path -LiteralPath $path | Should -BeTrue
        $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $document.counts | Should -Not -BeNullOrEmpty
        $document.statuses | Should -Not -BeNullOrEmpty
        $document.gaps | Should -Not -BeNullOrEmpty
        $document.caps | Should -Not -BeNullOrEmpty
        $document.hashes | Should -Not -BeNullOrEmpty
    }
}
