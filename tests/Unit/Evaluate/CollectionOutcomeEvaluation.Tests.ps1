BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Evaluator collection-outcome boundary' {
    It 'exposes Partial as a distinct manifest status with structured gaps rather than an empty successful dataset' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $entry = InModuleScope TenantPulse -ArgumentList $root {
            param($root)
            $store = New-PulseSnapshotStore -Path $root
            $gap = New-PulseCollectionGap -Scope 'child-a' -FailureClass 'DependencyUnavailable' -ReasonCode 'dependency-unavailable' -Detail @{ dependency = 'groups' } -Operation 'List' -ApiVersion 'beta'
            Write-PulseDataset -Store $store -Name 'compositeDataset' -Data @() -ApiVersion 'beta' -Status 'Partial' -ReasonCode 'partial-child' -Detail @{} -Provider 'GraphKit' -Operations @('List') -Gaps @($gap)
            (Get-PulseSnapshotManifest -Store $store).datasets.compositeDataset
        }

        $entry.status | Should -Be 'Partial'
        $entry.status | Should -Not -Be 'Collected'
        $entry.gaps.Count | Should -Be 1
        $entry.gaps[0].failureClass | Should -Be 'DependencyUnavailable'
        $entry.reasonCode | Should -Be 'partial-child'
    }
}
