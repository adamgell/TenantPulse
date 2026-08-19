BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Write-PulseDataset composite outcomes' {
    It 'round-trips Partial rows, structured gaps, and operation provenance through the snapshot' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $store = InModuleScope TenantPulse -ArgumentList $root {
                param($path)
                New-PulseSnapshotStore -Path $path -Tenant 'tp-test'
            }
            $gap = InModuleScope TenantPulse {
                New-PulseCollectionGap -Scope 'child-2' -FailureClass 'ProviderFailed' `
                    -ReasonCode 'child-failed' -Detail @{ child = 'child-2' } -Operation 'Get' -ApiVersion 'beta'
            }
            InModuleScope TenantPulse -ArgumentList $store, $gap {
                param($store, $gap)
                Write-PulseDataset -Store $store -Name 'compositeDataset' -Data @([pscustomobject]@{ id = 'row-1' }) `
                    -ApiVersion 'beta' -Status 'Partial' -ReasonCode 'partial' -Detail @{ childCount = 2 } `
                    -FailureClass $null -Provider 'GraphKit' -Operations @('List', 'Get') -Gaps @($gap)
            }

            $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
            $manifest.datasets.compositeDataset.status | Should -Be 'Partial'
            $manifest.datasets.compositeDataset.reasonCode | Should -Be 'partial'
            $manifest.datasets.compositeDataset.operations | Should -Be @('List', 'Get')
            $manifest.datasets.compositeDataset.gaps[0].scope | Should -Be 'child-2'
            $rows = InModuleScope TenantPulse -ArgumentList $store {
                param($store)
                Read-PulseDataset -Store $store -Name 'compositeDataset'
            }
            $rows.id | Should -Be 'row-1'
        }
        finally {
            if (Test-Path -LiteralPath $root) {
                Remove-Item -LiteralPath $root -Recurse -Force
            }
        }
    }
}
