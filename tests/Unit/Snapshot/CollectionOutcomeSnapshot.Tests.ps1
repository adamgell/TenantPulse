BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Task 1 snapshot outcome schema' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    It 'creates a schema 2.0.0 store and persists a structured Partial dataset entry' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($root)
            New-PulseSnapshotStore -Path $root
        }

        $gap = InModuleScope TenantPulse {
            New-PulseCollectionGap -Scope 'child-a' -FailureClass 'PermissionDenied' -ReasonCode 'permission-denied' -Detail @{ permission = 'Device.Read.All' } -Operation 'List' -ApiVersion 'beta'
        }

        InModuleScope TenantPulse -ArgumentList $store, $gap {
            param($store, $gap)
            Write-PulseDataset -Store $store -Name 'PartialDataset' -Data @([pscustomobject]@{ id = 'row-1' }) -ApiVersion 'beta' -Status 'Partial' -ReasonCode 'partial-child' -Detail @{ childCount = 2 } -Provider 'GraphKit' -Operations @('List') -Gaps @($gap)
        }

        $manifest = InModuleScope TenantPulse -ArgumentList $store {
            param($store)
            Get-PulseSnapshotManifest -Store $store
        }

        $manifest.schemaVersion | Should -Be '2.0.0'
        $entry = $manifest.datasets.PartialDataset
        $entry.status | Should -Be 'Partial'
        $entry.failureClass | Should -BeNullOrEmpty
        $entry.reasonCode | Should -Be 'partial-child'
        $entry.detail.childCount | Should -Be 2
        $entry.provider | Should -Be 'GraphKit'
        $entry.operations | Should -Be @('List')
        $entry.gaps.Count | Should -Be 1
        $entry.gaps[0].failureClass | Should -Be 'PermissionDenied'

        $rows = InModuleScope TenantPulse -ArgumentList $store {
            param($store)
            Read-PulseDataset -Store $store -Name 'PartialDataset'
        }
        $rows.Count | Should -Be 1
        $rows[0].id | Should -Be 'row-1'
    }

    It 'migrates released 1.0.0 and 1.1.0 manifests in memory without changing the declared schema or inferring from legacy reason text' {
        foreach ($legacyVersion in @('1.0.0', '1.1.0')) {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
            New-Item -Path $root -ItemType Directory -Force | Out-Null
            $manifestPath = Join-Path $root 'manifest.json'
            $legacyNamespaces = if ($legacyVersion -eq '1.1.0') { ',"references":{},"expansions":{}' } else { '' }
            $legacyJson = '{"schemaVersion":"' + $legacyVersion + '","createdUtc":"2026-08-19T00:00:00.000Z","tenant":"tp-legacy","producer":{},"collectionFailure":null,"datasets":{"ok":{"status":"Collected","apiVersion":"v1.0","reason":"descriptor-pending but actually collected","sha256":null,"itemCount":0,"collectedUtc":null},"bad":{"status":"Failed","apiVersion":"v1.0","reason":"descriptor-pending: old text must not be parsed","sha256":null,"itemCount":null,"collectedUtc":null},"skip":{"status":"Skipped","apiVersion":"v1.0","reason":"permission-denied: old text must not be parsed","sha256":null,"itemCount":null,"collectedUtc":null}}' + $legacyNamespaces + '}'
            Set-Content -LiteralPath $manifestPath -Value $legacyJson -NoNewline

            $store = InModuleScope TenantPulse -ArgumentList $root {
                param($root)
                Get-PulseSnapshotStore -Path $root
            }
            $manifest = InModuleScope TenantPulse -ArgumentList $store {
                param($store)
                Get-PulseSnapshotManifest -Store $store
            }

            $manifest.schemaVersion | Should -Be $legacyVersion
            $manifest.datasets.ok.failureClass | Should -BeNullOrEmpty
            $manifest.datasets.ok.gaps.Count | Should -Be 0
            $manifest.datasets.ok.operations.Count | Should -Be 0
            $manifest.datasets.bad.failureClass | Should -Be 'ProviderFailed'
            $manifest.datasets.bad.reasonCode | Should -Be 'legacy-failed'
            $manifest.datasets.skip.failureClass | Should -Be 'GateUnknown'
            $manifest.datasets.skip.reasonCode | Should -Be 'legacy-skipped'
        }
    }

    It 'rejects legacy Partial datasets without changing schema 1.0.0 or 1.1.0 manifest bytes' {
        foreach ($legacyVersion in @('1.0.0', '1.1.0')) {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
            New-Item -Path $root -ItemType Directory -Force | Out-Null
            $manifestPath = Join-Path $root 'manifest.json'
            $legacyNamespaces = if ($legacyVersion -eq '1.1.0') { ',"references":{},"expansions":{}' } else { '' }
            $legacyJson = '{"schemaVersion":"' + $legacyVersion + '","createdUtc":"2026-08-19T00:00:00.000Z","tenant":"tp-legacy","producer":{},"collectionFailure":null,"datasets":{"unsupported":{"status":"Partial","apiVersion":"beta","reason":"unsupported historical state","sha256":null,"itemCount":1,"collectedUtc":null}}' + $legacyNamespaces + '}'
            try {
                [System.IO.File]::WriteAllText($manifestPath, $legacyJson, [System.Text.UTF8Encoding]::new($false))
                $beforeBytes = [System.IO.File]::ReadAllBytes($manifestPath)
                $store = InModuleScope TenantPulse -ArgumentList $root {
                    param($root)
                    Get-PulseSnapshotStore -Path $root
                }

                {
                    InModuleScope TenantPulse -ArgumentList $store {
                        param($store)
                        Get-PulseSnapshotManifest -Store $store
                    }
                } | Should -Throw -ExpectedMessage "*legacy dataset*unsupported status 'Partial'*"

                [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($manifestPath)) |
                    Should -Be ([Convert]::ToBase64String($beforeBytes))
            } finally {
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'applies deterministic structured defaults for direct legacy dataset writes' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($root)
            New-PulseSnapshotStore -Path $root
        }

        InModuleScope TenantPulse -ArgumentList $store {
            param($store)
            Set-PulseManifestEntry -Store $store -Name 'SkippedDataset' -Status 'Skipped' -Reason 'not licensed'
            Set-PulseManifestEntry -Store $store -Name 'FailedDataset' -Status 'Failed'
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.SkippedDataset.failureClass | Should -Be 'GateUnknown'
        $manifest.datasets.SkippedDataset.reasonCode | Should -Be 'not licensed'
        $manifest.datasets.FailedDataset.failureClass | Should -Be 'ProviderFailed'
        $manifest.datasets.FailedDataset.reasonCode | Should -Be 'failed'
        $manifest.datasets.SkippedDataset.reasonCode | Should -Not -BeNullOrEmpty
        $manifest.datasets.FailedDataset.reasonCode | Should -Not -BeNullOrEmpty
    }

    It 'rejects reference writes against a legacy 1.0.0 store without changing its manifest' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $root -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-08-19T00:00:00.000Z","tenant":"tp-legacy","producer":{},"datasets":{}}' -NoNewline
        try {
            $store = InModuleScope TenantPulse -ArgumentList $root {
                param($root)
                Get-PulseSnapshotStore -Path $root
            }
            {
                InModuleScope TenantPulse -ArgumentList $store {
                    param($store)
                    Set-PulseReferenceEntry -Store $store -Name 'legacyReference' -Status 'Failed' -Reason 'not available'
                }
            } | Should -Throw -ExpectedMessage '*1.0.0*references*'

            $rawManifest = Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw
            $rawManifest | Should -Match '"schemaVersion":"1.0.0"'
            $rawManifest | Should -Not -Match '"references"'
        } finally {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rejects an unknown manifest schema version' {
        New-Item -Path $script:storeRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:storeRoot 'manifest.json') -Value '{"schemaVersion":"9.9.9","createdUtc":"2026-08-19T00:00:00.000Z","tenant":null,"producer":{},"datasets":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:storeRoot {
                param($root)
                Get-PulseSnapshotStore -Path $root
            }
        } | Should -Throw -ExpectedMessage '*schemaVersion*9.9.9*'
    }
}
