BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Invoke-PulseConflictDetection' {
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

    It 'is NotExpanded when no family expansions were ever produced (no gap - expected absence)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $result = Invoke-PulseConflictDetection -Store $store
            $result.Status | Should -Be 'NotExpanded'
        }
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.conflicts.status | Should -Be 'NotExpanded'
        $manifest.expansions.PSObject.Properties['conflicts'].Value.gaps | Should -BeNullOrEmpty
    }

    It 'detects a real conflict across two families sharing the same settingDefinitionId' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $complianceRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'Compliance One'
                    templateFamily = $null; isBaseline = $false; settingPath = 'shared-def'; settingDefinitionId = 'shared-def'
                    settingName = 'sharedSetting'; nameResolved = $true; instanceId = 'c1/p:shared-def'; value = 'valueA'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
                })
            $deviceConfigRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'd1'; policyType = 'deviceConfiguration'; policyName = 'DeviceConfig One'
                    templateFamily = $null; isBaseline = $false; settingPath = 'shared-def'; settingDefinitionId = 'shared-def'
                    settingName = 'sharedSetting'; nameResolved = $true; instanceId = 'd1/p:shared-def'; value = 'valueB'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
                })

            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $complianceRows -Gaps @() -PolicyCount 1
            Publish-PulseExpansionRows -Store $store -Name 'deviceConfiguration' -Rows $deviceConfigRows -Gaps @() -PolicyCount 1

            $result = Invoke-PulseConflictDetection -Store $store
            $result.Status | Should -Be 'Expanded'
            $result.ConflictCount | Should -Be 1
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $filePath = Join-Path $script:store.Root $manifest.expansions.conflicts.path
        $doc = Get-Content -LiteralPath $filePath -Raw | ConvertFrom-Json
        $doc.conflicts.Count | Should -Be 1
        $doc.conflicts[0].settingDefinitionId | Should -Be 'shared-def'
        $doc.conflicts[0].assignmentOverlap | Should -Be 'proven'
    }

    It 'a family expansion that was never run (no manifest entry) is silently skipped, not gapped' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1

            $result = Invoke-PulseConflictDetection -Store $store
            $result.Status | Should -Be 'Expanded'
            $result.Gaps.Count | Should -Be 0
        }
    }

    It 'gaps a family whose file no longer matches its recorded hash, still succeeds Partial from the other families' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $goodRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $goodRows -Gaps @() -PolicyCount 1

            $badRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'd1'; policyType = 'deviceConfiguration'; policyName = 'D1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-y'; settingDefinitionId = 'def-y'
                    settingName = 'y'; nameResolved = $true; instanceId = 'd1/p:def-y'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'deviceConfiguration' -Rows $badRows -Gaps @() -PolicyCount 1

            $manifest = Get-PulseSnapshotManifest -Store $store
            $badFilePath = Join-Path $store.Root $manifest.expansions.deviceConfiguration.path
            Add-Content -LiteralPath $badFilePath -Value 'tampered' -NoNewline

            $result = Invoke-PulseConflictDetection -Store $store
            $result.Status | Should -Be 'Partial'
            $result.Gaps.Count | Should -Be 1
            $result.Gaps[0].reason | Should -Match 'FamilyUnavailable'
        }
    }
}

Describe 'Resolve-PulseConflictSnapshotExpansion' {
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

    It 'is a no-op when the existing conflicts artifact still verifies' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1
            Invoke-PulseConflictDetection -Store $store | Out-Null

            $before = (Get-PulseSnapshotManifest -Store $store).expansions.conflicts.sha256

            Resolve-PulseConflictSnapshotExpansion -Store $store

            $after = (Get-PulseSnapshotManifest -Store $store).expansions.conflicts.sha256
            $after | Should -Be $before
        }
    }

    It 're-derives from the family jsonl artifacts, never Graph, when no conflicts entry exists yet' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1

            Resolve-PulseConflictSnapshotExpansion -Store $store

            $manifest = Get-PulseSnapshotManifest -Store $store
            $manifest.expansions.ContainsKey('conflicts') | Should -BeTrue
            $manifest.expansions.conflicts.status | Should -Be 'Expanded'
        }
    }
}
