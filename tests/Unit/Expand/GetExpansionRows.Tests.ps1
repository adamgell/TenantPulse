BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Get-PulseExpansionRows' {
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

    It 'throws naming the expansion when no manifest entry exists' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            { Get-PulseExpansionRows -Store $store -Name 'settingsCatalog' } | Should -Throw '*no manifest entry*settingsCatalog*'
        }
    }

    It 'throws naming the status when the expansion is NotExpanded' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseExpansionEntry -Store $store -Name 'settingsCatalog' -Status 'NotExpanded' -Reason 'no data'
            { Get-PulseExpansionRows -Store $store -Name 'settingsCatalog' } | Should -Throw "*status 'NotExpanded'*"
        }
    }

    It 'reads back rows written via Publish-PulseExpansionRows, verified' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{ policyId = 'p1'; settingPath = 's1'; instanceId = 'i1'; settingDefinitionId = 'def-1'; value = 'v1' })
            Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount 1

            $readBack = @(Get-PulseExpansionRows -Store $store -Name 'settingsCatalog')
            $readBack.Count | Should -Be 1
            $readBack[0].settingDefinitionId | Should -Be 'def-1'
        }
    }

    It 'throws naming the file on a hash mismatch (tamper detection)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{ policyId = 'p1'; settingPath = 's1'; instanceId = 'i1'; settingDefinitionId = 'def-1'; value = 'v1' })
            $publishResult = Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount 1

            $manifest = Get-PulseSnapshotManifest -Store $store
            $filePath = Join-Path $store.Root $manifest.expansions.settingsCatalog.path
            Add-Content -LiteralPath $filePath -Value 'tampered-line' -NoNewline

            { Get-PulseExpansionRows -Store $store -Name 'settingsCatalog' } | Should -Throw '*hash mismatch*'
        }
    }
}
