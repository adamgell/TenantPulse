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
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must never be called by Resolve-PulseSettingsCatalogSnapshotExpansion (P1-11: never Graph).' }

    function New-TestPolicyForSnapshot {
        param([string] $Id)
        return [pscustomobject]@{ id = $Id; name = 'P'; templateReference = [pscustomobject]@{ templateId = ''; templateFamily = 'none' } }
    }
}

Describe 'Resolve-PulseSettingsCatalogSnapshotExpansion (P1-11)' {
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

    It 'no-op when the snapshot never collected configurationPolicies (-ExpandSettings was never used)' {
        { InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store } } | Should -Not -Throw

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingsCatalog') | Should -BeFalse
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'VERIFIED branch: a hash-valid existing expansion is left untouched, no re-expansion attempted' {
        $policy = New-TestPolicyForSnapshot -Id 'policy-1'
        $index = [ordered]@{ 'setting-a' = [ordered]@{ Name = 'a'; DisplayName = 'A'; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false } }
        $response = @([pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'setting-a'; simpleSettingValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'original-value' } } })

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $index, $response {
            param($store, $policy, $index, $response)
            Write-PulseDataset -Store $store -Name 'configurationPolicies' -Data @($policy) -ApiVersion 'beta' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'configurationPolicySettings-policy-1' -Data $response -ApiVersion 'beta' -Status 'Collected'
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -Sequential -FromCapturedPayloads
        }

        $beforeManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store }
        $afterManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw

        $afterManifest | Should -Be $beforeManifest
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'ABSENT branch: no settingsCatalog expansion entry yet - re-expands via -FromCapturedPayloads, never Graph' {
        $policy = New-TestPolicyForSnapshot -Id 'policy-2'
        $rawDefinitions = @([pscustomobject]@{ id = 'setting-a'; name = 'a'; displayName = 'A' })
        $response = @([pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'setting-a'; simpleSettingValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'reexpanded-value' } } })

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $rawDefinitions, $response {
            param($store, $policy, $rawDefinitions, $response)
            Write-PulseDataset -Store $store -Name 'configurationPolicies' -Data @($policy) -ApiVersion 'beta' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'configurationPolicySettings-policy-2' -Data $response -ApiVersion 'beta' -Status 'Collected'

            $canonical = ConvertTo-PulseCanonicalJson -InputObject $rawDefinitions
            $tempPath = Join-Path $store.ReferencePath 'settingDefinitions.tmp'
            [System.IO.File]::WriteAllText($tempPath, $canonical, [System.Text.UTF8Encoding]::new($false))
            $sha256 = Get-PulseFileSha256 -Path $tempPath
            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' -Path 'reference/settingDefinitions.json' `
                -SchemaVersion '1.0.0' -Sha256 $sha256 -ItemCount $rawDefinitions.Count -RetrievedUtc '2026-01-01T00:00:00.000Z' -PublishFromTempPath $tempPath
        }

        # No settingsCatalog expansion entry exists yet - this is the ABSENT case.
        $beforeManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($beforeManifest.expansions.PSObject.Properties.Name -contains 'settingsCatalog') | Should -BeFalse

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store }

        $afterManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $afterManifest.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $afterManifest.expansions.settingsCatalog.rowCount | Should -Be 1

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'INVALID (hash-mismatch) branch: a tampered expansion file is treated as absent and re-derived, never trusted as-is' {
        $policy = New-TestPolicyForSnapshot -Id 'policy-3'
        $rawDefinitions = @([pscustomobject]@{ id = 'setting-a'; name = 'a'; displayName = 'A' })
        $response = @([pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'setting-a'; simpleSettingValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'v' } } })
        $index = [ordered]@{ 'setting-a' = [ordered]@{ Name = 'a'; DisplayName = 'A'; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false } }

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $response, $index, $rawDefinitions {
            param($store, $policy, $response, $index, $rawDefinitions)
            Write-PulseDataset -Store $store -Name 'configurationPolicies' -Data @($policy) -ApiVersion 'beta' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'configurationPolicySettings-policy-3' -Data $response -ApiVersion 'beta' -Status 'Collected'
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -Sequential -FromCapturedPayloads

            $canonical = ConvertTo-PulseCanonicalJson -InputObject $rawDefinitions
            $tempPath = Join-Path $store.ReferencePath 'settingDefinitions.tmp'
            [System.IO.File]::WriteAllText($tempPath, $canonical, [System.Text.UTF8Encoding]::new($false))
            $sha256 = Get-PulseFileSha256 -Path $tempPath
            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' -Path 'reference/settingDefinitions.json' `
                -SchemaVersion '1.0.0' -Sha256 $sha256 -ItemCount $rawDefinitions.Count -RetrievedUtc '2026-01-01T00:00:00.000Z' -PublishFromTempPath $tempPath
        }

        $manifestBefore = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $expandedFilePath = Join-Path $script:store.Root $manifestBefore.expansions.settingsCatalog.path
        # Tamper: append a byte, so the file no longer matches its recorded sha256.
        Add-Content -LiteralPath $expandedFilePath -Value 'TAMPERED' -NoNewline

        InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store }

        $manifestAfter = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        # Re-derived: a NEW generation-named file now exists and the manifest's sha256
        # matches it again (never left pointing at the tampered bytes).
        $newFilePath = Join-Path $script:store.Root $manifestAfter.expansions.settingsCatalog.path
        $actualBytes = [System.IO.File]::ReadAllBytes($newFilePath)
        $actualHash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($actualBytes)) -replace '-', '').ToLowerInvariant()
        $actualHash | Should -Be $manifestAfter.expansions.settingsCatalog.sha256

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}
