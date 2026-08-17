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
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads
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

    # Rider fix (a): configurationPolicies WAS collected but expansion was never
    # attempted for this snapshot (no manifest entry) AND neither payload source
    # -FromCapturedPayloads needs (settingDefinitions reference, or a per-policy
    # configurationPolicySettings-<id> dataset) exists - a guaranteed-futile
    # re-derivation attempt, skipped cleanly instead.
    It 'NEVER-EXPANDED, NO CAPTURED PAYLOADS (rider fix a): skips re-derivation cleanly, makes no re-derivation attempt at all' {
        $policy = New-TestPolicyForSnapshot -Id 'policy-never-expanded'
        InModuleScope TenantPulse -ArgumentList $script:store, $policy {
            param($store, $policy)
            Write-PulseDataset -Store $store -Name 'configurationPolicies' -Data @($policy) -ApiVersion 'beta' -Status 'Collected'
            # Deliberately: no settingDefinitions reference, no configurationPolicySettings-*
            # dataset - this snapshot never ran -ExpandSettings's own capture step at all.
        }
        Mock Get-PulseReferenceData -ModuleName TenantPulse { throw 'Get-PulseReferenceData must never be called - this is the skip-cleanly branch (rider fix a).' }

        { InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store } } | Should -Not -Throw

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingsCatalog') | Should -BeFalse
        Should-Invoke Get-PulseReferenceData -ModuleName TenantPulse -Times 0 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    # Rider fix (b): an existing Expanded entry that fails hash verification is tracked as
    # stale; if the re-derivation attempted to replace it then throws, the stale entry
    # must not survive claiming 'Expanded' for a file already proven untrustworthy.
    It 'STALE-ENTRY FAILURE (rider fix b): a hash-invalid Expanded entry whose re-derivation then throws is overwritten to Failed, not left claiming Expanded' {
        $policy = New-TestPolicyForSnapshot -Id 'policy-stale-fail'
        $rawDefinitions = @([pscustomobject]@{ id = 'setting-a'; name = 'a'; displayName = 'A' })
        $response = @([pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'setting-a'; simpleSettingValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'v' } } })
        $index = [ordered]@{ 'setting-a' = [ordered]@{ Name = 'a'; DisplayName = 'A'; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false } }

        InModuleScope TenantPulse -ArgumentList $script:store, $policy, $response, $index, $rawDefinitions {
            param($store, $policy, $response, $index, $rawDefinitions)
            Write-PulseDataset -Store $store -Name 'configurationPolicies' -Data @($policy) -ApiVersion 'beta' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'configurationPolicySettings-policy-stale-fail' -Data $response -ApiVersion 'beta' -Status 'Collected'
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads

            $canonical = ConvertTo-PulseCanonicalJson -InputObject $rawDefinitions
            $tempPath = Join-Path $store.ReferencePath 'settingDefinitions.tmp'
            [System.IO.File]::WriteAllText($tempPath, $canonical, [System.Text.UTF8Encoding]::new($false))
            $sha256 = Get-PulseFileSha256 -Path $tempPath
            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' -Path 'reference/settingDefinitions.json' `
                -SchemaVersion '1.0.0' -Sha256 $sha256 -ItemCount $rawDefinitions.Count -RetrievedUtc '2026-01-01T00:00:00.000Z' -PublishFromTempPath $tempPath
        }

        $manifestBefore = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifestBefore.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $expandedFilePath = Join-Path $script:store.Root $manifestBefore.expansions.settingsCatalog.path
        # Tamper: the recorded entry now fails hash verification (step 2's stale detection).
        Add-Content -LiteralPath $expandedFilePath -Value 'TAMPERED' -NoNewline

        # Force the re-derivation attempt itself to throw, simulating an unexpected
        # mid-walk failure AFTER staleness was already detected.
        Mock Invoke-PulseSettingsCatalogExpansion -ModuleName TenantPulse { throw 'simulated re-derivation failure' }

        { InModuleScope TenantPulse -ArgumentList $script:store { param($store) Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store } } | Should -Not -Throw

        $manifestAfter = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifestAfter.expansions.settingsCatalog.status | Should -Be 'Failed'
        $manifestAfter.expansions.settingsCatalog.reason | Should -Match 'simulated re-derivation failure'
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
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads

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
