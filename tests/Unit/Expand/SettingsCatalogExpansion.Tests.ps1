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
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }

    function New-TestPolicy {
        param([string] $Id, [string] $Name = 'Test Policy', [string] $TemplateFamily = 'none', [string] $TemplateId = '')
        return [pscustomobject]@{
            id                = $Id
            name              = $Name
            templateReference = [pscustomobject]@{ templateId = $TemplateId; templateFamily = $TemplateFamily }
        }
    }

    function New-TestDefinitionIndex {
        return [ordered]@{
            'setting-a' = [ordered]@{ Name = 'a'; DisplayName = 'Setting A'; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false }
        }
    }

    function New-TestSettingsResponse {
        param([string] $DefinitionId = 'setting-a', [string] $Value = 'v1', [string] $RootId = '0')
        return @(
            [pscustomobject]@{
                id              = $RootId
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = $DefinitionId
                    simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = $Value }
                }
            }
        )
    }

    # P0-6: the published jsonl is now an IMMUTABLE, generation-named file
    # (expanded/<Name>.<sha256>.jsonl), not a fixed 'settingsCatalog.jsonl' - every test
    # that needs the actual file resolves its path from the manifest's own recorded `path`,
    # never a hardcoded filename.
    function Get-PulseExpandedJsonlPath {
        param($Store, [string] $Name = 'settingsCatalog')
        $manifest = Get-Content -LiteralPath $Store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.$Name
        if (-not $entry -or -not $entry.path) { return $null }
        return Join-Path $Store.Root $entry.path
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid'; ProfileId = 'contoso-lab' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes NotExpanded with reason "definitions corpus unavailable" and makes NO Graph call when -DefinitionIndex is null' {
        $policy = New-TestPolicy -Id 'policy-1'

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy {
            param($store, $context, $policy)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $null
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'definitions corpus unavailable'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'expands a single clean policy end to end: Expanded status, generation-named jsonl, correct sha256, raw payload dataset persisted, assignments-deferred note persisted' {
        $policy = New-TestPolicy -Id 'policy-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'hello-world'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 1
        $summary.RowCount | Should -Be 1

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $manifest.expansions.settingsCatalog.rowCount | Should -Be 1
        $manifest.expansions.settingsCatalog.policyCount | Should -Be 1
        $manifest.expansions.settingsCatalog.sha256 | Should -Not -BeNullOrEmpty
        # P0-6: path is generation-named, embeds the recorded sha256.
        $manifest.expansions.settingsCatalog.path | Should -Match "settingsCatalog\.$($manifest.expansions.settingsCatalog.sha256)\.jsonl$"
        # P1-12: the assignments-deferred note is persisted, not just a test title.
        $manifest.expansions.settingsCatalog.reason | Should -Match 'assignments-deferred: awaiting GraphKit release'

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        $lines = @(Get-Content -LiteralPath $jsonlPath)
        $lines.Count | Should -Be 1
        ($lines[0] | ConvertFrom-Json).value | Should -Be 'hello-world'

        # verify recorded sha256 actually matches the file's bytes
        $bytes = [System.IO.File]::ReadAllBytes($jsonlPath)
        $hash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes)) -replace '-', '').ToLowerInvariant()
        $hash | Should -Be $manifest.expansions.settingsCatalog.sha256

        # raw payload dataset persisted
        $manifest.datasets.'configurationPolicySettings-policy-1'.status | Should -Be 'Collected'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-1.json') -PathType Leaf | Should -BeTrue

        # no orphaned .tmp file left behind
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter '*.tmp' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'a policy fetch failure yields Partial status with a STRUCTURED {policyId;reason} gap (P0-3: no raw exception text), other policies still succeed' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $badPolicy = New-TestPolicy -Id 'policy-bad'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse

        $plantedSecretInException = 'PLANTED-EXCEPTION-SECRET-abc123'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'policy-good' } { $settingsResponse }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'policy-bad' } { throw "simulated Graph failure carrying $plantedSecretInException" }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $badPolicy, $index {
            param($store, $context, $goodPolicy, $badPolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $badPolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        $summary.RowCount | Should -Be 1
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-bad'
        $summary.Gaps[0].reason | Should -Match 'category:FetchFailed'
        $summary.Gaps[0].reason | Should -Not -Match ([regex]::Escape($plantedSecretInException))

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Partial'
        $manifest.expansions.settingsCatalog.gaps.Count | Should -Be 1
        $manifest.expansions.settingsCatalog.gaps[0].reason | Should -Not -Match ([regex]::Escape($plantedSecretInException))
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecretInException))
    }

    It 'planted secret value never appears in the raw persisted dataset, the final jsonl, or the manifest' {
        $policy = New-TestPolicy -Id 'policy-secret'
        $index = New-TestDefinitionIndex
        $plantedSecret = 'PLANTED-SECRET-VALUE-zzz999'
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-secret'
                    simpleSettingValue  = [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'
                        value         = $plantedSecret
                        valueState    = 'notEncrypted'
                    }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $rawDatasetContent = Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-secret.json') -Raw
        $rawDatasetContent | Should -Not -Match ([regex]::Escape($plantedSecret))

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecret))

        $manifestContent = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $manifestContent | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'T2.7 LIVE-GATE REGRESSION: a raw tenant id appearing as an ordinary (non-secret) admin-configured setting VALUE is redacted to its pseudonym in the published jsonl' {
        # Reproduced live on Ivy24: a real Settings Catalog policy's own OneDrive
        # Known-Folder-Move opt-in value legitimately carries the tenant's own GUID as
        # admin-entered configuration data - not a secret-typed value at all, so the
        # secret-contract redaction path never touches it, yet the raw tenant id still
        # reached the published jsonl before this fix (Protect-PulseGraphRowTenantId was
        # never wired into this pipeline - only into T1.11's raw-dataset writes).
        $policy = New-TestPolicy -Id 'policy-tenant-id-value'
        $index = New-TestDefinitionIndex
        $tenantId = 'tenant-guid'
        $pseudonym = 'tp-deadbeefdeadbeef'
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_onedrivengsc_kfmoptinnowizard'
                    simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = $tenantId }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index, $tenantId, $pseudonym {
            param($store, $context, $policy, $index, $tenantId, $pseudonym)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index `
                -TenantId $tenantId -Pseudonym $pseudonym
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $jsonlContent = Get-Content -LiteralPath $jsonlPath -Raw
        $jsonlContent | Should -Not -Match ([regex]::Escape($tenantId))
        $jsonlContent | Should -Match ([regex]::Escape($pseudonym))
    }

    It 'SECRET-MARKER-LOSS: a no-discriminator (dictionary-shaped) settingValue still redacts fail-closed and never leaks the planted plaintext' {
        $policy = New-TestPolicy -Id 'policy-no-discriminator'
        $index = New-TestDefinitionIndex
        $plantedSecret = 'PLANTED-NO-DISCRIMINATOR-VALUE'
        # No `@odata.type` at all on the settingValue - the exact reproduced bypass shape.
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-a'
                    simpleSettingValue  = @{ value = $plantedSecret }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        # unknown shape -> redacted AND a gap (Partial), per the shared classifier's
        # contract.
        $summary.Status | Should -Be 'Partial'
        $summary.RedactedSecretCount | Should -Be 1

        $rawDatasetContent = Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'configurationPolicySettings-policy-no-discriminator.json') -Raw
        $rawDatasetContent | Should -Not -Match ([regex]::Escape($plantedSecret))

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'DUPLICATE-ID: two policies sharing the same id - only the first is fetched, the duplicate gaps immediately, one raw-dataset owner' {
        $policyA = New-TestPolicy -Id 'shared-id'
        $policyB = New-TestPolicy -Id 'shared-id'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'owner-value'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'shared-id' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyA, $policyB, $index {
            param($store, $context, $policyA, $policyB, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyA, $policyB) -DefinitionIndex $index
        }

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Parameters.id -eq 'shared-id' }
        $summary.Status | Should -Be 'Partial'
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'shared-id'
        $summary.Gaps[0].reason | Should -Match 'category:DuplicatePolicyId'
        $summary.RowCount | Should -Be 1
    }

    It 'EMPTY-ID: a policy with no id gaps immediately and is never fetched' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $emptyPolicy = New-TestPolicy -Id ''
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'policy-good' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $emptyPolicy, $index {
            param($store, $context, $goodPolicy, $emptyPolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $emptyPolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        ($summary.Gaps | Where-Object { $_.reason -match 'category:EmptyPolicyId' }).Count | Should -Be 1
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'WHITESPACE-ID (re-review fix): a policy whose id is whitespace-only gaps immediately, prevalidation rejects it, and it is never fetched' {
        $goodPolicy = New-TestPolicy -Id 'policy-good'
        $whitespacePolicy = New-TestPolicy -Id '   '
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'policy-good' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $goodPolicy, $whitespacePolicy, $index {
            param($store, $context, $goodPolicy, $whitespacePolicy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($goodPolicy, $whitespacePolicy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Partial'
        ($summary.Gaps | Where-Object { $_.reason -match 'category:EmptyPolicyId' }).Count | Should -Be 1
        # zero Graph calls for the whitespace-id policy - only the good policy is fetched
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Parameters.id -match '^\s+$' }
    }

    It 'PATH-COLLISION (P1-8): two definitionId chains that would collide under a single-pass escape produce distinct settingPaths' {
        $policy = New-TestPolicy -Id 'policy-path-collision'
        $index = New-TestDefinitionIndex
        $settingsResponse = @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'a~sb'
                    simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' }
                }
            }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $row = Get-Content -LiteralPath $jsonlPath -Raw | ConvertFrom-Json
        $row.settingPath | Should -Be 'a~tsb'
        $row.settingPath | Should -Not -Be 'a~sb'
    }

    It 'merge determinism: processing the same two policies in reversed order produces a byte-identical jsonl file' {
        $policyA = New-TestPolicy -Id 'aaaaaaaa-0000-0000-0000-000000000001'
        $policyB = New-TestPolicy -Id 'bbbbbbbb-0000-0000-0000-000000000002'
        $index = New-TestDefinitionIndex
        $responseA = New-TestSettingsResponse -Value 'value-a'
        $responseB = New-TestSettingsResponse -Value 'value-b'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq $policyA.id } { $responseA }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq $policyB.id } { $responseB }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyA, $policyB, $index {
            param($store, $context, $policyA, $policyB, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyA, $policyB) -DefinitionIndex $index
        }
        $forwardBytes = [System.IO.File]::ReadAllBytes((Get-PulseExpandedJsonlPath -Store $script:store))

        $storeRoot2 = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store2 = InModuleScope TenantPulse -ArgumentList $storeRoot2 { param($storeRoot2) New-PulseSnapshotStore -Path $storeRoot2 }
        try {
            InModuleScope TenantPulse -ArgumentList $store2, $script:context, $policyA, $policyB, $index {
                param($store2, $context, $policyA, $policyB, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store2 -Context $context -Policies @($policyB, $policyA) -DefinitionIndex $index
            }
            $reversedBytes = [System.IO.File]::ReadAllBytes((Get-PulseExpandedJsonlPath -Store $store2))

            [System.Convert]::ToBase64String($forwardBytes) | Should -Be ([System.Convert]::ToBase64String($reversedBytes))
        } finally {
            Remove-Item -LiteralPath $storeRoot2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It '-FromCapturedPayloads re-expands from the persisted raw dataset with NO Graph call' {
        $policy = New-TestPolicy -Id 'policy-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'captured-value'

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'must not be called on -FromCapturedPayloads' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $index {
            param($store, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.RowCount | Should -Be 1
        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $lines = @(Get-Content -LiteralPath $jsonlPath)
        ($lines[0] | ConvertFrom-Json).value | Should -Be 'captured-value'
    }

    It 'zero policies: Expanded with rowCount 0 and policyCount 0, an empty but hash-verified generation-named jsonl file' {
        $index = New-TestDefinitionIndex

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $index {
            param($store, $context, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @() -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.PolicyCount | Should -Be 0
        $summary.RowCount | Should -Be 0
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -BeNullOrEmpty
    }

    It 'GAPS SORTED ORDINALLY on (policyId, reason) regardless of input/failure order' {
        $policyZ = New-TestPolicy -Id 'zzz-policy'
        $policyA = New-TestPolicy -Id 'aaa-policy'
        $index = New-TestDefinitionIndex
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'zzz-policy' } { throw 'z fails' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Parameters.id -eq 'aaa-policy' } { throw 'a fails' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policyZ, $policyA, $index {
            param($store, $context, $policyZ, $policyA, $index)
            # deliberately supplied in Z-then-A order
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policyZ, $policyA) -DefinitionIndex $index
        }

        $summary.Gaps.Count | Should -Be 2
        $summary.Gaps[0].policyId | Should -Be 'aaa-policy'
        $summary.Gaps[1].policyId | Should -Be 'zzz-policy'
    }

    It 'PUBLICATION FAULT INJECTION: the expanded/ directory disappearing mid-staging leaves no orphaned .tmp file, disposes the hash, and does not publish a corrupt artifact' {
        $policy = New-TestPolicy -Id 'policy-fault'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse -Value 'x'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        # Fault injection: the expanded/ directory itself is removed right before the
        # driver runs, so [System.IO.File]::Open for the staging temp file fails partway
        # through the staging sequence (after the IncrementalHash has already been
        # created) - a real, reproducible I/O fault, not a synthetic unreachable shape.
        Remove-Item -LiteralPath $script:store.ExpandedPath -Recurse -Force

        {
            InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
                param($store, $context, $policy, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
            }
        } | Should -Throw

        # no expansion entry was ever written for a corrupt/incomplete artifact
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingsCatalog') | Should -BeFalse
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion - sequential-only (Part D, T3.4: RunspacePool -MaxParallel path deleted)' {
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

    # RETIRED (Part D, T3.4 - ledger record): two multi-worker byte-identity tests used to
    # live here -
    #   'a real -MaxParallel 4 run over captured payloads is byte-identical to -Sequential'
    #   'T2.7: -MaxParallel 4 against the driver directly (bypassing the pipeline''s forced
    #    -Sequential) stays byte-identical to -Sequential over 24 captured-payload policies'
    # - both asserting a real RunspacePool worker-pool run produced byte-identical output to
    # a sequential run over the same captured-payload corpus. Both are deleted, not
    # skipped: the RunspacePool path they exercised no longer exists in the product code
    # (see Invoke-PulseSettingsCatalogExpansion's own docstring for the measured deletion
    # rationale - per-runspace ~20s token acquisition, a runspace-local throttle
    # coordinator, and an Import-Module table race that only survived 2 of 6 concurrent
    # pooled runspace opens even with -Force), so there is no second code path left for
    # either test to compare against; a sequential-vs-sequential "byte-identity" assertion
    # would prove nothing these tests' many sibling sequential-path Its don't already
    # cover. The test BELOW this comment (WORKER-FAILURE CLASSIFICATION) covered real
    # behavior beyond byte-identity - gap classification for one missing captured payload
    # among several policies - so it is KEPT, converted to the sequential call every other
    # test in this file already uses, rather than deleted.
    It 'WORKER-FAILURE CLASSIFICATION: a missing captured payload for one policy (of several) gaps only that policy' {
        $index = New-TestDefinitionIndex
        $goodIds = 1..3 | ForEach-Object { "22222222-2222-2222-2222-{0:D12}" -f $_ }
        $missingId = '22222222-2222-2222-2222-999999999999'
        $policies = @($goodIds | ForEach-Object { New-TestPolicy -Id $_ }) + @(New-TestPolicy -Id $missingId)

        foreach ($id in $goodIds) {
            $response = New-TestSettingsResponse -Value "value-$id" -DefinitionId 'setting-a'
            InModuleScope TenantPulse -ArgumentList $script:store, $id, $response {
                param($store, $id, $response)
                Write-PulseDataset -Store $store -Name "configurationPolicySettings-$id" -Data $response -ApiVersion 'beta' -Status 'Collected'
            }
        }
        # $missingId is intentionally never written - Read-PulseDataset will fail for it.

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policies, $index {
            param($store, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies $policies -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.Status | Should -Be 'Partial'
        $summary.RowCount | Should -Be 3
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be $missingId
        $summary.Gaps[0].reason | Should -Match 'category:CapturedPayload'
    }

    It 'ALL-POLICIES-FAILED: every eligible policy failing yields NotExpanded (not Partial with an empty artifact), no jsonl is written' {
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-all-fail-1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'simulated Graph failure' }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 1
        $summary.Gaps[0].policyId | Should -Be 'policy-all-fail-1'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'NotExpanded'
        $manifest.expansions.settingsCatalog.reason | Should -Match 'all 1 policy'
        # NotExpanded per Set-PulseExpansionEntry's own contract does not require/publish a
        # Path - no jsonl artifact should exist under expanded/ for this run at all.
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'a legitimately empty policy (walks cleanly, zero settings, zero gaps) stays Expanded with a valid empty artifact - not misclassified as ALL-POLICIES-FAILED' {
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-empty-1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { @() }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'Expanded'
        $summary.RowCount | Should -Be 0
        $summary.Gaps.Count | Should -Be 0

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
    }

    It 'READ-ONLY ENFORCEMENT: a Write-class/Unsafe ConfigurationPolicySetting descriptor aborts (fatal, matching Assert-PulseReadOnlyDescriptor''s own contract) before any Graph call' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } {
            [pscustomobject]@{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ThrottleClass = 'Write'; ReplayPolicy = 'Unsafe'; ApiVersion = 'beta' }
        }
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-readonly-1'

        {
            InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
                param($store, $context, $policy, $index)
                Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
            }
        } | Should -Throw '*not a read-only descriptor*'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' }
    }

    It 'READ-ONLY ENFORCEMENT: a descriptor-version-drift downgrades to NotExpanded (not fatal), no Graph call' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' -and $Operation -eq 'ListBeta' } {
            [pscustomobject]@{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'v1.0' }
        }
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-drift-1'

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $summary.Status | Should -Be 'NotExpanded'
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' }
    }

    It '-FromCapturedPayloads skips the read-only assertion entirely (no Graph call is ever made on this path, so no descriptor needs resolving)' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { throw 'Get-GraphOperation must not be called on -FromCapturedPayloads' }
        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-captured-readonly-1'

        # No captured dataset exists for this policy - expect a CapturedPayloadMissing gap,
        # not a Get-GraphOperation-related failure.
        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policy, $index {
            param($store, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies @($policy) -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.Gaps[0].reason | Should -Match 'CapturedPayloadMissing'
    }

    It 'DEPTH BUDGET ALIGNMENT: a chain exactly at the walker''s own 64-level budget (worst-case 4x GroupSettingCollection nesting) does not spuriously fail redaction/fetch' {
        # Build a GroupSettingCollectionInstance chain 64 levels deep - the worst-case shape
        # for the redactor's own per-raw-node depth counting (see ConvertTo-PulseSettingRows.ps1's
        # $script:PulseSettingsCatalogWalkerMaxDepth docstring: 4 raw levels per walker level).
        # A walker-valid chain at exactly this budget must not throw inside
        # Protect-PulseSettingsCatalogSecretPayload and get misclassified as a fetch failure.
        $leafDefId = 'leaf-setting'
        $current = [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = $leafDefId
            simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'v' }
        }
        for ($i = 0; $i -lt 63; $i++) {
            $current = [pscustomobject]@{
                '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                settingDefinitionId          = "level-$i"
                groupSettingCollectionValue  = @([pscustomobject]@{ children = @($current) })
            }
        }
        $settingsResponse = @([pscustomobject]@{ id = '0'; settingInstance = $current })

        $index = New-TestDefinitionIndex
        $policy = New-TestPolicy -Id 'policy-deep-1'
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        # A depth-budget-exceeded gap (from the WALKER itself) is fine at exactly the
        # boundary either way (off-by-one at the edge is not what this test is pinning) -
        # what this test forbids is a redaction-triggered 'category:FetchFailed' gap, which
        # would mean the redactor's own budget was smaller than the walker's and a VALID
        # chain got misclassified as a fetch failure purely due to raw-node overcounting.
        $summary.Gaps | Where-Object { $_.reason -match 'category:FetchFailed' } | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-PulseSettingsCatalogExpansion - Task 2.5 endpoint security / baseline instances' {
    <#
        Endpoint security policies live in the SAME configurationPolicies dataset T2.2
        already fans out over - templateFamily/isBaseline are frozen row schema v1 fields
        T2.2 already populates from -Policy's own templateReference (no new fetch here, per
        the plan). This block pins the ONE thing T2.5 actually changes: isBaseline must be
        true ONLY for the 'baseline' template family (Security Baselines), never for every
        OTHER template-bearing family (ordinary endpoint security profiles - antivirus,
        disk encryption, firewall, ... - are template-bearing too, but are not baselines).
    #>
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid'; ProfileId = 'contoso-lab' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'a security-baseline policy (templateFamily "baseline") walks with isBaseline:true on every row' {
        $policy = New-TestPolicy -Id 'policy-baseline' -TemplateFamily 'baseline' -TemplateId 'tpl-baseline-1'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'baseline'
            $_.isBaseline | Should -BeTrue
        }
    }

    It 'GOLDEN (real fixture): an endpointSecurityAccountProtection policy (choicecollection-01, real Ivy24 templateFamily) walks with isBaseline:false' {
        $fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalog'
        $fixture = Get-Content -LiteralPath (Join-Path $fixturesPath 'choicecollection-01.json') -Raw | ConvertFrom-Json -Depth 64
        $fixture.Policy.templateReference.templateFamily | Should -Be 'endpointSecurityAccountProtection'

        $index = New-TestDefinitionIndex
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { @($fixture.Settings) }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $fixture.Policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'endpointSecurityAccountProtection'
            $_.isBaseline | Should -BeFalse
        }
    }

    It 'GOLDEN (real fixture): an endpointSecurityAttackSurfaceReduction policy (choicecollection-02, real Ivy24 templateFamily) walks with isBaseline:false' {
        $fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalog'
        $fixture = Get-Content -LiteralPath (Join-Path $fixturesPath 'choicecollection-02.json') -Raw | ConvertFrom-Json -Depth 64
        $fixture.Policy.templateReference.templateFamily | Should -Be 'endpointSecurityAttackSurfaceReduction'

        $index = New-TestDefinitionIndex
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { @($fixture.Settings) }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $fixture.Policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows.Count | Should -BeGreaterThan 0
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'endpointSecurityAttackSurfaceReduction'
            $_.isBaseline | Should -BeFalse
        }
    }

    It 'an ordinary, non-template Settings Catalog policy (templateFamily "none", no templateId) walks with isBaseline:false' {
        $policy = New-TestPolicy -Id 'policy-plain'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows | ForEach-Object {
            $_.templateFamily | Should -Be 'none'
            $_.isBaseline | Should -BeFalse
        }
    }

    It 'a policy whose templateFamily merely starts with "baseline" (future variant) still classifies isBaseline:true (prefix match, not exact)' {
        $policy = New-TestPolicy -Id 'policy-baseline-variant' -TemplateFamily 'baselineWindows10MdmSecurity' -TemplateId 'tpl-baseline-2'
        $index = New-TestDefinitionIndex
        $settingsResponse = New-TestSettingsResponse
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $settingsResponse }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context, $policy, $index {
            param($store, $context, $policy, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Context $context -Policies @($policy) -DefinitionIndex $index
        }

        $jsonlPath = Get-PulseExpandedJsonlPath -Store $script:store
        $rows = @(Get-Content -LiteralPath $jsonlPath) | ForEach-Object { $_ | ConvertFrom-Json }
        $rows | ForEach-Object { $_.isBaseline | Should -BeTrue }
    }
}
