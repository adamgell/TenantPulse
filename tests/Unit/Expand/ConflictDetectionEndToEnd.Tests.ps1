<#
    E2E golden pipeline test (review round 2, item 3): threads a REDACTED value from a raw,
    sanitized payload through the REAL T2.2 (Settings Catalog) and T2.3 (typed-policy)
    expansion pipelines - not hand-built row objects - into a REAL Invoke-PulseConflictDetection
    run, proving the cross-boundary property end to end: a planted secret survives raw
    collection, the typed-policy walk's own redaction, and conflict-index construction
    without ever reaching conflicts.json, while STILL correctly participating in a real
    conflict record (mixed redacted/plain group, deferred-assignment 'unknown' overlap).

    The two families are deliberately made to COLLIDE on settingDefinitionId
    ('omaSettings/0/value') - a Settings Catalog leaf definitionId is an opaque string with
    no format constraint, so this test's synthetic Settings Catalog fixture is built to
    literally reuse the SAME string T2.3's own windows10CustomConfiguration property map
    produces for omaSettings[0].value - proving Task 2.6's own "cross-family conflicts
    supported by construction" property against the REAL walkers, not just the pure
    ConvertTo-PulseConflictRecords unit tests' hand-built rows.
#>

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

    # Get-GraphOperation is deliberately left UNMOCKED here (matches
    # SettingsCatalogExpansionPipeline.Tests.ps1/TypedPolicyExpansionPipeline.Tests.ps1's
    # own convention) - both families' real Assert-PulseReadOnlyDescriptor calls resolve
    # against the REAL GraphKit descriptor catalog (metadata lookups only, never a network
    # call - see ReadOnly.tests.ps1's own docstring for why this is safe), which is what
    # this E2E test needs: a single hand-rolled fake descriptor cannot correctly answer
    # BOTH families' differing real ApiVersion expectations (ConfigurationPolicy.ListBeta
    # is 'beta'; DeviceConfiguration.List/DeviceConfigurationAssignment.List are 'v1.0') at
    # once, and a per-call filtered fake would just be re-deriving the real catalog by hand.
}

Describe 'Conflict detection end-to-end: redacted value crosses the T2.2/T2.3 expansion boundary into conflicts.json' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid-e2e'; ProfileId = 'contoso-lab' }
        $script:plantedSecret = 'PLANTED-E2E-CROSS-BOUNDARY-SECRET-qq777'
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'produces a real cross-family conflict, redaction intact, via the real T2.2 + T2.3 + conflict-detection pipeline' {
        # --- T2.2: Settings Catalog side - a PLAIN value at definitionId 'omaSettings/0/value' ---
        $catalogPolicies = @([pscustomobject]@{ id = 'catalog-policy-1'; name = 'Catalog Policy'; templateReference = [pscustomobject]@{ templateId = ''; templateFamily = 'none' } })
        $catalogDefinitions = @([pscustomobject]@{ id = 'omaSettings/0/value'; name = 'omaValue'; displayName = 'OMA Value' })
        $catalogSettingsResponse = @([pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId  = 'omaSettings/0/value'
                    simpleSettingValue   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'catalog-plain-value' }
                }
            })

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' -and $Operation -eq 'ListBeta' } { $catalogPolicies }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { $catalogDefinitions }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicySetting' } { $catalogSettingsResponse }

        # --- T2.3: typed-policy side - a REDACTED (Sensitive) omaSettings[0].value ---
        $plantedPolicy = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'typed-policy-with-secret'
            displayName   = 'WiFi Profile'
            omaSettings   = @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './Wifi/PSK'; value = $script:plantedSecret }
            )
        }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceConfiguration' -and $Operation -eq 'List' } { @($plantedPolicy) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceConfigurationAssignment' -and $Operation -eq 'List' } { @() }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)

            # STEP 1: T2.2 - real Settings Catalog fan-out/walk/publish.
            $null = Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'

            # STEP 2: T2.3's own raw collection (writes datasets/deviceConfigurations.json,
            # redacting Sensitive properties at the RAW WRITE per the C1 fix) + expansion.
            $manifestRows = @([pscustomobject]@{ Dataset = 'deviceConfigurations'; Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false })
            Invoke-PulseCollection -Store $store -Manifest $manifestRows -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
            $null = Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'

            # STEP 3: T2.6 - real conflict detection over whatever families just verified.
            $null = Invoke-PulseConflictDetection -Store $store -ProfileId 'contoso-lab' -Pseudonym 'tp-abc123' -TenantId $context.TenantId
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingsCatalog.status | Should -Be 'Expanded'
        $manifest.expansions.deviceConfiguration.status | Should -Be 'Expanded'
        $manifest.expansions.conflicts.status | Should -Be 'Expanded'

        $conflictsPath = Join-Path $script:store.Root $manifest.expansions.conflicts.path
        $conflictsDoc = Get-Content -LiteralPath $conflictsPath -Raw | ConvertFrom-Json

        $conflictsDoc.conflicts.Count | Should -Be 1
        $conflict = $conflictsDoc.conflicts[0]
        $conflict.settingDefinitionId | Should -Be 'omaSettings/0/value'
        # Deferred core-slice rule proven live: the settingsCatalog side's assignments:null
        # forces 'unknown', never a fabricated proven/possible/none.
        $conflict.assignmentOverlap | Should -Be 'unknown'
        $conflict.assignmentOverlapReason | Should -Match 'assignments-deferred'

        $conflict.values.Count | Should -Be 2
        $redactedValue = $conflict.values | Where-Object { $_.redacted }
        $plainValue = $conflict.values | Where-Object { -not $_.redacted }
        $redactedValue | Should -Not -BeNullOrEmpty
        $redactedValue.canonicalValue | Should -BeNullOrEmpty
        $plainValue.canonicalValue | Should -Be 'catalog-plain-value'
        @($redactedValue.policies.policyId) | Should -Contain 'typed-policy-with-secret'
        @($plainValue.policies.policyId) | Should -Contain 'catalog-policy-1'

        # CROSS-BOUNDARY SECRET-NEVER-LEAKS: walk EVERY file under the store root (mirrors
        # TypedPolicySecretContract.Tests.ps1's own capstone technique) and confirm the
        # planted secret text appears nowhere - including conflicts.json itself.
        $allFiles = @(Get-ChildItem -LiteralPath $script:store.Root -Recurse -Force -File -ErrorAction SilentlyContinue)
        $allFiles.Count | Should -BeGreaterThan 0
        $leakedFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $allFiles) {
            $text = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($file.FullName))
            if ($text.Contains($script:plantedSecret)) { $leakedFiles.Add($file.FullName) }
        }
        $leakedFiles | Should -BeNullOrEmpty -Because ("the planted secret must never reach any file under the store root, including conflicts.json; found it in: " + ($leakedFiles -join ', '))
    }
}
