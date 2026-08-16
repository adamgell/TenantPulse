<#
    Capstone SECRET CONTRACT regression (task-2.3-review C1 fix + coordinator addendum):
    plants a real-shaped WiFi-PSK-class secret (windows10CustomConfiguration's
    omaSettings[].value, flagged Sensitive in TypedPolicyMaps.psd1) through the FULL,
    real pipeline - Invoke-PulseCollection's raw dataset write (the C1 gap: this used to
    write Sensitive-flagged values in cleartext, independent of whether -ExpandSettings
    was ever used) followed by Invoke-PulseTypedPolicyExpansionPipeline's own expansion
    (raw assignment payload write + jsonl publish) - then walks EVERY file under the
    resulting snapshot store's root and asserts the planted marker appears in NONE of
    them: not the raw dataset file, not the jsonl artifact, not the manifest (reasons/
    gaps/anywhere), not a per-policy raw assignment payload, not a leftover temp/
    fragment file. One test that greps the entire tree is the cheapest COMPLETE version
    of "does this secret leak anywhere" - narrower per-artifact assertions (kept below
    too, for a more specific failure message when something does leak) can each pass
    while a leak lands in a file nobody thought to check individually; the capstone
    cannot have that blind spot by construction.
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
        function Get-GraphOperation { param() }
    }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }

    function New-TestReadDescriptor {
        param([string] $ApiVersion = 'v1.0')
        return [pscustomobject]@{
            ThrottleClass       = 'Read'
            ReplayPolicy        = 'Safe'
            ApiVersion          = $ApiVersion
            RequiredPermissions = @(@{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' })
        }
    }
    Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }

    function Get-PulseSnapshotFileTree {
        param($Store)
        return @(Get-ChildItem -LiteralPath $Store.Root -Recurse -File -ErrorAction SilentlyContinue)
    }
}

Describe 'SECRET CONTRACT capstone - planted PSK never reaches any file under the snapshot store' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid'; ProfileId = 'contoso-lab' }
        $script:plantedPsk = 'PLANTED-WIFI-PSK-CAPSTONE-zzz999'
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'a planted omaSettings[].value PSK never appears in ANY file under the store root, across the full collect + expand pipeline' {
        $plantedPolicy = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'policy-with-psk'
            displayName   = 'WiFi Profile'
            omaSettings   = @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './Wifi/PSK'; value = $script:plantedPsk }
            )
        }

        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceConfiguration' -and $Operation -eq 'List' } { @($plantedPolicy) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceConfigurationAssignment' -and $Operation -eq 'List' } { @() }

        # STEP 1 - raw collection (the C1 fix's own call site): writes datasets/
        # deviceConfigurations.json. Manifest matches Get-PulseCollectionManifest's own
        # row shape (Dataset/Type/Operation/ApiVersion/Pending).
        $manifest = @(
            [pscustomobject]@{ Dataset = 'deviceConfigurations'; Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false }
        )
        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        # STEP 2 - typed-policy expansion: reads deviceConfigurations back, fans out
        # assignments (mocked empty above), walks, publishes.
        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId 'contoso-lab' -TenantPseudonym 'tp-abc123'
        }

        # SPECIFIC ASSERTIONS FIRST (a more actionable failure message than the capstone
        # alone would give):

        # (1) raw dataset file - the C1 fix's own target.
        $rawDatasetPath = Join-Path $script:store.DatasetsPath 'deviceConfigurations.json'
        Test-Path -LiteralPath $rawDatasetPath -PathType Leaf | Should -BeTrue
        $rawDatasetText = Get-Content -LiteralPath $rawDatasetPath -Raw
        $rawDatasetText | Should -Not -Match ([regex]::Escape($script:plantedPsk))
        $rawDatasetText | Should -Match '"redacted"\s*:\s*true' -Because 'the redaction marker must actually be present, not just the plaintext absent (a field silently dropped would also pass a bare not-match check)'

        # (2) final jsonl expansion artifact.
        $manifestJson = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifestJson.expansions.deviceConfiguration.status | Should -Be 'Expanded'
        $jsonlPath = Join-Path $script:store.Root $manifestJson.expansions.deviceConfiguration.path
        Test-Path -LiteralPath $jsonlPath -PathType Leaf | Should -BeTrue
        (Get-Content -LiteralPath $jsonlPath -Raw) | Should -Not -Match ([regex]::Escape($script:plantedPsk))

        # (3) manifest text (reasons/gaps/anywhere).
        (Get-Content -LiteralPath $script:store.ManifestPath -Raw) | Should -Not -Match ([regex]::Escape($script:plantedPsk))

        # (4)/(5) per-policy raw assignment payload (deviceConfigurationAssignments-<id>) -
        # empty in this scenario, but must still not somehow carry the planted marker.
        $rawAssignmentPath = Join-Path $script:store.DatasetsPath 'deviceConfigurationAssignments-policy-with-psk.json'
        if (Test-Path -LiteralPath $rawAssignmentPath -PathType Leaf) {
            (Get-Content -LiteralPath $rawAssignmentPath -Raw) | Should -Not -Match ([regex]::Escape($script:plantedPsk))
        }

        # (6) no orphaned temp/fragment file anywhere under expanded/ - staging cleanup
        # already proven by T2.2/T2.3's own dedicated tests, re-asserted here as part of
        # the same end-to-end run.
        @(Get-ChildItem -LiteralPath $script:store.ExpandedPath -Filter '*.tmp' -ErrorAction SilentlyContinue).Count | Should -Be 0

        # CAPSTONE - walk the ENTIRE snapshot directory tree and grep every single file,
        # regardless of what it is or whether this test's author thought to check it by
        # name. The cheapest complete version of "does this secret leak anywhere".
        $allFiles = Get-PulseSnapshotFileTree -Store $script:store
        $allFiles.Count | Should -BeGreaterThan 0 -Because 'a run that produced zero files would make this capstone vacuously true - not a real assertion'

        $leakedFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $allFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            if ($text.Contains($script:plantedPsk)) {
                $leakedFiles.Add($file.FullName)
            }
        }
        $leakedFiles | Should -BeNullOrEmpty -Because ("the planted PSK must never reach any file under the store root; found it in: " + ($leakedFiles -join ', '))
    }
}
