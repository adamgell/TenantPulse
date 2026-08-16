BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $script:fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalog'

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function Get-Fixture {
        param([string] $Name)
        $path = Join-Path $script:fixturesPath "$Name.json"
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 64
    }

    # SHAPE NEUTRALITY regression (Task 2.2 P0 re-review "headline defect"): GraphKit's
    # real production response shape is an OrderedHashtable tree
    # (`ConvertFrom-Json -AsHashtable`), not pscustomobject - every golden fixture here is
    # also re-materialized this way and MUST walk identically.
    function Get-FixtureAsHashtable {
        param([string] $Name)
        $path = Join-Path $script:fixturesPath "$Name.json"
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 64 -AsHashtable
    }
}

Describe 'ConvertTo-PulseSettingRows' {
    It 'walks a golden choice-01 fixture (a SimpleSettingCollectionInstance root) into one root row with schema v1 fields' {
        $fixture = Get-Fixture -Name 'choice-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -PolicyType 'settingsCatalog' `
                -PolicyName $fixture.Policy.name -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $result.Rows.Count | Should -Be 1
        $row = $result.Rows[0]
        $row.schemaVersion | Should -Be '1'
        $row.policyId | Should -Be $fixture.Policy.id
        $row.instanceId | Should -Be 'n:0'
        $row.settingDefinitionId | Should -Be $fixture.Settings.settingInstance.settingDefinitionId
        $row.settingPath | Should -Be $fixture.Settings.settingInstance.settingDefinitionId
        , $row.value | Should -Not -BeNullOrEmpty
        $row.redacted | Should -BeFalse
        $row.assignments | Should -BeNullOrEmpty
    }

    It 'walks a golden simple-01 fixture (a ChoiceSettingInstance root with children) into a root row carrying the choice value' {
        $fixture = Get-Fixture -Name 'simple-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $root = $result.Rows | Where-Object { $_.settingDefinitionId -eq $fixture.Settings.settingInstance.settingDefinitionId }
        $root.value | Should -Be $fixture.Settings.settingInstance.choiceSettingValue.value
        $root.redacted | Should -BeFalse
    }

    It 'walks a golden simplecollection-01 fixture into one row whose value is an array' {
        $fixture = Get-Fixture -Name 'simplecollection-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Rows.Count | Should -Be 1
        , $result.Rows[0].value | Should -Not -BeNullOrEmpty
        $result.Rows[0].value.Count | Should -Be 1
        $result.Rows[0].value[0] | Should -Be $fixture.Settings.settingInstance.simpleSettingCollectionValue[0].value
    }

    It 'walks a golden choicecollection-01 fixture, nested children get synthetic instance ids under the collection row' {
        $fixture = Get-Fixture -Name 'choicecollection-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $result.Rows.Count | Should -BeGreaterThan 1
        $rootRow = $result.Rows | Where-Object { $_.instanceId -eq 'n:0' }
        $rootRow | Should -Not -BeNullOrEmpty
        # every non-root row's instanceId must be synthetic and reference the root
        ($result.Rows | Where-Object { $_.instanceId -ne 'n:0' } | ForEach-Object { $_.instanceId }) |
            ForEach-Object { $_ | Should -Match '^n:0/' }
        # every instanceId is unique (collision-rejection means duplicates would have thrown)
        (@($result.Rows.instanceId) | Select-Object -Unique).Count | Should -Be $result.Rows.Count
    }

    It 'walks the richly-nested groupcollection-02-nested fixture without gaps and produces multiple rows' {
        $fixture = Get-Fixture -Name 'groupcollection-02-nested'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Gaps.Count | Should -Be 0
        $result.Rows.Count | Should -BeGreaterThan 5
        # a group row itself carries no value
        $groupRows = $result.Rows | Where-Object { $_.settingDefinitionId -eq 'com.apple.servicemanagement_com.apple.servicemanagement' }
        $groupRows.Count | Should -Be 1
        $groupRows[0].value | Should -BeNullOrEmpty
    }

    It 'resolves settingName and valueLabel from a supplied DefinitionIndex' {
        $fixture = Get-Fixture -Name 'simple-01'
        $definitionId = $fixture.Settings.settingInstance.settingDefinitionId
        $value = $fixture.Settings.settingInstance.choiceSettingValue.value

        $index = [ordered]@{
            $definitionId = [ordered]@{
                Name             = 'raw_name'
                DisplayName      = 'Friendly Display Name'
                RootDefinitionId = $null
                OptionLabels     = [ordered]@{ $value = 'Friendly Option Label' }
                Applicability    = $null
                IsSecretCapable  = $false
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $fixture, $index {
            param($fixture, $index)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings -DefinitionIndex $index
        }

        $row = $result.Rows[0]
        $row.settingName | Should -Be 'Friendly Display Name'
        $row.nameResolved | Should -BeTrue
        $row.valueLabel | Should -Be 'Friendly Option Label'
        $row.labelResolved | Should -BeTrue
    }

    It 'leaves settingName/valueLabel null and *Resolved false with no DefinitionIndex supplied' {
        $fixture = Get-Fixture -Name 'choice-01'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $row = $result.Rows[0]
        $row.settingName | Should -BeNullOrEmpty
        $row.nameResolved | Should -BeFalse
        $row.valueLabel | Should -BeNullOrEmpty
        $row.labelResolved | Should -BeFalse
    }

    It 'redacts a secret SimpleSettingInstance: value is null, redacted true, valueState carried, the planted secret never appears anywhere in the row' {
        $plantedSecret = 'sw0rdfish-do-not-leak-1234567890'
        $settingsPayload = [pscustomobject]@{
            id             = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'device_vendor_msft_policy_config_example_secret'
                simpleSettingValue  = [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'
                    value         = $plantedSecret
                    valueState    = 'encryptedValueToken'
                }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-secret-1' -SettingsPayload $settingsPayload
        }

        $result.Rows.Count | Should -Be 1
        $row = $result.Rows[0]
        $row.redacted | Should -BeTrue
        $row.value | Should -BeNullOrEmpty
        $row.valueState | Should -Be 'encryptedValueToken'

        $serialized = $row | ConvertTo-Json -Depth 20 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'redacts a SimpleSettingCollectionInstance when any element is secret-typed (fail-closed: whole row null)' {
        $plantedSecret = 'another-planted-secret-value'
        $settingsPayload = [pscustomobject]@{
            id             = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'                 = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                settingDefinitionId          = 'device_vendor_msft_policy_config_example_secret_collection'
                simpleSettingCollectionValue = @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'ordinary' }
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'; value = $plantedSecret; valueState = 'notEncrypted' }
                )
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-secret-2' -SettingsPayload $settingsPayload
        }

        $row = $result.Rows[0]
        $row.redacted | Should -BeTrue
        $row.value | Should -BeNullOrEmpty
        $row.valueState | Should -Be 'notEncrypted'

        $serialized = $row | ConvertTo-Json -Depth 20 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'reports a gap for an unknown @odata.type and skips only that node, continuing the walk' {
        $settingsPayload = @(
            [pscustomobject]@{
                id             = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationFutureUnknownInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_future'
                }
            }
            [pscustomobject]@{
                id             = '1'
                settingInstance = [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_known'
                    simpleSettingValue   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'known-value' }
                }
            }
        )

        $result = InModuleScope TenantPulse -ArgumentList (, $settingsPayload) {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-unknown-1' -SettingsPayload $settingsPayload
        }

        $result.Gaps.Count | Should -Be 1
        $result.Gaps[0] | Should -Match 'unknown-instance-type'
        $result.Rows.Count | Should -Be 1
        $result.Rows[0].settingDefinitionId | Should -Be 'device_vendor_msft_policy_config_known'
    }

    It 'assigns synthetic instance ids per the frozen scheme when the raw payload carries no native id' {
        $settingsPayload = [pscustomobject]@{
            settingInstance = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'device_vendor_msft_policy_config_noid'
                simpleSettingValue   = [pscustomobject]@{ value = 'v' }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-noid-1' -SettingsPayload $settingsPayload
        }

        $result.Rows[0].instanceId | Should -Be 'policy-noid-1/s:device_vendor_msft_policy_config_noid#0'
    }

    It 'escapes a "/" inside a settingDefinitionId as ~s in settingPath' {
        $settingsPayload = [pscustomobject]@{
            id             = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'weird/definition/id'
                simpleSettingValue   = [pscustomobject]@{ value = 'v' }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-escape-1' -SettingsPayload $settingsPayload
        }

        $result.Rows[0].settingPath | Should -Be 'weird~sdefinition~sid'
    }

    It 'reports a depth-budget gap rather than throwing for a pathologically deep choice-child chain' {
        $leaf = [pscustomobject]@{
            '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = 'leaf'
            simpleSettingValue   = [pscustomobject]@{ value = 'v' }
        }
        $current = $leaf
        for ($i = 0; $i -lt 70; $i++) {
            $current = [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = "level$i"
                choiceSettingValue   = [pscustomobject]@{ value = 'v'; children = @($current) }
            }
        }
        $settingsPayload = [pscustomobject]@{ id = '0'; settingInstance = $current }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload {
            param($settingsPayload)
            ConvertTo-PulseSettingRows -PolicyId 'policy-deep-1' -SettingsPayload $settingsPayload -MaxDepth 64
        }

        $result.Gaps | Where-Object { $_ -match 'depth-budget-exceeded' } | Should -Not -BeNullOrEmpty
    }

    It 'always emits assignments:null on every row (assignments-deferred, G-gate sequencing amendment)' {
        $fixture = Get-Fixture -Name 'groupcollection-02-nested'

        $result = InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
        }

        $result.Rows | ForEach-Object { $_.assignments | Should -BeNullOrEmpty }
    }

    # --- P1-8: escape-the-escape --------------------------------------------------------

    It 'ESCAPE THE ESCAPE: a literal "~" in a definitionId is escaped before "/" so two distinct chains never collide (reproduced: a/b vs a~sb)' {
        $payloadSlash = [pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'a/b'
                simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' }
            } }
        $payloadTilde = [pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'a~sb'
                simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' }
            } }

        $resultSlash = InModuleScope TenantPulse -ArgumentList $payloadSlash { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }
        $resultTilde = InModuleScope TenantPulse -ArgumentList $payloadTilde { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }

        $resultSlash.Rows[0].settingPath | Should -Be 'a~sb'
        $resultTilde.Rows[0].settingPath | Should -Be 'a~tsb'
        $resultSlash.Rows[0].settingPath | Should -Not -Be $resultTilde.Rows[0].settingPath
    }

    # --- P1-9: exact instance-type match, not a suffix regex ----------------------------

    It 'EXACT TYPE MATCH: a hypothetical type merely ENDING with a known suffix is NOT misclassified as the real kind (reproduced bypass)' {
        $settingsPayload = [pscustomobject]@{
            id              = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationFutureSimpleSettingInstance'
                settingDefinitionId = 'device_vendor_msft_example'
                simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'should-not-be-read-as-a-plain-value' }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }

        $result.Rows.Count | Should -Be 0
        $result.Gaps.Count | Should -Be 1
        $result.Gaps[0] | Should -Match 'unknown-instance-type'
    }

    # --- P1-9: malformed shapes gap instead of silent success ---------------------------

    It 'MALFORMED ROOT: a Settings[] root entry with no settingInstance gaps instead of silently contributing zero rows and zero gaps' {
        $settingsPayload = @([pscustomobject]@{ id = '0' })

        $result = InModuleScope TenantPulse -ArgumentList (, $settingsPayload) { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }

        $result.Rows.Count | Should -Be 0
        $result.Gaps.Count | Should -Be 1
        $result.Gaps[0] | Should -Match 'malformed-root'
    }

    It 'MALFORMED CHILD: a scalar element inside a children array gaps instead of a silent early return' {
        $settingsPayload = [pscustomobject]@{
            id              = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = 'root_def'
                choiceSettingValue  = [pscustomobject]@{ value = 'v'; children = @('not-an-object') }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }

        $result.Rows.Count | Should -Be 1
        $result.Gaps.Count | Should -Be 1
        $result.Gaps[0] | Should -Match 'malformed-instance'
    }

    It 'INVALID VALUE CONTAINER: a non-object simpleSettingValue redacts fail-closed (never value:null/redacted:false) and gaps' {
        $settingsPayload = [pscustomobject]@{
            id              = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'root_def'
                simpleSettingValue  = 'not-an-object-either'
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }

        $result.Rows.Count | Should -Be 1
        $result.Rows[0].redacted | Should -BeTrue
        $result.Rows[0].value | Should -BeNullOrEmpty
        $result.Gaps.Count | Should -Be 1
        $result.Gaps[0] | Should -Match 'unknown-value-shape'
    }

    It 'DICTIONARY-SHAPED / NO-DISCRIMINATOR secret bypass (reproduced): a hashtable value with no @odata.type redacts fail-closed' {
        $plantedSecret = 'no-discriminator-plaintext-must-not-leak'
        $settingsPayload = [pscustomobject]@{
            id              = '0'
            settingInstance = [pscustomobject]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'root_def'
                simpleSettingValue  = @{ value = $plantedSecret }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $settingsPayload, $plantedSecret {
            param($p, $secret)
            $r = ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p
            $line = ConvertTo-PulseCanonicalJsonLine -InputObject $r.Rows[0]
            if ($line -match [regex]::Escape($secret)) { throw 'PLANTED SECRET LEAKED (no-discriminator bypass)' }
            return $r
        }

        $result.Rows[0].redacted | Should -BeTrue
        $result.Rows[0].value | Should -BeNullOrEmpty
        $result.Gaps[0] | Should -Match 'unknown-value-shape'
    }

    # --- P1-7/P1-8: instanceId collision throws, caught by the caller -------------------

    # --- SHAPE NEUTRALITY regression (the review's "headline" reproduced defect) --------

    It 'SHAPE NEUTRALITY: every golden fixture walks to the SAME rows/gaps whether materialized as PSObject or as a real GraphKit-shaped hashtable tree' {
        foreach ($name in @('simple-01', 'choice-01', 'simplecollection-01', 'choicecollection-01', 'groupcollection-01', 'groupcollection-02-nested', 'groupcollection-03', 'choicecollection-02', 'choicecollection-03', 'simple-02', 'simple-03', 'simplecollection-02', 'simplecollection-03', 'choice-02', 'choice-03')) {
            $psObjectFixture = Get-Fixture -Name $name
            $hashtableFixture = Get-FixtureAsHashtable -Name $name

            $psObjectResult = InModuleScope TenantPulse -ArgumentList $psObjectFixture {
                param($fixture)
                ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
            }
            $hashtableResult = InModuleScope TenantPulse -ArgumentList $hashtableFixture {
                param($fixture)
                ConvertTo-PulseSettingRows -PolicyId $fixture.Policy.id -SettingsPayload $fixture.Settings
            }

            # The headline reproduced defect: a hashtable-shaped walk silently produced
            # ZERO rows and ZERO gaps on real, populated data. Assert it does not regress.
            $hashtableResult.Rows.Count | Should -BeGreaterThan 0 -Because "fixture '$name' must not silently walk to zero rows under a hashtable-shaped payload"
            $hashtableResult.Rows.Count | Should -Be $psObjectResult.Rows.Count -Because "fixture '$name' row count must match between shapes"
            $hashtableResult.Gaps.Count | Should -Be $psObjectResult.Gaps.Count -Because "fixture '$name' gap count must match between shapes"

            $psLines = InModuleScope TenantPulse -ArgumentList (, $psObjectResult.Rows) { param($rows) $rows | ForEach-Object { ConvertTo-PulseCanonicalJsonLine -InputObject $_ } }
            $htLines = InModuleScope TenantPulse -ArgumentList (, $hashtableResult.Rows) { param($rows) $rows | ForEach-Object { ConvertTo-PulseCanonicalJsonLine -InputObject $_ } }
            ($psLines -join '') | Should -Be ($htLines -join '') -Because "fixture '$name' row content must be byte-identical between shapes"
        }
    }

    It 'COLLISION REJECTION: an instanceId collision throws rather than silently overwriting a row' {
        # Two roots sharing the SAME native id '0' - the only way to force a genuine
        # collision given the namespaced-id scheme (both would resolve to 'n:0').
        $settingsPayload = @(
            [pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'def-a'; simpleSettingValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'x' } } }
            [pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'def-b'; simpleSettingValue = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'y' } } }
        )

        {
            InModuleScope TenantPulse -ArgumentList (, $settingsPayload) { param($p) ConvertTo-PulseSettingRows -PolicyId 'p1' -SettingsPayload $p }
        } | Should -Throw -ExpectedMessage '*instanceId collision*'
    }
}
