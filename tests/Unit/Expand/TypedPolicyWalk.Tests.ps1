BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:typedPolicyMaps = Import-PowerShellDataFile -LiteralPath (Join-Path $built.FullName 'Data/TypedPolicyMaps.psd1')

    function Get-PulseComplianceTypeEntry {
        param([string] $ODataType)
        return $script:typedPolicyMaps.compliance[$ODataType]
    }

    function Get-PulseDeviceConfigTypeEntry {
        param([string] $ODataType)
        return $script:typedPolicyMaps.deviceConfiguration[$ODataType]
    }

    # GOLDEN FIXTURES (post-review follow-up): sanitized-real captures off Ivy24's own
    # deviceCompliancePolicies/deviceConfigurations datasets (scratch/live-011, scripted
    # exhaustive value walk - id/displayName/description/createdDateTime/lastModifiedDateTime
    # replaced with fixed placeholders, every OTHER property kept exactly as observed since
    # these are policy toggles/thresholds, never secret values - see
    # TypedPolicyMaps.psd1's own docstring; PROVENANCE'd in tests/Fixtures/PROVENANCE.md).
    $script:fixturesPath = Join-Path $script:repoRoot 'tests/Fixtures/TypedPolicy'

    function Get-PulseTypedPolicyFixture {
        param([string] $Name)
        $path = Join-Path $script:fixturesPath "$Name.json"
        return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 64
    }
}

Describe 'ConvertTo-PulseTypedPolicyRows' {
    It 'GOLDEN: walks the real, sanitized windows10CompliancePolicy fixture into one row per mapped property, schema v1 fields populated, policyType compliance, no gaps' {
        $policy = Get-PulseTypedPolicyFixture -Name 'compliance-windows10'
        $entry = Get-PulseComplianceTypeEntry -ODataType $policy.'@odata.type'
        $assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry, $assignments {
            param($policy, $entry, $assignments)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'compliance' -PolicyName $policy.displayName `
                -Policy $policy -TypeEntry $entry -Assignments $assignments
        }

        $result.Rows.Count | Should -Be @($entry.Properties).Count
        $bitLockerRow = $result.Rows | Where-Object { $_.settingPath -eq 'bitLockerEnabled' }
        $bitLockerRow.value | Should -Be $policy.bitLockerEnabled
        $bitLockerRow.schemaVersion | Should -Be '1'
        $bitLockerRow.policyType | Should -Be 'compliance'
        $bitLockerRow.policyId | Should -Be $policy.id
        $bitLockerRow.policyName | Should -Be $policy.displayName
        $bitLockerRow.templateFamily | Should -BeNullOrEmpty
        $bitLockerRow.isBaseline | Should -BeFalse
        $bitLockerRow.nameResolved | Should -BeTrue
        $bitLockerRow.redacted | Should -BeFalse
        $bitLockerRow.instanceId | Should -Be "$($policy.id)/p:bitLockerEnabled"
        $bitLockerRow.assignments[0].groupId | Should -Be 'g1'
    }

    It 'GOLDEN: walks the real, sanitized androidWorkProfileCompliancePolicy fixture cleanly, one row per mapped property' {
        $policy = Get-PulseTypedPolicyFixture -Name 'compliance-androidWorkProfile'
        $entry = Get-PulseComplianceTypeEntry -ODataType $policy.'@odata.type'

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'compliance' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be @($entry.Properties).Count
        ($result.Rows | Where-Object { $_.settingPath -eq 'securityRequireGooglePlayServices' }).value | Should -Be $policy.securityRequireGooglePlayServices
        $result.Rows | ForEach-Object { $_.redacted | Should -BeFalse }
    }

    It 'GOLDEN: walks the real, sanitized macOSCompliancePolicy fixture cleanly, one row per mapped property' {
        $policy = Get-PulseTypedPolicyFixture -Name 'compliance-macOS'
        $entry = Get-PulseComplianceTypeEntry -ODataType $policy.'@odata.type'

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'compliance' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be @($entry.Properties).Count
        ($result.Rows | Where-Object { $_.settingPath -eq 'firewallEnabled' }).value | Should -Be $policy.firewallEnabled
    }

    It 'GOLDEN: walks the real, sanitized iosCompliancePolicy fixture cleanly, one row per mapped property' {
        $policy = Get-PulseTypedPolicyFixture -Name 'compliance-ios'
        $entry = Get-PulseComplianceTypeEntry -ODataType $policy.'@odata.type'

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'compliance' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be @($entry.Properties).Count
        ($result.Rows | Where-Object { $_.settingPath -eq 'passcodeRequired' }).value | Should -Be $policy.passcodeRequired
    }

    It 'GOLDEN: walks the real, sanitized windows10CustomConfiguration fixture - omaSettings[].value redacts fail-closed on REAL observed data' {
        $policy = Get-PulseTypedPolicyFixture -Name 'deviceConfiguration-windows10Custom'
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType $policy.'@odata.type'

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $containerRow = $result.Rows | Where-Object { $_.settingPath -eq 'omaSettings' }
        $containerRow | Should -Not -BeNullOrEmpty
        $valueRow = $result.Rows | Where-Object { $_.settingPath -eq 'omaSettings/0/value' }
        $valueRow.redacted | Should -BeTrue
        $valueRow.value | Should -BeNullOrEmpty
        $serialized = $result.Rows | ConvertTo-Json -Depth 10 -Compress
        # the real fixture's own omaSettings[0].value ($true) must never appear un-redacted
        # anywhere the row landed - proven structurally (redacted:true, value:$null) above,
        # and here that no OTHER stray copy of the raw omaSetting node leaked a value.
        $serialized | Should -Not -Match '"omaSettings/0/value"[^}]*"value":\s*(true|false)'
    }

    It 'GOLDEN: walks the real, sanitized windowsUpdateForBusinessConfiguration fixture cleanly, including the Nested installationSchedule container' {
        $policy = Get-PulseTypedPolicyFixture -Name 'deviceConfiguration-windowsUpdateForBusiness'
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType $policy.'@odata.type'

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        ($result.Rows | Where-Object { $_.settingPath -eq 'automaticUpdateMode' }).value | Should -Be $policy.automaticUpdateMode
        $scheduleRow = $result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule' }
        $scheduleRow | Should -Not -BeNullOrEmpty
        # installationSchedule is null on this real fixture (an unpopulated shell) -
        # container row only, no gap/throw.
        $scheduleRow.value | Should -BeNullOrEmpty
    }

    It 'GOLDEN: walks the real, sanitized sharedPCConfiguration fixture cleanly - accountManagerPolicy is a flat (non-Nested) property, carried as one row with an object value' {
        $policy = Get-PulseTypedPolicyFixture -Name 'deviceConfiguration-sharedPC'
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType $policy.'@odata.type'

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be @($entry.Properties).Count
        ($result.Rows | Where-Object { $_.settingPath -eq 'enabled' }).value | Should -Be $policy.enabled
        $acctRow = $result.Rows | Where-Object { $_.settingPath -eq 'accountManagerPolicy' }
        $acctRow.value.inactiveThresholdDays | Should -Be $policy.accountManagerPolicy.inactiveThresholdDays
        $result.Rows | ForEach-Object { $_.redacted | Should -BeFalse }
    }

    It 'walks identically whether the raw policy is a [pscustomobject] or an AsHashtable-shaped [IDictionary] (shape neutrality)' {
        $entry = Get-PulseComplianceTypeEntry -ODataType '#microsoft.graph.windows10CompliancePolicy'
        $json = '{"@odata.type":"#microsoft.graph.windows10CompliancePolicy","id":"p1","bitLockerEnabled":true,"passwordRequired":false}'
        $pso = $json | ConvertFrom-Json -Depth 10
        $hash = $json | ConvertFrom-Json -Depth 10 -AsHashtable

        $rowsFromPso = InModuleScope TenantPulse -ArgumentList $pso, $entry {
            param($policy, $entry)
            (ConvertTo-PulseTypedPolicyRows -PolicyId 'p1' -PolicyType 'compliance' -Policy $policy -TypeEntry $entry -Assignments @()).Rows
        }
        $rowsFromHash = InModuleScope TenantPulse -ArgumentList $hash, $entry {
            param($policy, $entry)
            (ConvertTo-PulseTypedPolicyRows -PolicyId 'p1' -PolicyType 'compliance' -Policy $policy -TypeEntry $entry -Assignments @()).Rows
        }

        $bitLockerFromPso = ($rowsFromPso | Where-Object { $_.settingPath -eq 'bitLockerEnabled' }).value
        $bitLockerFromHash = ($rowsFromHash | Where-Object { $_.settingPath -eq 'bitLockerEnabled' }).value
        $bitLockerFromPso | Should -BeTrue
        $bitLockerFromHash | Should -BeTrue
        $rowsFromPso.Count | Should -Be $rowsFromHash.Count
    }

    It 'a Sensitive-flagged nested property (windows10CustomConfiguration.omaSettings[].value) redacts fail-closed: redacted:true, value never persisted, container row emitted first' {
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType '#microsoft.graph.windows10CustomConfiguration'
        $plantedSecret = 'PLANTED-OMA-SECRET-zzz999'
        $policy = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'c1'
            omaSettings   = @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './x'; value = $plantedSecret }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'c1' -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be 2
        $containerRow = $result.Rows | Where-Object { $_.settingPath -eq 'omaSettings' }
        $containerRow.value | Should -BeNullOrEmpty
        $containerRow.redacted | Should -BeFalse

        $valueRow = $result.Rows | Where-Object { $_.settingPath -eq 'omaSettings/0/value' }
        $valueRow.redacted | Should -BeTrue
        $valueRow.value | Should -BeNullOrEmpty

        $serialized = $result.Rows | ConvertTo-Json -Depth 10 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'a Nested object property (windowsUpdateForBusinessConfiguration.installationSchedule) walks once directly, not per-element' {
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType '#microsoft.graph.windowsUpdateForBusinessConfiguration'
        $policy = [pscustomobject]@{
            '@odata.type'         = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
            id                    = 'w1'
            installationSchedule  = [pscustomobject]@{ scheduledInstallDay = 'sunday'; scheduledInstallTime = '02:00:00' }
        }

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'w1' -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $dayRow = $result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule/scheduledInstallDay' }
        $dayRow.value | Should -Be 'sunday'
        $dayRow.redacted | Should -BeFalse
    }

    # T2.3 rider (Task 3): the real, sanitized windowsUpdateForBusinessConfiguration
    # fixture's own installationSchedule is null (an unpopulated shell - see the GOLDEN
    # test above), which never exercises the full container-row + all-4-sub-property-rows
    # path (TypedPolicyMaps.psd1's own installationSchedule.Nested.Properties: 4 entries -
    # scheduledInstallDay, scheduledInstallTime, activeHoursStart, activeHoursEnd). This
    # synthetic policy fills every one of those 4 with a non-null value.
    It 'a Nested object property (windowsUpdateForBusinessConfiguration.installationSchedule) POPULATED with all 4 sub-properties walks to the container row plus exactly 4 sub-property rows' {
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType '#microsoft.graph.windowsUpdateForBusinessConfiguration'
        $policy = [pscustomobject]@{
            '@odata.type'        = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
            id                   = 'w2'
            installationSchedule = [pscustomobject]@{
                scheduledInstallDay  = 'tuesday'
                scheduledInstallTime = '03:30:00'
                activeHoursStart     = '08:00:00'
                activeHoursEnd       = '17:00:00'
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'w2' -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $containerRow = $result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule' }
        $containerRow | Should -Not -BeNullOrEmpty
        $containerRow.value | Should -BeNullOrEmpty
        $containerRow.redacted | Should -BeFalse

        $subRows = @($result.Rows | Where-Object { $_.settingPath -like 'installationSchedule/*' })
        $subRows.Count | Should -Be 4

        ($result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule/scheduledInstallDay' }).value | Should -Be 'tuesday'
        ($result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule/scheduledInstallTime' }).value | Should -Be '03:30:00'
        ($result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule/activeHoursStart' }).value | Should -Be '08:00:00'
        ($result.Rows | Where-Object { $_.settingPath -eq 'installationSchedule/activeHoursEnd' }).value | Should -Be '17:00:00'
        $subRows | ForEach-Object { $_.redacted | Should -BeFalse }
    }

    It 'a Nested property whose raw value is absent (unpopulated shell) emits only the container row, not a gap/throw' {
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType '#microsoft.graph.windows10CustomConfiguration'
        $policy = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'; id = 'c2' }

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'c2' -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be 1
        $result.Rows[0].settingPath | Should -Be 'omaSettings'
        $result.Rows[0].value | Should -BeNullOrEmpty
    }

    # --- DEEPER NESTING (Part C, T3.4 - closes the deferred-F3/T2.7-live-gate gap,
    # docs/STATUS.md, TypedPolicyMaps.psd1's own windows10CustomConfiguration comment).
    # covers all 8 live-confirmed windows10CustomConfiguration policies' real shape. -------

    It 'GOLDEN (deeper-nesting): the real, sanitized live-27 fixture whose omaSettings[].value is ITSELF an object still redacts fail-closed - Sensitive wins over the newly-added Nested description' {
        $policy = Get-PulseTypedPolicyFixture -Name 'deviceConfiguration-windows10Custom-deeperNesting'
        $entry = Get-PulseDeviceConfigTypeEntry -ODataType $policy.'@odata.type'

        # Sanity on the fixture itself: the real observed shape genuinely is a 2-level
        # object under `value`, not a scalar - otherwise this test would not be exercising
        # the gap it claims to close.
        $policy.omaSettings[0].value | Should -Not -BeNullOrEmpty
        $policy.omaSettings[0].value.redacted | Should -BeTrue

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId $policy.id -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        # Exactly 2 rows (container + the Sensitive `value` leaf) - IDENTICAL row count to
        # the pre-Part-C scalar-secret case (see the sibling 'redacts fail-closed on REAL
        # observed data' GOLDEN test above) - adding a Nested description to a Sensitive
        # property must never add rows nobody asked for; Sensitive still wins, unconditionally.
        $result.Rows.Count | Should -Be 2
        $containerRow = $result.Rows | Where-Object { $_.settingPath -eq 'omaSettings' }
        $containerRow.redacted | Should -BeFalse
        $containerRow.value | Should -BeNullOrEmpty

        $valueRow = $result.Rows | Where-Object { $_.settingPath -eq 'omaSettings/0/value' }
        $valueRow | Should -Not -BeNullOrEmpty
        $valueRow.redacted | Should -BeTrue
        $valueRow.value | Should -BeNullOrEmpty

        # No row for the deeper 'redacted' marker property exists at all - proof the walker
        # never descended into value's own Nested description (Sensitive short-circuited
        # before it was ever consulted).
        ($result.Rows | Where-Object { $_.settingPath -eq 'omaSettings/0/value/redacted' }) | Should -BeNullOrEmpty
    }

    It 'a Sensitive property that ALSO carries its own Nested description still redacts wholesale and never emits a row for its declared sub-property (synthetic, decoupled from the real map)' {
        # Direct, synthetic map entry proving the "Sensitive always wins, at every depth"
        # rule independent of whether the real map happens to exercise it - mirrors this
        # file's own existing "redacts a top-level Sensitive property UNCONDITIONALLY"
        # sibling test in ProtectTypedPolicySensitivePayload.Tests.ps1.
        $syntheticEntry = @{
            Properties = @(
                @{
                    Name      = 'topContainer'
                    Sensitive = $false
                    Nested    = @{
                        Properties = @(
                            @{
                                Name      = 'secretLeafWithOwnShape'
                                Sensitive = $true
                                Nested    = @{
                                    Properties = @(
                                        @{ Name = 'innerFieldThatMustNeverAppear'; Sensitive = $false }
                                    )
                                }
                            }
                        )
                    }
                }
            )
        }
        $plantedInnerSecret = 'PLANTED-inner-field-zzz111'
        $policy = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.syntheticDeeperNestingType'
            id            = 'synthetic-1'
            topContainer  = [pscustomobject]@{
                secretLeafWithOwnShape = [pscustomobject]@{ innerFieldThatMustNeverAppear = $plantedInnerSecret }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $policy, $syntheticEntry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'synthetic-1' -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        $result.Rows.Count | Should -Be 2
        $leafRow = $result.Rows | Where-Object { $_.settingPath -eq 'topContainer/secretLeafWithOwnShape' }
        $leafRow.redacted | Should -BeTrue
        $leafRow.value | Should -BeNullOrEmpty
        ($result.Rows | Where-Object { $_.settingPath -eq 'topContainer/secretLeafWithOwnShape/innerFieldThatMustNeverAppear' }) | Should -BeNullOrEmpty
        $serialized = $result.Rows | ConvertTo-Json -Depth 10 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedInnerSecret))
    }

    It 'RECURSION MECHANISM PROOF: a genuinely NON-Sensitive property nested 3 levels deep walks all the way down to a real leaf row, with a Sensitive leaf at the SAME depth still redacting independently (synthetic, proves depth is not artificially capped at 1 or 2)' {
        $syntheticEntry = @{
            Properties = @(
                @{
                    Name      = 'level1'
                    Sensitive = $false
                    Nested    = @{
                        Properties = @(
                            @{
                                Name      = 'level2'
                                Sensitive = $false
                                Nested    = @{
                                    Properties = @(
                                        @{ Name = 'level3Plain'; Sensitive = $false }
                                        @{ Name = 'level3Secret'; Sensitive = $true }
                                    )
                                }
                            }
                        )
                    }
                }
            )
        }
        $plantedSecret = 'PLANTED-level3-secret-zzz222'
        $policy = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.syntheticThreeLevelType'
            id            = 'synthetic-3level'
            level1        = [pscustomobject]@{
                level2 = [pscustomobject]@{
                    level3Plain  = 'plain-value-42'
                    level3Secret = $plantedSecret
                }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $policy, $syntheticEntry {
            param($policy, $entry)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'synthetic-3level' -PolicyType 'deviceConfiguration' -Policy $policy -TypeEntry $entry -Assignments @()
        }

        # level1 container + level2 container + level3Plain leaf + level3Secret leaf = 4 rows.
        $result.Rows.Count | Should -Be 4

        $level1Row = $result.Rows | Where-Object { $_.settingPath -eq 'level1' }
        $level1Row.value | Should -BeNullOrEmpty
        $level1Row.redacted | Should -BeFalse

        $level2Row = $result.Rows | Where-Object { $_.settingPath -eq 'level1/level2' }
        $level2Row.value | Should -BeNullOrEmpty
        $level2Row.redacted | Should -BeFalse

        $plainRow = $result.Rows | Where-Object { $_.settingPath -eq 'level1/level2/level3Plain' }
        $plainRow.value | Should -Be 'plain-value-42'
        $plainRow.redacted | Should -BeFalse

        $secretRow = $result.Rows | Where-Object { $_.settingPath -eq 'level1/level2/level3Secret' }
        $secretRow.value | Should -BeNullOrEmpty
        $secretRow.redacted | Should -BeTrue

        $serialized = $result.Rows | ConvertTo-Json -Depth 10 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    # --- SHAPE NEUTRALITY (task-2.3-review I1 fix): matches T2.2's own standard exactly -
    # EVERY typed fixture family, through BOTH -AsHashtable and PSObject materializations,
    # not just the one token flat-property case the original T2.3 delivery covered. -------

    It 'SHAPE NEUTRALITY: every golden fixture family walks to the SAME rows whether materialized as PSObject or as a real GraphKit-shaped AsHashtable tree' {
        # Covers every shape this map schema supports and both policyTypes in one sweep:
        # flat properties (compliance-windows10/androidWorkProfile/macOS/ios,
        # deviceConfiguration-sharedPC), a Sensitive-flagged NESTED ARRAY
        # (deviceConfiguration-windows10Custom's omaSettings[].value - the redaction path),
        # and a NESTED OBJECT (deviceConfiguration-windowsUpdateForBusiness's
        # installationSchedule).
        $cases = @(
            @{ Fixture = 'compliance-windows10'; PolicyType = 'compliance'; Map = { $script:typedPolicyMaps.compliance } }
            @{ Fixture = 'compliance-androidWorkProfile'; PolicyType = 'compliance'; Map = { $script:typedPolicyMaps.compliance } }
            @{ Fixture = 'compliance-macOS'; PolicyType = 'compliance'; Map = { $script:typedPolicyMaps.compliance } }
            @{ Fixture = 'compliance-ios'; PolicyType = 'compliance'; Map = { $script:typedPolicyMaps.compliance } }
            @{ Fixture = 'deviceConfiguration-sharedPC'; PolicyType = 'deviceConfiguration'; Map = { $script:typedPolicyMaps.deviceConfiguration } }
            @{ Fixture = 'deviceConfiguration-windows10Custom'; PolicyType = 'deviceConfiguration'; Map = { $script:typedPolicyMaps.deviceConfiguration } }
            @{ Fixture = 'deviceConfiguration-windowsUpdateForBusiness'; PolicyType = 'deviceConfiguration'; Map = { $script:typedPolicyMaps.deviceConfiguration } }
        )

        foreach ($case in $cases) {
            $path = Join-Path $script:fixturesPath "$($case.Fixture).json"
            $rawJson = Get-Content -LiteralPath $path -Raw

            $psObjectPolicy = $rawJson | ConvertFrom-Json -Depth 64
            $hashtablePolicy = $rawJson | ConvertFrom-Json -Depth 64 -AsHashtable

            $typeMap = & $case.Map
            $psEntry = $typeMap[$psObjectPolicy.'@odata.type']
            $htEntry = $typeMap[[string] $hashtablePolicy.'@odata.type']

            $psResult = InModuleScope TenantPulse -ArgumentList $psObjectPolicy, $psEntry, $case.PolicyType {
                param($policy, $entry, $policyType)
                (ConvertTo-PulseTypedPolicyRows -PolicyId 'shape-neutrality-test' -PolicyType $policyType -Policy $policy -TypeEntry $entry -Assignments @()).Rows
            }
            $htResult = InModuleScope TenantPulse -ArgumentList $hashtablePolicy, $htEntry, $case.PolicyType {
                param($policy, $entry, $policyType)
                (ConvertTo-PulseTypedPolicyRows -PolicyId 'shape-neutrality-test' -PolicyType $policyType -Policy $policy -TypeEntry $entry -Assignments @()).Rows
            }

            $htResult.Count | Should -BeGreaterThan 0 -Because "fixture '$($case.Fixture)' must not silently walk to zero rows under a hashtable-shaped payload"
            $htResult.Count | Should -Be $psResult.Count -Because "fixture '$($case.Fixture)' row count must match between shapes"

            $psLines = InModuleScope TenantPulse -ArgumentList (, $psResult) { param($rows) $rows | ForEach-Object { ConvertTo-PulseCanonicalJsonLine -InputObject $_ } }
            $htLines = InModuleScope TenantPulse -ArgumentList (, $htResult) { param($rows) $rows | ForEach-Object { ConvertTo-PulseCanonicalJsonLine -InputObject $_ } }
            ($psLines -join '') | Should -Be ($htLines -join '') -Because "fixture '$($case.Fixture)' row content must be byte-identical between shapes"

            # Sensitive-redaction path (deviceConfiguration-windows10Custom's
            # omaSettings[].value): both shapes must redact identically, never one shape
            # accidentally leaking the raw value the other correctly redacted.
            if ($case.Fixture -eq 'deviceConfiguration-windows10Custom') {
                $psValueRow = $psResult | Where-Object { $_.settingPath -eq 'omaSettings/0/value' }
                $htValueRow = $htResult | Where-Object { $_.settingPath -eq 'omaSettings/0/value' }
                $psValueRow.redacted | Should -BeTrue -Because 'PSObject-shaped omaSettings[].value must redact'
                $htValueRow.redacted | Should -BeTrue -Because 'Hashtable-shaped omaSettings[].value must redact'
                $psValueRow.value | Should -BeNullOrEmpty
                $htValueRow.value | Should -BeNullOrEmpty
            }
        }
    }
}
