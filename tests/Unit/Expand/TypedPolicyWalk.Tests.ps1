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
