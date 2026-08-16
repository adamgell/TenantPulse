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
}

Describe 'ConvertTo-PulseTypedPolicyRows' {
    It 'walks a windows10CompliancePolicy into one row per mapped property, schema v1 fields populated, policyType compliance' {
        $entry = Get-PulseComplianceTypeEntry -ODataType '#microsoft.graph.windows10CompliancePolicy'
        $policy = [pscustomobject]@{
            '@odata.type'     = '#microsoft.graph.windows10CompliancePolicy'
            id                = 'p1'
            displayName       = 'Win10 Compliance'
            bitLockerEnabled  = $true
            passwordRequired  = $false
        }
        $assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })

        $result = InModuleScope TenantPulse -ArgumentList $policy, $entry, $assignments {
            param($policy, $entry, $assignments)
            ConvertTo-PulseTypedPolicyRows -PolicyId 'p1' -PolicyType 'compliance' -PolicyName 'Win10 Compliance' `
                -Policy $policy -TypeEntry $entry -Assignments $assignments
        }

        $result.Rows.Count | Should -Be @($entry.Properties).Count
        $bitLockerRow = $result.Rows | Where-Object { $_.settingPath -eq 'bitLockerEnabled' }
        $bitLockerRow.value | Should -BeTrue
        $bitLockerRow.schemaVersion | Should -Be '1'
        $bitLockerRow.policyType | Should -Be 'compliance'
        $bitLockerRow.policyId | Should -Be 'p1'
        $bitLockerRow.policyName | Should -Be 'Win10 Compliance'
        $bitLockerRow.templateFamily | Should -BeNullOrEmpty
        $bitLockerRow.isBaseline | Should -BeFalse
        $bitLockerRow.nameResolved | Should -BeTrue
        $bitLockerRow.redacted | Should -BeFalse
        $bitLockerRow.instanceId | Should -Be 'p1/p:bitLockerEnabled'
        $bitLockerRow.assignments[0].groupId | Should -Be 'g1'
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
}
