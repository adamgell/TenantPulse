BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulseBitlockerRow {
        param(
            [string] $PolicyId,
            [string] $PolicyType = 'settingsCatalog',
            [string] $Value = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_1',
            [bool] $Redacted = $false,
            [AllowNull()] [object[]] $Assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
        )
        [pscustomobject]@{
            schemaVersion = '1'; policyId = $PolicyId; policyType = $PolicyType; policyName = "Policy-$PolicyId"
            templateFamily = $null; isBaseline = $false
            settingPath = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype'
            settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype'
            settingName = 'SystemDrivesEncryptionType'; nameResolved = $true
            instanceId = "$PolicyId/n:device_vendor_msft_bitlocker_systemdrivesencryptiontype"
            value = if ($Redacted) { $null } else { $Value }
            valueLabel = $null; labelResolved = $false; redacted = $Redacted; valueState = $null; applicability = $null
            assignments = $Assignments
        }
    }

    # Fixture builder: real store functions throughout (New-PulseSnapshotStore,
    # Publish-PulseExpansionRows, Invoke-PulseSettingPresenceIndexBuild) - only the ROWS
    # themselves are hand-authored fixture data, matching TP.INT.0006's own established
    # convention. $Rows $null means "never publish a settingsCatalog expansion at all"
    # (the NotApplicable/no-index fixture, since Invoke-PulseSettingPresenceIndexBuild
    # itself is never called either in that case).
    function script:Invoke-PulseBitlockerCheckFixture {
        param(
            [AllowNull()]
            [object[]] $Rows,
            [switch] $BuildIndex = $true
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $Rows, ([bool] $BuildIndex) {
                param($storeRoot, $keyPath, $rows, $buildIndex)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0031' }
                if (-not $check) { throw "fixture setup: check 'TP.INT.0031' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'

                if ($null -ne $rows) {
                    Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount ($rows | Select-Object -ExpandProperty policyId -Unique).Count | Out-Null
                    if ($buildIndex) {
                        Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null
                    }
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.INT.0031 - BitLocker CSP settings present and correct across all Settings Catalog policies' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0031' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: Full encryption resolved on an ASSIGNED policy' {
        $rows = @(New-PulseBitlockerRow -PolicyId 'p1')
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'Full encryption'
    }

    It 'Fail: setting not present in any expanded policy at all' {
        # An Expanded, empty index (a real settingsCatalog run that produced zero rows).
        $finding = Invoke-PulseBitlockerCheckFixture -Rows @()

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'not found'
    }

    It 'Fail: correct value exists but ONLY on unassigned policies - disclosed, never silently Passed' {
        $rows = @(New-PulseBitlockerRow -PolicyId 'p1' -Assignments @())
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'could be confirmed as assigned'
    }

    It 'Fail: wrong value (used-space-only) on an assigned policy' {
        $rows = @(New-PulseBitlockerRow -PolicyId 'p1' -Value 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_2')
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'never resolves to Full encryption'
    }

    It 'Warn (REDACTION HONESTY): value present on an assigned policy but redacted - never Pass on a value that could not be read' {
        $rows = @(New-PulseBitlockerRow -PolicyId 'p1' -Redacted $true)
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'Warn (UNKNOWN-ASSIGNMENT HONESTY): a satisfying value exists only on a policy with deferred/unknown assignment status - never silently counted as assigned' {
        $rows = @(New-PulseBitlockerRow -PolicyId 'p1' -Assignments $null)
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $rows

        # Not assigned (assignments $null -> Unknown, never counted as Assigned) and not
        # NotAssigned either (Unknown != empty array) - falls into the
        # present-but-not-confirmed-assigned Fail path, with the unknown-assignment
        # disclosure appended.
        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'deferred/unknown assignment status'
    }

    It 'anyUnknownAssignment disclosure appears ALONGSIDE a confident Pass (a different policy has the ambiguity)' {
        $rows = @(
            (New-PulseBitlockerRow -PolicyId 'p1')
            (New-PulseBitlockerRow -PolicyId 'p2' -Assignments $null)
        )
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'deferred/unknown assignment status'
    }

    It 'NotApplicable: no settingPresenceIndex expansion entry at all (expansion was never run for this snapshot)' {
        $finding = Invoke-PulseBitlockerCheckFixture -Rows $null

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expansions.settingPresenceIndex'
    }

    It 'PARTIAL SCAN disclosure: a Partial index (gap on another family) still evaluates, but discloses the incomplete scan in Reason' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'
        try {
            $finding = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath {
                param($storeRoot, $keyPath)
                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0031' }
                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'

                $rows = @([pscustomobject]@{
                        schemaVersion = '1'; policyId = 'p1'; policyType = 'settingsCatalog'; policyName = 'P1'
                        templateFamily = $null; isBaseline = $false
                        settingPath = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype'
                        settingName = 'SystemDrivesEncryptionType'; nameResolved = $true
                        instanceId = 'p1/n:device_vendor_msft_bitlocker_systemdrivesencryptiontype'
                        value = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_1'
                        valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                        assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
                    })
                Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount 1 | Out-Null

                # deviceConfiguration family: written with a tampered file so its own read
                # fails hash verification inside Invoke-PulseSettingPresenceIndexBuild -
                # a genuine PARTIAL outcome, not an absent-family no-op.
                $badRows = @([pscustomobject]@{
                        schemaVersion = '1'; policyId = 'd1'; policyType = 'deviceConfiguration'; policyName = 'D1'
                        templateFamily = $null; isBaseline = $false; settingPath = 'def-y'; settingDefinitionId = 'def-y'
                        settingName = 'y'; nameResolved = $true; instanceId = 'd1/p:def-y'; value = 'v'
                        valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                        assignments = @()
                    })
                Publish-PulseExpansionRows -Store $store -Name 'deviceConfiguration' -Rows $badRows -Gaps @() -PolicyCount 1 | Out-Null
                $manifest = Get-PulseSnapshotManifest -Store $store
                $badFilePath = Join-Path $store.Root $manifest.expansions.deviceConfiguration.path
                Add-Content -LiteralPath $badFilePath -Value 'tampered' -NoNewline

                Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null

                $evaluation = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
                $evaluation.Document.findings[0]
            }

            $finding.status | Should -Be 'Pass'
            $finding.reason | Should -Match 'PARTIAL SCAN'
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'produces the identical status and reason across two evaluations of the SAME snapshot (determinism)' {
        $rows = @(New-PulseBitlockerRow -PolicyId 'p1')
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'
        try {
            $results = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $rows {
                param($storeRoot, $keyPath, $rows)
                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0031' }
                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount 1 | Out-Null
                Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null

                $first = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
                $second = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
                [pscustomobject]@{ First = $first.Document.findings[0]; Second = $second.Document.findings[0] }
            }
            $results.Second.status | Should -Be $results.First.status
            $results.Second.reason | Should -Be $results.First.reason
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
