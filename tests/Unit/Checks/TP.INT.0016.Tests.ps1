BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:AsrRuleGuids = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b'
    )

    function script:New-PulseAsrRuleRow {
        param(
            [string] $PolicyId,
            [string] $Guid,
            [string] $Value = '1',
            [bool] $Redacted = $false,
            [AllowNull()] [object[]] $Assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
        )
        $defId = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_$Guid"
        [pscustomobject]@{
            schemaVersion = '1'; policyId = $PolicyId; policyType = 'settingsCatalog'; policyName = "Policy-$PolicyId"
            templateFamily = $null; isBaseline = $false
            settingPath = $defId; settingDefinitionId = $defId
            settingName = "ASR rule $Guid"; nameResolved = $true
            instanceId = "$PolicyId/n:$defId"
            value = if ($Redacted) { $null } else { $Value }
            valueLabel = $null; labelResolved = $false; redacted = $Redacted; valueState = $null; applicability = $null
            assignments = $Assignments
        }
    }

    function script:New-PulseAllThreeRulesRows {
        param([string] $PolicyId = 'p1', [string] $Value = '1', [AllowNull()] [object[]] $Assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null }))
        return @($script:AsrRuleGuids | ForEach-Object { New-PulseAsrRuleRow -PolicyId $PolicyId -Guid $_ -Value $Value -Assignments $Assignments })
    }

    function script:Invoke-PulseAsrCheckFixture {
        param(
            [AllowNull()]
            [object[]] $Rows
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $Rows {
                param($storeRoot, $keyPath, $rows)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0016' }
                if (-not $check) { throw "fixture setup: check 'TP.INT.0016' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'

                if ($null -ne $rows) {
                    Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount ($rows | Select-Object -ExpandProperty policyId -Unique).Count | Out-Null
                    Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.INT.0016 - Attack Surface Reduction "Standard Protection" baseline rules configured' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0016' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: all 3 Standard Protection rules Block on the SAME assigned policy' {
        $rows = New-PulseAllThreeRulesRows -Value '1'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'All 3 Standard Protection ASR rules'
    }

    It 'Pass: UNION across policies - rule 1 on policy A, rules 2+3 on policy B, still counts as a combined Pass' {
        $rows = @(
            (New-PulseAsrRuleRow -PolicyId 'pA' -Guid $script:AsrRuleGuids[0] -Value '1')
            (New-PulseAsrRuleRow -PolicyId 'pB' -Guid $script:AsrRuleGuids[1] -Value '2')
            (New-PulseAsrRuleRow -PolicyId 'pB' -Guid $script:AsrRuleGuids[2] -Value '1')
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: Audit mode (value 2) also satisfies the rule, not just Block' {
        $rows = New-PulseAllThreeRulesRows -Value '2'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: no ASR rules configured anywhere' {
        $finding = Invoke-PulseAsrCheckFixture -Rows @()

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match '3 of 3 Standard Protection ASR rule'
    }

    It 'Fail: 2 of 3 rules configured, 1 missing entirely' {
        $rows = @(
            (New-PulseAsrRuleRow -PolicyId 'p1' -Guid $script:AsrRuleGuids[0] -Value '1')
            (New-PulseAsrRuleRow -PolicyId 'p1' -Guid $script:AsrRuleGuids[1] -Value '1')
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match '1 of 3'
    }

    It 'Fail: value 0 (Disabled) does not satisfy the rule' {
        $rows = New-PulseAllThreeRulesRows -Value '0'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: value 6 (Warn) does not satisfy the rule (Standard Protection requires Block or Audit)' {
        $rows = New-PulseAllThreeRulesRows -Value '6'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: correct value exists but only on an unassigned policy - disclosed, never silently Passed' {
        $rows = New-PulseAllThreeRulesRows -Value '1' -Assignments @()
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'unassigned policy protects nothing'
    }

    It 'Warn (REDACTION HONESTY): a rule''s value is present on an assigned policy but redacted - never Pass on a value that could not be read' {
        $rows = @(
            (New-PulseAsrRuleRow -PolicyId 'p1' -Guid $script:AsrRuleGuids[0] -Value '1')
            (New-PulseAsrRuleRow -PolicyId 'p1' -Guid $script:AsrRuleGuids[1] -Redacted $true)
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'Warn (UNKNOWN-ASSIGNMENT HONESTY): unknown-assignment disclosure appears alongside a confident Pass' {
        $rows = @(
            (New-PulseAllThreeRulesRows -PolicyId 'p1' -Value '1')
            (New-PulseAsrRuleRow -PolicyId 'p2' -Guid $script:AsrRuleGuids[0] -Value '1' -Assignments $null)
        ) | ForEach-Object { $_ }

        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'deferred/unknown assignment status'
    }

    It 'NotApplicable: no settingPresenceIndex expansion entry at all' {
        $finding = Invoke-PulseAsrCheckFixture -Rows $null

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expansions.settingPresenceIndex'
    }

    It 'accepts a Settings-Catalog-choice-style suffixed value (definitionId plus _1) as satisfying, not just the bare integer' {
        $guid = $script:AsrRuleGuids[0]
        $defId = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_$guid"
        $rows = @($script:AsrRuleGuids | ForEach-Object {
                New-PulseAsrRuleRow -PolicyId 'p1' -Guid $_ -Value "${defId}_1"
            })
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
    }

    It 'produces the identical status and reason across two evaluations of the SAME snapshot (determinism)' {
        $rows = New-PulseAllThreeRulesRows -Value '1'
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'
        try {
            $results = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $rows {
                param($storeRoot, $keyPath, $rows)
                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0016' }
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
