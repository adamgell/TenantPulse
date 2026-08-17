<#
    T3.4 dual-review fix round 1, CRITICAL/convergent finding: the original version of
    this file used fabricated settingDefinitionIds (GUID-suffixed) and fabricated option
    values (bare '1'/'2') that do not exist in Intune's real Settings Catalog schema. Every
    definitionId and option-value string in this file is now taken VERBATIM from
    scratch/live-27/snapshot/reference/settingDefinitions.json (the Phase 2 captured
    corpus, 18,227 real definitions) - grep the definitionId strings below against that
    file directly to re-verify; do not hand-edit them without re-checking the corpus.
    RED-THEN-GREEN: these tests were run against the PRE-fix rule function (GUID-suffixed
    defIds, bare-integer predicate) and failed - confirmed the fixtures actually exercise
    the fix, not just restate it. See this task's own report for the failure transcript.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    # CORPUS-VERIFIED (scratch/live-27/snapshot/reference/settingDefinitions.json,
    # grep'd by line number - see this task's own report for the exact JSON fragments):
    #   line 795166: "id": "...blockabuseofexploitedvulnerablesigneddrivers"
    #   line 703138: "id": "...blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem"
    #   line 976658: "id": "...blockpersistencethroughwmieventsubscription"
    # Each definition's own displayName is the human-readable rule name; the definitionId
    # is a lowercase name-slug of that displayName, never a GUID.
    $script:AsrDefinitionIds = @(
        'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers'
        'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem'
        'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription'
    )

    function script:New-PulseAsrRuleRow {
        param(
            [string] $PolicyId,
            [string] $DefinitionId,
            # CORPUS-VERIFIED option itemIds: "<definitionId>_off"/"_block"/"_audit"/"_warn"
            # - the FULL string is the option identity, never a bare integer.
            [string] $OptionSuffix = 'block',
            [bool] $Redacted = $false,
            [AllowNull()] [object[]] $Assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
        )
        $itemId = "${DefinitionId}_$OptionSuffix"
        [pscustomobject]@{
            schemaVersion = '1'; policyId = $PolicyId; policyType = 'settingsCatalog'; policyName = "Policy-$PolicyId"
            templateFamily = $null; isBaseline = $false
            settingPath = $DefinitionId; settingDefinitionId = $DefinitionId
            settingName = "ASR rule $DefinitionId"; nameResolved = $true
            instanceId = "$PolicyId/n:$DefinitionId"
            value = if ($Redacted) { $null } else { $itemId }
            valueLabel = $null; labelResolved = $false; redacted = $Redacted; valueState = $null; applicability = $null
            assignments = $Assignments
        }
    }

    function script:New-PulseAllThreeRulesRows {
        param([string] $PolicyId = 'p1', [string] $OptionSuffix = 'block', [AllowNull()] [object[]] $Assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null }))
        return @($script:AsrDefinitionIds | ForEach-Object { New-PulseAsrRuleRow -PolicyId $PolicyId -DefinitionId $_ -OptionSuffix $OptionSuffix -Assignments $Assignments })
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

    It 'Pass: all 3 Standard Protection rules Block (corpus-verified itemId) on the SAME assigned policy' {
        $rows = New-PulseAllThreeRulesRows -OptionSuffix 'block'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'All 3 Standard Protection ASR rules'
        # I4 (Phase 3 whole-phase review): every status path now attaches per-rule
        # evidence (presence/assignment counts, no policy names).
        $finding.evidence.Count | Should -Be 3
        $finding.evidence.identity | Should -Contain $script:AsrDefinitionIds[0]
    }

    It 'Pass: UNION across policies - rule 1 on policy A, rules 2+3 on policy B, still counts as a combined Pass' {
        $rows = @(
            (New-PulseAsrRuleRow -PolicyId 'pA' -DefinitionId $script:AsrDefinitionIds[0] -OptionSuffix 'block')
            (New-PulseAsrRuleRow -PolicyId 'pB' -DefinitionId $script:AsrDefinitionIds[1] -OptionSuffix 'audit')
            (New-PulseAsrRuleRow -PolicyId 'pB' -DefinitionId $script:AsrDefinitionIds[2] -OptionSuffix 'block')
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: Audit mode (corpus-verified "_audit" itemId) also satisfies the rule, not just Block' {
        $rows = New-PulseAllThreeRulesRows -OptionSuffix 'audit'
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
            (New-PulseAsrRuleRow -PolicyId 'p1' -DefinitionId $script:AsrDefinitionIds[0] -OptionSuffix 'block')
            (New-PulseAsrRuleRow -PolicyId 'p1' -DefinitionId $script:AsrDefinitionIds[1] -OptionSuffix 'block')
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match '1 of 3'
    }

    It 'Fail: corpus-verified "_off" itemId (Disabled) does not satisfy the rule' {
        $rows = New-PulseAllThreeRulesRows -OptionSuffix 'off'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: corpus-verified "_warn" itemId does not satisfy the rule (Standard Protection requires Block or Audit)' {
        $rows = New-PulseAllThreeRulesRows -OptionSuffix 'warn'
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: a value that merely CONTAINS the definitionId as a substring (e.g. a sibling _perruleexclusions row) never satisfies - exact itemId match only' {
        $rows = @(New-PulseAsrRuleRow -PolicyId 'p1' -DefinitionId $script:AsrDefinitionIds[0] -OptionSuffix 'perruleexclusions')
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: correct value exists but only on an unassigned policy - disclosed, never silently Passed' {
        $rows = New-PulseAllThreeRulesRows -OptionSuffix 'block' -Assignments @()
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'unassigned policy protects nothing'
    }

    It 'Warn (REDACTION HONESTY): a rule''s value is present on an assigned policy but redacted - never Pass on a value that could not be read' {
        $rows = @(
            (New-PulseAsrRuleRow -PolicyId 'p1' -DefinitionId $script:AsrDefinitionIds[0] -OptionSuffix 'block')
            (New-PulseAsrRuleRow -PolicyId 'p1' -DefinitionId $script:AsrDefinitionIds[1] -Redacted $true)
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'Warn (REDACTION HONESTY, ZERO SATISFIED): a rule value is redacted-assigned even when 0 of 3 rules are satisfied - never Fail claiming "not configured" for a value that could not be read' {
        $rows = @(
            (New-PulseAsrRuleRow -PolicyId 'p1' -DefinitionId $script:AsrDefinitionIds[0] -Redacted $true)
        )
        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'Warn (UNKNOWN-ASSIGNMENT HONESTY): unknown-assignment disclosure appears alongside a confident Pass' {
        $rows = @(New-PulseAllThreeRulesRows -PolicyId 'p1' -OptionSuffix 'block') + @(
            New-PulseAsrRuleRow -PolicyId 'p2' -DefinitionId $script:AsrDefinitionIds[0] -OptionSuffix 'block' -Assignments $null
        )

        $finding = Invoke-PulseAsrCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'deferred/unknown assignment status'
    }

    It 'NotApplicable: no settingPresenceIndex expansion entry at all' {
        $finding = Invoke-PulseAsrCheckFixture -Rows $null

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expansions.settingPresenceIndex'
    }

    It 'produces the identical status and reason across two evaluations of the SAME snapshot (determinism)' {
        $rows = New-PulseAllThreeRulesRows -OptionSuffix 'block'
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
