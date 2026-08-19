<#
    TP.INT.0017 - App Control for Business policy enforcing (not audit-only).
    Every definitionId and option-itemId string in this file is taken VERBATIM from
    scratch/live-27/snapshot/reference/settingDefinitions.json (the Phase 2 captured
    corpus, 18,227 real definitions). Maester's own source keys two strings that do
    NOT exist in that capture (`...applicationcontrolv2_policy` and
    `*upload_policy_selected`); these fixtures use the live ids
    (`...xmlupload` / `...buildoptions_upload_xml_selected`) instead.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:BuildOptionsId = 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions'
    $script:AuditModeId = 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode'
    $script:XmlUploadId = 'device_vendor_msft_policy_config_applicationcontrolv2_xmlupload'
    $script:ManagedInstallerId = 'device_vendor_msft_policy_config_applicationcontrolv2_trustappsfrommanagedinstaller'
    $script:BuiltInItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions_built_in_controls_selected'
    $script:UploadItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions_upload_xml_selected'
    $script:AuditDisabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode_disabled'
    $script:AuditEnabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode_enabled'
    $script:MiEnabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_trustappsfrommanagedinstaller_enabled'

    function script:New-PulseAppControlRow {
        param(
            [string] $PolicyId,
            [string] $DefinitionId,
            [AllowNull()] [object] $Value,
            [bool] $Redacted = $false
        )
        [pscustomobject]@{
            schemaVersion       = '1'
            policyId            = $PolicyId
            policyType          = 'settingsCatalog'
            policyName          = "Policy-$PolicyId"
            templateFamily      = 'endpointSecurityApplicationControl'
            isBaseline          = $false
            settingPath         = $DefinitionId
            settingDefinitionId = $DefinitionId
            settingName         = $DefinitionId
            nameResolved        = $true
            instanceId          = "$PolicyId/n:$DefinitionId"
            value               = if ($Redacted) { $null } else { $Value }
            valueLabel          = $null
            labelResolved       = $false
            redacted            = $Redacted
            valueState          = $null
            applicability       = $null
            assignments         = $null
        }
    }

    function script:New-PulseEnforcingBuiltInRows {
        param([string] $PolicyId = 'p1')
        @(
            (New-PulseAppControlRow -PolicyId $PolicyId -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId $PolicyId -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
        )
    }

    function script:Invoke-PulseAppControlCheckFixture {
        param(
            [AllowNull()]
            [object[]] $Rows,
            [string] $CheckId = 'TP.INT.0017'
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $Rows, $CheckId {
                param($storeRoot, $keyPath, $rows, $checkId)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq $checkId }
                if (-not $check) { throw "fixture setup: check '$checkId' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'

                if ($null -ne $rows) {
                    $policyCount = @($rows | Select-Object -ExpandProperty policyId -Unique).Count
                    Publish-PulseExpansionRows -Store $store -Name 'settingsCatalog' -Rows $rows -Gaps @() -PolicyCount $policyCount | Out-Null
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

Describe 'TP.INT.0017 - App Control for Business policy enforcing (not audit-only)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0017' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: built-in controls + audit-mode disabled (Enforce) on the SAME policy' {
        $finding = Invoke-PulseAppControlCheckFixture -Rows (New-PulseEnforcingBuiltInRows)

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'Enforce mode with an active control'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'p1'
    }

    It 'Pass: XML upload with a non-empty payload + Enforce on the SAME policy' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p-xml' -DefinitionId $script:BuildOptionsId -Value $script:UploadItemId)
            (New-PulseAppControlRow -PolicyId 'p-xml' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-xml' -DefinitionId $script:XmlUploadId -Value '<SiPolicy>real</SiPolicy>')
        )
        $finding = Invoke-PulseAppControlCheckFixture -Rows $rows

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: SAME-POLICY AND - audit-only on policy A and empty-XML upload on policy B is not a Pass' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p-audit' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p-audit' -DefinitionId $script:AuditModeId -Value $script:AuditEnabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-empty' -DefinitionId $script:BuildOptionsId -Value $script:UploadItemId)
            (New-PulseAppControlRow -PolicyId 'p-empty' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-empty' -DefinitionId $script:XmlUploadId -Value '')
        )
        $finding = Invoke-PulseAppControlCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'None of 2'
        $finding.evidence.Count | Should -Be 2
    }

    It 'Fail: audit-only built-in policy does not satisfy (zero real-world blocking)' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Value $script:AuditEnabledItemId)
        )
        $finding = Invoke-PulseAppControlCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'Audit-only'
    }

    It 'Fail: XML upload with an empty payload is not an active control' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:UploadItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:XmlUploadId -Value '   ')
        )
        $finding = Invoke-PulseAppControlCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'empty XML'
    }

    It 'Fail: no App Control settings configured anywhere' {
        $finding = Invoke-PulseAppControlCheckFixture -Rows @()

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No App Control for Business policy is configured'
    }

    It 'Warn (REDACTION HONESTY): redacted audit-mode on an otherwise-active policy - never Pass on a value that could not be read' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Redacted $true)
        )
        $finding = Invoke-PulseAppControlCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'Warn (REDACTION HONESTY): redacted XML payload on an Enforce upload policy is not treated as present' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:UploadItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:XmlUploadId -Redacted $true)
        )
        $finding = Invoke-PulseAppControlCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'NotApplicable: no settingPresenceIndex expansion entry at all' {
        $finding = Invoke-PulseAppControlCheckFixture -Rows $null

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expansions.settingPresenceIndex'
    }

    It 'does not require confirmed assignment - Settings Catalog assignments are deferred and Maester keys existence' {
        $finding = Invoke-PulseAppControlCheckFixture -Rows (New-PulseEnforcingBuiltInRows)

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'deferred/unknown'
    }

    It 'produces the identical status and reason across two evaluations of the SAME snapshot (determinism)' {
        $rows = New-PulseEnforcingBuiltInRows
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'
        try {
            $results = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $rows {
                param($storeRoot, $keyPath, $rows)
                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0017' }
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
