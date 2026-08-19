<#
    TP.INT.0018 - Managed Installer rules paired with an enforcing App Control policy.
    Same corpus-verified definitionIds as TP.INT.0017.Tests.ps1 (live capture, not
    Maester's dead `..._policy` / `*upload_policy_selected` strings).
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
    $script:MiDisabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_trustappsfrommanagedinstaller_disabled'

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

    function script:New-PulseEnforcingMiRows {
        param([string] $PolicyId = 'p1')
        @(
            (New-PulseAppControlRow -PolicyId $PolicyId -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId $PolicyId -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId $PolicyId -DefinitionId $script:ManagedInstallerId -Value $script:MiEnabledItemId)
        )
    }

    function script:Invoke-PulseManagedInstallerCheckFixture {
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
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0018' }
                if (-not $check) { throw "fixture setup: check 'TP.INT.0018' not found in the catalog." }

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

Describe 'TP.INT.0018 - Managed Installer rules paired with an enforcing App Control policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0018' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: Managed Installer enabled on the SAME enforcing built-in policy' {
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows (New-PulseEnforcingMiRows)

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'Managed Installer enabled'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'p1'
    }

    It 'Fail: DEPENDENCY TRAP - enforcing App Control without Managed Installer is not enough' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:ManagedInstallerId -Value $script:MiDisabledItemId)
        )
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'None of 1'
    }

    It 'Fail: Managed Installer enabled only on an audit-only policy is a false sense of protection' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p-audit' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p-audit' -DefinitionId $script:AuditModeId -Value $script:AuditEnabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-audit' -DefinitionId $script:ManagedInstallerId -Value $script:MiEnabledItemId)
        )
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'audit-only'
    }

    It 'Fail: SAME-POLICY AND - Managed Installer on policy A and enforce+active-control on policy B is not a Pass' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p-mi' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p-mi' -DefinitionId $script:AuditModeId -Value $script:AuditEnabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-mi' -DefinitionId $script:ManagedInstallerId -Value $script:MiEnabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-enforce' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p-enforce' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p-enforce' -DefinitionId $script:ManagedInstallerId -Value $script:MiDisabledItemId)
        )
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 2
    }

    It 'Fail: Managed Installer on an Enforce upload with empty XML is not an active control' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:UploadItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:XmlUploadId -Value '')
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:ManagedInstallerId -Value $script:MiEnabledItemId)
        )
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'no active control'
    }

    It 'Fail: no App Control settings configured anywhere' {
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows @()

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No App Control for Business policy is configured'
    }

    It 'Warn (REDACTION HONESTY): redacted Managed Installer on an otherwise-enforcing policy' {
        $rows = @(
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:BuildOptionsId -Value $script:BuiltInItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:AuditModeId -Value $script:AuditDisabledItemId)
            (New-PulseAppControlRow -PolicyId 'p1' -DefinitionId $script:ManagedInstallerId -Redacted $true)
        )
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows $rows

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'redacted'
    }

    It 'NotApplicable: no settingPresenceIndex expansion entry at all' {
        $finding = Invoke-PulseManagedInstallerCheckFixture -Rows $null

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expansions.settingPresenceIndex'
    }
}
