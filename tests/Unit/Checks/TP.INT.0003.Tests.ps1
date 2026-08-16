BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:Invoke-PulseCheckFixture {
        param(
            [Parameter(Mandatory)] [string] $CheckId,
            [Parameter(Mandatory)] [hashtable[]] $Datasets
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets {
                param($storeRoot, $keyPath, $checkId, $datasets)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq $checkId }
                if (-not $check) { throw "fixture setup: check '$checkId' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                foreach ($d in $datasets) {
                    $params = @{
                        Store      = $store
                        Name       = $d.Name
                        ApiVersion = $d.ApiVersion
                        Status     = $d.Status
                    }
                    if ($d.ContainsKey('Data')) { $params.Data = $d.Data }
                    if ($d.ContainsKey('Reason')) { $params.Reason = $d.Reason }
                    Write-PulseDataset @params
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.INT.0003 - Devices without an assigned compliance policy are marked noncompliant' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0003' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: secureByDefault is true (the secure polarity - unassigned devices are marked noncompliant)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0003' -Datasets @(
            @{ Name = 'deviceManagementSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ secureByDefault = $true }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: secureByDefault is false (unassigned devices silently read as compliant)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0003' -Datasets @(
            @{ Name = 'deviceManagementSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ secureByDefault = $false }) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Error: an ABSENT secureByDefault property never reads as Pass or Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0003' -Datasets @(
            @{ Name = 'deviceManagementSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ someOtherProperty = 'x' }) }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'Error: deviceManagementSettings returning zero rows never reads as Pass or Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0003' -Datasets @(
            @{ Name = 'deviceManagementSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'gate-degraded: NotApplicable when deviceManagementSettings failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0003' -Datasets @(
            @{ Name = 'deviceManagementSettings'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: DeviceManagementConfiguration.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: DeviceManagementConfiguration.Read.All'
    }
}
