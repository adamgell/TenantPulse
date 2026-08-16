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

    $script:isoNow = [datetime]::UtcNow.ToString('o')
    $script:isoStale = [datetime]::UtcNow.AddDays(-120).ToString('o')
}

Describe 'TP.INT.0005 - Devices inactive for more than 90 days' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0005' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: every device in both populations synced/signed in recently' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'device-1'; lastSyncDateTime = $script:isoNow; azureADDeviceId = 'aad-1' }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'e1'; displayName = 'device-1'; deviceId = 'aad-1'; approximateLastSignInDateTime = $script:isoNow }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: a managed device has not synced in over 90 days' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'stale-device'; lastSyncDateTime = $script:isoStale; azureADDeviceId = 'aad-1' }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'managed:m1'
    }

    It 'Fail: an Entra-registered device has not signed in for over 90 days, evidence identity is source-prefixed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'e1'; displayName = 'stale-entra-device'; deviceId = 'aad-9'; approximateLastSignInDateTime = $script:isoStale }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].identity | Should -Be 'entra:e1'
    }

    It 'Fail: a device with no recorded sync/sign-in timestamp at all is treated as stale, not skipped' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'never-synced' }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: reports the Entra-registered-but-not-Intune-managed population gap in the Reason' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'stale'; lastSyncDateTime = $script:isoStale; azureADDeviceId = 'aad-1' }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'e1'; displayName = 'device-1'; deviceId = 'aad-1'; approximateLastSignInDateTime = $script:isoNow }
                [pscustomobject]@{ id = 'e2'; displayName = 'unmanaged-device'; deviceId = 'aad-unmanaged'; approximateLastSignInDateTime = $script:isoNow }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match '1 Entra-registered device'
    }

    It 'gate-degraded: NotApplicable when managedDevices failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Failed'; Reason = 'throttled: too many requests' }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }
}
