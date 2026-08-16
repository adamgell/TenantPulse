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

    # ---- post-review: newly-enrolled, never-synced devices (L5) ----

    It 'Pass: a device enrolled recently (< 30 days) with no sync yet is NOT counted as stale' {
        $recentEnroll = [datetime]::UtcNow.AddDays(-3).ToString('o')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'brand-new'; enrolledDateTime = $recentEnroll }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.status | Should -Be 'newly enrolled, never synced'
    }

    It 'Fail: a device never synced with an OLD enrolledDateTime (>= 30 days) keeps the original fail-closed behavior' {
        $oldEnroll = [datetime]::UtcNow.AddDays(-200).ToString('o')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'old-never-synced'; enrolledDateTime = $oldEnroll }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].identity | Should -Be 'managed:m1'
        $finding.evidence[0].detail.status | Should -BeNullOrEmpty
    }

    # ---- post-review: population gap as evidence entries, not just Reason text (Important) ----

    It 'Fail: the Entra-vs-Intune population gap appears as evidence entries (a summary plus one per unmanaged device)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'm1'; deviceName = 'stale'; lastSyncDateTime = $script:isoStale; azureADDeviceId = 'aad-1' }) }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'e1'; displayName = 'device-1'; deviceId = 'aad-1'; approximateLastSignInDateTime = $script:isoNow }
                [pscustomobject]@{ id = 'e2'; displayName = 'unmanaged-device'; deviceId = 'aad-unmanaged'; approximateLastSignInDateTime = $script:isoNow }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $summary = $finding.evidence | Where-Object { $_.identity -eq 'gap:summary' }
        $summary | Should -Not -BeNullOrEmpty
        $summary.detail.entraRegisteredNotIntuneManagedCount | Should -Be 1

        $perDevice = $finding.evidence | Where-Object { $_.identity -eq 'gap:e2' }
        $perDevice | Should -Not -BeNullOrEmpty
        $perDevice.detail.displayName | Should -Be 'unmanaged-device'
    }

    # ---- post-review: wall-clock determinism (H2 adjudicated) ----

    It 'produces the identical status and evidence across two evaluations of the SAME snapshot (wall-clock determinism, borderline timing)' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $results = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath {
                param($storeRoot, $keyPath)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0005' }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                $manifestCreatedUtc = (Get-PulseSnapshotManifest -Store $store).createdUtc
                # Borderline by design: exactly 1 hour past the 90-day cutoff, measured from
                # THIS store's own createdUtc - a wall-clock-based cutoff would risk this
                # flipping between two evaluations seconds apart; a manifest-anchored cutoff
                # cannot, because both evaluations read the same createdUtc from disk.
                $borderlineSync = ([datetime]::Parse($manifestCreatedUtc)).AddDays(-90).AddHours(-1).ToString('o')

                Write-PulseDataset -Store $store -Name 'managedDevices' -ApiVersion 'v1.0' -Status 'Collected' -Data @([pscustomobject]@{ id = 'm1'; deviceName = 'borderline'; lastSyncDateTime = $borderlineSync })
                Write-PulseDataset -Store $store -Name 'entraDevices' -ApiVersion 'v1.0' -Status 'Collected' -Data @()

                $first = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
                Start-Sleep -Milliseconds 1200
                $second = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath

                [pscustomobject]@{
                    First  = $first.Document.findings[0]
                    Second = $second.Document.findings[0]
                }
            }

            $results.Second.status | Should -Be $results.First.status
            $results.Second.reason | Should -Be $results.First.reason
            @($results.Second.evidence).Count | Should -Be @($results.First.evidence).Count
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'gate-degraded: NotApplicable when managedDevices failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0005' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Failed'; Reason = 'throttled: too many requests' }
            @{ Name = 'entraDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }

    # Item 13 (final fix wave): a malformed snapshot createdUtc must surface as Error, never
    # silently fall back to wall-clock "now" (which would mask the staleness cutoff being
    # undeterminable). Invoke-PulseEvaluation always populates $Context.EvaluationCutoffBase
    # from the manifest's own createdUtc, so this hand-corrupts manifest.json directly - the
    # only way to reach this path, since New-PulseSnapshotStore itself always writes a valid
    # timestamp.
    It 'Error: a malformed snapshot createdUtc never falls back to wall-clock time (final fix wave, item 13)' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $finding = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath {
                param($storeRoot, $keyPath)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0005' }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                Write-PulseDataset -Store $store -Name 'managedDevices' -ApiVersion 'v1.0' -Status 'Collected' -Data @([pscustomobject]@{ id = 'm1'; deviceName = 'device-1'; lastSyncDateTime = (Get-Date).ToString('o') })
                Write-PulseDataset -Store $store -Name 'entraDevices' -ApiVersion 'v1.0' -Status 'Collected' -Data @()

                # Corrupt createdUtc directly - the only way to reach this without a
                # dedicated malformed-manifest constructor.
                $manifestJson = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
                $manifestJson.createdUtc = 'banana'
                Set-Content -LiteralPath $store.ManifestPath -Value ($manifestJson | ConvertTo-Json -Depth 10) -NoNewline -Encoding utf8

                $evaluation = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
                $evaluation.Document.findings[0]
            }

            $finding.status | Should -Be 'Error'
            $finding.reason | Should -Match 'banana'
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
