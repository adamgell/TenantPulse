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

    function script:New-PulseTodayString {
        # Mirrors what Invoke-PulseEvaluation derives EvaluationCutoffBase from
        # (the snapshot manifest's own createdUtc, set at New-PulseSnapshotStore time to
        # real wall-clock "now") - tests build sync timestamps relative to actual today so
        # the same-day sync comparison behaves correctly regardless of which day this suite
        # happens to run.
        return [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

Describe 'TP.INT.0020 - Apple Automated Device Enrollment tokens valid and syncing' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0020' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: token valid far into the future and synced today' {
        $today = New-PulseTodayString
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'tok1'; appleIdentifier = 'redacted@example.com'; tokenName = 'Primary'; tokenExpirationDateTime = '2028-01-01T00:00:00Z'; lastSuccessfulSyncDateTime = $today }) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: token has already expired' {
        $today = New-PulseTodayString
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'tok1'; appleIdentifier = 'redacted@example.com'; tokenName = 'Primary'; tokenExpirationDateTime = '2026-01-01T00:00:00Z'; lastSuccessfulSyncDateTime = $today }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: token valid but last successful sync was not today' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'tok1'; appleIdentifier = 'redacted@example.com'; tokenName = 'Primary'; tokenExpirationDateTime = '2028-01-01T00:00:00Z'; lastSuccessfulSyncDateTime = '2020-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'sync'
    }

    It 'Warn: token expires within 30 days but sync is current' {
        $today = New-PulseTodayString
        $soon = [datetime]::UtcNow.AddDays(10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'tok1'; appleIdentifier = 'redacted@example.com'; tokenName = 'Primary'; tokenExpirationDateTime = $soon; lastSuccessfulSyncDateTime = $today }) }
        )
        $finding.status | Should -Be 'Warn'
    }

    It 'NotApplicable: zero ADE tokens configured (skip, not fail)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Fail (not Error): two id-less tokens sharing the SAME appleIdentifier do not collide on evidence identity (I2 ordinal fallback)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                    [pscustomobject]@{ appleIdentifier = 'shared@example.com'; tokenName = 'A'; tokenExpirationDateTime = '2026-01-01T00:00:00Z'; lastSuccessfulSyncDateTime = '2020-01-01T00:00:00Z' }
                    [pscustomobject]@{ appleIdentifier = 'shared@example.com'; tokenName = 'B'; tokenExpirationDateTime = '2026-01-02T00:00:00Z'; lastSuccessfulSyncDateTime = '2020-01-01T00:00:00Z' }
                ) }
        )
        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 2
        ($finding.evidence.identity | Select-Object -Unique).Count | Should -Be 2
    }

    It 'Error: tokenExpirationDateTime is absent on an existing token row (field-absence lens)' {
        $today = New-PulseTodayString
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0020' -Datasets @(
            @{ Name = 'depOnboardingSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'tok1'; appleIdentifier = 'redacted@example.com'; lastSuccessfulSyncDateTime = $today }) }
        )
        $finding.status | Should -Be 'Error'
    }
}
