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

Describe 'TP.INT.0021 - Apple Volume Purchase Program tokens valid and syncing' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0021' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: token valid far into the future and synced within the last day' {
        $recent = [datetime]::UtcNow.AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0021' -Datasets @(
            @{ Name = 'vppTokens'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'vpp1'; organizationName = 'Contoso'; expirationDateTime = '2028-01-01T00:00:00Z'; lastSyncDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: token has already expired' {
        $recent = [datetime]::UtcNow.AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0021' -Datasets @(
            @{ Name = 'vppTokens'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'vpp1'; organizationName = 'Contoso'; expirationDateTime = '2026-01-01T00:00:00Z'; lastSyncDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: token valid but last sync was more than a day ago' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0021' -Datasets @(
            @{ Name = 'vppTokens'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'vpp1'; organizationName = 'Contoso'; expirationDateTime = '2028-01-01T00:00:00Z'; lastSyncDateTime = '2020-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'sync'
    }

    It 'Warn: token expires within 30 days but sync is current' {
        $recent = [datetime]::UtcNow.AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $soon = [datetime]::UtcNow.AddDays(10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0021' -Datasets @(
            @{ Name = 'vppTokens'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'vpp1'; organizationName = 'Contoso'; expirationDateTime = $soon; lastSyncDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Warn'
    }

    It 'NotApplicable: zero VPP tokens configured (skip, not fail)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0021' -Datasets @(
            @{ Name = 'vppTokens'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: lastSyncDateTime is absent on an existing token row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0021' -Datasets @(
            @{ Name = 'vppTokens'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'vpp1'; organizationName = 'Contoso'; expirationDateTime = '2028-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Error'
    }
}
