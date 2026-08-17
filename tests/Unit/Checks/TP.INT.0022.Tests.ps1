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

Describe 'TP.INT.0022 - Android Enterprise connection bound, validated, and syncing' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0022' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: bound, validated, and synced within the last day' {
        $recent = [datetime]::UtcNow.AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'settings1'; bindStatus = 'boundAndValidated'; lastAppSyncStatus = 'success'; lastAppSyncDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable: bindStatus is notBound (Android Enterprise not in use, skip not fail)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'settings1'; bindStatus = 'notBound' }) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Fail: bound but not validated' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'settings1'; bindStatus = 'unbound' }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: validated but last sync status is not success' {
        $recent = [datetime]::UtcNow.AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'settings1'; bindStatus = 'boundAndValidated'; lastAppSyncStatus = 'failed'; lastAppSyncDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: validated and successful status but sync is stale (more than a day old)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'settings1'; bindStatus = 'boundAndValidated'; lastAppSyncStatus = 'success'; lastAppSyncDateTime = '2020-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: zero rows returned' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }

    It 'Error: bindStatus is absent on an existing row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0022' -Datasets @(
            @{ Name = 'androidManagedStoreAccountEnterpriseSettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'settings1' }) }
        )
        $finding.status | Should -Be 'Error'
    }
}
