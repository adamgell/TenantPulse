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

Describe 'TP.INT.0023 - Intune Certificate Connectors healthy and on a supported version' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0023' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: active, above the version floor, connected recently' {
        $recent = [datetime]::UtcNow.AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0023' -Datasets @(
            @{ Name = 'ndesConnectors'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'conn1'; displayName = 'CC01'; state = 'active'; connectorVersion = '6.2510.3.3007'; lastConnectionDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: state is not active' {
        $recent = [datetime]::UtcNow.AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0023' -Datasets @(
            @{ Name = 'ndesConnectors'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'conn1'; displayName = 'CC01'; state = 'error'; connectorVersion = '6.2510.3.3007'; lastConnectionDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: version is below the supported floor' {
        $recent = [datetime]::UtcNow.AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0023' -Datasets @(
            @{ Name = 'ndesConnectors'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'conn1'; displayName = 'CC01'; state = 'active'; connectorVersion = '6.2202.38.0'; lastConnectionDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: last connection was more than an hour ago' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0023' -Datasets @(
            @{ Name = 'ndesConnectors'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'conn1'; displayName = 'CC01'; state = 'active'; connectorVersion = '6.2510.3.3007'; lastConnectionDateTime = '2020-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: zero connectors registered (skip, not fail)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0023' -Datasets @(
            @{ Name = 'ndesConnectors'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: connectorVersion is absent on an existing connector row (field-absence lens)' {
        $recent = [datetime]::UtcNow.AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0023' -Datasets @(
            @{ Name = 'ndesConnectors'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'conn1'; displayName = 'CC01'; state = 'active'; lastConnectionDateTime = $recent }) }
        )
        $finding.status | Should -Be 'Error'
    }
}
