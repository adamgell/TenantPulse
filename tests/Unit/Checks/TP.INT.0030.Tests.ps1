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

    function script:New-PulseFleetData {
        param([int] $Compliant, [int] $Noncompliant)
        $rows = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $Compliant; $i++) { $rows.Add([pscustomobject]@{ id = "c$i"; complianceState = 'compliant' }) }
        for ($i = 0; $i -lt $Noncompliant; $i++) { $rows.Add([pscustomobject]@{ id = "n$i"; complianceState = 'noncompliant' }) }
        return $rows.ToArray()
    }
}

Describe 'TP.INT.0030 - Fleet compliance rate below acceptable threshold' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0030' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: noncompliance rate below 5%' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 98 -Noncompliant 2) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Warn: noncompliance rate between 5% and 10%' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 93 -Noncompliant 7) }
        )
        $finding.status | Should -Be 'Warn'
    }

    It 'Fail: noncompliance rate above 10%' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = (New-PulseFleetData -Compliant 80 -Noncompliant 20) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: zero managed devices' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: complianceState is absent on an existing device row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0030' -Datasets @(
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'd1' }) }
        )
        $finding.status | Should -Be 'Error'
    }
}
