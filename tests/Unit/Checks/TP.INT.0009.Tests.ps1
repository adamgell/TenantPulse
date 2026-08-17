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

Describe 'TP.INT.0009 - Windows diagnostic data processor configuration enabled' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0009' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: both hasValidWindowsLicense and areDataProcessorServiceForWindowsFeaturesEnabled are true' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ hasValidWindowsLicense = $true; areDataProcessorServiceForWindowsFeaturesEnabled = $true }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: both booleans false (licensing gap, worded distinctly)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ hasValidWindowsLicense = $false; areDataProcessorServiceForWindowsFeaturesEnabled = $false }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'LICENSING gap'
    }

    It 'Fail: licensed but feature not enabled (worded distinctly from the licensing case)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ hasValidWindowsLicense = $true; areDataProcessorServiceForWindowsFeaturesEnabled = $false }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'has not been enabled'
    }

    It 'Fail: feature enabled but not licensed (worded distinctly)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ hasValidWindowsLicense = $false; areDataProcessorServiceForWindowsFeaturesEnabled = $true }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'does not \(or has not attested to\) hold a qualifying Windows license'
    }

    It 'Fail: hasValidWindowsLicense absent entirely reads the same as false (field-absence, never a silent Pass)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ areDataProcessorServiceForWindowsFeaturesEnabled = $true }) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Error: dataProcessorServiceForWindowsFeaturesOnboarding returning zero rows never reads as Pass or Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'gate-degraded: NotApplicable when the dataset failed to collect (e.g. Pending, on a live tenant today)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0009' -Datasets @(
            @{ Name = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
