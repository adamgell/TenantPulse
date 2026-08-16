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

    function script:New-PulseManagedDevice {
        param([string] $Id, [string] $OperatingSystem)
        [pscustomobject]@{ id = $Id; deviceName = "device-$Id"; operatingSystem = $OperatingSystem }
    }
}

Describe 'TP.INT.0002 - A compliance policy exists for every enrolled platform' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0002' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: no managed devices enrolled at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: Windows and iOS enrolled, both have a compliance policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'p1'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy' }
                [pscustomobject]@{ id = 'p2'; '@odata.type' = '#microsoft.graph.iosCompliancePolicy' }
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
                (New-PulseManagedDevice -Id 'd2' -OperatingSystem 'iOS')
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: Android is enrolled but has no compliance policy of any Android variant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'p1'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy' }
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Windows')
                (New-PulseManagedDevice -Id 'd2' -OperatingSystem 'Android')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'Android'
    }

    It 'Pass: Android compliance matches any Android policy variant (androidWorkProfileCompliancePolicy)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'p1'; '@odata.type' = '#microsoft.graph.androidWorkProfileCompliancePolicy' }
            ) }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseManagedDevice -Id 'd1' -OperatingSystem 'Android')
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'gate-degraded: NotApplicable when managedDevices failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0002' -Datasets @(
            @{ Name = 'deviceCompliancePolicies'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'managedDevices'; ApiVersion = 'v1.0'; Status = 'Failed'; Reason = 'throttled: too many requests' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }
}
