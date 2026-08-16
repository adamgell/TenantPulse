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

    function script:New-PulseUpdateRing {
        param([string] $Id, [Nullable[int]] $FeatureDeadline = $null, [Nullable[int]] $QualityDeadline = $null)
        [pscustomobject]@{
            id                                 = $Id
            displayName                        = "ring-$Id"
            '@odata.type'                       = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
            deadlineForFeatureUpdatesInDays     = $FeatureDeadline
            deadlineForQualityUpdatesInDays     = $QualityDeadline
        }
    }
}

Describe 'TP.INT.0004 - At least 2 Windows Update rings have deadlines configured' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0004' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: 2 rings, both with a feature-update deadline configured' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -FeatureDeadline 3)
                (New-PulseUpdateRing -Id 'broad' -FeatureDeadline 14)
            ) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 2
    }

    It 'Pass: a quality-update-only deadline still counts' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -QualityDeadline 2)
                (New-PulseUpdateRing -Id 'broad' -QualityDeadline 7)
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: only 1 of 2 rings has a deadline configured' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                (New-PulseUpdateRing -Id 'pilot' -FeatureDeadline 3)
                (New-PulseUpdateRing -Id 'broad')
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'broad'
    }

    It 'Fail: no Windows Update ring profiles exist at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when deviceConfigurations failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0004' -Datasets @(
            @{ Name = 'deviceConfigurations'; ApiVersion = 'v1.0'; Status = 'Skipped'; Reason = 'permission-denied: DeviceManagementConfiguration.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
    }
}
