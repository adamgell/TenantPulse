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

Describe 'TP.INT.0025 - Personally-owned Windows device enrollment blocked' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0025' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: default policy blocks personal Windows enrollment' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0025' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'cfg1'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; displayName = 'All Users'; priority = 0; windowsRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true } }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: default policy does not block personal Windows enrollment' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0025' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'cfg1'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; displayName = 'All Users'; priority = 0; windowsRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false } }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Pass: lowest-priority row wins when multiple restriction policies exist' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0025' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'cfg-custom'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; displayName = 'Custom (higher priority)'; priority = 1; windowsRestriction = [pscustomobject]@{ personalDeviceEnrollmentBlocked = $false } }
                [pscustomobject]@{ id = 'cfg-default'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; displayName = 'All Users'; priority = 0; windowsRestriction = [pscustomobject]@{ personalDeviceEnrollmentBlocked = $true } }
            ) }
        )
        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].identity | Should -Be 'cfg-default'
    }

    It 'skips non-restriction rows in the mixed deviceEnrollmentConfigurations collection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0025' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; priority = 0 }
                [pscustomobject]@{ id = 'cfg1'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; displayName = 'All Users'; priority = 0; windowsRestriction = [pscustomobject]@{ personalDeviceEnrollmentBlocked = $true } }
            ) }
        )
        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].identity | Should -Be 'cfg1'
    }

    It 'NotApplicable: no platform restriction policy present' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0025' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: windowsRestriction is absent on the default policy (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0025' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'cfg1'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; displayName = 'All Users'; priority = 0 }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }
}
