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

Describe 'TP.INT.0028 - Enrollment Status Page configured with blocking failure behavior' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0028' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an assigned ESP profile has blocking enabled' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ groupId = 'g1' } }) }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: assigned but blocking disabled' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $true; assignments = @([pscustomobject]@{ id = 'a1'; target = [pscustomobject]@{ groupId = 'g1' } }) }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: blocking enabled but not assigned to any group' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @() }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'skips non-ESP rows in the mixed deviceEnrollmentConfigurations collection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'cfg1'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; priority = 0 }
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP'; allowDeviceUseOnInstallFailure = $false; assignments = @([pscustomobject]@{ id = 'a1' }) }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable: no ESP profile present' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: allowDeviceUseOnInstallFailure is absent on an ESP row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0028' -Datasets @(
            @{ Name = 'deviceEnrollmentConfigurations'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'esp1'; '@odata.type' = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'; displayName = 'Corp ESP' }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }
}
