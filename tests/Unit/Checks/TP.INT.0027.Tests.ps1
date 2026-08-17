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

Describe 'TP.INT.0027 - No orphaned Windows Autopilot device identities' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0027' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: every identity is covered by a deployment profile' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0027' -Datasets @(
            @{ Name = 'windowsAutopilotDeviceIdentities'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'd1'; serialNumber = 'REDACTED-1'; model = 'Surface Laptop'; deploymentProfileAssignmentStatus = 'assignedInSync' }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: at least one identity is notAssigned' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0027' -Datasets @(
            @{ Name = 'windowsAutopilotDeviceIdentities'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'd1'; serialNumber = 'REDACTED-1'; model = 'Surface Laptop'; deploymentProfileAssignmentStatus = 'assignedInSync' }
                [pscustomobject]@{ id = 'd2'; serialNumber = 'REDACTED-2'; model = 'Surface Laptop'; deploymentProfileAssignmentStatus = 'notAssigned' }
            ) }
        )
        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'd2'
    }

    It 'Pass: pending/failed sync status is not treated as orphaned (a targeted-but-syncing device is not "never targeted")' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0027' -Datasets @(
            @{ Name = 'windowsAutopilotDeviceIdentities'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'd1'; serialNumber = 'REDACTED-1'; model = 'Surface Laptop'; deploymentProfileAssignmentStatus = 'pending' }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable: zero Autopilot identities registered (skip, not fail)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0027' -Datasets @(
            @{ Name = 'windowsAutopilotDeviceIdentities'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Error: deploymentProfileAssignmentStatus is absent on an existing identity row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0027' -Datasets @(
            @{ Name = 'windowsAutopilotDeviceIdentities'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'd1'; serialNumber = 'REDACTED-1'; model = 'Surface Laptop' }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }
}
