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

Describe 'TP.INT.0029 - Security baselines assigned and not on a deprecated version' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0029' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: every baseline instance is assigned and current' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: unassigned instance' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: assigned but deprecated version' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Defender baseline (old)'; templateFamily = 'baselineDefenderForEndpoint'; hasAssignment = $true; isDeprecated = $true }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: no baseline instance of any tracked family in use' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }

    It 'Error: isDeprecated is absent on an existing row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $true }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }
}
