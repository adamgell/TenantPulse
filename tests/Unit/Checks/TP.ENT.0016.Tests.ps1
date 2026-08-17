BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

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

Describe 'TP.ENT.0016 - Guest group ownership restriction (EIDSCA.ST08)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0016' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: AllowGuestsToBeGroupOwner explicitly set to false (hashtable shape)' {
        $rows = @(@{ id = 's1'; values = @(@{ name = 'AllowGuestsToBeGroupOwner'; value = 'false' }) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.ST08').detail.explicitlyConfigured | Should -Be $true
    }

    It 'Pass (PSObject shape)' {
        $rows = @(@{ id = 's1'; values = @(@{ name = 'AllowGuestsToBeGroupOwner'; value = 'false' }) })
        $pso = @(ConvertTo-PSObjectShape -Value $rows[0])
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $pso }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: guests can be group owners' {
        $rows = @(@{ id = 's1'; values = @(@{ name = 'AllowGuestsToBeGroupOwner'; value = 'true' }) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match "'true'"
    }

    It 'Pass: setting never customized - the un-customized EIDSCA default (false) already matches recommended' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.ST08').detail.explicitlyConfigured | Should -Be $false
    }

    It 'descriptor-pending: NotApplicable when directorySettings was skipped (no released GraphKit descriptor)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Pass: ST08/ST09 both explicitly set to their recommended values' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'AllowGuestsToBeGroupOwner'; value = 'false' }
                    @{ name = 'AllowGuestsToAccessGroups'; value = 'True' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.ST09').detail.explicitlyConfigured | Should -Be $true
    }

    It 'Fail: ST09 explicitly disabled - guest group-content access master toggle switched off' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'AllowGuestsToBeGroupOwner'; value = 'false' }
                    @{ name = 'AllowGuestsToAccessGroups'; value = 'False' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0016' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.ST09'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.ST09').detail.ok | Should -Be $false
    }
}
