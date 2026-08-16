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

Describe 'TP.ENT.0013 - Group/team owner consent restriction (EIDSCA.CP01)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0013' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: EnableGroupSpecificConsent explicitly set to False (hashtable shape)' {
        $rows = @(@{ id = 's1'; templateId = 'tmpl-consent'; values = @(@{ name = 'EnableGroupSpecificConsent'; value = 'False' }) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0013' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.CP01').detail.explicitlyConfigured | Should -Be $true
    }

    It 'Pass (PSObject shape)' {
        $rows = @(@{ id = 's1'; values = @(@{ name = 'EnableGroupSpecificConsent'; value = 'False' }) })
        $pso = @(ConvertTo-PSObjectShape -Value $rows[0])
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0013' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $pso }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: EnableGroupSpecificConsent explicitly set to True' {
        $rows = @(@{ id = 's1'; values = @(@{ name = 'EnableGroupSpecificConsent'; value = 'True' }) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0013' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match "explicitly set to 'True'"
    }

    It 'Fail: setting never customized - defaults to the permissive EIDSCA default (True)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0013' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'never customized and defaults to'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.CP01').detail.explicitlyConfigured | Should -Be $false
    }

    It 'descriptor-pending: NotApplicable when directorySettings was skipped (no released GraphKit descriptor)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0013' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
