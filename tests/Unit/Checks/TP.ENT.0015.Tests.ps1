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

Describe 'TP.ENT.0015 - Password Protection mode (EIDSCA.PR01)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0015' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: all five PR0x settings explicitly set to their recommended values (hashtable shape)' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Enforce' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'True' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'True' }
                    @{ name = 'LockoutDurationInSeconds'; value = '120' }
                    @{ name = 'LockoutThreshold'; value = '5' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass (PSObject shape)' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Enforce' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'True' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'True' }
                    @{ name = 'LockoutDurationInSeconds'; value = '60' }
                    @{ name = 'LockoutThreshold'; value = '10' }
                )
            })
        $pso = @(ConvertTo-PSObjectShape -Value $rows[0])
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $pso }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: mode explicitly set to Audit - the audit-vs-enforce trap' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Audit' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'True' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'True' }
                    @{ name = 'LockoutDurationInSeconds'; value = '60' }
                    @{ name = 'LockoutThreshold'; value = '10' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match "mode 'Audit'"
    }

    It 'Fail: setting never customized - defaults to the non-enforcing EIDSCA defaults (Audit, PR02 False)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match "mode 'Audit'"
        $finding.reason | Should -Match 'EIDSCA.PR02'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.PR03').detail.ok | Should -Be $true
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.PR05').detail.ok | Should -Be $true
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.PR06').detail.ok | Should -Be $true
    }

    It 'Fail: PR02 on-premises proxy explicitly disabled' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Enforce' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'False' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'True' }
                    @{ name = 'LockoutDurationInSeconds'; value = '60' }
                    @{ name = 'LockoutThreshold'; value = '10' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.PR02'
    }

    It 'Fail: PR03 custom banned-password list explicitly disabled' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Enforce' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'True' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'False' }
                    @{ name = 'LockoutDurationInSeconds'; value = '60' }
                    @{ name = 'LockoutThreshold'; value = '10' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.PR03'
    }

    It 'Fail: PR05 lockout duration below the 60-second minimum' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Enforce' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'True' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'True' }
                    @{ name = 'LockoutDurationInSeconds'; value = '30' }
                    @{ name = 'LockoutThreshold'; value = '10' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.PR05'
    }

    It 'Fail: PR06 lockout threshold above the 10-attempt maximum' {
        $rows = @(@{
                id     = 's1'
                values = @(
                    @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Enforce' }
                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = 'True' }
                    @{ name = 'EnableBannedPasswordCheck'; value = 'True' }
                    @{ name = 'LockoutDurationInSeconds'; value = '60' }
                    @{ name = 'LockoutThreshold'; value = '15' }
                )
            })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.PR06'
    }

    It 'descriptor-pending: NotApplicable when directorySettings was skipped (no released GraphKit descriptor)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0015' -Datasets @(
            @{ Name = 'directorySettings'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
    }
}
