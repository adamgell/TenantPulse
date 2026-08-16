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

    $script:compliantAuthMethodsPolicyHashtable = @{
        id                    = 'authenticationMethodsPolicy'
        policyMigrationState  = 'migrationComplete'
        reportSuspiciousActivitySettings = @{
            state         = 'enabled'
            includeTarget = @{ id = 'all_users' }
        }
    }
}

Describe 'TP.ENT.0007 - Authentication methods policy general settings (EIDSCA.AG01-AG03)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0007' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: migration complete, suspicious-activity reporting enabled and scoped to all users (hashtable shape)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($script:compliantAuthMethodsPolicyHashtable) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 3
    }

    It 'Pass (PSObject shape)' {
        $pso = ConvertTo-PSObjectShape -Value $script:compliantAuthMethodsPolicyHashtable
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($pso) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: migration state never started fresh (empty string) still passes AG01' {
        $row = $script:compliantAuthMethodsPolicyHashtable.Clone()
        $row.policyMigrationState = ''
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.AG01').detail.ok | Should -Be $true
    }

    It 'Fail: migration stuck in premigration is evidence-only (AG01 Informational) but AG02 disabled gates' {
        $row = @{
            id                    = 'authenticationMethodsPolicy'
            policyMigrationState  = 'premigration'
            reportSuspiciousActivitySettings = @{
                state         = 'default'
                includeTarget = @{ id = 'all_users' }
            }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.AG02'
        ($finding.evidence | Where-Object identity -eq 'EIDSCA.AG01').detail.ok | Should -Be $false
    }

    It 'Fail: suspicious-activity reporting scoped away from all users' {
        $row = $script:compliantAuthMethodsPolicyHashtable.Clone()
        $row.reportSuspiciousActivitySettings = @{ state = 'enabled'; includeTarget = @{ id = 'pilot-group-guid' } }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'EIDSCA.AG03'
    }

    It 'Error: authenticationMethodsPolicy row missing the reportSuspiciousActivitySettings property (unrecognized shape)' {
        $row = @{ id = 'authenticationMethodsPolicy'; policyMigrationState = 'migrationComplete' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'Fail: no authenticationMethodsPolicy row collected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0007' -Datasets @(
            @{ Name = 'authenticationMethodsPolicy'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No authenticationMethodsPolicy row'
    }
}
