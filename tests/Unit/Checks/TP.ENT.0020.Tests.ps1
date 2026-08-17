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

    function script:New-PulseGaAssignment {
        param([string] $PrincipalId, [string] $RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10')
        [pscustomobject]@{ id = "ra-$PrincipalId"; roleDefinitionId = $RoleDefinitionId; principalId = $PrincipalId }
    }

    function script:Invoke-PulseGaCountFixture {
        param([int] $Count)
        $assignments = @()
        if ($Count -gt 0) {
            $assignments = @(1..$Count | ForEach-Object { New-PulseGaAssignment -PrincipalId "ga-$_" })
        }
        Invoke-PulseCheckFixture -CheckId 'TP.ENT.0020' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
    }
}

Describe 'TP.ENT.0020 - Global Administrator count within ScuBAs 2-8 SHALL range' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0020' }) | Should -Not -BeNullOrEmpty
    }

    It 'Fail: zero Global Administrators (below the floor)' {
        (Invoke-PulseGaCountFixture -Count 0).status | Should -Be 'Fail'
    }

    It 'Fail: exactly 1 Global Administrator - passes TP.ENT.0002 (<5) but fails this floor' {
        (Invoke-PulseGaCountFixture -Count 1).status | Should -Be 'Fail'
    }

    It 'Pass: exactly 2 Global Administrators (the floor, inclusive)' {
        (Invoke-PulseGaCountFixture -Count 2).status | Should -Be 'Pass'
    }

    It 'Pass: exactly 8 Global Administrators (the ceiling, inclusive)' {
        (Invoke-PulseGaCountFixture -Count 8).status | Should -Be 'Pass'
    }

    It 'Fail: 9 Global Administrators (above the ceiling)' {
        (Invoke-PulseGaCountFixture -Count 9).status | Should -Be 'Fail'
    }

    It 'Pass: 4 Global Administrators (within range, well under TP.ENT.0002s <5 bar too)' {
        (Invoke-PulseGaCountFixture -Count 4).status | Should -Be 'Pass'
    }
}
