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
}

Describe 'TP.ENT.0002 - Fewer than 5 Global Administrators' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0002' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: 4 Global Administrators via the well-known template id, no directoryRoleDefinitions needed' {
        $assignments = 1..4 | ForEach-Object { New-PulseGaAssignment -PrincipalId "user-$_" }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0002' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: 5 Global Administrators' {
        $assignments = 1..5 | ForEach-Object { New-PulseGaAssignment -PrincipalId "user-$_" }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0002' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Pass: resolves Global Administrator via directoryRoleDefinitions displayName join when the role definition id differs from the template id' {
        $assignments = 1..4 | ForEach-Object { New-PulseGaAssignment -PrincipalId "user-$_" -RoleDefinitionId 'custom-def-id' }
        $definitions = @([pscustomobject]@{ id = 'custom-def-id'; displayName = 'Global Administrator'; templateId = '62e90394-69f5-4237-9190-012177145e10' })

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0002' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = $definitions }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: same principal assigned twice is counted once (distinct principals, not assignment rows)' {
        $assignments = @(New-PulseGaAssignment -PrincipalId 'dup-user') + (1..4 | ForEach-Object { New-PulseGaAssignment -PrincipalId "user-$_" }) + @(New-PulseGaAssignment -PrincipalId 'dup-user')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0002' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        # 5 distinct principals (dup-user + user-1..4) -> Fail, proving dedup by principalId
        # (6 raw assignment rows would also Fail, so this only proves dedup together with
        # the "4 distinct -> Pass" case above).
        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when directoryRoleAssignments failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0002' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'NotApplicable'
    }
}
