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

    $script:privilegedRoleId = 'role-app-admin'
    $script:unprivilegedRoleId = 'role-helpdesk'

    function script:New-PulseRoleDefinitions {
        @(
            @{ id = $script:privilegedRoleId; displayName = 'Application Administrator'; isPrivileged = $true }
            @{ id = $script:unprivilegedRoleId; displayName = 'Helpdesk Administrator'; isPrivileged = $false }
        )
    }

    function script:New-PulseRoleAssignment {
        param([string] $PrincipalId, [string] $RoleDefinitionId)
        @{ id = "ra-$PrincipalId-$RoleDefinitionId"; roleDefinitionId = $RoleDefinitionId; principalId = $PrincipalId }
    }
}

Describe 'TP.ENT.0021 - Fewer than 10 total privileged role assignments' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0021' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: 3 privileged assignments (below 10), unprivileged assignments not counted' {
        $assignments = @(
            (New-PulseRoleAssignment -PrincipalId 'u1' -RoleDefinitionId $script:privilegedRoleId)
            (New-PulseRoleAssignment -PrincipalId 'u2' -RoleDefinitionId $script:privilegedRoleId)
            (New-PulseRoleAssignment -PrincipalId 'u3' -RoleDefinitionId $script:privilegedRoleId)
            (New-PulseRoleAssignment -PrincipalId 'u4' -RoleDefinitionId $script:unprivilegedRoleId)
        )
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0021' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = New-PulseRoleDefinitions }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match '^3 '
    }

    It 'Fail: exactly 10 privileged assignments meets the threshold (values round-trip through PSObjects before Write-PulseDataset - cosmetic re: shape, the fixture harness always re-materializes to hashtable before the rule runs)' {
        $assignments = @(1..10 | ForEach-Object { ConvertTo-PSObjectShape -Value (New-PulseRoleAssignment -PrincipalId "u$_" -RoleDefinitionId $script:privilegedRoleId) })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0021' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseRoleDefinitions | ForEach-Object { ConvertTo-PSObjectShape -Value $_ }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 10
    }

    It 'Fail: no role definition is flagged isPrivileged at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0021' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(@{ id = $script:unprivilegedRoleId; displayName = 'Helpdesk Administrator'; isPrivileged = $false }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No role definition'
    }

    It 'a role definition missing isPrivileged entirely defaults to not-privileged, not thrown on' {
        $assignments = @((New-PulseRoleAssignment -PrincipalId 'u1' -RoleDefinitionId 'role-legacy'))
        $roleDefs = @(
            @{ id = 'role-legacy'; displayName = 'Some Legacy Role' }
            @{ id = $script:privilegedRoleId; displayName = 'Application Administrator'; isPrivileged = $true }
        )
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0021' -Datasets @(
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $assignments }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = $roleDefs }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match '^0 '
    }
}
