BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:privilegedRoleId = 'role-ga'

    function script:Invoke-PulseCheckFixture {
        param(
            [Parameter(Mandatory)] [string] $CheckId,
            [Parameter(Mandatory)] [hashtable[]] $Datasets,
            [hashtable] $Context = @{}
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets, $Context {
                param($storeRoot, $keyPath, $checkId, $datasets, $context)

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

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -Context $context
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function script:New-PulseRoleDefinitions {
        @(@{ id = $script:privilegedRoleId; displayName = 'Global Administrator'; isPrivileged = $true })
    }

    function script:New-PulseScheduleInstance {
        param([string] $Id, [string] $PrincipalId, [string] $AssignmentType = 'Assigned', $EndDateTime = $null, [string] $RoleDefinitionId = $script:privilegedRoleId)
        @{ id = $Id; principalId = $PrincipalId; roleDefinitionId = $RoleDefinitionId; assignmentType = $AssignmentType; endDateTime = $EndDateTime }
    }

    function script:Invoke-PulsePimFixture {
        param([hashtable[]] $Instances, [hashtable] $Context = @{})
        Invoke-PulseCheckFixture -CheckId 'TP.ENT.0022' -Datasets @(
            @{ Name = 'roleAssignmentScheduleInstances'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = $Instances }
            @{ Name = 'roleEligibilityScheduleInstances'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = New-PulseRoleDefinitions }
        ) -Context $Context
    }
}

Describe 'TP.ENT.0022 - Zero permanent-active assignments for privileged roles (PIM posture)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0022' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: no permanent-active assignments, only Activated (time-bound) ones' {
        $instances = @(New-PulseScheduleInstance -Id 'i1' -PrincipalId 'u1' -AssignmentType 'Activated' -EndDateTime '2026-09-01T00:00:00Z')
        (Invoke-PulsePimFixture -Instances $instances).status | Should -Be 'Pass'
    }

    It 'Fail: a permanent-active (Assigned, no endDateTime) privileged-role assignment' {
        $instances = @(New-PulseScheduleInstance -Id 'i1' -PrincipalId 'u1')
        $finding = Invoke-PulsePimFixture -Instances $instances
        $finding.status | Should -Be 'Fail'
        $finding.evidence[0].detail.exempt | Should -Be $false
    }

    It 'Pass, exempt: a permanent-active assignment held by a declared ServiceAccount is not flagged as offending' {
        $svcAccountId = '33333333-3333-3333-3333-333333333333'
        $instances = @(New-PulseScheduleInstance -Id 'i1' -PrincipalId $svcAccountId)
        $finding = Invoke-PulsePimFixture -Instances $instances -Context @{ ServiceAccounts = @($svcAccountId) }
        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'legitimate'
    }

    It 'Pass, exempt: a permanent-active assignment held by a declared break-glass account is not flagged' {
        $bgId = '44444444-4444-4444-4444-444444444444'
        $instances = @(New-PulseScheduleInstance -Id 'i1' -PrincipalId $bgId)
        $finding = Invoke-PulsePimFixture -Instances $instances -Context @{ BreakGlassAccounts = @($bgId) }
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail with mixed evidence: an offending assignment alongside an exempt one, both appear in evidence' {
        $svcAccountId = '55555555-5555-5555-5555-555555555555'
        $instances = @(
            (New-PulseScheduleInstance -Id 'i-offending' -PrincipalId 'u-not-exempt')
            (New-PulseScheduleInstance -Id 'i-exempt' -PrincipalId $svcAccountId)
        )
        $finding = Invoke-PulsePimFixture -Instances $instances -Context @{ ServiceAccounts = @($svcAccountId) }
        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 2
        ($finding.evidence | Where-Object identity -eq 'i-offending').detail.exempt | Should -Be $false
        ($finding.evidence | Where-Object identity -eq 'i-exempt').detail.exempt | Should -Be $true
    }

    It 'Fail: not flagged when isPrivileged has no true entries at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0022' -Datasets @(
            @{ Name = 'roleAssignmentScheduleInstances'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'roleEligibilityScheduleInstances'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
            @{ Name = 'directoryRoleDefinitions'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(@{ id = 'role-x'; displayName = 'Helpdesk'; isPrivileged = $false }) }
        )
        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No role definition'
    }
}
