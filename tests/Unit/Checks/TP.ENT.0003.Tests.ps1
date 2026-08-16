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

    function script:New-PulseCaPolicy {
        param([string] $DisplayName, [string] $State = 'enabled', [string[]] $ExcludeUsers = @(), [string[]] $IncludeUsers = @())
        [pscustomobject]@{
            id          = "ca-$DisplayName"
            displayName = $DisplayName
            state       = $State
            conditions  = [pscustomobject]@{ users = [pscustomobject]@{ excludeUsers = $ExcludeUsers; includeUsers = $IncludeUsers } }
        }
    }

    $script:bg1Guid = '11111111-1111-1111-1111-111111111111'
    $script:bg2Guid = '22222222-2222-2222-2222-222222222222'
}

Describe 'TP.ENT.0003 - Break-glass accounts exist and are excluded from Conditional Access' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0003' }) | Should -Not -BeNullOrEmpty
    }

    It 'Fail: no break-glass accounts declared in the assessment context at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{}

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No break-glass accounts'
    }

    It 'Pass: break-glass account (GUID) excluded from every enabled Conditional Access policy that can reach it' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Block Legacy Auth' -ExcludeUsers @($script:bg1Guid)
            New-PulseCaPolicy -DisplayName 'MFA All Users' -ExcludeUsers @($script:bg1Guid)
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid) }

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: break-glass account (GUID) is NOT excluded from one enabled policy that CAN reach it' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Block Legacy Auth' -ExcludeUsers @($script:bg1Guid)
            New-PulseCaPolicy -DisplayName 'MFA All Users' -ExcludeUsers @()
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid) }

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be $script:bg1Guid
    }

    It 'Pass: a disabled/report-only policy that does not exclude the break-glass account is ignored (only enabled policies count)' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Report Only Policy' -State 'enabledForReportingButNotEnforced' -ExcludeUsers @()
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid) }

        $finding.status | Should -Be 'Pass'
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Failed'; Reason = 'throttled: too many requests' }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid) }

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }

    # ---- post-review, M2: GUID format contract ----

    It 'Warn: a declared break-glass account that is not GUID-shaped cannot be resolved against excludeUsers' {
        $policies = @(New-PulseCaPolicy -DisplayName 'Block Legacy Auth' -ExcludeUsers @())

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @('breakglass@contoso.onmicrosoft.com') }

        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'cannot be resolved'
        $finding.evidence[0].detail.issue | Should -Match 'cannot resolve format'
    }

    It 'Fail (not Warn): a genuine exclusion gap on a resolvable GUID account wins over a format warning on a different malformed account' {
        $policies = @(New-PulseCaPolicy -DisplayName 'Block Legacy Auth' -ExcludeUsers @())

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid, 'not-a-guid@contoso.com') }

        $finding.status | Should -Be 'Fail'
    }

    # ---- post-review, M2: include-scope exemption ----

    It 'Pass: a policy explicitly scoped (includeUsers) to OTHER users, not the break-glass account, is exempted - not a gap' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Scoped To Someone Else' -IncludeUsers @($script:bg2Guid) -ExcludeUsers @()
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid) }

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'exempted'
    }

    It 'Fail: a policy scoped to includeUsers "All" CAN reach the account and is not exempted' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'All Users Policy' -IncludeUsers @('All') -ExcludeUsers @()
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @($script:bg1Guid) }

        $finding.status | Should -Be 'Fail'
    }
}
