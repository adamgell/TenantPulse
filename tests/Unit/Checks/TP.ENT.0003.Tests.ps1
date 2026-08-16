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
        param([string] $DisplayName, [string] $State = 'enabled', [string[]] $ExcludeUsers = @())
        [pscustomobject]@{
            id         = "ca-$DisplayName"
            displayName = $DisplayName
            state      = $State
            conditions = [pscustomobject]@{ users = [pscustomobject]@{ excludeUsers = $ExcludeUsers } }
        }
    }
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

    It 'Pass: break-glass account excluded from every enabled Conditional Access policy' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Block Legacy Auth' -ExcludeUsers @('bg1@contoso.com')
            New-PulseCaPolicy -DisplayName 'MFA All Users' -ExcludeUsers @('bg1@contoso.com')
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @('bg1@contoso.com') }

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: break-glass account is NOT excluded from one enabled policy' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Block Legacy Auth' -ExcludeUsers @('bg1@contoso.com')
            New-PulseCaPolicy -DisplayName 'MFA All Users' -ExcludeUsers @()
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @('bg1@contoso.com') }

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'bg1@contoso.com'
    }

    It 'Pass: a disabled/report-only policy that does not exclude the break-glass account is ignored (only enabled policies count)' {
        $policies = @(
            New-PulseCaPolicy -DisplayName 'Report Only Policy' -State 'enabledForReportingButNotEnforced' -ExcludeUsers @()
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $policies }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @('bg1@contoso.com') }

        $finding.status | Should -Be 'Pass'
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0003' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Failed'; Reason = 'throttled: too many requests' }
            @{ Name = 'directoryRoleAssignments'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        ) -Context @{ BreakGlassAccounts = @('bg1@contoso.com') }

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }
}
