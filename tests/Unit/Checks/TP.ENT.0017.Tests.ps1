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

    function script:New-PulseAllUsersMfaPolicy {
        param(
            [string] $DisplayName = 'MFA For All Users',
            [string] $State = 'enabled',
            [string[]] $ExcludeUsers = @(),
            [switch] $UseAuthenticationStrength
        )
        $grants = if ($UseAuthenticationStrength) {
            @{ authenticationStrength = @{ id = 'phishingResistant'; displayName = 'Phishing-resistant MFA' } }
        } else {
            @{ builtInControls = @('mfa') }
        }
        @{
            id            = "ca-$DisplayName"
            displayName   = $DisplayName
            state         = $State
            conditions    = @{ users = @{ includeUsers = @('All'); excludeUsers = $ExcludeUsers } }
            grantControls = $grants
        }
    }
}

Describe 'TP.ENT.0017 - MFA required for all users by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0017' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an enabled all-users policy with builtInControls mfa' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'builtInControls:mfa'
    }

    It 'Pass: an enabled all-users policy using authenticationStrength (value round-trips through a PSObject before Write-PulseDataset - cosmetic re: shape, the fixture harness always re-materializes to hashtable before the rule runs; see ConvertTo-PulseCaPolicyView.Tests.ps1 for genuine shape-neutrality coverage at the view layer)' {
        $policy = ConvertTo-PSObjectShape -Value (New-PulseAllUsersMfaPolicy -UseAuthenticationStrength)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'authenticationStrength'
    }

    It 'Fail: report-only-only all-users MFA policy does not count as enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy -State 'enabledForReportingButNotEnforced') }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'report-only'
    }

    It 'Fail: no policy at all targets all users' {
        $rolePolicy = @{
            id            = 'ca-admins-only'
            displayName   = 'MFA For Admins'
            state         = 'enabled'
            conditions    = @{ users = @{ includeRoles = @('62e90394-69f5-4237-9190-012177145e10') } }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($rolePolicy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Pass, no undocumented-exclusion note: an excluded break-glass account declared in Context is not flagged' {
        $bg = '11111111-1111-1111-1111-111111111111'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy -ExcludeUsers @($bg)) }
        ) -Context @{ BreakGlassAccounts = @($bg) }

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Not -Match 'not in the operator-declared'
    }

    It 'Pass, with undocumented-exclusion note: an excluded identifier not declared anywhere is surfaced but does not fail the check' {
        $undeclared = '22222222-2222-2222-2222-222222222222'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy -ExcludeUsers @($undeclared)) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'not in the operator-declared'
    }
}
