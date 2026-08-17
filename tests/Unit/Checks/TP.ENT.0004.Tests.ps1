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

    function script:New-PulseLegacyAuthPolicy {
        param(
            [string] $DisplayName = 'Block Legacy Auth',
            [string] $State = 'enabled',
            [string[]] $ExcludeUsers = @()
        )
        [pscustomobject]@{
            id             = "ca-$DisplayName"
            displayName    = $DisplayName
            state          = $State
            conditions     = [pscustomobject]@{
                clientAppTypes = @('exchangeActiveSync', 'other')
                users          = [pscustomobject]@{ excludeUsers = $ExcludeUsers }
            }
            grantControls  = [pscustomobject]@{ builtInControls = @('block') }
        }
    }

    $script:bgGuid = '11111111-1111-1111-1111-111111111111'
}

Describe 'TP.ENT.0004 - Legacy authentication is blocked by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0004' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an enabled policy blocks legacy authentication' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass (post-review, L1): clientAppTypes "all" covers legacy protocols too, not just itemized exchangeActiveSync/other' {
        $allAppsPolicy = [pscustomobject]@{
            id            = 'ca-all-apps-block'
            displayName   = 'Block All Client App Types'
            state         = 'enabled'
            conditions    = [pscustomobject]@{ clientAppTypes = @('all') }
            grantControls = [pscustomobject]@{ builtInControls = @('block') }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($allAppsPolicy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: policy exists but is report-only, not enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -State 'enabledForReportingButNotEnforced') }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'report-only'
    }

    It 'Fail: no policy at all blocks legacy authentication' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies was skipped (no EntraP1 data)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All'
    }

    # ---- Task 3.5: exclusion-context wiring (evidence only, never a Status input) ----

    It 'no exclusion evidence at all when no -Context is supplied (empty exclusion context, existing evidence shape unchanged)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass with honored-exclusion evidence: a declared break-glass account excluded from the enforced block policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        $exclusionEntry.detail.excludedFromEnforcedBlockPolicies | Should -Contain 'Block Legacy Auth'
        @($exclusionEntry.detail.excludedFromReportOnlyBlockPolicies).Count | Should -Be 0
    }

    It 'report-only exclusion is surfaced but distinguished from enforced honoring - never counted as protection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -State 'enabledForReportingButNotEnforced' -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Fail'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        @($exclusionEntry.detail.excludedFromEnforcedBlockPolicies).Count | Should -Be 0
        $exclusionEntry.detail.excludedFromReportOnlyBlockPolicies | Should -Contain 'Block Legacy Auth'
    }

    It 'a declared identifier not named in any evaluated policy''s excludeUsers gets no exclusion evidence entry' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        ($finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }) | Should -BeNullOrEmpty
    }
}
