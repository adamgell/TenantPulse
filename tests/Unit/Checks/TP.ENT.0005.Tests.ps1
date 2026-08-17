BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:allNineRoles = @(
        '62e90394-69f5-4237-9190-012177145e10'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f'
        'b0f54661-2d74-4c50-afa3-1ec803f12efe'
        '158c047a-c907-4556-b7ef-446551a6b5f7'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
        '29232cdf-9323-42fd-ade2-1d097af3e4de'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        '966707d0-3269-4727-9be2-8c3a10f19b9d'
    )

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

    function script:New-PulseMfaPolicy {
        param(
            [string] $DisplayName = 'MFA For Admins',
            [string] $State = 'enabled',
            [string[]] $IncludeRoles,
            [string[]] $ExcludeUsers = @()
        )
        [pscustomobject]@{
            id            = "ca-$DisplayName"
            displayName   = $DisplayName
            state         = $State
            conditions    = [pscustomobject]@{ users = [pscustomobject]@{ includeRoles = $IncludeRoles; excludeUsers = $ExcludeUsers } }
            grantControls = [pscustomobject]@{ builtInControls = @('mfa') }
        }
    }

    $script:adminGuid = '33333333-3333-3333-3333-333333333333'
}

Describe 'TP.ENT.0005 - MFA is required for admin roles by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0005' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass (post-review, H1): a policy using authenticationStrength (Microsoft''s own phishing-resistant template shape) satisfies MFA, not just builtInControls mfa' {
        $authStrengthPolicy = [pscustomobject]@{
            id            = 'ca-phish-resistant'
            displayName   = 'Phishing-Resistant MFA For Admins'
            state         = 'enabled'
            conditions    = [pscustomobject]@{ users = [pscustomobject]@{ includeRoles = $script:allNineRoles } }
            grantControls = [pscustomobject]@{ authenticationStrength = [pscustomobject]@{ id = 'phishingResistant'; displayName = 'Phishing-resistant MFA' } }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($authStrengthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'authenticationStrength'
    }

    It 'Pass: a single enabled policy covers all 9 required roles' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allNineRoles) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: a single enabled policy with includeUsers "All" covers all 9 required roles by definition' {
        $allUsersPolicy = [pscustomobject]@{
            id            = 'ca-all-users-mfa'
            displayName   = 'MFA For All Users'
            state         = 'enabled'
            conditions    = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') } }
            grantControls = [pscustomobject]@{ builtInControls = @('mfa') }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($allUsersPolicy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: coverage split across two enabled policies still satisfies the union' {
        $half1 = $script:allNineRoles[0..4]
        $half2 = $script:allNineRoles[5..8]
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseMfaPolicy -DisplayName 'MFA Set 1' -IncludeRoles $half1)
                (New-PulseMfaPolicy -DisplayName 'MFA Set 2' -IncludeRoles $half2)
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: one of the 9 required roles is not covered by any enabled policy' {
        $missingOne = $script:allNineRoles[0..7]
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $missingOne) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be $script:allNineRoles[8]
    }

    It 'Fail: coverage only exists in a report-only policy, never enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -State 'enabledForReportingButNotEnforced' -IncludeRoles $script:allNineRoles) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 9
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies was skipped (no EntraP1 data)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All'
    }

    # ---- Task 3.5: exclusion-context wiring (evidence only, never a Status input) ----

    It 'no exclusion evidence at all when no -Context is supplied (existing evidence shape unchanged)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allNineRoles) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass with honored-exclusion evidence: a declared break-glass account excluded from the enforced admin-MFA policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allNineRoles -ExcludeUsers @($script:adminGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:adminGuid) }

        $finding.status | Should -Be 'Pass'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:adminGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        $exclusionEntry.detail.excludedFromEnforcedMfaPolicies | Should -Contain 'MFA For Admins'
        @($exclusionEntry.detail.excludedFromReportOnlyMfaPolicies).Count | Should -Be 0
    }

    It 'report-only exclusion is surfaced but distinguished from enforced honoring - never counted as protection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -State 'enabledForReportingButNotEnforced' -IncludeRoles $script:allNineRoles -ExcludeUsers @($script:adminGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:adminGuid) }

        $finding.status | Should -Be 'Fail'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:adminGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        @($exclusionEntry.detail.excludedFromEnforcedMfaPolicies).Count | Should -Be 0
        $exclusionEntry.detail.excludedFromReportOnlyMfaPolicies | Should -Contain 'MFA For Admins'
    }
}
