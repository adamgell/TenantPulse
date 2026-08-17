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

    function script:New-PulsePhishResistantPolicy {
        param(
            [string] $DisplayName = 'Phishing-Resistant MFA For Admins',
            [string] $State = 'enabled',
            [string[]] $IncludeRoles = $script:allNineRoles,
            [string] $StrengthId = '00000000-0000-0000-0000-000000000004'
        )
        @{
            id            = "ca-$DisplayName"
            displayName   = $DisplayName
            state         = $State
            conditions    = @{ users = @{ includeRoles = $IncludeRoles } }
            grantControls = @{ authenticationStrength = @{ id = $StrengthId; displayName = 'Phishing-resistant MFA' } }
        }
    }
}

Describe 'TP.ENT.0018 - Phishing-resistant authentication strength required for privileged roles' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0018' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an enforced policy on all 9 roles using the built-in phishing-resistant strength' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulsePhishResistantPolicy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'exercises the same rule via a value that was PSObject-shaped before Write-PulseDataset (the fixture harness always re-materializes to hashtable before the rule runs - see ConvertTo-PulseCaPolicyView.Tests.ps1 for genuine shape-neutrality coverage at the view layer)' {
        $policy = ConvertTo-PSObjectShape -Value (New-PulsePhishResistantPolicy)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail (post-review, F1): a fabricated non-built-in strength id is never trusted as phishing-resistant, and is surfaced in evidence as custom-or-unrecognized' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulsePhishResistantPolicy -StrengthId '00000000-0000-0000-0000-000000000005') }
        )

        $finding.status | Should -Be 'Fail'
        # 9 missing-role evidence rows (nothing counts toward coverage) + 1
        # custom-strength evidence row for the surfaced-but-not-trusted policy.
        $finding.evidence.Count | Should -Be 10
        ($finding.evidence | Where-Object { $_.detail.classification -eq 'custom-or-unrecognized-strength' }).Count | Should -Be 1
        $finding.reason | Should -Match 'custom/unrecognized authentication strength'
    }

    It 'Pass: a builtin policy completes coverage on its own; a sibling custom-strength policy is still surfaced in evidence, not silently omitted' {
        $custom = New-PulsePhishResistantPolicy -DisplayName 'Custom Strength For Admins' -StrengthId '11111111-2222-3333-4444-555555555555'
        $builtin = New-PulsePhishResistantPolicy -DisplayName 'Builtin For All 9 Roles'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($custom, $builtin) }
        )

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object { $_.detail.classification -eq 'custom-or-unrecognized-strength' }).Count | Should -Be 1
        $finding.reason | Should -Match 'custom/unrecognized authentication strength'
    }

    It 'Fail: generic MFA (builtInControls) does not satisfy this higher bar even though it satisfies TP.ENT.0005' {
        $policy = @{
            id            = 'ca-generic-mfa'
            displayName   = 'MFA For Admins'
            state         = 'enabled'
            conditions    = @{ users = @{ includeRoles = $script:allNineRoles } }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'generic MFA'
    }

    It 'Fail: report-only phishing-resistant policy does not count as enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulsePhishResistantPolicy -State 'enabledForReportingButNotEnforced') }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: one of the 9 roles is not covered' {
        $partialRoles = @($script:allNineRoles | Select-Object -First 8)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulsePhishResistantPolicy -IncludeRoles $partialRoles) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Fail (post-review, F2 - was a false-Pass bug): an includeAll policy that excludeRoles=[Global Administrator] does NOT count GA as covered' {
        $gaTemplateId = '62e90394-69f5-4237-9190-012177145e10'
        $policy = @{
            id            = 'ca-phish-all-minus-ga'
            displayName   = 'Phishing-Resistant MFA For All Users Except GA'
            state         = 'enabled'
            conditions    = @{ users = @{ includeUsers = @('All'); excludeRoles = @($gaTemplateId) } }
            grantControls = @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' } }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be $gaTemplateId
    }

    It 'Fail (F2): a role-scoped policy that both includes and excludes the same role does not cover it' {
        $gaTemplateId = '62e90394-69f5-4237-9190-012177145e10'
        $policy = New-PulsePhishResistantPolicy
        $policy.conditions.users.excludeRoles = @($gaTemplateId)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.identity | Should -Contain $gaTemplateId
    }

    It 'Pass, no undocumented-exclusion note: an excluded break-glass account declared in Context is not flagged' {
        $bg = '11111111-1111-1111-1111-111111111111'
        $policy = New-PulsePhishResistantPolicy
        $policy.conditions.users.excludeUsers = @($bg)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        ) -Context @{ BreakGlassAccounts = @($bg) }

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Not -Match 'not in the operator-declared'
    }

    It 'Pass, with undocumented-exclusion note: an excluded identifier not declared anywhere is surfaced but does not fail the check' {
        $undeclared = '22222222-2222-2222-2222-222222222222'
        $policy = New-PulsePhishResistantPolicy
        $policy.conditions.users.excludeUsers = @($undeclared)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'not in the operator-declared'
    }

    It 'Pass: an all-users-scoped phishing-resistant policy covers every admin role by definition' {
        $policy = @{
            id            = 'ca-phish-all'
            displayName   = 'Phishing-Resistant MFA For All Users'
            state         = 'enabled'
            conditions    = @{ users = @{ includeUsers = @('All') } }
            grantControls = @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' } }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
    }
}
