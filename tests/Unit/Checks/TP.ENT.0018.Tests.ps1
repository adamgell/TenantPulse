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

    It 'Pass (PSObject shape, second built-in strength id variant)' {
        $policy = ConvertTo-PSObjectShape -Value (New-PulsePhishResistantPolicy -StrengthId '00000000-0000-0000-0000-000000000005')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0018' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
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
