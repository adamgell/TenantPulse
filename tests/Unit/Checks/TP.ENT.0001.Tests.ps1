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

                $context = if ($null -ne $datasets -and $datasets.Count -gt 0 -and $datasets[0].ContainsKey('__Context')) { $datasets[0].__Context } else { @{} }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -Context $context
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.ENT.0001 - Security Defaults state is appropriate' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0001' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: Security Defaults enabled and no Conditional Access policies' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0001' -Datasets @(
            @{ Name = 'securityDefaultsPolicy'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isEnabled = $true }) }
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable (superseded, post-review): Conditional Access is in use, regardless of Security Defaults state - never Pass (would inflate the score with unearned credit)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0001' -Datasets @(
            @{ Name = 'securityDefaultsPolicy'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isEnabled = $false }) }
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'p1'; state = 'enabled' }) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'Conditional Access is in use'
    }

    It 'Fail: Security Defaults disabled and no Conditional Access policies at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0001' -Datasets @(
            @{ Name = 'securityDefaultsPolicy'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isEnabled = $false }) }
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Error: an absent isEnabled property on securityDefaultsPolicy never reads as Pass or Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0001' -Datasets @(
            @{ Name = 'securityDefaultsPolicy'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default' }) }
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isEnabled'
    }

    It 'gate-degraded: NotApplicable when securityDefaultsPolicy failed to collect' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0001' -Datasets @(
            @{ Name = 'securityDefaultsPolicy'; ApiVersion = 'v1.0'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }

    It 'Error: an absent/null state on a Conditional Access policy never silently reads as not-enabled (L2 field-absence fix)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0001' -Datasets @(
            @{ Name = 'securityDefaultsPolicy'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isEnabled = $true }) }
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'p1' }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'state'
    }

    It 'catalog: Severity is High (post-review, L3 - a zero-baseline-protection Fail, not a partial-credit Medium)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0001' }).Severity | Should -Be 'High'
    }
}
