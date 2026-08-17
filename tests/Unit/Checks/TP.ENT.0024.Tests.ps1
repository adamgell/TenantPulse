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

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.ENT.0024 - Conditional Access coverage for workload identities (awareness)' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check), Severity is Info' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        $descriptor = $catalog | Where-Object { $_.Id -eq 'TP.ENT.0024' }
        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.Severity | Should -Be 'Info'
    }

    It 'Pass (awareness, always Pass, never Fail): zero workload-identity CA policies' {
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding = $result.Document.findings[0]

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match '^0 enforced'
    }

    It 'Pass: one enforced workload-identity policy is counted and cited in evidence' {
        $policy = @{
            id            = 'ca-workload'
            displayName   = 'Workload Identity CA'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ includeApplications = @('sp-1', 'sp-2') } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.includedApplicationCount | Should -Be 2
    }

    It 'Pass: a report-only workload-identity policy does not count as coverage' {
        $policy = @{
            id            = 'ca-workload-ro'
            displayName   = 'Workload Identity CA Report-Only'
            state         = 'enabledForReportingButNotEnforced'
            conditions    = @{ clientApplications = @{ includeApplications = @('sp-1') } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match '^0 enforced'
    }

    It 'is Info-severity and contributes zero to the overall score (Scoring Model 1.0 weight)' {
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $scored = InModuleScope TenantPulse -ArgumentList $result.Document {
            param($doc)
            $doc.producer = @{ scoringModelVersion = '1.0' }
            Add-PulseScores -Findings $doc
        }

        $scored.scores.overall.possible | Should -Be 0
        $scored.scores.overall.earned | Should -Be 0
    }
}
