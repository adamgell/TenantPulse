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
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.INT.0008 - Intune Multi Admin Approval policy configured' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0008' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: at least one operation approval policy exists' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0008' -Datasets @(
            @{ Name = 'operationApprovalPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'policy-1'; displayName = 'Scripts MAA'; policyType = 'deviceManagementScript' }) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].detail.policyType | Should -Be 'deviceManagementScript'
    }

    It 'Pass: multiple policies all carried as evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0008' -Datasets @(
            @{ Name = 'operationApprovalPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'policy-1'; displayName = 'Scripts MAA'; policyType = 'deviceManagementScript' }
                [pscustomobject]@{ id = 'policy-2'; displayName = 'Device actions MAA'; policyType = 'deviceManagement' }
            ) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Fail: zero operation approval policies configured' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0008' -Datasets @(
            @{ Name = 'operationApprovalPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No Intune Multi Admin Approval'
        @($finding.evidence).Count | Should -Be 0
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0008' -Datasets @(
            @{ Name = 'operationApprovalPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
