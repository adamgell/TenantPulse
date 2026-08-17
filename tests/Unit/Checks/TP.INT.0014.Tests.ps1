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

Describe 'TP.INT.0014 - BitLocker full-disk encryption enforced via Endpoint Security policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0014' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: at least one policy enforces full-disk encryption' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Full'; isFullDiskEncryption = $true }) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'Fail: zero Disk Encryption policies exist' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No Endpoint Security Disk Encryption policy'
        @($finding.evidence).Count | Should -Be 0
    }

    It 'Fail: policies exist but none enforce full encryption (used-space-only)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Used-Space-Only'; isFullDiskEncryption = $false }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'none enforce full-disk encryption'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'Pass: a mix of full and used-space-only policies still passes on the presence of one full policy, evidence includes both' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Full'; isFullDiskEncryption = $true }
                [pscustomobject]@{ policyId = 'p2'; policyName = 'BitLocker Used-Space-Only'; isFullDiskEncryption = $false }
            ) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
