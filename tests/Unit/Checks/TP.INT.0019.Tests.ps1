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

Describe 'TP.INT.0019 - Apple MDM Push (APNs) certificate valid for more than 30 days' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0019' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: certificate expires far in the future' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0019' -Datasets @(
            @{ Name = 'applePushNotificationCertificate'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'cert1'; appleIdentifier = 'redacted@example.com'; expirationDateTime = '2028-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Warn: certificate expires within 30 days of the snapshot cutoff' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0019' -Datasets @(
            @{ Name = 'applePushNotificationCertificate'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'cert1'; appleIdentifier = 'redacted@example.com'; expirationDateTime = '2026-08-20T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Warn'
    }

    It 'Fail: certificate has already expired' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0019' -Datasets @(
            @{ Name = 'applePushNotificationCertificate'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'cert1'; appleIdentifier = 'redacted@example.com'; expirationDateTime = '2026-01-01T00:00:00Z' }) }
        )
        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'NotApplicable: no APNs certificate configured at all' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0019' -Datasets @(
            @{ Name = 'applePushNotificationCertificate'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0019' -Datasets @(
            @{ Name = 'applePushNotificationCertificate'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }

    It 'Error: expirationDateTime is absent on an existing certificate row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0019' -Datasets @(
            @{ Name = 'applePushNotificationCertificate'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'cert1'; appleIdentifier = 'redacted@example.com' }) }
        )
        $finding.status | Should -Be 'Error'
    }

    # Phase 3 closing fix series, item 4 audit finding: appleIdentifier is the Apple ID
    # (person-identifying) behind this APNs certificate - the same risk class as
    # TP.INT.0020/0021's own appleIdentifier/organizationName, missed on this sibling
    # check in the original fix. Verifies the evidence row marks it, and that
    # Invoke-PulseEvaluation's redaction map picks up the raw value as a result.
    It 'marks appleIdentifier for redaction - its raw value lands in the evaluation RedactionMap' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'
        try {
            $redactionMap = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath {
                param($storeRoot, $keyPath)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0019' }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                Write-PulseDataset -Store $store -Name 'applePushNotificationCertificate' -ApiVersion 'beta' -Status 'Collected' -Data @(
                    [pscustomobject]@{ id = 'cert1'; appleIdentifier = 'apnsadmin@contoso.example'; expirationDateTime = '2028-01-01T00:00:00Z' }
                )

                (Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath).RedactionMap
            }

            $redactionMap.Keys | Should -Contain 'apnsadmin@contoso.example'
            $redactionMap['apnsadmin@contoso.example'] | Should -Match '^tp-[0-9a-f]{64}$'
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
