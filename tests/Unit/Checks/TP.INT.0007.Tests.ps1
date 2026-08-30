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

                $manifest = Get-PulseSnapshotManifest -Store $store
                $gates = if ($null -eq $check.Data -or $null -eq $check.Data.Gates) { @() } else { @($check.Data.Gates) }
                if ($gates.Count -gt 0) {
                    if (-not $manifest.Contains('licenseEvidence') -or $manifest.licenseEvidence -isnot [System.Collections.IDictionary]) {
                        $manifest.licenseEvidence = [ordered]@{}
                    }
                    foreach ($gate in $gates) {
                        if ($null -ne $gate -and -not [string]::IsNullOrWhiteSpace([string] $gate)) {
                            $manifest.licenseEvidence[[string] $gate] = [ordered]@{
                                Status = 'Available'
                                Detail = 'fixture gate'
                            }
                        }
                    }
                    if ($manifest.licenseEvidence.Count -gt 0) {
                        $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
                        Set-PulseAtomicFileContent -Path $store.ManifestPath -Value $canonicalJson
                    }
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.INT.0007 - Intune device clean-up rule configured' {
    It 'catalog: consumes the per-platform managed-device cleanup rules dataset' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0007' }
        $check | Should -Not -BeNullOrEmpty
        @($check.Data.Datasets) | Should -Be @('managedDeviceCleanupRules')
    }

    It 'Pass: valid per-platform rules produce one deterministic evidence row per rule regardless of service order' {
        $rules = @(
            [pscustomobject]@{
                '@odata.type' = '#microsoft.graph.managedDeviceCleanupRule'
                id = 'rule-windows'
                displayName = 'Windows cleanup'
                description = 'Synthetic Windows fixture'
                deviceCleanupRulePlatformType = 'windows'
                lastModifiedDateTime = '2026-08-01T00:00:00Z'
                deviceInactivityBeforeRetirementInDays = [long] 90
            }
            [pscustomobject]@{
                '@odata.type' = '#microsoft.graph.managedDeviceCleanupRule'
                id = 'rule-all'
                displayName = 'All platforms cleanup'
                description = 'Synthetic all-platform fixture'
                deviceCleanupRulePlatformType = 'all'
                lastModifiedDateTime = '2026-08-02T00:00:00Z'
                deviceInactivityBeforeRetirementInDays = [long] 60
            }
        )
        $forward = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
            @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rules }
        )
        $reversed = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
            @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($rules[1], $rules[0]) }
        )

        $forward.status | Should -Be 'Pass'
        $forward.reason | Should -Match '2 Intune device clean-up rules are configured'
        @($forward.evidence).Count | Should -Be 2
        @($forward.evidence.identity) | Should -Be @('rule-all', 'rule-windows')
        $forward.evidence[0].detail | ConvertTo-Json -Compress | Should -Be '{"deviceCleanupRulePlatformType":"all","deviceInactivityBeforeRetirementInDays":60,"displayName":"All platforms cleanup"}'
        ($forward.evidence | ConvertTo-Json -Depth 10 -Compress) | Should -Be ($reversed.evidence | ConvertTo-Json -Depth 10 -Compress)
    }

    It 'Fail: a successful empty collection authoritatively means no clean-up rule is configured' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
            @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No Intune device clean-up rule is configured'
        @($finding.evidence).Count | Should -Be 0
    }

    It 'Fail: a collection containing only a zero-day rule has no configured rule' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
            @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{
                    id = 'rule-disabled'
                    displayName = 'Disabled cleanup'
                    deviceCleanupRulePlatformType = 'all'
                    deviceInactivityBeforeRetirementInDays = [long] 0
                }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'rule-disabled'
    }

    It 'Error: missing, null, string, fractional, negative, or out-of-range days are malformed rather than unconfigured' {
        $malformedRules = @(
            [pscustomobject]@{ id = 'missing'; displayName = 'Missing'; deviceCleanupRulePlatformType = 'all' }
            [pscustomobject]@{ id = 'null'; displayName = 'Null'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = $null }
            [pscustomobject]@{ id = 'string'; displayName = 'String'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = '90' }
            [pscustomobject]@{ id = 'fractional'; displayName = 'Fractional'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = 90.5 }
            [pscustomobject]@{ id = 'negative'; displayName = 'Negative'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = [long] -1 }
            [pscustomobject]@{ id = 'overflow'; displayName = 'Overflow'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = [long] ([int]::MaxValue) + 1 }
        )

        foreach ($rule in $malformedRules) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
                @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($rule) }
            )
            $finding.status | Should -Be 'Error' -Because "days on rule '$($rule.id)' are malformed"
        }
    }

    It 'Error: a malformed row beside a valid configured rule never invents authoritative success' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
            @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'valid'; displayName = 'Valid'; deviceCleanupRulePlatformType = 'windows'; deviceInactivityBeforeRetirementInDays = [long] 90 }
                [pscustomobject]@{ id = 'malformed'; displayName = 'Malformed'; deviceCleanupRulePlatformType = 'ios'; deviceInactivityBeforeRetirementInDays = 'not-an-integer' }
            ) }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'gate-degraded: NotApplicable while managedDeviceCleanupRules cannot be collected by the pinned GraphKit release' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0007' -Datasets @(
            @{ Name = 'managedDeviceCleanupRules'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting a GraphKit release with ManagedDeviceCleanupRule.ListBeta' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting a GraphKit release with ManagedDeviceCleanupRule.ListBeta'
    }
}
