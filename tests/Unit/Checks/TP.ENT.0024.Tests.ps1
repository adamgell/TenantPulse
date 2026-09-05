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
        $finding.reason | Should -Match '^0 valid enforced'
    }

    It 'Pass: one enforced workload-identity policy is counted and cited in evidence' {
        $servicePrincipalId = [guid]::ParseExact(('8' * 32), 'N').ToString('D')
        $policy = @{
            id            = 'ca-workload'
            displayName   = 'Workload Identity CA'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ includeServicePrincipals = @('ServicePrincipalsInMyTenant', $servicePrincipalId) } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.includedServicePrincipalCount | Should -Be 1
        $finding.evidence[0].detail.includesAllServicePrincipals | Should -BeTrue
    }

    It 'Pass: a report-only workload-identity policy does not count as coverage' {
        $policy = @{
            id            = 'ca-workload-ro'
            displayName   = 'Workload Identity CA Report-Only'
            state         = 'enabledForReportingButNotEnforced'
            conditions    = @{ clientApplications = @{ includeServicePrincipals = @('ServicePrincipalsInMyTenant') } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match '^0 valid enforced'
    }

    It 'does not count the nonexistent includeApplications workload-identity shape as coverage' {
        $policy = @{
            id            = 'ca-workload-invalid-shape'
            displayName   = 'Invalid Workload Identity Shape'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ includeApplications = @('sp-1') } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match '^0 valid enforced'
        $finding.reason | Should -Match '1 malformed'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].detail.classification | Should -Be 'Malformed'
    }

    It 'does not count blank or malformed service-principal targets as workload-identity coverage' -ForEach @(
        @{ Target = '' }
        @{ Target = 'not-a-service-principal-id' }
    ) {
        $policy = @{
            id            = 'ca-workload-malformed-target'
            displayName   = 'Malformed Workload Identity Target'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ includeServicePrincipals = @($Target) } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.reason | Should -Match '^0 valid enforced'
        $finding.reason | Should -Match '1 malformed'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].detail.classification | Should -Be 'Malformed'
    }

    It 'counts a valid service-principal filter even without an explicit include list' {
        $policy = @{
            id            = 'ca-workload-filter'
            displayName   = 'Filtered Workload Identity CA'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ servicePrincipalFilter = @{ mode = 'include'; rule = 'customSecurityAttributes.Project -eq "Tier0"' } } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.reason | Should -Match '^1 valid enforced'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.classification | Should -Be 'Valid'
        $finding.evidence[0].detail.hasServicePrincipalFilter | Should -BeTrue
    }

    It 'reports a malformed present filter even when an explicit service-principal include is valid' {
        $servicePrincipalId = [guid]::ParseExact(('9' * 32), 'N').ToString('D')
        $policy = @{
            id            = 'ca-workload-malformed-filter'
            displayName   = 'Malformed workload filter'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{
                includeServicePrincipals = @($servicePrincipalId)
                servicePrincipalFilter = @{ mode = 'futureMode'; rule = 'customSecurityAttributes.Project -eq \"Tier0\"' }
            } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.reason | Should -Match '^0 valid enforced'
        $finding.reason | Should -Match '1 malformed'
        $finding.evidence[0].detail.classification | Should -Be 'Malformed'
    }

    It 'counts valid beta agent-identity targeting separately from service-principal targeting' {
        $agentServicePrincipalId = [guid]::ParseExact(('a' * 32), 'N').ToString('D')
        $policy = @{
            id            = 'ca-agent-workload'
            displayName   = 'Agent workload CA'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ includeAgentIdServicePrincipals = @($agentServicePrincipalId) } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.reason | Should -Match '^1 valid enforced'
        $finding.evidence[0].detail.includedAgentIdServicePrincipalCount | Should -Be 1
        $finding.evidence[0].detail.includedServicePrincipalCount | Should -Be 0
    }

    It 'accepts the documented beta All sentinel for tenant-wide agent identities' {
        $policy = @{
            id            = 'ca-all-agent-workloads'
            displayName   = 'All agent workloads'
            state         = 'enabled'
            conditions    = @{ clientApplications = @{ includeAgentIdServicePrincipals = @('All') } }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0024' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding = $result.Document.findings[0]

        $finding.reason | Should -Match '^1 valid enforced'
        $finding.evidence[0].detail.classification | Should -Be 'Valid'
        $finding.evidence[0].detail.includesAllAgentIdServicePrincipals | Should -BeTrue
        $finding.evidence[0].detail.includedAgentIdServicePrincipalCount | Should -Be 0
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
