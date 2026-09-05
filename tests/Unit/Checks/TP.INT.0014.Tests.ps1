BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulsePartialGapFixture {
        param(
            [string] $Scope,
            [string] $ProviderDetail,
            [string] $FailureClass = 'PermissionDenied',
            [string] $ReasonCode = 'permission-denied',
            [string] $Operation = 'ConfigurationPolicySettings.ListBeta'
        )

        if ([string]::IsNullOrEmpty($Scope)) { $Scope = 'scope-canary-' + (@('7f3f19ea', '8af2', '4ca9', 'b708', '80e6688cc8e0') -join '-') }
        if ([string]::IsNullOrEmpty($ProviderDetail)) { $ProviderDetail = 'provider-detail-canary ' + ('admin' + [char] 64 + 'example' + '.invalid') + ' ' + ('sec' + 'ret=fixture-only') }

        InModuleScope TenantPulse -ArgumentList $Scope, $ProviderDetail, $FailureClass, $ReasonCode, $Operation {
            param($scope, $providerDetail, $failureClass, $reasonCode, $operation)
            New-PulseCollectionGap -Scope $scope -FailureClass $FailureClass `
                -ReasonCode $ReasonCode -Detail @{ message = $providerDetail } `
                -Operation $Operation -ApiVersion 'beta'
        }
    }

    function script:Invoke-PulseCheckFixture {
        param(
            [Parameter(Mandatory)] [string] $CheckId,
            [Parameter(Mandatory)] [hashtable[]] $Datasets,
            [switch] $ReturnFixture
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets, ([bool] $ReturnFixture) {
                param($storeRoot, $keyPath, $checkId, $datasets, $returnFixture)

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
                    foreach ($field in @('Reason', 'ReasonCode', 'Detail', 'FailureClass', 'Provider', 'Operations', 'Gaps')) {
                        if ($d.ContainsKey($field)) { $params[$field] = $d[$field] }
                    }
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

                foreach ($d in $datasets) {
                    if (-not $d.ContainsKey('ManifestOverrides')) { continue }
                    foreach ($key in $d.ManifestOverrides.Keys) {
                        $manifest.datasets[$d.Name][$key] = $d.ManifestOverrides[$key]
                    }
                }
                if (@($datasets | Where-Object { $_.ContainsKey('ManifestOverrides') }).Count -gt 0) {
                    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
                    Set-PulseAtomicFileContent -Path $store.ManifestPath -Value $canonicalJson
                    $manifest = Get-PulseSnapshotManifest -Store $store
                }

                $evaluation = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider @{ Intune = @{ Status = 'Available'; Detail = 'fixture' } }
                if (-not $returnFixture) { return $evaluation.Document.findings[0] }

                $scored = Add-PulseScores -Findings $evaluation.Document
                return [pscustomobject]@{
                    Finding          = $evaluation.Document.findings[0]
                    Evaluation       = $evaluation
                    ScoredDocument   = $scored
                    FindingJson      = ConvertTo-PulseCanonicalJson -InputObject $evaluation.Document.findings[0]
                    ScoreJson        = ConvertTo-PulseCanonicalJson -InputObject $scored
                    SnapshotManifest = $manifest
                    Store            = $store
                    StoreRoot        = $storeRoot
                }
            }
            return $result
        } finally {
            if (-not $ReturnFixture) {
                Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe 'TP.INT.0014 - BitLocker full-disk encryption enforced via Endpoint Security policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0014' }
        $check | Should -Not -BeNullOrEmpty
        @($check.Data.PartialDatasets).Count | Should -Be 1
        $check.Data.PartialDatasets[0] | Should -BeExactly 'endpointSecurityDiskEncryptionPolicies'
        InModuleScope TenantPulse { (Get-Command Test-PulseBitLockerFullDiskEncryption).Parameters.Keys } | Should -Contain 'DatasetOutcomes'
    }

    It 'Partial: a native-boolean full-disk witness proves Pass despite an unrelated malformed row in either order, exposes only gap count, and scores 10/10' {
        $gaps = @(
            (New-PulsePartialGapFixture)
            (New-PulsePartialGapFixture -Scope 'second-scope-canary' -ProviderDetail 'second-provider-detail-canary')
        )
        $witness = [pscustomobject]@{ policyId = 'p-witness'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }
        $malformed = [pscustomobject]@{ policyId = 'p-broken'; policyName = 'Broken'; isFullDiskEncryption = 1 }
        $upnCanary = 'admin' + [char] 64 + 'example' + '.invalid'
        $secretCanary = 'sec' + 'ret=fixture-only'

        foreach ($rows in @(@($witness, $malformed), @($malformed, $witness))) {
            $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -ReturnFixture -Datasets @(
                @{
                    Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = @{ canary = 'top-detail-canary' }
                    Provider = 'provider-canary'; Operations = @('ConfigurationPolicy.ListBeta', 'ConfigurationPolicySettings.ListBeta'); Gaps = $gaps
                }
            )
            try {
                $fixture.Finding.status | Should -Be 'Pass'
                @($fixture.Finding.evidence).Count | Should -Be 1
                $fixture.Finding.evidence[0].identity | Should -Be 'p-witness'
                $fixture.Finding.reason | Should -Match '2 unresolved gaps'
                $fixture.Finding.reason | Should -Match 'known qualifying'
                $fixture.ScoredDocument.scores.overall.earned | Should -Be 10
                $fixture.ScoredDocument.scores.overall.possible | Should -Be 10
                $fixture.ScoredDocument.coverage.overall.assessed | Should -Be 1
                $fixture.ScoredDocument.coverage.overall.applicable | Should -Be 1
                $fixture.Evaluation.Document.schemaVersion | Should -Be '1.0'
                $fixture.SnapshotManifest.schemaVersion | Should -Be '2.0.0'
                $fixture.Evaluation.Document.producer.scoringModelVersion | Should -Be '1.0'
                foreach ($canary in @('scope-canary', 'provider-detail-canary', $upnCanary, $secretCanary, 'top-detail-canary', 'provider-canary', 'second-scope-canary', 'second-provider-detail-canary')) {
                    $fixture.FindingJson | Should -Not -Match ([regex]::Escape($canary))
                    $fixture.ScoreJson | Should -Not -Match ([regex]::Escape($canary))
                }
            } finally {
                Remove-Item -LiteralPath $fixture.StoreRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'Partial: valid non-witness rows cannot prove existential failure and are not assessed' {
        $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -ReturnFixture -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Used space only'; isFullDiskEncryption = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        try {
            $fixture.Finding.status | Should -Be 'NotApplicable'
            $fixture.Finding.reason | Should -Match '1 unresolved gap'
            $fixture.Finding.reason | Should -Match 'no known qualifying'
            $fixture.ScoredDocument.scores.overall.earned | Should -Be 0
            $fixture.ScoredDocument.scores.overall.possible | Should -Be 0
            $fixture.ScoredDocument.coverage.overall.assessed | Should -Be 0
            $fixture.ScoredDocument.coverage.overall.applicable | Should -Be 1
            ($fixture.ScoredDocument.coverage.overall.applicable - $fixture.ScoredDocument.coverage.overall.assessed) | Should -Be 1
        } finally {
            Remove-Item -LiteralPath $fixture.StoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Partial: a malformed-only assignment on an otherwise qualifying policy is NotApplicable, never Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ policyId = 'p-malformed'; policyName = 'Full but unresolved'; isFullDiskEncryption = $true; assignmentIntent = 'Malformed' })
                FailureClass = $null; ReasonCode = 'partial'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta')
                Gaps = @((New-PulsePartialGapFixture -Scope 'policy:p-malformed' -FailureClass 'InvalidProviderData' -ReasonCode 'assignment-intent-incomplete' -Operation 'ConfigurationPolicyAssignment.ListBeta'))
            }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.status | Should -Not -Be 'Fail'
        $finding.reason | Should -Match 'no known qualifying'
    }

    It 'Partial: a known assigned qualifying witness Passes with an unrelated malformed assignment gap' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @(
                    [pscustomobject]@{ policyId = 'p-witness'; policyName = 'Full and assigned'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }
                    [pscustomobject]@{ policyId = 'p-malformed'; policyName = 'Full but unresolved'; isFullDiskEncryption = $true; assignmentIntent = 'Malformed' }
                )
                FailureClass = $null; ReasonCode = 'partial'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta')
                Gaps = @((New-PulsePartialGapFixture -Scope 'policy:p-malformed' -FailureClass 'InvalidProviderData' -ReasonCode 'assignment-intent-incomplete' -Operation 'ConfigurationPolicyAssignment.ListBeta'))
            }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'p-witness'
    }

    It 'Collected: a known assigned nonqualifying policy is a deterministic Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'
                Data = @([pscustomobject]@{ policyId = 'p-nonqualifying'; policyName = 'Used space only'; isFullDiskEncryption = $false; assignmentIntent = 'Include' })
            }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'none enforce full-disk encryption'
    }

    It 'rejects boolean-like non-native values in both Collected and non-decisive Partial inputs' {
        foreach ($value in @('true', 1, 'false', 0)) {
            $collected = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
                @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Malformed'; isFullDiskEncryption = $value }) }
            )
            $collected.status | Should -Be 'Error'
            $collected.reason | Should -Match 'native boolean'

            $partial = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
                @{
                    Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                    Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Malformed'; isFullDiskEncryption = $value })
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                    Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
                }
            )
            $partial.status | Should -Be 'Error'
            $partial.reason | Should -Match 'native boolean'
        }
    }

    It 'Complete and non-decisive Partial reject a non-witness row without a usable policyId' {
        $row = [pscustomobject]@{ policyName = 'Used space only'; isFullDiskEncryption = $false }

        $complete = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
        )
        $complete.status | Should -Be 'Error'
        $complete.reason | Should -Match 'policyId'

        $partial = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = @($row)
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $partial.status | Should -Be 'Error'
        $partial.reason | Should -Match 'policyId'
    }

    It 'Partial: a valid witness outranks a non-witness row with no identity in either row order' {
        $witness = [pscustomobject]@{ policyId = 'p-witness'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }
        $malformed = [pscustomobject]@{ policyName = 'Used space only'; isFullDiskEncryption = $false }

        foreach ($rows in @(@($witness, $malformed), @($malformed, $witness))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
                @{
                    Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                    Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
                }
            )
            $finding.status | Should -Be 'Pass'
            @($finding.evidence).Count | Should -Be 1
            $finding.evidence[0].identity | Should -Be 'p-witness'
        }
    }

    It 'Collected: any malformed row returns Error even when a valid witness exists, in either order' {
        $witness = [pscustomobject]@{ policyId = 'p-witness'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }
        $malformed = [pscustomobject]@{ policyId = 'p-broken'; policyName = 'Broken'; isFullDiskEncryption = 1 }
        foreach ($rows in @(@($witness, $malformed), @($malformed, $witness))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
                @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
            )
            $finding.status | Should -Be 'Error'
        }
    }

    It 'Partial: a qualifying row without a usable policyId is malformed and cannot become evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ policyName = 'Full but unidentified'; isFullDiskEncryption = $true; assignmentIntent = 'Include' })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'policyId'
    }

    It 'Partial: zero usable rows fail closed before the rule can manufacture a decision' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = @()
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'no usable rows'
    }

    It 'Partial: a malformed persisted outcome projection fails closed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
                ManifestOverrides = @{ gaps = 'not-an-array' }
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'invalid Partial outcome'
    }

    It 'the persisted engine bounds an unsupported status and reason without serializing either canary' {
        $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -ReturnFixture -Datasets @(
            @{
                Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'
                Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' })
                ManifestOverrides = @{ status = 'persisted-status-canary'; reason = 'persisted-reason-canary' }
            }
        )
        try {
            $fixture.Finding.status | Should -Be 'NotApplicable'
            $fixture.Finding.reason | Should -BeExactly "dataset 'endpointSecurityDiskEncryptionPolicies' has an unsupported collection status."
            $fixture.FindingJson | Should -Not -Match 'persisted-status-canary|persisted-reason-canary'
            $fixture.ScoreJson | Should -Not -Match 'persisted-status-canary|persisted-reason-canary'
        } finally {
            Remove-Item -LiteralPath $fixture.StoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not mutate direct caller datasets or outcome projections' {
        $datasets = @{ endpointSecurityDiskEncryptionPolicies = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }) }
        $outcomes = @{ endpointSecurityDiskEncryptionPolicies = @{ Status = 'Partial'; Gaps = @(@{ Scope = 'x' }) } }
        $before = $datasets | ConvertTo-Json -Depth 20 -Compress
        $outcomeBefore = $outcomes | ConvertTo-Json -Depth 20 -Compress

        $result = InModuleScope TenantPulse -ArgumentList $datasets, $outcomes {
            param($datasets, $outcomes)
            Test-PulseBitLockerFullDiskEncryption -Datasets $datasets -DatasetOutcomes $outcomes
        }

        $result.Status | Should -Be 'Pass'
        ($datasets | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $before
        ($outcomes | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $outcomeBefore
    }

    It 'direct calls reject null, unsupported, and non-scalar outcome projections with one bounded canary-free error' {
        $observed = InModuleScope TenantPulse {
            $datasets = @{ endpointSecurityDiskEncryptionPolicies = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }) }
            $statusCanary = 'unsupported-status-canary'
            $cases = @(
                @{ Name = 'missing declared key'; Outcomes = @{} }
                @{ Name = 'null root'; Outcomes = $null }
                @{ Name = 'null entry'; Outcomes = @{ endpointSecurityDiskEncryptionPolicies = $null } }
                @{ Name = 'non-dictionary entry'; Outcomes = @{ endpointSecurityDiskEncryptionPolicies = 'not-a-dictionary' } }
                @{ Name = 'unsupported scalar'; Outcomes = @{ endpointSecurityDiskEncryptionPolicies = @{ Status = $statusCanary } } }
                @{ Name = 'non-scalar'; Outcomes = @{ endpointSecurityDiskEncryptionPolicies = @{ Status = @('Partial') } } }
            )

            @($cases | ForEach-Object {
                try {
                    $null = Test-PulseBitLockerFullDiskEncryption -Datasets $datasets -DatasetOutcomes $_.Outcomes
                    [pscustomobject]@{ Name = $_.Name; Threw = $false; Message = '' }
                } catch {
                    [pscustomobject]@{ Name = $_.Name; Threw = $true; Message = $_.Exception.Message }
                }
            })
        }

        $observed.Count | Should -Be 6
        foreach ($case in $observed) {
            $case.Threw | Should -BeTrue -Because $case.Name
            $case.Message | Should -BeExactly 'Test-PulseBitLockerFullDiskEncryption: the dataset outcome projection is invalid.' -Because $case.Name
            $case.Message | Should -Not -Match 'unsupported-status-canary|System\.Object|null-valued' -Because $case.Name
        }
    }

    It 'Pass: at least one policy enforces full-disk encryption' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }) }
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
                [pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Full'; isFullDiskEncryption = $true; assignmentIntent = 'Include' }
                [pscustomobject]@{ policyId = 'p2'; policyName = 'BitLocker Used-Space-Only'; isFullDiskEncryption = $false }
            ) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Error: a policy has no isFullDiskEncryption value - absent must never read as not-full-disk-encryption' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Unresolved' }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isFullDiskEncryption'
    }

    It 'Fail still holds: present-$false alone is decidable and correctly Fails (not an Error)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ policyId = 'p1'; policyName = 'BitLocker Used-Space-Only'; isFullDiskEncryption = $false }) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0014' -Datasets @(
            @{ Name = 'endpointSecurityDiskEncryptionPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
