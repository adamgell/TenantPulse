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

    # [object]-typed (not [bool]) so a caller can pass $null to mean "omit this property
    # entirely" - a [bool]-typed param cannot ever be $null, which made the absent-field
    # case this check's own field-absence lens needs to test unbuildable. $null means
    # "leave the property off the row" (absent); $true/$false mean "include it with this
    # value" (present, decidable either way).
    function script:New-PulseLapsPolicyFixture {
        param(
            [string] $PolicyId,
            [string] $PolicyName,
            [object] $BacksUpToEntra = $true,
            [object] $HasSufficientComplexity = $true,
            [object] $HasSufficientLength = $true,
            [object] $HasPostAuthAction = $true
        )
        $row = [ordered]@{
            policyId          = $PolicyId
            policyName        = $PolicyName
            assignmentIntent  = 'Include'
        }
        if ($null -ne $BacksUpToEntra) { $row.backsUpToEntra = $BacksUpToEntra }
        if ($null -ne $HasSufficientComplexity) { $row.hasSufficientComplexity = $HasSufficientComplexity }
        if ($null -ne $HasSufficientLength) { $row.hasSufficientLength = $HasSufficientLength }
        if ($null -ne $HasPostAuthAction) { $row.hasPostAuthAction = $HasPostAuthAction }
        [pscustomobject] $row
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

Describe 'TP.INT.0015 - LAPS configuration policy meets minimum security bar' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0015' }
        $check | Should -Not -BeNullOrEmpty
        @($check.Data.PartialDatasets).Count | Should -Be 1
        $check.Data.PartialDatasets[0] | Should -BeExactly 'endpointSecurityLapsPolicies'
        InModuleScope TenantPulse { (Get-Command Test-PulseLapsConfigurationMeetsBar).Parameters.Keys } | Should -Contain 'DatasetOutcomes'
    }

    It 'Partial: one native-boolean all-four-criteria witness proves Pass despite an unrelated malformed row in either order, exposes only gap count, and scores 6/6' {
        $gaps = @(
            (New-PulsePartialGapFixture)
            (New-PulsePartialGapFixture -Scope 'second-scope-canary' -ProviderDetail 'second-provider-detail-canary')
        )
        $witness = New-PulseLapsPolicyFixture -PolicyId 'p-witness' -PolicyName 'Compliant'
        $malformed = New-PulseLapsPolicyFixture -PolicyId 'p-broken' -PolicyName 'Broken' -HasSufficientLength 1
        $upnCanary = 'admin' + [char] 64 + 'example' + '.invalid'
        $secretCanary = 'sec' + 'ret=fixture-only'

        foreach ($rows in @(@($witness, $malformed), @($malformed, $witness))) {
            $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -ReturnFixture -Datasets @(
                @{
                    Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
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
                $fixture.ScoredDocument.scores.overall.earned | Should -Be 6
                $fixture.ScoredDocument.scores.overall.possible | Should -Be 6
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
        $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -ReturnFixture -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Short' -HasSufficientLength $false))
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
        } finally {
            Remove-Item -LiteralPath $fixture.StoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Partial: a malformed-only assignment on an otherwise qualifying policy is NotApplicable, never Fail' {
        $policy = New-PulseLapsPolicyFixture -PolicyId 'p-malformed' -PolicyName 'Compliant but unresolved'
        $policy.assignmentIntent = 'Malformed'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = @($policy)
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
        $malformed = New-PulseLapsPolicyFixture -PolicyId 'p-malformed' -PolicyName 'Compliant but unresolved'
        $malformed.assignmentIntent = 'Malformed'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @(
                    (New-PulseLapsPolicyFixture -PolicyId 'p-witness' -PolicyName 'Compliant and assigned')
                    $malformed
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
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'
                Data = @((New-PulseLapsPolicyFixture -PolicyId 'p-nonqualifying' -PolicyName 'Short but assigned' -HasSufficientLength $false))
            }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'none meet all four'
    }

    It 'rejects boolean-like non-native values for each criterion in Collected and non-decisive Partial inputs' {
        foreach ($field in @('backsUpToEntra', 'hasSufficientComplexity', 'hasSufficientLength', 'hasPostAuthAction')) {
            foreach ($value in @('true', 1, 'false', 0)) {
                $row = [ordered]@{
                    policyId = 'p1'; policyName = 'Malformed'; backsUpToEntra = $true
                    hasSufficientComplexity = $true; hasSufficientLength = $true; hasPostAuthAction = $true
                }
                $row[$field] = $value

                $collected = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
                    @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject] $row) }
                )
                $collected.status | Should -Be 'Error'
                $collected.reason | Should -Match 'native boolean'

                $partial = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
                    @{
                        Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = @([pscustomobject] $row)
                        FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                        Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
                    }
                )
                $partial.status | Should -Be 'Error'
                $partial.reason | Should -Match 'native boolean'
            }
        }
    }

    It 'Complete and non-decisive Partial reject a non-witness row without a usable policyId' {
        $row = [pscustomobject]@{
            policyName = 'Short'; backsUpToEntra = $true; hasSufficientComplexity = $true
            hasSufficientLength = $false; hasPostAuthAction = $true
        }

        $complete = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
        )
        $complete.status | Should -Be 'Error'
        $complete.reason | Should -Match 'policyId'

        $partial = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = @($row)
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $partial.status | Should -Be 'Error'
        $partial.reason | Should -Match 'policyId'
    }

    It 'Partial: a valid witness outranks a non-witness row with no identity in either row order' {
        $witness = New-PulseLapsPolicyFixture -PolicyId 'p-witness' -PolicyName 'Compliant'
        $malformed = [pscustomobject]@{
            policyName = 'Short'; backsUpToEntra = $true; hasSufficientComplexity = $true
            hasSufficientLength = $false; hasPostAuthAction = $true
        }

        foreach ($rows in @(@($witness, $malformed), @($malformed, $witness))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
                @{
                    Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
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
        $witness = New-PulseLapsPolicyFixture -PolicyId 'p-witness' -PolicyName 'Compliant'
        $malformed = New-PulseLapsPolicyFixture -PolicyId 'p-broken' -PolicyName 'Broken' -HasSufficientLength 1
        foreach ($rows in @(@($witness, $malformed), @($malformed, $witness))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
                @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
            )
            $finding.status | Should -Be 'Error'
        }
    }

    It 'Partial: a qualifying row without a usable policyId is malformed and cannot become evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ policyName = 'Compliant but unidentified'; backsUpToEntra = $true; hasSufficientComplexity = $true; hasSufficientLength = $true; hasPostAuthAction = $true })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'policyId'
    }

    It 'Partial: zero usable rows fail closed before the rule can manufacture a decision' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'; Data = @()
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'no usable rows'
    }

    It 'Partial: a malformed persisted outcome projection fails closed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{
                Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Compliant'))
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicySettings.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
                ManifestOverrides = @{ gaps = 'not-an-array' }
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'invalid Partial outcome'
    }

    It 'does not mutate direct caller datasets or outcome projections' {
        $datasets = @{ endpointSecurityLapsPolicies = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Compliant')) }
        $outcomes = @{ endpointSecurityLapsPolicies = @{ Status = 'Partial'; Gaps = @(@{ Scope = 'x' }) } }
        $before = $datasets | ConvertTo-Json -Depth 20 -Compress
        $outcomeBefore = $outcomes | ConvertTo-Json -Depth 20 -Compress

        $result = InModuleScope TenantPulse -ArgumentList $datasets, $outcomes {
            param($datasets, $outcomes)
            Test-PulseLapsConfigurationMeetsBar -Datasets $datasets -DatasetOutcomes $outcomes
        }

        $result.Status | Should -Be 'Pass'
        ($datasets | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $before
        ($outcomes | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $outcomeBefore
    }

    It 'direct calls reject null, unsupported, and non-scalar outcome projections with one bounded canary-free error' {
        $observed = InModuleScope TenantPulse {
            $datasets = @{ endpointSecurityLapsPolicies = @([pscustomobject]@{ policyId = 'p1'; policyName = 'Compliant'; backsUpToEntra = $true; hasSufficientComplexity = $true; hasSufficientLength = $true; hasPostAuthAction = $true }) }
            $statusCanary = 'unsupported-status-canary'
            $cases = @(
                @{ Name = 'missing declared key'; Outcomes = @{} }
                @{ Name = 'null root'; Outcomes = $null }
                @{ Name = 'null entry'; Outcomes = @{ endpointSecurityLapsPolicies = $null } }
                @{ Name = 'non-dictionary entry'; Outcomes = @{ endpointSecurityLapsPolicies = 'not-a-dictionary' } }
                @{ Name = 'unsupported scalar'; Outcomes = @{ endpointSecurityLapsPolicies = @{ Status = $statusCanary } } }
                @{ Name = 'non-scalar'; Outcomes = @{ endpointSecurityLapsPolicies = @{ Status = @('Partial') } } }
            )

            @($cases | ForEach-Object {
                try {
                    $null = Test-PulseLapsConfigurationMeetsBar -Datasets $datasets -DatasetOutcomes $_.Outcomes
                    [pscustomobject]@{ Name = $_.Name; Threw = $false; Message = '' }
                } catch {
                    [pscustomobject]@{ Name = $_.Name; Threw = $true; Message = $_.Exception.Message }
                }
            })
        }

        $observed.Count | Should -Be 6
        foreach ($case in $observed) {
            $case.Threw | Should -BeTrue -Because $case.Name
            $case.Message | Should -BeExactly 'Test-PulseLapsConfigurationMeetsBar: the dataset outcome projection is invalid.' -Because $case.Name
            $case.Message | Should -Not -Match 'unsupported-status-canary|System\.Object|null-valued' -Because $case.Name
        }
    }

    It 'Pass: a single policy meets all four criteria' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'LAPS Baseline')) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'Fail: zero LAPS policies exist' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No Windows LAPS Endpoint Security policy'
    }

    It 'Fail: a policy missing exactly one criterion (password length) does not pass, and is not compensated by another policy missing a different criterion' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Short passwords' -HasSufficientLength $false)
                (New-PulseLapsPolicyFixture -PolicyId 'p2' -PolicyName 'Weak complexity' -HasSufficientComplexity $false)
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'not OR''d across separate policies'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Fail: backs up to AD instead of Entra (backsUpToEntra false) alone is disqualifying' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'AD-backed' -BacksUpToEntra $false)) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Pass: one fully-compliant policy passes even alongside a non-compliant one, both carried as evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Baseline (compliant)')
                (New-PulseLapsPolicyFixture -PolicyId 'p2' -PolicyName 'Legacy (weak)' -HasPostAuthAction $false)
            ) }
        )

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Error: a policy has no backsUpToEntra value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -BacksUpToEntra $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'backsUpToEntra'
    }

    It 'Error: a policy has no hasSufficientComplexity value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -HasSufficientComplexity $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'hasSufficientComplexity'
    }

    It 'Error: a policy has no hasSufficientLength value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -HasSufficientLength $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'hasSufficientLength'
    }

    It 'Error: a policy has no hasPostAuthAction value - absent must never read as does-not-meet-the-bar' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Unresolved' -HasPostAuthAction $null)) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'hasPostAuthAction'
    }

    It 'Fail still holds: all four criteria present-$false is decidable and correctly Fails (not an Error)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @((New-PulseLapsPolicyFixture -PolicyId 'p1' -PolicyName 'Non-compliant' -BacksUpToEntra $false -HasSufficientComplexity $false -HasSufficientLength $false -HasPostAuthAction $false)) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0015' -Datasets @(
            @{ Name = 'endpointSecurityLapsPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
