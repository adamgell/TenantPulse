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
            [string] $ProviderDetail
        )

        if ([string]::IsNullOrEmpty($Scope)) { $Scope = 'scope-canary-' + (@('7f3f19ea', '8af2', '4ca9', 'b708', '80e6688cc8e0') -join '-') }
        if ([string]::IsNullOrEmpty($ProviderDetail)) { $ProviderDetail = 'provider-detail-canary ' + ('admin' + [char] 64 + 'example' + '.invalid') + ' ' + ('sec' + 'ret=fixture-only') }

        InModuleScope TenantPulse -ArgumentList $Scope, $ProviderDetail {
            param($scope, $providerDetail)
            New-PulseCollectionGap -Scope $scope -FailureClass 'PermissionDenied' `
                -ReasonCode 'permission-denied' -Detail @{ message = $providerDetail } `
                -Operation 'ConfigurationPolicyAssignment.ListBeta' -ApiVersion 'beta'
        }
    }

    function script:Invoke-PulseCheckFixture {
        param(
            [Parameter(Mandatory)] [string] $CheckId,
            [Parameter(Mandatory)] [hashtable[]] $Datasets,
            [Parameter()] $GateProvider = @{ Intune = @{ Status = 'Available'; Detail = 'fixture gate' } },
            [switch] $ReturnFixture
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets, $GateProvider, ([bool] $ReturnFixture) {
                param($storeRoot, $keyPath, $checkId, $datasets, $gateProvider, $returnFixture)

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

                $evaluation = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider $gateProvider
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

Describe 'TP.INT.0029 - Security baselines assigned and not on a deprecated version' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0029' }
        $check | Should -Not -BeNullOrEmpty
        @($check.Data.PartialDatasets).Count | Should -Be 1
        $check.Data.PartialDatasets[0] | Should -BeExactly 'securityBaselinesAssignedAndCurrent'
        InModuleScope TenantPulse { (Get-Command Test-PulseSecurityBaselinesAssignedAndCurrent).Parameters.Keys } | Should -Contain 'DatasetOutcomes'
    }

    It 'Partial: a known unassigned/deprecated baseline proves Fail despite an unrelated malformed row in either order, exposes only gap count, and scores 0/3' {
        $gaps = @(
            (New-PulsePartialGapFixture)
            (New-PulsePartialGapFixture -Scope 'second-scope-canary' -ProviderDetail 'second-provider-detail-canary')
        )
        $offender = [pscustomobject]@{ id = 'b-offender'; name = 'Unsafe'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
        $malformed = [pscustomobject]@{ id = 'b-broken'; name = 'Broken'; templateFamily = 'baseline'; hasAssignment = 'false'; isDeprecated = $false }
        $upnCanary = 'admin' + [char] 64 + 'example' + '.invalid'
        $secretCanary = 'sec' + 'ret=fixture-only'

        foreach ($rows in @(@($offender, $malformed), @($malformed, $offender))) {
            $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -ReturnFixture -Datasets @(
                @{
                    Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = @{ canary = 'top-detail-canary' }
                    Provider = 'provider-canary'; Operations = @('ConfigurationPolicy.ListBeta', 'ConfigurationPolicyAssignment.ListBeta'); Gaps = $gaps
                }
            )
            try {
                $fixture.Finding.status | Should -Be 'Fail'
                @($fixture.Finding.evidence).Count | Should -Be 1
                $fixture.Finding.evidence[0].identity | Should -Be 'b-offender'
                $fixture.Finding.reason | Should -Match '2 unresolved gaps'
                $fixture.Finding.reason | Should -Match 'known unassigned or deprecated'
                $fixture.ScoredDocument.scores.overall.earned | Should -Be 0
                $fixture.ScoredDocument.scores.overall.possible | Should -Be 3
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

    It 'Partial: known assigned/current rows cannot prove universal success and are not assessed' {
        $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -ReturnFixture -Datasets @(
            @{
                Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ id = 'b1'; name = 'Current'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        try {
            $fixture.Finding.status | Should -Be 'NotApplicable'
            $fixture.Finding.reason | Should -Match '1 unresolved gap'
            $fixture.Finding.reason | Should -Match 'cannot prove universal baseline posture'
            $fixture.ScoredDocument.scores.overall.earned | Should -Be 0
            $fixture.ScoredDocument.scores.overall.possible | Should -Be 0
            $fixture.ScoredDocument.coverage.overall.assessed | Should -Be 0
            $fixture.ScoredDocument.coverage.overall.applicable | Should -Be 1
        } finally {
            Remove-Item -LiteralPath $fixture.StoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Partial: malformed known rows without a decisive offender return Error' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{
                Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ id = 'b1'; name = 'Broken'; templateFamily = 'baseline'; hasAssignment = 'true'; isDeprecated = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'native boolean'
    }

    It 'Collected: any malformed row returns Error even when a valid offender exists, in either order' {
        $offender = [pscustomobject]@{ id = 'b-offender'; name = 'Unsafe'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
        $malformed = [pscustomobject]@{ id = 'b-broken'; name = 'Broken'; templateFamily = 'baseline'; hasAssignment = 'false'; isDeprecated = $false }
        foreach ($rows in @(@($offender, $malformed), @($malformed, $offender))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
                @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
            )
            $finding.status | Should -Be 'Error'
        }
    }

    It 'Partial: an offender without a usable id or name is malformed and cannot become evidence' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{
                Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'identity'
    }

    It 'Partial: zero usable rows fail closed before the rule can manufacture a decision' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{
                Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Partial'; Data = @()
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'no usable rows'
    }

    It 'Partial: a malformed persisted outcome projection fails closed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{
                Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ id = 'b1'; name = 'Unsafe'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('ConfigurationPolicyAssignment.ListBeta'); Gaps = @((New-PulsePartialGapFixture))
                ManifestOverrides = @{ gaps = 'not-an-array' }
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'invalid Partial outcome'
    }

    It 'does not mutate direct caller datasets or outcome projections' {
        $datasets = @{ securityBaselinesAssignedAndCurrent = @([pscustomobject]@{ id = 'b1'; name = 'Unsafe'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }) }
        $outcomes = @{ securityBaselinesAssignedAndCurrent = @{ Status = 'Partial'; Gaps = @(@{ Scope = 'x' }) } }
        $before = $datasets | ConvertTo-Json -Depth 20 -Compress
        $outcomeBefore = $outcomes | ConvertTo-Json -Depth 20 -Compress

        $result = InModuleScope TenantPulse -ArgumentList $datasets, $outcomes {
            param($datasets, $outcomes)
            Test-PulseSecurityBaselinesAssignedAndCurrent -Datasets $datasets -DatasetOutcomes $outcomes
        }

        $result.Status | Should -Be 'Fail'
        ($datasets | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $before
        ($outcomes | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $outcomeBefore
    }

    It 'Pass: every baseline instance is assigned and current' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false }
            ) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: unassigned instance' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: assigned but deprecated version' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Defender baseline (old)'; templateFamily = 'baselineDefenderForEndpoint'; hasAssignment = $true; isDeprecated = $true }
            ) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: no baseline instance of any tracked family in use' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }

    It 'Error: isDeprecated is absent on an existing row (field-absence lens)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $true }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }

    It 'HOSTILE (post-review MEDIUM fix): hasAssignment as the STRING ''false'' errors instead of [bool]-coercing to $true (an unassigned baseline must never silently Pass)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = 'false'; isDeprecated = $false }
            ) }
        )
        $finding.status | Should -Be 'Error'
        $finding.status | Should -Not -Be 'Pass'
    }

    It 'HOSTILE: isDeprecated as the STRING ''false'' also errors instead of coercing (same trap on the second boolean field)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0029' -Datasets @(
            @{ Name = 'securityBaselinesAssignedAndCurrent'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'b1'; name = 'Windows 10/11 baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = 'false' }
            ) }
        )
        $finding.status | Should -Be 'Error'
    }
}
