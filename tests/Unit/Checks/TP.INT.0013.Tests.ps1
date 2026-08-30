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
                -Operation 'Group.Get' -ApiVersion 'v1.0'
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

Describe 'TP.INT.0013 - Intune RBAC groups protected via RMAU or role-assignable groups' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0013' }
        $check | Should -Not -BeNullOrEmpty
        @($check.Data.PartialDatasets).Count | Should -Be 1
        $check.Data.PartialDatasets[0] | Should -BeExactly 'intuneRbacGroupProtection'
        InModuleScope TenantPulse { (Get-Command Test-PulseRbacGroupsProtected).Parameters.Keys } | Should -Contain 'DatasetOutcomes'
    }

    It 'Partial: a known unprotected group proves Fail despite an unrelated malformed row in either order, exposes only gap count, and scores 0/6' {
        $gaps = @(
            (New-PulsePartialGapFixture)
            (New-PulsePartialGapFixture -Scope 'second-scope-canary' -ProviderDetail 'second-provider-detail-canary')
        )
        $offender = [pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g-offender'; groupDisplayName = 'Unsafe'; isManagementRestricted = $false; isAssignableToRole = $false }
        $malformed = [pscustomobject]@{ roleDefinitionName = 'Broken'; groupId = 'g-broken'; groupDisplayName = 'Broken'; isManagementRestricted = 'false'; isAssignableToRole = $false }
        $upnCanary = 'admin' + [char] 64 + 'example' + '.invalid'
        $secretCanary = 'sec' + 'ret=fixture-only'

        foreach ($rows in @(@($offender, $malformed), @($malformed, $offender))) {
            $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -ReturnFixture -Datasets @(
                @{
                    Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = @{ canary = 'top-detail-canary' }
                    Provider = 'provider-canary'; Operations = @('RoleDefinition.List', 'Group.Get'); Gaps = $gaps
                }
            )
            try {
                $fixture.Finding.status | Should -Be 'Fail'
                @($fixture.Finding.evidence).Count | Should -Be 1
                $fixture.Finding.evidence[0].identity | Should -Be 'g-offender'
                $fixture.Finding.reason | Should -Match '2 unresolved gaps'
                $fixture.Finding.reason | Should -Match 'known unprotected'
                $fixture.ScoredDocument.scores.overall.earned | Should -Be 0
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

    It 'Partial: protected known rows cannot prove universal success and are not assessed' {
        $gap = New-PulsePartialGapFixture
        $fixture = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -ReturnFixture -Datasets @(
            @{
                Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'Protected'; isManagementRestricted = $true; isAssignableToRole = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('Group.Get'); Gaps = @($gap)
            }
        )
        try {
            $fixture.Finding.status | Should -Be 'NotApplicable'
            $fixture.Finding.reason | Should -Match '1 unresolved gap'
            $fixture.Finding.reason | Should -Match 'cannot prove universal protection'
            $fixture.ScoredDocument.scores.overall.earned | Should -Be 0
            $fixture.ScoredDocument.scores.overall.possible | Should -Be 0
            $fixture.ScoredDocument.coverage.overall.assessed | Should -Be 0
            $fixture.ScoredDocument.coverage.overall.applicable | Should -Be 1
            ($fixture.ScoredDocument.coverage.overall.applicable - $fixture.ScoredDocument.coverage.overall.assessed) | Should -Be 1
        } finally {
            Remove-Item -LiteralPath $fixture.StoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Partial: malformed known rows without a decisive offender return Error' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{
                Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ roleDefinitionName = 'Broken'; groupId = 'g1'; groupDisplayName = 'Broken'; isManagementRestricted = 'false'; isAssignableToRole = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('Group.Get'); Gaps = @((New-PulsePartialGapFixture))
            }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'native boolean'
    }

    It 'Complete and non-decisive Partial reject every protected row without a usable groupId, including whitespace' {
        $invalidRows = @(
            [pscustomobject]@{ roleDefinitionName = 'Protected'; groupDisplayName = 'Missing identity'; isManagementRestricted = $true; isAssignableToRole = $false }
            [pscustomobject]@{ roleDefinitionName = 'Protected'; groupId = '   '; groupDisplayName = 'Whitespace identity'; isManagementRestricted = $true; isAssignableToRole = $false }
        )

        foreach ($row in $invalidRows) {
            $complete = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
                @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($row) }
            )
            $complete.status | Should -Be 'Error'
            $complete.reason | Should -Match 'groupId'

            $partial = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
                @{
                    Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'; Data = @($row)
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                    Operations = @('Group.Get'); Gaps = @((New-PulsePartialGapFixture))
                }
            )
            $partial.status | Should -Be 'Error'
            $partial.reason | Should -Match 'groupId'
        }
    }

    It 'Partial: a valid offender outranks a protected row with no identity in either row order' {
        $offender = [pscustomobject]@{ roleDefinitionName = 'Unsafe'; groupId = 'g-offender'; groupDisplayName = 'Unsafe'; isManagementRestricted = $false; isAssignableToRole = $false }
        $malformed = [pscustomobject]@{ roleDefinitionName = 'Protected'; groupId = '   '; groupDisplayName = 'Unidentified'; isManagementRestricted = $true; isAssignableToRole = $false }

        foreach ($rows in @(@($offender, $malformed), @($malformed, $offender))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
                @{
                    Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'; Data = $rows
                    FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                    Operations = @('Group.Get'); Gaps = @((New-PulsePartialGapFixture))
                }
            )
            $finding.status | Should -Be 'Fail'
            @($finding.evidence).Count | Should -Be 1
            $finding.evidence[0].identity | Should -Be 'g-offender'
        }
    }

    It 'Collected: any malformed row returns Error even when a valid offender exists, in either order' {
        $offender = [pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g-offender'; groupDisplayName = 'Unsafe'; isManagementRestricted = $false; isAssignableToRole = $false }
        $malformed = [pscustomobject]@{ roleDefinitionName = 'Broken'; groupId = 'g-broken'; groupDisplayName = 'Broken'; isManagementRestricted = 'false'; isAssignableToRole = $false }
        foreach ($rows in @(@($offender, $malformed), @($malformed, $offender))) {
            $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
                @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = $rows }
            )
            $finding.status | Should -Be 'Error'
        }
    }

    It 'Partial: zero usable rows fail closed before the rule can manufacture a decision' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{
                Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'; Data = @()
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('Group.Get'); Gaps = @((New-PulsePartialGapFixture))
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'no usable rows'
    }

    It 'Partial: a malformed persisted outcome projection fails closed' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{
                Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Partial'
                Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'Unsafe'; isManagementRestricted = $false; isAssignableToRole = $false })
                FailureClass = $null; ReasonCode = 'partial-provider'; Detail = $null; Provider = 'GraphKit'
                Operations = @('Group.Get'); Gaps = @((New-PulsePartialGapFixture))
                ManifestOverrides = @{ gaps = 'not-an-array' }
            }
        )
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'invalid Partial outcome'
    }

    It 'does not mutate direct caller datasets or outcome projections' {
        $datasets = @{ intuneRbacGroupProtection = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'Unsafe'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        $outcomes = @{ intuneRbacGroupProtection = @{ Status = 'Partial'; Gaps = @(@{ Scope = 'x' }) } }
        $before = $datasets | ConvertTo-Json -Depth 20 -Compress
        $outcomeBefore = $outcomes | ConvertTo-Json -Depth 20 -Compress

        $result = InModuleScope TenantPulse -ArgumentList $datasets, $outcomes {
            param($datasets, $outcomes)
            Test-PulseRbacGroupsProtected -Datasets $datasets -DatasetOutcomes $outcomes
        }

        $result.Status | Should -Be 'Fail'
        ($datasets | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $before
        ($outcomes | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $outcomeBefore
    }

    It 'direct calls reject null, unsupported, and non-scalar outcome projections with one bounded canary-free error' {
        $observed = InModuleScope TenantPulse {
            $datasets = @{ intuneRbacGroupProtection = @([pscustomobject]@{ roleDefinitionName = 'Safe'; groupId = 'g1'; groupDisplayName = 'Safe'; isManagementRestricted = $true; isAssignableToRole = $false }) }
            $statusCanary = 'unsupported-status-canary'
            $cases = @(
                @{ Name = 'null root'; Outcomes = $null }
                @{ Name = 'null entry'; Outcomes = @{ intuneRbacGroupProtection = $null } }
                @{ Name = 'non-dictionary entry'; Outcomes = @{ intuneRbacGroupProtection = 'not-a-dictionary' } }
                @{ Name = 'unsupported scalar'; Outcomes = @{ intuneRbacGroupProtection = @{ Status = $statusCanary } } }
                @{ Name = 'non-scalar'; Outcomes = @{ intuneRbacGroupProtection = @{ Status = @('Partial') } } }
            )

            @($cases | ForEach-Object {
                try {
                    $null = Test-PulseRbacGroupsProtected -Datasets $datasets -DatasetOutcomes $_.Outcomes
                    [pscustomobject]@{ Name = $_.Name; Threw = $false; Message = '' }
                } catch {
                    [pscustomobject]@{ Name = $_.Name; Threw = $true; Message = $_.Exception.Message }
                }
            })
        }

        $observed.Count | Should -Be 5
        foreach ($case in $observed) {
            $case.Threw | Should -BeTrue -Because $case.Name
            $case.Message | Should -BeExactly 'Test-PulseRbacGroupsProtected: the dataset outcome projection is invalid.' -Because $case.Name
            $case.Message | Should -Not -Match 'unsupported-status-canary|System\.Object|null-valued' -Because $case.Name
        }
    }

    It 'Pass: zero role-assignment groups exist at all (mirrors Maester, never a skip)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'nothing to protect'
    }

    It 'Pass: the only group is isAssignableToRole' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: the only group is isManagementRestricted' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $true; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: a group is neither RMAU-scoped nor role-assignable' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'g1'
    }

    It 'Fail: the same unprotected group backing two role assignments is deduplicated to one evidence entry' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
                [pscustomobject]@{ roleDefinitionName = 'School Administrator'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
    }

    It 'Fail: one protected and one unprotected group - only the unprotected one is offending' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $true }
                [pscustomobject]@{ roleDefinitionName = 'School Administrator'; groupId = 'g2'; groupDisplayName = 'School Admins'; isManagementRestricted = $false; isAssignableToRole = $false }
            ) }
        )

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'g2'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }

    It 'Error: an unprotected row has a missing groupId - must throw, never silently vanish into a false Pass' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'groupId'
    }

    It 'Error: an unprotected row has an empty-string groupId - must throw, never silently vanish into a false Pass' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = ''; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'groupId'
    }

    It 'Error: a row is missing isManagementRestricted entirely - a failed sub-call must never read as verified unprotected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isManagementRestricted'
    }

    It 'Error: a row is missing isAssignableToRole entirely - a failed sub-call must never read as verified unprotected' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isAssignableToRole'
    }

    It 'Error: isManagementRestricted is explicitly $null - absent, not decidable, must throw' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $null; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'isManagementRestricted'
    }

    It 'Error: string-valued protection flags are not native booleans and cannot become a false Pass' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = 'false'; isAssignableToRole = 'false' }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'native boolean'
    }

    It 'Pass still holds: present-$false on both fields is decidable and correctly Fails (not a false Pass, not an Error)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ roleDefinitionName = 'App Manager'; groupId = 'g1'; groupDisplayName = 'App Admins'; isManagementRestricted = $false; isAssignableToRole = $false }) }
        )

        $finding.status | Should -Be 'Fail'
    }
    
    It 'NotApplicable: a failed group lookup with no rows never becomes an empty-result Pass' {
        $gap = InModuleScope TenantPulse {
            New-PulseCollectionGap -Scope 'group:g1' -FailureClass 'PermissionDenied' -ReasonCode 'permission-denied' `
                -Detail @{ groupId = 'g1' } -Operation 'Get' -ApiVersion 'v1.0'
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0013' -Datasets @(
            @{ Name = 'intuneRbacGroupProtection'; ApiVersion = 'beta'; Status = 'Failed'; Reason = 'provider-failed'; Gaps = @($gap) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'provider-failed'
    }
}
