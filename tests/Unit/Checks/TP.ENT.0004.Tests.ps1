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
            [Parameter(Mandatory)] [hashtable[]] $Datasets,
            [hashtable] $Context = @{}
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets, $Context {
                param($storeRoot, $keyPath, $checkId, $datasets, $context)

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

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -Context $context
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function script:New-PulseLegacyAuthPolicy {
        param(
            [string] $DisplayName = 'Block Legacy Auth',
            [string] $State = 'enabled',
            [string[]] $ExcludeUsers = @()
        )
        [pscustomobject]@{
            id             = "ca-$DisplayName"
            displayName    = $DisplayName
            state          = $State
            conditions     = [pscustomobject]@{
                clientAppTypes = @('exchangeActiveSync', 'other')
                users          = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = $ExcludeUsers }
                applications   = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls  = [pscustomobject]@{ builtInControls = @('block') }
        }
    }

    $script:bgGuid = '11111111-1111-1111-1111-111111111111'
}

Describe 'TP.ENT.0004 - Legacy authentication is blocked by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0004' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an enabled policy blocks legacy authentication' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'does not promote malformed or alternative block grants to enforced legacy protection' -ForEach @(
        @{ Name = 'invalid operator'; GrantControls = [pscustomobject]@{ operator = 'XOR'; builtInControls = @('block') } }
        @{ Name = 'OR sibling'; GrantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('block', 'mfa') } }
        @{ Name = 'missing-operator sibling'; GrantControls = [pscustomobject]@{ builtInControls = @('block', 'mfa') } }
    ) {
        $policy = New-PulseLegacyAuthPolicy
        $policy.grantControls = $GrantControls
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable' -Because $Name
    }

    It 'Pass (post-review, L1): clientAppTypes "all" covers legacy protocols too, not just itemized exchangeActiveSync/other' {
        $allAppsPolicy = [pscustomobject]@{
            id            = 'ca-all-apps-block'
            displayName   = 'Block All Client App Types'
            state         = 'enabled'
            conditions    = [pscustomobject]@{
                clientAppTypes = @('all')
                users = [pscustomobject]@{ includeUsers = @('All') }
                applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = [pscustomobject]@{ builtInControls = @('block') }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($allAppsPolicy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: blocking only exchangeActiveSync leaves the other legacy-client bucket open' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.clientAppTypes = @('exchangeActiveSync')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: an unknown future client-app type cannot broaden a known EAS-only legacy block' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.clientAppTypes = @('exchangeActiveSync', 'futureClient')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'other'
    }

    It 'Fail: blocking only other leaves Exchange ActiveSync open' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.clientAppTypes = @('other')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'does not let an incomplete ancillary condition broaden a recognized legacy client bucket' -ForEach @(
        @{ ClientType = 'exchangeActiveSync'; MissingBucket = 'other' }
        @{ ClientType = 'other'; MissingBucket = 'exchangeActiveSync' }
    ) {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.clientAppTypes = @($ClientType)
        $policy.conditions | Add-Member -NotePropertyName authenticationFlows -NotePropertyValue @{ transferMethods = 'futureTransferMethod' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match $MissingBucket
    }

    It 'Fail with mixed certainty: names only the provably absent bucket as definitively uncovered' {
        $policy = New-PulseLegacyAuthPolicy -DisplayName 'Possibly universal EAS block'
        $policy.conditions.clientAppTypes = @('exchangeActiveSync')
        $policy.conditions | Add-Member -NotePropertyName futureCondition -NotePropertyValue @{ mode = 'future' }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'Definitively uncovered: other'
        $finding.reason | Should -Match 'Coverage unknown[^.]*exchangeActiveSync'
        $finding.reason | Should -Not -Match 'Definitively uncovered:[^.]*exchangeActiveSync'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'ca-Possibly universal EAS block'
        $finding.evidence[0].detail.signInScope | Should -Be 'Incomplete'
    }

    It 'preserves unknown grant controls as incomplete candidate evidence' -ForEach @(
        @{ Control = 'unknownFutureValue' }
        @{ Control = 'futureGrantControl' }
    ) {
        $policy = New-PulseLegacyAuthPolicy
        $policy.grantControls = [pscustomobject]@{ builtInControls = @($Control) }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.evidence[0].detail.blockRequirementReason | Should -Be 'unresolved-grant-control'
    }

    It 'Pass: separate complete policies may cover the two legacy-client buckets as a union' {
        $eas = New-PulseLegacyAuthPolicy -DisplayName 'Block EAS'
        $eas.conditions.clientAppTypes = @('exchangeActiveSync')
        $other = New-PulseLegacyAuthPolicy -DisplayName 'Block Other'
        $other.conditions.clientAppTypes = @('other')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($eas, $other) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: an iOS-only legacy block does not establish universal legacy-client coverage' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions | Add-Member -NotePropertyName platforms -NotePropertyValue @{ includePlatforms = @('iOS') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: absent clientAppTypes is incomplete evidence for legacy-client coverage' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.PSObject.Properties.Remove('clientAppTypes')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Fail: policy exists but is report-only, not enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -State 'enabledForReportingButNotEnforced') }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'report-only'
    }

    It 'Fail: mixed enforced and report-only coverage reports the remaining enforced gap accurately' {
        $enforcedEas = New-PulseLegacyAuthPolicy -DisplayName 'Enforced EAS'
        $enforcedEas.conditions.clientAppTypes = @('exchangeActiveSync')
        $reportOnlyBoth = New-PulseLegacyAuthPolicy -DisplayName 'Report-Only Both' -State 'enabledForReportingButNotEnforced'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($enforcedEas, $reportOnlyBoth) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'Definitively uncovered: other'
        $finding.reason | Should -Not -Match 'nothing is actually enforced'
        @($finding.evidence.detail.displayName) | Should -Contain 'Enforced EAS'
        @($finding.evidence.detail.displayName) | Should -Contain 'Report-Only Both'
    }

    It 'Fail: no policy at all blocks legacy authentication' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: a legacy-auth block scoped to one user and one application is not tenant-wide protection' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.users.includeUsers = @('11111111-1111-1111-1111-111111111111')
        $policy.conditions.applications.includeApplications = @('22222222-2222-2222-2222-222222222222')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'tenant-wide'
    }

    It 'Fail: excluding one application leaves legacy authentication unblocked for that resource' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.applications.excludeApplications = @('33333333-3333-3333-3333-333333333333')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: an application filter narrows an otherwise all-resource legacy-auth block' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.applications | Add-Member -NotePropertyName applicationFilter -NotePropertyValue @{ mode = 'exclude'; rule = 'CustomSecurityAttribute.Apps_Project -eq "Legacy"' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: missing application scope cannot be promoted to tenant-wide protection or a known gap' {
        $policy = New-PulseLegacyAuthPolicy
        $policy.conditions.PSObject.Properties.Remove('applications')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'application scope'
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies was skipped (no EntraP1 data)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All'
    }

    # ---- Task 3.5: exclusion-context wiring (evidence only, never a Status input) ----

    It 'no exclusion evidence at all when no -Context is supplied (empty exclusion context, existing evidence shape unchanged)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass with honored-exclusion evidence: a declared break-glass account excluded from the enforced block policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        $exclusionEntry.detail.excludedFromEnforcedBlockPolicies | Should -Contain 'Block Legacy Auth'
        @($exclusionEntry.detail.excludedFromReportOnlyBlockPolicies).Count | Should -Be 0
        # fully enforced-honored - no misreading-risk warning needed
        $exclusionEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'
    }

    It 'Fail: an active Global Administrator is not an accepted direct-user exception unless explicitly declared' {
        $activeAdminId = [guid]::ParseExact(('4' * 32), 'N').ToString('D')
        $policy = New-PulseLegacyAuthPolicy -ExcludeUsers @($activeAdminId)

        $finding = InModuleScope TenantPulse -ArgumentList $policy, $activeAdminId {
            param($policy, $activeAdminId)
            Test-PulseLegacyAuthBlocked -Datasets @{
                conditionalAccessPolicies = @($policy)
                directoryRoleAssignments = @(
                    @{
                        roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'
                        principalId      = $activeAdminId
                    }
                )
            }
        }

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'tenant-wide'
    }

    It 'report-only exclusion is surfaced but distinguished from enforced honoring - never counted as protection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -State 'enabledForReportingButNotEnforced' -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Fail'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        @($exclusionEntry.detail.excludedFromEnforcedBlockPolicies).Count | Should -Be 0
        $exclusionEntry.detail.excludedFromReportOnlyBlockPolicies | Should -Contain 'Block Legacy Auth'
        # misreading-risk fold-in: report-only-ONLY exclusion carries an explicit warning
        $exclusionEntry.detail.reportOnlyProtectionWarning | Should -Match 'do not protect'
    }

    It 'a declared identifier not named in any evaluated policy''s excludeUsers gets no per-identity exclusion evidence entry (fold-in: the group-exclusion-resolution note still surfaces, since something WAS declared)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        ($finding.evidence | Where-Object { $_.identity -eq $script:bgGuid }) | Should -BeNullOrEmpty
        # policy evidence (1) + group-exclusion-resolution note (1, declared-context gate) = 2
        $finding.evidence.Count | Should -Be 2
        ($finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }) | Should -Not -BeNullOrEmpty
    }

    # ---- dual-review fix round: completeness fold-in hostile cases ----

    It 'a malformed (non-GUID) declared account is surfaced in evidence even though it can never match any policy' {
        $rawAccount = 'not-a-guid@contoso.com'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        ) -Context @{ BreakGlassAccounts = @($rawAccount) }

        $finding.status | Should -Be 'Pass'
        $malformedEntry = $finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' }
        $malformedEntry | Should -Not -BeNullOrEmpty
        $malformedEntry.detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($rawAccount))
    }

    It 'Fail: a malformed declared account cannot legitimize the same malformed policy exclusion' {
        $malformed = 'breakglass@contoso.com'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseLegacyAuthPolicy -ExcludeUsers @($malformed)
            ) }
        ) -Context @{ BreakGlassAccounts = @($malformed) }

        $finding.status | Should -Be 'Fail'
        $malformedEntry = @($finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' })
        $malformedEntry.Count | Should -Be 1
        $malformedEntry[0].detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($malformed))
    }

    It 'Fail: a parseable but noncanonical declared account cannot legitimize the same malformed policy exclusion' {
        $nonCanonical = "{$($script:bgGuid)}"
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseLegacyAuthPolicy -ExcludeUsers @($nonCanonical)
            ) }
        ) -Context @{ BreakGlassAccounts = @($nonCanonical) }

        $finding.status | Should -Be 'Fail'
        $malformedEntry = @($finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' })
        $malformedEntry.Count | Should -Be 1
        $malformedEntry[0].detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($nonCanonical))
    }

    It 'a group-exclusion-resolution note is surfaced when the operator declared something and group exclusions are unresolved' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy -ExcludeUsers @($script:bgGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:bgGuid) }

        $finding.status | Should -Be 'Pass'
        $noteEntry = $finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }
        $noteEntry | Should -Not -BeNullOrEmpty
        $noteEntry.detail.note | Should -Match 'Group-based exclusion'
    }

    It 'no group-exclusion-resolution note when -Context declares nothing at all (backward-compat, no noise)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseLegacyAuthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        ($finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }) | Should -BeNullOrEmpty
    }

    It 'multiple declared identifiers straddling enforced/report-only/no-match/malformed all resolve independently in one evaluation' {
        $enforcedGuid = '44444444-4444-4444-4444-444444444444'
        $reportOnlyGuid = '55555555-5555-5555-5555-555555555555'
        $noMatchGuid = '66666666-6666-6666-6666-666666666666'
        $malformed = 'still-not-a-guid'

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0004' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseLegacyAuthPolicy -DisplayName 'Enforced Block' -ExcludeUsers @($enforcedGuid))
                (New-PulseLegacyAuthPolicy -DisplayName 'Report-Only Block' -State 'enabledForReportingButNotEnforced' -ExcludeUsers @($reportOnlyGuid))
            ) }
        ) -Context @{ BreakGlassAccounts = @($enforcedGuid, $reportOnlyGuid, $noMatchGuid, $malformed) }

        # An enforced block policy exists, so this is Pass regardless of the report-only one.
        $finding.status | Should -Be 'Pass'

        $enforcedEntry = $finding.evidence | Where-Object { $_.identity -eq $enforcedGuid }
        $enforcedEntry | Should -Not -BeNullOrEmpty
        $enforcedEntry.detail.excludedFromEnforcedBlockPolicies | Should -Contain 'Enforced Block'
        $enforcedEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'

        $reportOnlyEntry = $finding.evidence | Where-Object { $_.identity -eq $reportOnlyGuid }
        $reportOnlyEntry | Should -Not -BeNullOrEmpty
        @($reportOnlyEntry.detail.excludedFromEnforcedBlockPolicies).Count | Should -Be 0
        $reportOnlyEntry.detail.excludedFromReportOnlyBlockPolicies | Should -Contain 'Report-Only Block'
        $reportOnlyEntry.detail.reportOnlyProtectionWarning | Should -Match 'do not protect'

        # No-match identifier gets no evidence entry at all (unchanged prior behavior).
        ($finding.evidence | Where-Object { $_.identity -eq $noMatchGuid }) | Should -BeNullOrEmpty

        $malformedEntry = $finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' }
        $malformedEntry | Should -Not -BeNullOrEmpty
        $malformedEntry.detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($malformed))

        $noteEntry = $finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }
        $noteEntry | Should -Not -BeNullOrEmpty

        # Pass-branch policy evidence only includes the ENFORCED block policy (1) + the
        # enforced-exclusion, report-only-exclusion, malformed, and note exclusion entries
        # (4) = 5; the no-match identifier and the report-only policy itself (not a Pass-
        # branch policy entry) contribute nothing to this count.
        $finding.evidence.Count | Should -Be 5
    }
}
