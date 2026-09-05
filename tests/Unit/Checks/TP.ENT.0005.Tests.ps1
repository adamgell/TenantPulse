BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:legacyNineRoles = @(
        '62e90394-69f5-4237-9190-012177145e10'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f'
        'b0f54661-2d74-4c50-afa3-1ec803f12efe'
        '158c047a-c907-4556-b7ef-446551a6b5f7'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
        '29232cdf-9323-42fd-ade2-1d097af3e4de'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        '966707d0-3269-4727-9be2-8c3a10f19b9d'
    )
    $script:allRequiredRoles = @(
        $script:legacyNineRoles
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        'e8611ab8-c189-46e8-94e1-60213ab1f814'
        '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
        'fe930be7-5e62-47db-91af-98c3a49a38b1'
    )

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

    function script:New-PulseMfaPolicy {
        param(
            [string] $DisplayName = 'MFA For Admins',
            [string] $State = 'enabled',
            [string[]] $IncludeRoles,
            [string[]] $ExcludeUsers = @(),
            [string[]] $ExcludeRoles = @()
        )
        [pscustomobject]@{
            id            = "ca-$DisplayName"
            displayName   = $DisplayName
            state         = $State
            conditions    = [pscustomobject]@{
                clientAppTypes = @('all')
                users = [pscustomobject]@{ includeRoles = $IncludeRoles; excludeUsers = $ExcludeUsers; excludeRoles = $ExcludeRoles }
                applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = [pscustomobject]@{ builtInControls = @('mfa') }
        }
    }

    $script:adminGuid = '33333333-3333-3333-3333-333333333333'
}

Describe 'TP.ENT.0005 - MFA is required for admin roles by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0005' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass (post-review, H1): a policy using authenticationStrength (Microsoft''s own phishing-resistant template shape) satisfies MFA, not just builtInControls mfa' {
        $authStrengthPolicy = [pscustomobject]@{
            id            = 'ca-phish-resistant'
            displayName   = 'Phishing-Resistant MFA For Admins'
            state         = 'enabled'
            conditions    = [pscustomobject]@{
                clientAppTypes = @('all')
                users = [pscustomobject]@{ includeRoles = $script:allRequiredRoles }
                applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = [pscustomobject]@{ authenticationStrength = [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA' } }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($authStrengthPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'authenticationStrength'
    }

    It 'Pass: a single enabled policy covers all 14 required roles' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: the superseded nine-role set does not satisfy Microsoft''s current 14-role minimum' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:legacyNineRoles) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 5
    }

    It 'Pass: a single enabled policy with includeUsers "All" covers all 14 required roles by definition' {
        $allUsersPolicy = [pscustomobject]@{
            id            = 'ca-all-users-mfa'
            displayName   = 'MFA For All Users'
            state         = 'enabled'
            conditions    = [pscustomobject]@{
                clientAppTypes = @('all')
                users = [pscustomobject]@{ includeUsers = @('All') }
                applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = [pscustomobject]@{ builtInControls = @('mfa') }
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($allUsersPolicy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: coverage split across two enabled policies still satisfies the union' {
        $half1 = $script:allRequiredRoles[0..6]
        $half2 = $script:allRequiredRoles[7..13]
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseMfaPolicy -DisplayName 'MFA Set 1' -IncludeRoles $half1)
                (New-PulseMfaPolicy -DisplayName 'MFA Set 2' -IncludeRoles $half2)
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: one of the 14 required roles is not covered by any enabled policy' {
        $missingOne = $script:allRequiredRoles[0..12]
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $missingOne) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be $script:allRequiredRoles[13]
    }

    It 'Fail: coverage only exists in a report-only policy, never enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -State 'enabledForReportingButNotEnforced' -IncludeRoles $script:allRequiredRoles) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.Count | Should -Be 14
    }

    It 'Fail: all 14 roles on one application do not establish tenant-wide admin MFA coverage' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions.applications.includeApplications = @('11111111-1111-1111-1111-111111111111')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: a role included and excluded by the same policy is not covered' {
        $excludedRole = $script:allRequiredRoles[0]
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles -ExcludeRoles @($excludedRole)
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.identity | Should -Contain $excludedRole
    }

    It 'NotApplicable: missing application scope on an otherwise complete enabled policy cannot settle coverage' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions.PSObject.Properties.Remove('applications')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'application scope'
    }

    It 'Fail: incomplete scope on a policy targeting only already-covered roles cannot hide a different missing role' {
        $coveredThirteen = $script:allRequiredRoles[0..12]
        $incomplete = New-PulseMfaPolicy -DisplayName 'Incomplete Duplicate' -IncludeRoles @($script:allRequiredRoles[0])
        $incomplete.conditions.PSObject.Properties.Remove('applications')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseMfaPolicy -DisplayName 'Known Thirteen' -IncludeRoles $coveredThirteen)
                $incomplete
            ) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.identity | Should -Contain $script:allRequiredRoles[13]
    }

    It 'Fail: an incomplete policy that could cover only one of two missing roles cannot hide the other definite gap' {
        $knownTwelve = New-PulseMfaPolicy -DisplayName 'Known Twelve' -IncludeRoles $script:allRequiredRoles[0..11]
        $incompleteThirteenth = New-PulseMfaPolicy -DisplayName 'Maybe Thirteenth' -IncludeRoles @($script:allRequiredRoles[12])
        $incompleteThirteenth.conditions.PSObject.Properties.Remove('applications')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($knownTwelve, $incompleteThirteenth) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.evidence.identity | Should -Contain $script:allRequiredRoles[13]
    }

    It 'Fail: OR with compliantDevice makes MFA optional' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Pass: AND with compliantDevice still requires MFA' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.grantControls = [pscustomobject]@{ operator = 'AND'; builtInControls = @('mfa', 'compliantDevice') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable: a custom authentication strength cannot establish MFA until requirementsSatisfied is collected' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.grantControls = [pscustomobject]@{ authenticationStrength = @{ id = '11111111-1111-1111-1111-111111111111' } }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'grant'
    }

    It 'NotApplicable: an empty authenticationStrength object is incomplete evidence, never MFA proof' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.grantControls = [pscustomobject]@{ authenticationStrength = @{} }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Fail: a platform-scoped policy does not establish universal admin MFA' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions | Add-Member -NotePropertyName platforms -NotePropertyValue @{ includePlatforms = @('iOS') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: missing clientAppTypes cannot establish universal sign-in coverage' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions.PSObject.Properties.Remove('clientAppTypes')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'NotApplicable: missing user scope on an otherwise qualifying policy could hide role coverage' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions.PSObject.Properties.Remove('users')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'gate-degraded: NotApplicable when conditionalAccessPolicies was skipped (no EntraP1 data)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All'
    }

    # ---- Task 3.5: exclusion-context wiring and accepted exception semantics ----

    It 'no exclusion evidence at all when no -Context is supplied (existing evidence shape unchanged)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
    }

    It 'Pass with honored-exclusion evidence: a declared break-glass account excluded from the enforced admin-MFA policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($script:adminGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:adminGuid) }

        $finding.status | Should -Be 'Pass'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:adminGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        $exclusionEntry.detail.excludedFromEnforcedMfaPolicies | Should -Contain 'MFA For Admins'
        @($exclusionEntry.detail.excludedFromReportOnlyMfaPolicies).Count | Should -Be 0
        # fully enforced-honored - no misreading-risk warning needed
        $exclusionEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'
    }

    It 'Pass with honored-exclusion evidence for a canonical service account declared in Context' {
        $serviceAccountId = '44444444-4444-4444-4444-444444444444'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($serviceAccountId)) }
        ) -Context @{ ServiceAccounts = @($serviceAccountId) }

        $finding.status | Should -Be 'Pass'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $serviceAccountId }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        $exclusionEntry.detail.excludedFromEnforcedMfaPolicies | Should -Contain 'MFA For Admins'
        $exclusionEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'
    }

    It 'NotApplicable: an unaccepted direct-user exclusion cannot prove complete admin-role coverage' {
        $unacceptedId = '55555555-5555-5555-5555-555555555555'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($unacceptedId)) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.roleScopeReason | Should -Be 'unaccepted-excluded-user-id'
        $finding.evidence[0].detail.roleScopeUnacceptedExcludedUserCount | Should -Be 1
    }

    It 'NotApplicable: a group exclusion cannot prove complete admin-role coverage' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions.users | Add-Member -NotePropertyName excludeGroups -NotePropertyValue @('66666666-6666-6666-6666-666666666666')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.roleScopeReason | Should -Be 'excluded-group-membership-unresolved'
        $finding.evidence[0].detail.roleScopeExcludedGroupCount | Should -Be 1
    }

    It 'NotApplicable: a guest or external-user carve-out cannot prove complete admin-role coverage' {
        $policy = New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles
        $policy.conditions.users | Add-Member -NotePropertyName excludeGuestsOrExternalUsers -NotePropertyValue ([pscustomobject]@{
            guestOrExternalUserTypes = 'b2bCollaborationGuest'
            externalTenants          = [pscustomobject]@{ membershipKind = 'all' }
        })
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.roleScopeReason | Should -Be 'excluded-guests-or-external-users'
        $finding.evidence[0].detail.roleScopeHasExcludedGuestsOrExternalUsers | Should -BeTrue
    }

    It 'report-only exclusion is surfaced but distinguished from enforced honoring - never counted as protection' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -State 'enabledForReportingButNotEnforced' -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($script:adminGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:adminGuid) }

        $finding.status | Should -Be 'Fail'
        $exclusionEntry = $finding.evidence | Where-Object { $_.identity -eq $script:adminGuid }
        $exclusionEntry | Should -Not -BeNullOrEmpty
        @($exclusionEntry.detail.excludedFromEnforcedMfaPolicies).Count | Should -Be 0
        $exclusionEntry.detail.excludedFromReportOnlyMfaPolicies | Should -Contain 'MFA For Admins'
        # misreading-risk fold-in: report-only-ONLY exclusion carries an explicit warning
        $exclusionEntry.detail.reportOnlyProtectionWarning | Should -Match 'do not protect'
    }

    # ---- dual-review fix round: completeness fold-in hostile cases ----

    It 'a malformed (non-GUID) declared account is surfaced in evidence even though it can never match any policy' {
        $rawAccount = 'not-a-guid@contoso.com'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles) }
        ) -Context @{ BreakGlassAccounts = @($rawAccount) }

        $finding.status | Should -Be 'Pass'
        $malformedEntry = $finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' }
        $malformedEntry | Should -Not -BeNullOrEmpty
        $malformedEntry.detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($rawAccount))
    }

    It 'a group-exclusion-resolution note is surfaced when the operator declared something and group exclusions are unresolved' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($script:adminGuid)) }
        ) -Context @{ BreakGlassAccounts = @($script:adminGuid) }

        $finding.status | Should -Be 'Pass'
        $noteEntry = $finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }
        $noteEntry | Should -Not -BeNullOrEmpty
        $noteEntry.detail.note | Should -Match 'Group-based exclusion'
    }

    It 'no group-exclusion-resolution note when -Context declares nothing at all (backward-compat, no noise)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseMfaPolicy -IncludeRoles $script:allRequiredRoles) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 1
        ($finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }) | Should -BeNullOrEmpty
    }

    It 'multiple declared identifiers straddling enforced/report-only/no-match/malformed all resolve independently in one evaluation' {
        $enforcedGuid = '77777777-7777-7777-7777-777777777777'
        $reportOnlyGuid = '88888888-8888-8888-8888-888888888888'
        $noMatchGuid = '99999999-9999-9999-9999-999999999999'
        $malformed = 'still-not-a-guid'

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0005' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseMfaPolicy -DisplayName 'Enforced MFA' -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($enforcedGuid))
                (New-PulseMfaPolicy -DisplayName 'Report-Only MFA' -State 'enabledForReportingButNotEnforced' -IncludeRoles $script:allRequiredRoles -ExcludeUsers @($reportOnlyGuid))
            ) }
        ) -Context @{ BreakGlassAccounts = @($enforcedGuid, $reportOnlyGuid, $noMatchGuid, $malformed) }

        # The enforced policy alone covers all 14 roles, so this is Pass.
        $finding.status | Should -Be 'Pass'

        $enforcedEntry = $finding.evidence | Where-Object { $_.identity -eq $enforcedGuid }
        $enforcedEntry | Should -Not -BeNullOrEmpty
        $enforcedEntry.detail.excludedFromEnforcedMfaPolicies | Should -Contain 'Enforced MFA'
        $enforcedEntry.detail.PSObject.Properties.Name | Should -Not -Contain 'reportOnlyProtectionWarning'

        $reportOnlyEntry = $finding.evidence | Where-Object { $_.identity -eq $reportOnlyGuid }
        $reportOnlyEntry | Should -Not -BeNullOrEmpty
        @($reportOnlyEntry.detail.excludedFromEnforcedMfaPolicies).Count | Should -Be 0
        $reportOnlyEntry.detail.excludedFromReportOnlyMfaPolicies | Should -Contain 'Report-Only MFA'
        $reportOnlyEntry.detail.reportOnlyProtectionWarning | Should -Match 'do not protect'

        # No-match identifier gets no evidence entry at all (unchanged prior behavior).
        ($finding.evidence | Where-Object { $_.identity -eq $noMatchGuid }) | Should -BeNullOrEmpty

        $malformedEntry = $finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' }
        $malformedEntry | Should -Not -BeNullOrEmpty
        $malformedEntry.detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($malformed))

        $noteEntry = $finding.evidence | Where-Object { $_.identity -eq 'group-exclusion-resolution' }
        $noteEntry | Should -Not -BeNullOrEmpty

        # Pass-branch policy evidence includes the ENFORCED covering policy (1) + enforced-
        # exclusion, report-only-exclusion, malformed, and note entries (4) = 5.
        $finding.evidence.Count | Should -Be 5
    }
}
