BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

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

    function script:New-PulseAllUsersMfaPolicy {
        param(
            [string] $DisplayName = 'MFA For All Users',
            [string] $State = 'enabled',
            [string[]] $ExcludeUsers = @(),
            [switch] $UseAuthenticationStrength
        )
        $grants = if ($UseAuthenticationStrength) {
            @{ authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA' } }
        } else {
            @{ builtInControls = @('mfa') }
        }
        @{
            id            = "ca-$DisplayName"
            displayName   = $DisplayName
            state         = $State
            conditions    = @{
                clientAppTypes = @('all')
                users = @{ includeUsers = @('All'); excludeUsers = $ExcludeUsers }
                applications = @{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = $grants
        }
    }
}

Describe 'TP.ENT.0017 - MFA required for all users by an enforced Conditional Access policy' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0017' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: an enabled all-users policy with builtInControls mfa' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'builtInControls:mfa'
    }

    It 'Pass: an enabled all-users policy using authenticationStrength (value round-trips through a PSObject before Write-PulseDataset - cosmetic re: shape, the fixture harness always re-materializes to hashtable before the rule runs; see ConvertTo-PulseCaPolicyView.Tests.ps1 for genuine shape-neutrality coverage at the view layer)' {
        $policy = ConvertTo-PSObjectShape -Value (New-PulseAllUsersMfaPolicy -UseAuthenticationStrength)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'authenticationStrength'
    }

    It 'Fail: report-only-only all-users MFA policy does not count as enforced' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy -State 'enabledForReportingButNotEnforced') }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'report-only'
    }

    It 'Fail with structured evidence when a report-only qualifying policy honors an accepted exclusion' {
        $bg = '11111111-1111-1111-1111-111111111111'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseAllUsersMfaPolicy -State 'enabledForReportingButNotEnforced' -ExcludeUsers @($bg)
            ) }
        ) -Context @{ BreakGlassAccounts = @($bg) }

        $finding.status | Should -Be 'Fail'
        $acceptedEvidence = @($finding.evidence | Where-Object { $_.detail.classification -eq 'accepted-all-users-mfa-exclusion' })
        $acceptedEvidence.Count | Should -Be 1
        $acceptedEvidence[0].identity | Should -Be $bg
        $acceptedEvidence[0].detail.excludedFromReportOnlyMfaPolicies | Should -Contain 'MFA For All Users'
        @($acceptedEvidence[0].detail.excludedFromEnforcedMfaPolicies).Count | Should -Be 0
    }

    It 'Fail: no policy at all targets all users' {
        $rolePolicy = @{
            id            = 'ca-admins-only'
            displayName   = 'MFA For Admins'
            state         = 'enabled'
            conditions    = @{
                users = @{ includeRoles = @('62e90394-69f5-4237-9190-012177145e10') }
                applications = @{ includeApplications = @('All'); excludeApplications = @() }
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($rolePolicy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Pass with structured evidence when an excluded break-glass account is accepted from Context' {
        $bg = '11111111-1111-1111-1111-111111111111'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy -ExcludeUsers @($bg)) }
        ) -Context @{ BreakGlassAccounts = @($bg) }

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Not -Match 'not in the operator-declared'
        $acceptedEvidence = @($finding.evidence | Where-Object { $_.detail.classification -eq 'accepted-all-users-mfa-exclusion' })
        $acceptedEvidence.Count | Should -Be 1
        $acceptedEvidence[0].identity | Should -Be $bg
        $acceptedEvidence[0].detail.excludedFromEnforcedMfaPolicies | Should -Contain 'MFA For All Users'
    }

    It 'Passes with one evidence row when the same accepted account is duplicated and cross-listed' {
        $accountId = [guid]::ParseExact(('d' * 32), 'N').ToString('D')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseAllUsersMfaPolicy -ExcludeUsers @($accountId)
            ) }
        ) -Context @{
            BreakGlassAccounts = @($accountId, $accountId)
            ServiceAccounts    = @($accountId)
        }

        $finding.status | Should -Be 'Pass'
        $acceptedEvidence = @($finding.evidence | Where-Object { $_.detail.classification -eq 'accepted-all-users-mfa-exclusion' })
        $acceptedEvidence.Count | Should -Be 1
        $acceptedEvidence[0].identity | Should -Be $accountId
    }

    It 'Fail: an active Global Administrator is not an accepted direct-user exception unless explicitly declared' {
        $activeAdminId = [guid]::ParseExact(('4' * 32), 'N').ToString('D')
        $policy = New-PulseAllUsersMfaPolicy -ExcludeUsers @($activeAdminId)

        $finding = InModuleScope TenantPulse -ArgumentList $policy, $activeAdminId {
            param($policy, $activeAdminId)
            Test-PulseAllUsersMfaEnforced -Datasets @{
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
        $finding.reason | Should -Match 'all intended users'
    }

    It 'Fail: an excluded identifier not declared as an accepted exception narrows all-users coverage' {
        $undeclared = '22222222-2222-2222-2222-222222222222'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(New-PulseAllUsersMfaPolicy -ExcludeUsers @($undeclared)) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'all intended users'
    }

    It 'Fail: a malformed declared account cannot legitimize the same malformed policy exclusion' {
        $malformed = 'breakglass@contoso.com'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseAllUsersMfaPolicy -ExcludeUsers @($malformed)
            ) }
        ) -Context @{ BreakGlassAccounts = @($malformed) }

        $finding.status | Should -Be 'Fail'
        $malformedEntry = @($finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' })
        $malformedEntry.Count | Should -Be 1
        $malformedEntry[0].detail.issue | Should -Match 'not GUID-shaped'
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($malformed))
    }

    It 'Fail: a parseable but noncanonical GUID cannot legitimize the same malformed policy exclusion' {
        $noncanonical = '{11111111-1111-1111-1111-111111111111}'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                New-PulseAllUsersMfaPolicy -ExcludeUsers @($noncanonical)
            ) }
        ) -Context @{ BreakGlassAccounts = @($noncanonical) }

        $finding.status | Should -Be 'Fail'
        @($finding.evidence | Where-Object { $_.detail.classification -eq 'accepted-all-users-mfa-exclusion' }).Count | Should -Be 0
        @($finding.evidence | Where-Object { $_.identity -like 'malformed-declared-account:*' }).Count | Should -Be 1
        ($finding | ConvertTo-Json -Depth 20 -Compress) | Should -Not -Match ([regex]::Escape($noncanonical))
    }

    It 'Fail: a group exclusion cannot be treated as a declared per-user exception' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.users.excludeGroups = @('group-1')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: excluding guests or external users narrows an all-users MFA policy' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.users.excludeGuestsOrExternalUsers = @{
            guestOrExternalUserTypes = 'b2bCollaborationGuest'
            externalTenants = @{ membershipKind = 'all' }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: an all-users policy scoped to one application does not protect all resources' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.applications.includeApplications = @('application-1')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: authentication-context-only targeting does not protect all resources' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.applications = @{
            includeApplications                         = @()
            includeAuthenticationContextClassReferences = @('c1')
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: an application filter narrows all-users MFA protection' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.applications.applicationFilter = @{ mode = 'exclude'; rule = 'CustomSecurityAttribute.Apps_Project -eq "Legacy"' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: missing application scope cannot settle all-resource coverage' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.Remove('applications')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'application scope'
    }

    It 'Pass: one complete covering policy settles posture despite an unrelated sibling with missing application scope' {
        $incomplete = New-PulseAllUsersMfaPolicy -DisplayName 'Incomplete Sibling'
        $incomplete.conditions.Remove('applications')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                (New-PulseAllUsersMfaPolicy -DisplayName 'Complete Witness')
                $incomplete
            ) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Fail: OR with compliantDevice makes MFA optional for all users' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.grantControls = @{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Pass: AND with compliantDevice still requires MFA for all users' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.grantControls = @{ operator = 'AND'; builtInControls = @('mfa', 'compliantDevice') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'NotApplicable: passwordChange with MFA but no userRiskLevels is an invalid remediation policy, never universal MFA' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.grantControls = @{ operator = 'AND'; builtInControls = @('mfa', 'passwordChange') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.evidence[0].detail.grantReason | Should -Be 'invalid-remediation-policy-conditions'
    }

    It 'NotApplicable: riskRemediation with authentication strength but no userRiskLevels is never universal MFA' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.grantControls = @{
            operator               = 'AND'
            builtInControls        = @('riskRemediation')
            authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002' }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.evidence[0].detail.grantReason | Should -Be 'invalid-remediation-policy-conditions'
    }

    It 'NotApplicable: a custom strength cannot establish MFA without authoritative strength evidence' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.grantControls = @{ authenticationStrength = @{ id = '11111111-1111-1111-1111-111111111111' } }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'Pass: a custom strength explicitly reporting requirementsSatisfied mfa establishes generic MFA' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.grantControls = @{
            authenticationStrength = @{
                id                    = '11111111-1111-1111-1111-111111111111'
                requirementsSatisfied = 'mfa'
            }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.evidence[0].detail.mfaMechanism | Should -Be 'authenticationStrength:requirementsSatisfied'
    }

    It 'Fail: an iOS-only policy does not establish MFA across all sign-ins' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.platforms = @{ includePlatforms = @('iOS') }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: a beta time window cannot establish MFA across all sign-ins' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.times = @{ daysOfWeek = @('monday'); startTime = '09:00:00'; endTime = '17:00:00' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: an unrecognized non-null beta condition leaves universal scope unsettled' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.futureCondition = @{ mode = 'include' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'incomplete'
    }

    It 'Fail: an unknown future client-app type cannot broaden a known browser-only MFA policy' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.clientAppTypes = @('browser', 'futureClient')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'No enabled, enforced Conditional Access policy'
    }

    It 'Fail: an invalid application filter cannot broaden a known single-application MFA policy' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.applications = @{
            includeApplications = @([guid]::ParseExact(('8' * 32), 'N').ToString('D'))
            applicationFilter   = @{ mode = 'futureMode'; rule = 'x' }
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: a blank exclusion cannot broaden a known single-user MFA policy' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.users = @{
            includeUsers = @([guid]::ParseExact(('9' * 32), 'N').ToString('D'))
            excludeUsers = @('')
        }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: missing clientAppTypes is incomplete universal sign-in evidence' {
        $policy = New-PulseAllUsersMfaPolicy
        $policy.conditions.Remove('clientAppTypes')
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0017' -Datasets @(
            @{ Name = 'conditionalAccessPolicies'; ApiVersion = 'beta'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'NotApplicable'
    }
}
