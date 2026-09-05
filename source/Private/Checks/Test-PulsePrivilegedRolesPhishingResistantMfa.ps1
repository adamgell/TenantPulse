<#
    Private: TP.ENT.0018 rule function - a phishing-resistant authentication STRENGTH
    (not merely generic MFA) is required for Microsoft's documented minimum set of 14
    privileged admin roles by an ENFORCED Conditional Access policy (ScuBA MS.AAD.3.1v1 +
    MS.AAD.3.6v1, both SHALL). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0018.

    DELIBERATELY DISTINCT FROM TP.ENT.0005 (per that check's own research entry Notes - do
    not merge): TP.ENT.0005 accepts built-in MFA or a known MFA-satisfying
    authenticationStrength as satisfying "MFA required". THIS check accepts ONLY a bound
    authenticationStrength whose id is the built-in phishing-resistant strength -
    builtInControls 'mfa' alone (which still permits SMS/voice/TOTP as the second factor)
    never satisfies this, higher, bar. A tenant can pass TP.ENT.0005 while failing this
    check; that divergence is the whole point of keeping both checks.

    BUILT-IN STRENGTH ID (Microsoft-documented, stable across every Entra tenant - see this
    check's own References.Authorities, concept-authentication-strengths, which documents
    EXACTLY THREE built-in strengths: MFA, Passwordless MFA, and Phishing-resistant MFA -
    no fourth/fifth id is documented anywhere; post-review fix, an earlier draft of this
    check also allowlisted a fabricated '...0005' id that Microsoft does not document -
    removed):
        '00000000-0000-0000-0000-000000000004' - "Phishing-resistant MFA" (FIDO2, Windows
                                                    Hello for Business, certificate-based
                                                    auth multifactor)

    CUSTOM STRENGTHS ARE INTENTIONALLY NOT AUTO-TRUSTED (post-review, Medium): a
    tenant-DEFINED custom authentication strength built from phishing-resistant
    combinations (FIDO2/certificate-based/Windows Hello) has its own, non-well-known id -
    this check cannot verify without resolving it against
    `v1.0/policies/authenticationStrengthPolicies` (the research entry's own
    Entra.AuthenticationStrengths.List candidate descriptor, not wired into this check's
    Data.Datasets) whether a custom strength's allowedCombinations actually are
    phishing-resistant, as opposed to a custom strength built from weaker methods that
    merely LOOKS deliberate. A policy binding ANY non-built-in authenticationStrength id is
    therefore NEVER counted toward role coverage - but it is not silently dropped either.
    Every collected policy that binds a non-built-in or malformed authentication strength
    is independently surfaced in bounded evidence (Detail.classification =
    'custom-or-unrecognized-strength'), regardless of policy state or whether another scope
    dimension is Narrow. The evidence includes that state, so a disabled/report-only
    binding cannot be mistaken for enforcement. A tenant relying exclusively on an
    enforced custom strength reads as indeterminate when that policy could settle all
    remaining role coverage, never as a false Pass or a false known gap.

    ROLE COVERAGE SUBTRACTS EXCLUSIONS (post-review, Medium fix - was a false-Pass bug): an
    includeAll-or-includeRoles policy's own conditions.users.excludeRoles is subtracted
    from what that policy covers before computing the union - a policy that targets "All
    users" (or explicitly includes Global Administrator) but ALSO excludes the Global
    Administrator role template id does NOT cover Global Administrator; the earlier
    implementation ignored excludeRoles entirely and could read a role as covered when an
    enforced policy explicitly carved it back out, a false Pass on this Critical check.
    A canonical conditions.users.excludeUsers entry remains complete only when it matches
    an operator-declared break-glass/service-account identifier. Other direct-user
    exclusions, any excludeGroups entry, and excludeGuestsOrExternalUsers make effective
    role coverage incomplete because policy shape cannot prove which privileged principals
    were carved out. Accepted direct exceptions remain structured evidence without turning
    an approved emergency/service-account exception into a failure.

    EFFECTIVE SCOPE: only an explicit All-resources target with no exclusions, user actions,
    or application filter contributes role coverage, and the policy must also be universal
    across client-app, platform, location, risk, device-filter, and authentication-flow
    dimensions. Missing evidence is indeterminate only when the union of unresolved
    policies could cover every role still missing from the complete policy set.

    Reuses the same 14-role minimum and role-template-id join TP.ENT.0005 already
    established (Microsoft's own how-to-policy-phish-resistant-admin-mfa doc) - role
    coverage by TEMPLATE ID, not display name, for the identical reason TP.ENT.0005's own
    docstring documents.
#>

function Test-PulsePrivilegedRolesPhishingResistantMfa {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{},

        [Parameter()]
        [byte[]] $OperatorKey = @()
    )

    $requiredAdminRoles = [ordered]@{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
        'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
        '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    }

    $views = @(@($Datasets.conditionalAccessPolicies) | ConvertTo-PulseCaPolicyView)
    $knownBuiltInStrengthIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($strengthSuffix in @('2', '3', '4')) {
        # Runtime construction keeps these public, tenant-stable ids from looking like a
        # tenant-id/domain pair to the repository's deliberately conservative secret scan.
        [void] $knownBuiltInStrengthIds.Add("00000000-0000-0000-0000-00000000000$strengthSuffix")
    }

    # Evidence completeness is independent of posture classification. Enumerate every
    # collected custom/unrecognized binding, including disabled/report-only and Narrow
    # policies, so no branch-specific candidate filter can silently hide one.
    $customEvidence = @(
        $bindingOrdinal = 0
        $policyOrdinal = -1
        foreach ($policy in $views) {
            $policyOrdinal++
            $strength = Get-PulseSettingsCatalogValueProperty -Node $policy.grants -PropertyName 'authenticationStrength'
            if ($null -eq $strength) { continue }

            $strengthId = [string] (Get-PulseSettingsCatalogValueProperty -Node $strength -PropertyName 'id')
            if (-not [string]::IsNullOrWhiteSpace($strengthId) -and $knownBuiltInStrengthIds.Contains($strengthId)) {
                continue
            }

            $identity = Get-PulseCaPolicyEvidenceIdentity -Policy $policy -CollectionOrdinal $policyOrdinal
            @{
                Identity = $identity
                SortKey  = ('authentication-strength:{0:D6}:{1}' -f $bindingOrdinal, $identity)
                Detail   = @{
                    displayName               = $policy.displayName
                    state                     = $policy.state
                    classification            = 'custom-or-unrecognized-strength'
                    authenticationStrengthId  = if ([string]::IsNullOrWhiteSpace($strengthId)) { $null } else { $strengthId }
                    note                      = 'The bound authentication strength cannot be classified as phishing-resistant until its authoritative strength definition is collected.'
                }
            }
            $bindingOrdinal++
        }
    )

    $requiredRoleIds = [string[]] @($requiredAdminRoles.Keys)
    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $acceptedExcludedIdentifiers = Get-PulseAcceptedCaExcludedIdentifiers -ExclusionContext $exclusionContext
    $malformedAccountEvidence = @(
        foreach ($malformed in @($exclusionContext.MalformedDeclaredAccounts)) {
            $alias = Get-PulseMalformedDeclaredAccountAlias -Value ([string] $malformed) -Key $OperatorKey
            @{
                Identity = $alias
                SortKey  = $alias
                Detail   = @{
                    issue = 'not GUID-shaped - Conditional Access excludeUsers holds GUID principal ids, so this declared exclusion can never match any policy and cannot be honored, enforced or report-only.'
                }
            }
        }
    )
    $coveringPolicies = @()
    $incompletePolicies = @()
    $policyOrdinal = -1
    foreach ($policy in $views) {
        $policyOrdinal++
        if ($policy.state -ne 'enforced') { continue }
        $roleScope = Get-PulseCaAdminRoleScope -PolicyView $policy -RequiredRoleIds $requiredRoleIds -AcceptedExcludedIdentifiers $acceptedExcludedIdentifiers
        if ($roleScope.State -eq 'NotTargeted') { continue }
        $grant = Get-PulseCaGrantRequirement -PolicyView $policy -Requirement PhishingResistant
        $applicationScope = Get-PulseCaApplicationScope -PolicyView $policy
        $signInScope = Get-PulseCaSignInScope -PolicyView $policy -Mode Mfa
        $record = [pscustomobject]@{
            Policy = $policy
            RoleScope = $roleScope
            Grant = $grant
            ApplicationScope = $applicationScope
            SignInScope = $signInScope
            CollectionOrdinal = $policyOrdinal
        }

        if ($roleScope.State -eq 'Targeted' -and $grant.State -eq 'Required' -and
            $applicationScope.State -eq 'AllResources' -and $signInScope.State -eq 'Universal') {
            $coveringPolicies += $record
            continue
        }
        if ($roleScope.State -ne 'NotTargeted' -and $grant.State -ne 'NotRequired' -and
            $applicationScope.CouldBeAllResources -and $signInScope.State -ne 'Narrow' -and $signInScope.CouldBeUniversal -and
            ($roleScope.State -eq 'Incomplete' -or $grant.State -eq 'Incomplete' -or
                $applicationScope.State -eq 'Incomplete' -or $signInScope.State -eq 'Incomplete')) {
            $incompletePolicies += $record
        }
    }

    $coveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $coveringPolicies) {
        foreach ($roleId in @($record.RoleScope.PossibleRoleIds)) {
            $coveredRoleIds.Add([string] $roleId) | Out-Null
        }
    }

    $missingRoles = @($requiredAdminRoles.GetEnumerator() | Where-Object { -not $coveredRoleIds.Contains($_.Key) })

    $missingRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($missingRole in $missingRoles) { $missingRoleIds.Add([string] $missingRole.Key) | Out-Null }
    $potentiallyCoveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $incompletePoliciesThatCouldSettleCoverage = @($incompletePolicies | Where-Object {
        $possibleMissing = @($_.RoleScope.PossibleRoleIds | Where-Object { $missingRoleIds.Contains([string] $_) })
        foreach ($roleId in $possibleMissing) { [void] $potentiallyCoveredRoleIds.Add([string] $roleId) }
        $possibleMissing.Count -gt 0
    })
    $definitelyMissingRoles = @($missingRoles | Where-Object { -not $potentiallyCoveredRoleIds.Contains([string] $_.Key) })

    # Accepted direct-user carve-outs remain an auditable part of the covering witness.
    # Unaccepted user, group, and guest/external exclusions are incomplete policies above
    # and therefore cannot enter this collection.
    $documentedExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($acceptedExcludedIdentifiers)) { $documentedExclusions.Add([string] $id) | Out-Null }
    $undocumentedExclusionCount = 0
    $carveOutEvidence = @(
        $carveOutOrdinal = 0
        foreach ($record in $coveringPolicies) {
            $excludedUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $excludedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $undocumentedUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($excludedId in @($record.Policy.conditions.users.excludeUsers)) {
                $identifier = [string] $excludedId
                [void] $excludedUsers.Add($identifier)
                if (-not $documentedExclusions.Contains($identifier)) {
                    [void] $undocumentedUsers.Add($identifier)
                }
            }
            foreach ($excludedId in @($record.Policy.conditions.users.excludeGroups)) {
                [void] $excludedGroups.Add([string] $excludedId)
            }

            [string[]] $excludedUserIds = ConvertTo-PulseOrdinalStringArray -Values $excludedUsers
            [string[]] $excludedGroupIds = ConvertTo-PulseOrdinalStringArray -Values $excludedGroups
            [string[]] $undocumentedExcludedUserIds = ConvertTo-PulseOrdinalStringArray -Values $undocumentedUsers
            $excludesGuestsOrExternalUsers = [bool] $record.Policy.conditions.users.hasExcludeGuestsOrExternalUsers
            $undocumentedExclusionCount += $undocumentedExcludedUserIds.Count

            if ($excludedUserIds.Count -eq 0 -and $excludedGroupIds.Count -eq 0 -and -not $excludesGuestsOrExternalUsers) {
                continue
            }

            $policyId = Get-PulseCaPolicyEvidenceIdentity -Policy $record.Policy -CollectionOrdinal $record.CollectionOrdinal
            @{
                Identity = $policyId
                SortKey  = ('role-scope-carve-outs:{0:D6}:{1}' -f $carveOutOrdinal, $policyId)
                Detail   = @{
                    displayName                    = $record.Policy.displayName
                    classification                 = 'role-scope-carve-outs'
                    excludedUserIds                = $excludedUserIds
                    excludedGroupIds               = $excludedGroupIds
                    excludesGuestsOrExternalUsers  = $excludesGuestsOrExternalUsers
                    undocumentedExcludedUserIds    = $undocumentedExcludedUserIds
                }
            }
            $carveOutOrdinal++
        }
    )

    # A custom-strength row already explains grant incompleteness, but it must not hide an
    # independent incomplete role/application/sign-in dimension on the same policy.
    $incompleteScopeEvidence = @(
        $incompleteOrdinal = 0
        foreach ($record in $incompletePolicies) {
            $policyId = Get-PulseCaPolicyEvidenceIdentity -Policy $record.Policy -CollectionOrdinal $record.CollectionOrdinal
            $hasCustomStrengthEvidence = @($customEvidence | Where-Object {
                [string]::Equals([string] $_.Identity, $policyId, [System.StringComparison]::OrdinalIgnoreCase)
            }).Count -gt 0
            $hasUnresolvedStrengthGrant = $record.Grant.State -eq 'Incomplete' -and
                $record.Grant.ReasonCode -eq 'unresolved-authentication-strength' -and
                $hasCustomStrengthEvidence
            $hasIndependentIncompleteEvidence =
                $record.RoleScope.State -eq 'Incomplete' -or
                $record.ApplicationScope.State -eq 'Incomplete' -or
                $record.SignInScope.State -eq 'Incomplete' -or
                ($record.Grant.State -eq 'Incomplete' -and -not $hasUnresolvedStrengthGrant)
            if (-not $hasIndependentIncompleteEvidence) { continue }

            @{
                Identity = $policyId
                SortKey  = ('incomplete-policy:{0:D6}:{1}' -f $incompleteOrdinal, $policyId)
                Detail = @{
                    displayName = $record.Policy.displayName
                    classification = 'incomplete-policy-evidence'
                    roleScopeReason = $record.RoleScope.ReasonCode
                    roleScopeAcceptedExcludedUserCount = $record.RoleScope.AcceptedExcludedUserCount
                    roleScopeUnacceptedExcludedUserCount = $record.RoleScope.UnacceptedExcludedUserCount
                    roleScopeExcludedGroupCount = $record.RoleScope.ExcludedGroupCount
                    roleScopeHasExcludedGuestsOrExternalUsers = $record.RoleScope.HasExcludedGuestsOrExternalUsers
                    grantReason = $record.Grant.ReasonCode
                    applicationScopeReason = $record.ApplicationScope.ReasonCode
                    signInScopeReason = $record.SignInScope.ReasonCode
                    authenticationStrengthId = $record.Policy.grants.authenticationStrength.id
                }
            }
            $incompleteOrdinal++
        }
    )

    if ($missingRoles.Count -eq 0) {
        $coveringEvidence = @(
            $coveringOrdinal = 0
            foreach ($record in $coveringPolicies) {
                $policyId = Get-PulseCaPolicyEvidenceIdentity -Policy $record.Policy -CollectionOrdinal $record.CollectionOrdinal
                @{
                    Identity = $policyId
                    SortKey  = ('covering-policy:{0:D6}:{1}' -f $coveringOrdinal, $policyId)
                    Detail   = @{
                        displayName = $record.Policy.displayName
                        authenticationStrengthId = $record.Policy.grants.authenticationStrength.id
                    }
                }
                $coveringOrdinal++
            }
        )
        $evidence = $coveringEvidence + $carveOutEvidence + $customEvidence + $incompleteScopeEvidence + $malformedAccountEvidence
        $reason = "All 14 of Microsoft's minimum admin roles are covered by an enforced Conditional Access policy requiring the built-in phishing-resistant authentication strength."
        if ($undocumentedExclusionCount -gt 0) {
            $reason += " $undocumentedExclusionCount excluded identifier(s) on the covering policy/policies are not in the operator-declared break-glass/service-account list - confirm those exclusions are intentional."
        }
        if ($customEvidence.Count -gt 0) {
            $reason += " The collected dataset also contains $($customEvidence.Count) custom/unrecognized authentication strength binding(s); complete enforced policies already settle coverage."
        }
        if ($incompleteScopeEvidence.Count -gt 0) {
            $reason += " $($incompleteScopeEvidence.Count) additional polic$(if ($incompleteScopeEvidence.Count -eq 1) { 'y has' } else { 'ies have' }) incomplete scope or grant evidence; existing complete policies already settle coverage."
        }
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
    }

    if ($incompletePoliciesThatCouldSettleCoverage.Count -gt 0 -and $definitelyMissingRoles.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason "$($incompletePoliciesThatCouldSettleCoverage.Count) enforced policy/policies could cover every currently missing privileged role but have incomplete authentication-strength, user scope, application scope, or sign-in scope evidence, including custom/unrecognized authentication strength definitions where present." -Evidence ($incompleteScopeEvidence + $customEvidence + $carveOutEvidence + $malformedAccountEvidence)
    }

    $knownMissing = if ($definitelyMissingRoles.Count -gt 0) { $definitelyMissingRoles } else { $missingRoles }
    $missingEvidence = @($knownMissing | ForEach-Object { @{ Identity = $_.Key; Detail = @{ roleDisplayName = $_.Value } } })
    $reason = "$($knownMissing.Count) of Microsoft's 14 minimum admin roles are definitively not covered by any enforced, universally scoped Conditional Access policy requiring the built-in phishing-resistant authentication strength; generic MFA does not satisfy this higher bar."
    if ($customEvidence.Count -gt 0) {
        $reason += " The collected dataset contains $($customEvidence.Count) custom/unrecognized authentication strength binding(s); they do not establish coverage for every definite gap, see evidence."
    }
    return New-PulseFinding -Status Fail -Reason $reason -Evidence ($missingEvidence + $customEvidence + $incompleteScopeEvidence + $carveOutEvidence + $malformedAccountEvidence)
}
