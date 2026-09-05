<#
    Private: TP.ENT.0005 rule function - MFA is required for admin roles by an ENFORCED
    Conditional Access policy.

    The 14-role minimum is Microsoft's own documented floor (policy-admin-phish-resistant-
    admin-mfa - see this check's References.Authorities): Global Administrator, Application
    Administrator, Authentication Administrator, Billing Administrator, Cloud Application
    Administrator, Conditional Access Administrator, Exchange Administrator, Helpdesk
    Administrator, Password Administrator, Privileged Authentication Administrator,
    Privileged Role Administrator, Security Administrator, SharePoint Administrator, and
    User Administrator. Role coverage is checked by TEMPLATE ID (stable
    across every Entra tenant, documented by Microsoft), not by display name - a renamed or
    localized role name can never mask coverage.

    Coverage is computed as the UNION of includeRoles across every ENABLED policy whose
    grantControls require MFA - an organization commonly splits "MFA for admins" across more
    than one policy (e.g. one for cloud apps, one for Azure management), and this check does
    not penalize that split as long as every one of the 14 roles is covered by AT LEAST one
    of them. Report-only-only coverage (no enabled policy covers a role at all) is reported
    as a gap, same distinction TP.ENT.0004 makes for legacy auth.

    MFA-SATISFACTION: the shared grant classifier applies Graph's AND/OR operator. Built-in
    MFA or one of Microsoft's three built-in MFA-satisfying strengths counts only when it
    is mandatory. A custom/empty strength is indeterminate until requirementsSatisfied is
    collected; an OR alternative such as compliantDevice makes MFA optional, not required.

    EFFECTIVE SCOPE: only policies explicitly covering all resources contribute role
    coverage. A role named in conditions.users.excludeRoles is subtracted from that policy's
    includeRoles or includeAll contribution. Known resource, client-app, platform, location,
    risk, device-filter, or authentication-flow narrowing cannot establish universal
    coverage; missing evidence is indeterminate only when it could cover every remaining
    role. A canonical direct-user exclusion remains complete only when it is an
    operator-declared break-glass/service-account exception. Other direct-user exclusions,
    group exclusions, and guest/external carve-outs make role coverage indeterminate rather
    than allowing a false Pass.

    EXCLUSION-CONTEXT WIRING (Task 3.5): same pattern as TP.ENT.0004's own wiring note -
    consumes Get-PulseCaExclusionContext for BreakGlassAccounts and ServiceAccounts, passes
    their canonical identifiers into effective role-scope classification, and records which
    of THIS check's covering policies (the enabled, MFA-requiring, role/'All'-scoped ones)
    and which report-only-shaped-but-not-enforced equivalents actually exclude each declared
    identifier - split
    excludedFromEnforcedMfaPolicies vs. excludedFromReportOnlyMfaPolicies, with the same
    REPORT-ONLY-NEVER-COUNTS-AS-PROTECTION binding this check already applies to admin MFA
    coverage itself. An excluded admin identity here is a DIFFERENT signal than TP.ENT.0003's
    - it means that identity's admin role would not be forced through MFA by this policy set
    (a break-glass account is deliberately excluded from MFA for exactly this reason; a
    workaday admin excluded from a policy that is supposed to require MFA for its role is
    worth an operator's attention, but this check does not fail on it - it only surfaces the
    fact). Only 'conditionalAccessPolicies' is declared in this check's own Data.Datasets
    (unchanged by this wiring), so -Datasets.directoryRoleAssignments is never present here
    and ActiveGlobalAdmins is always empty - read defensively by Get-PulseCaExclusionContext
    itself rather than added as a new required dataset (same field-absence rationale as
    TP.ENT.0004's wiring note).

    COMPLETENESS FOLD-IN (dual review, fix round): same fix as TP.ENT.0004's own wiring -
    MalformedDeclaredAccounts (surfaced unconditionally when non-empty, since a non-GUID
    declared identifier can never match ANY policy's excludeUsers regardless of whether a
    matching MFA policy exists) and GroupExclusionNote (surfaced once, whenever
    GroupExclusionsResolved is $false AND the operator declared some exclusion-relevant
    context at all) are now both read - see TP.ENT.0004's own docstring for the full
    rationale, identical here.

    MISREADING-RISK FOLD-IN (dual review, fix round): an admin identity excluded ONLY from a
    report-only-shaped MFA policy (never from any enabled one) now carries an explicit
    reportOnlyProtectionWarning on its evidence entry - same fix, same rationale as
    TP.ENT.0004's own docstring note.
#>

function Test-PulseAdminMfaEnforced {
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

    # Microsoft's well-known, tenant-stable role template ids for the 14 named roles - see
    # this file's own docstring and the check descriptor's References.Authorities.
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
    $requiredRoleIds = [string[]] @($requiredAdminRoles.Keys)
    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $acceptedExcludedIdentifiers = Get-PulseAcceptedCaExcludedIdentifiers -ExclusionContext $exclusionContext
    $enabledRecords = @()
    $reportOnlyRecords = @()
    $incompleteEnabledPolicies = @()

    $policyOrdinal = -1
    foreach ($policy in $views) {
        $policyOrdinal++
        if ($policy.state -notin @('enforced', 'reportOnly')) { continue }

        $roleScope = Get-PulseCaAdminRoleScope -PolicyView $policy -RequiredRoleIds $requiredRoleIds -AcceptedExcludedIdentifiers $acceptedExcludedIdentifiers
        if ($roleScope.State -eq 'NotTargeted') { continue }

        $grant = Get-PulseCaGrantRequirement -PolicyView $policy -Requirement Mfa
        $applicationScope = Get-PulseCaApplicationScope -PolicyView $policy
        $signInScope = Get-PulseCaSignInScope -PolicyView $policy -Mode Mfa
        $record = [pscustomobject]@{
            Policy           = $policy
            RoleScope        = $roleScope
            Grant            = $grant
            ApplicationScope = $applicationScope
            SignInScope      = $signInScope
            CollectionOrdinal = $policyOrdinal
        }

        if ($roleScope.State -eq 'Targeted' -and $grant.State -eq 'Required' -and
            $applicationScope.State -eq 'AllResources' -and $signInScope.State -eq 'Universal') {
            if ($policy.state -eq 'enforced') { $enabledRecords += $record }
            else { $reportOnlyRecords += $record }
            continue
        }

        if ($policy.state -eq 'enforced' -and
            $roleScope.State -ne 'NotTargeted' -and $grant.State -ne 'NotRequired' -and
            $applicationScope.CouldBeAllResources -and $signInScope.State -ne 'Narrow' -and $signInScope.CouldBeUniversal -and
            ($roleScope.State -eq 'Incomplete' -or $grant.State -eq 'Incomplete' -or
                $applicationScope.State -eq 'Incomplete' -or $signInScope.State -eq 'Incomplete')) {
            $incompleteEnabledPolicies += $record
        }
    }

    $enabledMfaPolicies = @($enabledRecords | ForEach-Object { $_.Policy })
    $reportOnlyMfaPolicies = @($reportOnlyRecords | ForEach-Object { $_.Policy })

    # Honored-exclusion evidence is additive after the accepted identifiers have already
    # participated in effective role-scope classification above.
    $exclusionEvidence = @()
    $malformedAccounts = @($exclusionContext.MalformedDeclaredAccounts)
    # "Declared something" gate (fix-round addition) - see TP.ENT.0004's own identical
    # comment for the full rationale.
    $hasDeclaredExclusionContext = @($exclusionContext.BreakGlassAccounts).Count -gt 0 -or
        @($exclusionContext.ServiceAccounts).Count -gt 0

    if ($acceptedExcludedIdentifiers.Count -gt 0 -and ($enabledMfaPolicies.Count -gt 0 -or $reportOnlyMfaPolicies.Count -gt 0)) {
        foreach ($identifier in $acceptedExcludedIdentifiers) {
            $enforcedNames = @($enabledMfaPolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            $reportOnlyNames = @($reportOnlyMfaPolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            if ($enforcedNames.Count -eq 0 -and $reportOnlyNames.Count -eq 0) { continue }
            $detail = @{
                excludedFromEnforcedMfaPolicies   = $enforcedNames
                excludedFromReportOnlyMfaPolicies = $reportOnlyNames
            }
            # MISREADING-RISK FOLD-IN: report-only-ONLY exclusion (never also excluded from
            # an enabled policy) gets an explicit warning - see this file's own docstring.
            if ($reportOnlyNames.Count -gt 0 -and $enforcedNames.Count -eq 0) {
                $detail.reportOnlyProtectionWarning = 'Report-only policies do not protect this account - nothing is actually enforced, so this identity''s admin role is NOT actually forced through MFA by these polic' + $(if ($reportOnlyNames.Count -eq 1) { 'y' } else { 'ies' }) + ' today.'
            }
            $exclusionEvidence += @{
                Identity = $identifier
                SortKey  = "exclusion:$identifier"
                Detail   = $detail
            }
        }
    }

    # COMPLETENESS FOLD-IN: malformed declared accounts can never match ANY policy's
    # excludeUsers - surfaced unconditionally when non-empty.
    foreach ($malformed in $malformedAccounts) {
        $alias = Get-PulseMalformedDeclaredAccountAlias -Value ([string] $malformed) -Key $OperatorKey
        $exclusionEvidence += @{
            Identity = $alias
            SortKey  = $alias
            Detail   = @{
                issue = 'not GUID-shaped - Conditional Access excludeUsers holds GUID principal ids, so this declared exclusion can never match any policy and cannot be honored, enforced or report-only.'
            }
        }
    }

    # COMPLETENESS FOLD-IN: surfaces "group-based exclusion cannot be verified" whenever the
    # operator declared some exclusion-relevant context at all - see this file's own
    # docstring and TP.ENT.0004's identical rationale for why an empty -Context call does
    # not get this entry.
    if ($hasDeclaredExclusionContext -and -not $exclusionContext.GroupExclusionsResolved) {
        $exclusionEvidence += @{
            Identity = 'group-exclusion-resolution'
            SortKey  = 'group-exclusion-resolution'
            Detail   = @{
                note = $exclusionContext.GroupExclusionNote
            }
        }
    }

    $coveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $enabledRecords) {
        foreach ($roleId in @($record.RoleScope.PossibleRoleIds)) {
            $coveredRoleIds.Add([string] $roleId) | Out-Null
        }
    }

    $missingRoles = @($requiredAdminRoles.GetEnumerator() | Where-Object { -not $coveredRoleIds.Contains($_.Key) })
    $missingRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($missingRole in $missingRoles) { $missingRoleIds.Add([string] $missingRole.Key) | Out-Null }
    $potentiallyCoveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $incompletePoliciesThatCouldSettleCoverage = @($incompleteEnabledPolicies | Where-Object {
        $possibleMissing = @($_.RoleScope.PossibleRoleIds | Where-Object { $missingRoleIds.Contains([string] $_) })
        foreach ($roleId in $possibleMissing) { [void] $potentiallyCoveredRoleIds.Add([string] $roleId) }
        $possibleMissing.Count -gt 0
    })
    $definitelyMissingRoles = @($missingRoles | Where-Object { -not $potentiallyCoveredRoleIds.Contains([string] $_.Key) })

    if ($missingRoles.Count -eq 0) {
        $evidence = @($enabledRecords | ForEach-Object {
            $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
            @{ Identity = $policyIdentity; Detail = @{ displayName = $_.Policy.displayName; mfaMechanism = $_.Grant.Mechanism } }
        }) + $exclusionEvidence
        return New-PulseFinding -Status Pass -Reason "All 14 of Microsoft's minimum admin roles are covered by MFA-requiring, enabled Conditional Access polic$(if ($enabledMfaPolicies.Count -eq 1) { 'y' } else { 'ies' })." -Evidence $evidence
    }

    if ($incompletePoliciesThatCouldSettleCoverage.Count -gt 0 -and $definitelyMissingRoles.Count -eq 0) {
        $evidence = @($incompletePoliciesThatCouldSettleCoverage | ForEach-Object {
            $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
            @{
                Identity = $policyIdentity
                Detail = @{
                    displayName = $_.Policy.displayName
                    roleScope = $_.RoleScope.State
                    roleScopeReason = $_.RoleScope.ReasonCode
                    roleScopeAcceptedExcludedUserCount = $_.RoleScope.AcceptedExcludedUserCount
                    roleScopeUnacceptedExcludedUserCount = $_.RoleScope.UnacceptedExcludedUserCount
                    roleScopeExcludedGroupCount = $_.RoleScope.ExcludedGroupCount
                    roleScopeHasExcludedGuestsOrExternalUsers = $_.RoleScope.HasExcludedGuestsOrExternalUsers
                    grantState = $_.Grant.State
                    grantReason = $_.Grant.ReasonCode
                    applicationScope = $_.ApplicationScope.State
                    applicationScopeReason = $_.ApplicationScope.ReasonCode
                    signInScope = $_.SignInScope.State
                    signInScopeReason = $_.SignInScope.ReasonCode
                }
            }
        }) + $exclusionEvidence
        return New-PulseFinding -Status NotApplicable -Reason "$($incompletePoliciesThatCouldSettleCoverage.Count) enabled admin-MFA policy/policies could cover every currently missing role but have incomplete role scope, grant, application scope, or sign-in scope evidence; TenantPulse cannot determine universal role coverage." -Evidence $evidence
    }

    $knownMissing = if ($definitelyMissingRoles.Count -gt 0) { $definitelyMissingRoles } else { $missingRoles }
    $evidence = @($knownMissing | ForEach-Object { @{ Identity = $_.Key; Detail = @{ roleDisplayName = $_.Value } } }) + $exclusionEvidence
    return New-PulseFinding -Status Fail -Reason "$($knownMissing.Count) of Microsoft's 14 minimum admin roles are definitively not covered by any enabled, universally scoped, MFA-requiring Conditional Access policy." -Evidence $evidence
}
