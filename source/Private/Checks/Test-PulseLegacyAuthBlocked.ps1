<#
    Private: TP.ENT.0004 rule function - legacy authentication is blocked by an ENFORCED
    Conditional Access policy.

    "Enforced" is the load-bearing word: Rule.State must be exactly 'enabled' - a policy in
    'enabledForReportingButNotEnforced' (report-only) proves nothing is actually blocked,
    only that Microsoft's own managed-policies feature (or an operator) staged it. This
    check distinguishes those two outcomes in its Reason so an operator sees "you have a
    policy, it just isn't turned on" rather than "you have nothing".

    Legacy-auth coverage is the union of the two distinct client buckets
    'exchangeActiveSync' and 'other' across complete enforced policies; one without the
    other is not tenant-wide protection. The 'all' sentinel covers both. Each contributing
    policy must use the Block grant and be universal across its user, resource, platform,
    location, risk, device-filter, and authentication-flow dimensions.

    EFFECTIVE SCOPE: a qualifying policy must cover all resources and all intended users.
    Get-PulseCaExclusionContext supplies the explicit direct-account exceptions accepted by
    the all-users classifier; undeclared user exclusions and any group or role exclusion
    make the policy known Narrow. Application-specific targeting, exclusions, user actions,
    and application filters also make it Narrow. Missing or malformed scope is incomplete
    evidence and cannot produce either a Pass or a known tenant-wide gap. For every declared
    ExcludedIdentifier, evidence records which of the policies THIS check evaluated (the
    legacy-auth-block-shaped ones) actually name it in excludeUsers, split by
    excludedFromEnforcedBlockPolicies vs. excludedFromReportOnlyBlockPolicies - REPORT-ONLY
    EXCLUSION NEVER COUNTS AS HONORED PROTECTION (same enforced-vs-report-only binding this
    check already applies to the block itself), it is surfaced only so an operator can see
    declared intent that a report-only policy has not yet made real. This additive exclusion
    evidence remains informational. Only
    'conditionalAccessPolicies' is declared in this check's own Data.Datasets (unchanged by
    this wiring) - -Datasets.directoryRoleAssignments is therefore never present here, so
    ActiveGlobalAdmins is always empty for this check; that absence is read defensively by
    Get-PulseCaExclusionContext itself (field-absence, not a failure) rather than by adding
    a new required dataset that would degrade this check to NotApplicable in any tenant
    collection that never gathered directoryRoleAssignments.

    COMPLETENESS FOLD-IN (dual review, fix round): the first cut of this wiring silently
    dropped two of Get-PulseCaExclusionContext's own "never silently dropped" fields -
    MalformedDeclaredAccounts (a declared identifier that can never match ANY policy's
    excludeUsers, GUID-shape mismatch) and GroupExclusionNote (set whenever
    GroupExclusionsResolved is $false) were never read, so a malformed declared account left
    zero evidence trace here even though the shared context function's own contract says it
    is always enumerated for a caller that cares. Fixed: every malformed declared account
    gets its own evidence entry UNCONDITIONALLY when the list is non-empty (independent of
    whether any legacy-auth-block-shaped policy exists at all - a malformed identifier can
    never match one regardless), and a single group-exclusion-resolution note entry is added
    whenever GroupExclusionsResolved is $false AND the operator declared some exclusion-
    relevant context at all (a resolvable ExcludedIdentifier or a malformed account) - gating
    on "declared something" keeps the zero-Context call shape (most existing tests, and any
    caller that never opts into -Context) producing byte-identical evidence to before this
    fix, since telling an operator who declared nothing that "group exclusions aren't
    resolved" has no action to attach to.

    MISREADING-RISK FOLD-IN (dual review, fix round): an identity excluded ONLY from a
    report-only-shaped policy (never from any enforced one) now carries an explicit
    reportOnlyProtectionWarning message on its evidence entry, mirroring
    Get-PulseCaExclusionContext's own ENFORCED VS. REPORT-ONLY docstring warning - a
    skimming operator who sees "excludedFromReportOnlyBlockPolicies: [...]" without reading
    the field name closely could otherwise misread "excluded" as "safe." The warning is
    omitted when the identity is ALSO excluded from at least one enforced policy (genuinely
    honored there already, nothing to warn about).
#>

function Test-PulseLegacyAuthBlocked {
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

    $views = @(@($Datasets.conditionalAccessPolicies) | ConvertTo-PulseCaPolicyView)

    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $acceptedExcludedIdentifiers = Get-PulseAcceptedCaExcludedIdentifiers -ExclusionContext $exclusionContext

    $enforcedShapePolicies = @()
    $reportOnlyShapePolicies = @()
    $enforcedBlockPolicies = @()
    $reportOnlyBlockPolicies = @()
    $incompleteEnforcedPolicies = @()
    $policyOrdinal = -1
    foreach ($policy in $views) {
        $policyOrdinal++
        if ($policy.state -notin @('enforced', 'reportOnly')) { continue }
        $blockRequirement = Get-PulseCaBlockRequirement -PolicyView $policy
        $applicationScope = Get-PulseCaApplicationScope -PolicyView $policy
        $userScope = Get-PulseCaAllUsersScope -PolicyView $policy -AcceptedExcludedIdentifiers $acceptedExcludedIdentifiers
        $signInScope = Get-PulseCaSignInScope -PolicyView $policy -Mode Legacy
        $record = [pscustomobject]@{
            Policy = $policy
            ApplicationScope = $applicationScope
            UserScope = $userScope
            SignInScope = $signInScope
            BlockRequirement = $blockRequirement
            CollectionOrdinal = $policyOrdinal
        }

        # Retain every policy that could still be a block under the collected shape.
        # Known non-block controls are excluded; future/unknown controls remain candidate
        # evidence instead of being discarded before certainty analysis sees them.
        if ($blockRequirement.State -ne 'NotRequired') {
            if ($policy.state -eq 'enforced') { $enforcedShapePolicies += $policy }
            else { $reportOnlyShapePolicies += $policy }
        }

        if ($blockRequirement.State -eq 'Required' -and $applicationScope.State -eq 'AllResources' -and $userScope.State -eq 'AllIntendedUsers' -and $signInScope.State -eq 'Universal') {
            if ($policy.state -eq 'enforced') { $enforcedBlockPolicies += $record }
            else { $reportOnlyBlockPolicies += $record }
            continue
        }

        # An incomplete dimension can still hide a tenant-wide policy only when the other
        # dimension is not already known Narrow. Preserve that uncertainty rather than
        # manufacturing either a Pass or a known coverage gap.
        if ($policy.state -eq 'enforced' -and
            ($blockRequirement.State -eq 'Incomplete' -or $applicationScope.State -eq 'Incomplete' -or $userScope.State -eq 'Incomplete' -or $signInScope.State -eq 'Incomplete') -and
            $blockRequirement.State -ne 'NotRequired' -and
            $applicationScope.CouldBeAllResources -and $userScope.CouldBeAllUsers -and
            $signInScope.State -ne 'Narrow' -and $signInScope.CouldBeUniversal) {
            $incompleteEnforcedPolicies += $record
        }
    }

    # Honored-exclusion evidence is additive. The accepted identifier set already informed
    # effective user scope above; these rows explain which policy carried each exception.
    # Built once and appended to whichever branch below returns, so the same evidence shape
    # is available on Pass, report-only-Fail, and no-policy-Fail alike.
    $exclusionEvidence = @()
    $malformedAccounts = @($exclusionContext.MalformedDeclaredAccounts)
    # "Declared something" gate (fix-round addition): true when the operator's -Context
    # contributed EITHER a resolvable ExcludedIdentifier or a malformed one - used below to
    # decide whether the malformed-account and group-exclusion-note entries are worth
    # surfacing at all. See this file's own COMPLETENESS FOLD-IN docstring note.
    $hasDeclaredExclusionContext = @($exclusionContext.BreakGlassAccounts).Count -gt 0 -or
        @($exclusionContext.ServiceAccounts).Count -gt 0

    if ($acceptedExcludedIdentifiers.Count -gt 0 -and ($enforcedShapePolicies.Count -gt 0 -or $reportOnlyShapePolicies.Count -gt 0)) {
        foreach ($identifier in $acceptedExcludedIdentifiers) {
            $enforcedNames = @($enforcedShapePolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            $reportOnlyNames = @($reportOnlyShapePolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            if ($enforcedNames.Count -eq 0 -and $reportOnlyNames.Count -eq 0) { continue }
            $detail = @{
                excludedFromEnforcedBlockPolicies   = $enforcedNames
                excludedFromReportOnlyBlockPolicies = $reportOnlyNames
            }
            # MISREADING-RISK FOLD-IN: report-only-ONLY exclusion (never also excluded from
            # an enforced policy) gets an explicit warning - see this file's own docstring.
            if ($reportOnlyNames.Count -gt 0 -and $enforcedNames.Count -eq 0) {
                $detail.reportOnlyProtectionWarning = 'Report-only policies do not protect this account - nothing is actually enforced, so this identity is NOT locked out of legacy authentication by these polic' + $(if ($reportOnlyNames.Count -eq 1) { 'y' } else { 'ies' }) + ' today.'
            }
            $exclusionEvidence += @{
                Identity = $identifier
                SortKey  = "exclusion:$identifier"
                Detail   = $detail
            }
        }
    }

    # COMPLETENESS FOLD-IN: malformed declared accounts can never match ANY policy's
    # excludeUsers (not GUID-shaped), so they are surfaced unconditionally - independent of
    # whether any legacy-auth-block-shaped policy exists at all.
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
    # operator declared some exclusion-relevant context at all - see the "declared
    # something" gate comment above and this file's own docstring for why an empty -Context
    # call does not get this entry (nothing declared, nothing actionable to warn about).
    if ($hasDeclaredExclusionContext -and -not $exclusionContext.GroupExclusionsResolved) {
        $exclusionEvidence += @{
            Identity = 'group-exclusion-resolution'
            SortKey  = 'group-exclusion-resolution'
            Detail   = @{
                note = $exclusionContext.GroupExclusionNote
            }
        }
    }

    $enforcedCoversEas = @($enforcedBlockPolicies | Where-Object { $_.SignInScope.CoversExchangeActiveSync }).Count -gt 0
    $enforcedCoversOther = @($enforcedBlockPolicies | Where-Object { $_.SignInScope.CoversOther }).Count -gt 0
    $missingBuckets = @()
    if (-not $enforcedCoversEas) { $missingBuckets += 'exchangeActiveSync' }
    if (-not $enforcedCoversOther) { $missingBuckets += 'other' }

    if ($missingBuckets.Count -eq 0) {
        $evidence = @($enforcedBlockPolicies | ForEach-Object {
            $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
            @{ Identity = $policyIdentity; Detail = @{
                displayName = $_.Policy.displayName
                coversExchangeActiveSync = $_.SignInScope.CoversExchangeActiveSync
                coversOther = $_.SignInScope.CoversOther
            } }
        }) + $exclusionEvidence
        return New-PulseFinding -Status Pass -Reason "$($enforcedBlockPolicies.Count) enabled Conditional Access polic$(if ($enforcedBlockPolicies.Count -eq 1) { 'y blocks' } else { 'ies collectively block' }) both legacy authentication client buckets." -Evidence $evidence
    }

    $potentialEas = $enforcedCoversEas
    $potentialOther = $enforcedCoversOther
    foreach ($record in $incompleteEnforcedPolicies) {
        if ($record.SignInScope.CouldCoverExchangeActiveSync) { $potentialEas = $true }
        if ($record.SignInScope.CouldCoverOther) { $potentialOther = $true }
    }
    $allMissingCouldBeCovered = $potentialEas -and $potentialOther

    if ($incompleteEnforcedPolicies.Count -gt 0 -and $allMissingCouldBeCovered) {
        $evidence = @($incompleteEnforcedPolicies | ForEach-Object {
            $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
            @{
                Identity = $policyIdentity
                Detail = @{
                    displayName = $_.Policy.displayName
                    applicationScope = $_.ApplicationScope.State
                    applicationScopeReason = $_.ApplicationScope.ReasonCode
                    userScope = $_.UserScope.State
                    userScopeReason = $_.UserScope.ReasonCode
                    signInScope = $_.SignInScope.State
                    signInScopeReason = $_.SignInScope.ReasonCode
                    blockRequirement = $_.BlockRequirement.State
                    blockRequirementReason = $_.BlockRequirement.ReasonCode
                }
            }
        }) + $exclusionEvidence
        return New-PulseFinding -Status NotApplicable -Reason "$($incompleteEnforcedPolicies.Count) enabled legacy-auth block policy/policies could cover every missing legacy client bucket but have incomplete grant, user scope, application scope, or sign-in scope evidence." -Evidence $evidence
    }

    $reportOnlyCoversEas = @($reportOnlyBlockPolicies | Where-Object { $_.SignInScope.CoversExchangeActiveSync }).Count -gt 0
    $reportOnlyCoversOther = @($reportOnlyBlockPolicies | Where-Object { $_.SignInScope.CoversOther }).Count -gt 0
    if ($reportOnlyCoversEas -and $reportOnlyCoversOther) {
        $evidence = @($reportOnlyBlockPolicies | ForEach-Object {
            $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
            @{ Identity = $policyIdentity; Detail = @{ displayName = $_.Policy.displayName; state = 'enabledForReportingButNotEnforced' } }
        }) + $exclusionEvidence
        return New-PulseFinding -Status Fail -Reason "$($reportOnlyBlockPolicies.Count) Conditional Access polic$(if ($reportOnlyBlockPolicies.Count -eq 1) { 'y' } else { 'ies' }) would block legacy authentication but $(if ($reportOnlyBlockPolicies.Count -eq 1) { 'is' } else { 'are' }) still in report-only mode - nothing is actually enforced." -Evidence $evidence
    }

    return New-PulseFinding -Status Fail -Reason "No complete, tenant-wide enforced Conditional Access policy set blocks both legacy client buckets. Definitively uncovered: $($missingBuckets -join ', ')." -Evidence $exclusionEvidence
}
