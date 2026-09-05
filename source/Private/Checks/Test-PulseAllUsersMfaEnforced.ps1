<#
    Private: TP.ENT.0017 rule function - MFA (or a stronger authentication-strength grant)
    is required for ALL users by an ENFORCED Conditional Access policy (ScuBA MS.AAD.3.2v2,
    SHALL). All-users complement to the already-seeded admin-scoped TP.ENT.0005; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0017.

    Consumes ConvertTo-PulseCaPolicyView (Task 4.1) - never reads a raw policy row's
    conditions/grantControls/state directly, per that function's own docstring.

    REPORT-ONLY VS. ENFORCED TRAP, SAME AS TP.ENT.0004/0005/0016: only view.state -eq
    'enforced' counts. Microsoft auto-deploys several "Require MFA for all users" managed
    policies in report-only by default - a tenant showing the policy "exists" but never
    switched On must Fail, not read as covered.

    EFFECTIVE SCOPE: a policy must explicitly include All users and All resources. Direct
    excludeUsers entries are accepted only when they are canonical D-format GUIDs that
    match the operator-declared break-glass or service-account set returned by
    Get-PulseCaExclusionContext. A parseable noncanonical value is still malformed and can
    never legitimize the same malformed policy exclusion. Undeclared users and all
    group/role exclusions make the policy known Narrow. Application includes/exclusions,
    user actions, and application filters likewise make it Narrow. Missing or malformed
    user/application/sign-in scope is incomplete and never promoted to Pass. Known
    platform, location, risk, device-filter, authentication-flow, or client-app narrowing
    cannot support this universal claim. Whenever an accepted excludeUsers value is used by
    an otherwise-qualifying enforced or report-only policy, structured evidence records the
    identifier and the exact policy names whose universal-user claim depends on it.

    MFA-SATISFACTION: identical shared grant semantics to TP.ENT.0005. Graph's AND/OR
    operator is honored; known built-in MFA-satisfying strengths count, OR alternatives do
    not require MFA, and custom strengths remain indeterminate until their authoritative
    requirementsSatisfied value is available.
#>

function Test-PulseAllUsersMfaEnforced {
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

    $coveringPolicies = @()
    $reportOnlyCoveringPolicies = @()
    $incompleteEnforcedPolicies = @()

    $policyOrdinal = -1
    foreach ($policy in $views) {
        $policyOrdinal++
        if ($policy.state -notin @('enforced', 'reportOnly')) { continue }
        $grant = Get-PulseCaGrantRequirement -PolicyView $policy -Requirement Mfa
        if ($grant.State -eq 'NotRequired') { continue }
        $applicationScope = Get-PulseCaApplicationScope -PolicyView $policy
        $userScope = Get-PulseCaAllUsersScope -PolicyView $policy -AcceptedExcludedIdentifiers $acceptedExcludedIdentifiers
        $signInScope = Get-PulseCaSignInScope -PolicyView $policy -Mode Mfa
        $record = [pscustomobject]@{
            Policy = $policy
            Grant = $grant
            ApplicationScope = $applicationScope
            UserScope = $userScope
            SignInScope = $signInScope
            CollectionOrdinal = $policyOrdinal
        }

        if ($grant.State -eq 'Required' -and $applicationScope.State -eq 'AllResources' -and
            $userScope.State -eq 'AllIntendedUsers' -and $signInScope.State -eq 'Universal') {
            if ($policy.state -eq 'enforced') { $coveringPolicies += $record }
            else { $reportOnlyCoveringPolicies += $record }
            continue
        }

        if ($policy.state -eq 'enforced' -and
            $grant.State -ne 'NotRequired' -and $applicationScope.CouldBeAllResources -and
            $userScope.CouldBeAllUsers -and $signInScope.State -ne 'Narrow' -and $signInScope.CouldBeUniversal -and
            ($grant.State -eq 'Incomplete' -or $applicationScope.State -eq 'Incomplete' -or
                $userScope.State -eq 'Incomplete' -or $signInScope.State -eq 'Incomplete')) {
            $incompleteEnforcedPolicies += $record
        }
    }

    # Accepted exclusions are part of the policy witness, not invisible configuration.
    # Emit one bounded row per accepted identifier and keep enforced/report-only policy
    # names distinct because report-only never establishes protection.
    $acceptedExclusionEvidence = @(
        foreach ($identifier in @($acceptedExcludedIdentifiers)) {
            $enforcedPolicyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $reportOnlyPolicyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

            foreach ($record in @($coveringPolicies)) {
                if (@($record.Policy.conditions.users.excludeUsers) -contains $identifier) {
                    [void] $enforcedPolicyNames.Add([string] $record.Policy.displayName)
                }
            }
            foreach ($record in @($reportOnlyCoveringPolicies)) {
                if (@($record.Policy.conditions.users.excludeUsers) -contains $identifier) {
                    [void] $reportOnlyPolicyNames.Add([string] $record.Policy.displayName)
                }
            }

            [string[]] $enforcedNames = ConvertTo-PulseOrdinalStringArray -Values $enforcedPolicyNames
            [string[]] $reportOnlyNames = ConvertTo-PulseOrdinalStringArray -Values $reportOnlyPolicyNames
            if ($enforcedNames.Count -eq 0 -and $reportOnlyNames.Count -eq 0) { continue }

            @{
                Identity = [string] $identifier
                SortKey  = "accepted-exclusion:$identifier"
                Detail   = @{
                    classification                         = 'accepted-all-users-mfa-exclusion'
                    excludedFromEnforcedMfaPolicies        = $enforcedNames
                    excludedFromReportOnlyMfaPolicies      = $reportOnlyNames
                }
            }
        }
    )
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

    if ($coveringPolicies.Count -eq 0) {
        if ($incompleteEnforcedPolicies.Count -gt 0) {
            $evidence = @($incompleteEnforcedPolicies | ForEach-Object {
                $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
                @{
                    Identity = $policyIdentity
                    Detail = @{
                        displayName = $_.Policy.displayName
                        grantState = $_.Grant.State
                        grantReason = $_.Grant.ReasonCode
                        applicationScope = $_.ApplicationScope.State
                        applicationScopeReason = $_.ApplicationScope.ReasonCode
                        userScope = $_.UserScope.State
                        userScopeReason = $_.UserScope.ReasonCode
                        signInScope = $_.SignInScope.State
                        signInScopeReason = $_.SignInScope.ReasonCode
                    }
                }
            })
            return New-PulseFinding -Status NotApplicable -Reason "$($incompleteEnforcedPolicies.Count) enabled MFA policy/policies have incomplete grant, user scope, application scope, or sign-in scope evidence; TenantPulse cannot determine whether universal coverage exists." -Evidence ($evidence + $acceptedExclusionEvidence + $malformedAccountEvidence)
        }
        if ($reportOnlyCoveringPolicies.Count -gt 0) {
            $evidence = @($reportOnlyCoveringPolicies | ForEach-Object {
                $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
                @{ Identity = $policyIdentity; Detail = @{ displayName = $_.Policy.displayName; state = $_.Policy.state } }
            })
            return New-PulseFinding -Status Fail -Reason "$($reportOnlyCoveringPolicies.Count) all-intended-users, all-resource MFA-requiring Conditional Access policy/policies exist but are report-only, not enforced - report-only is functionally the same as not having the policy." -Evidence ($evidence + $acceptedExclusionEvidence + $malformedAccountEvidence)
        }
        return New-PulseFinding -Status Fail -Reason 'No enabled, enforced Conditional Access policy requires MFA (or a stronger authentication-strength grant) for all intended users across all resources.' -Evidence $malformedAccountEvidence
    }

    $evidence = @($coveringPolicies | ForEach-Object {
        $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $_.Policy -CollectionOrdinal $_.CollectionOrdinal
        @{ Identity = $policyIdentity; Detail = @{ displayName = $_.Policy.displayName; mfaMechanism = $_.Grant.Mechanism } }
    })

    return New-PulseFinding -Status Pass -Reason 'An enabled, enforced Conditional Access policy requires MFA (or a stronger authentication-strength grant) for all intended users across all resources.' -Evidence ($evidence + $acceptedExclusionEvidence + $malformedAccountEvidence)
}
