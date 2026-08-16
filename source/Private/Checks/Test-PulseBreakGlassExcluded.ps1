<#
    Private: TP.ENT.0003 rule function - break-glass accounts exist and are excluded from
    every enabled Conditional Access policy that could actually reach them.

    Consumes the shared Get-PulseCaExclusionContext (Task 1.9 stub) for its
    BreakGlassAccounts list - this check is specifically about the OPERATOR-DECLARED
    emergency-access accounts (an -AssessmentProfile's BreakGlassAccounts, threaded through
    as $Context - see Invoke-PulseEvaluation's own -Context docstring for how a Function
    rule opts in by declaring -Context), not the broader ActiveGlobalAdmins heuristic
    Get-PulseCaExclusionContext also computes (see that function's own docstring for why it
    is named Active, not Permanent).

    Fails closed when no break-glass accounts are declared at all - Microsoft's own
    emergency-access guidance requires at least 2 dedicated, cloud-only accounts excluded
    from every Conditional Access policy; a tenant that has never told TenantPulse which
    accounts those are cannot have this verified, and "unverified" is reported as a finding
    (Fail), not silently skipped.

    ACCOUNT FORMAT CONTRACT (post-review, M2): conditions.users.excludeUsers holds GUID
    principal ids per the Graph schema - a declared BreakGlassAccounts entry that is not
    GUID-shaped (a UPN, a display name, anything else) can never be matched against it, and
    that is a DIFFERENT problem from "genuinely not excluded": it means this check cannot
    resolve the account at all. That case is reported Warn ("cannot resolve format"), not
    Fail - Fail is reserved for a genuine, provable exclusion gap. See the descriptor's own
    Remediation for the GUID requirement stated to the operator.

    INCLUDE-SCOPE EXEMPTION (post-review, M2; narrowed post-review, fail-closed fix): a
    policy whose conditions.users.includeUsers is explicitly scoped (non-empty, and not the
    literal 'All'), does not name the break-glass account, AND has no non-empty
    includeGroups or includeRoles either is exempted from that account's evidence entirely
    (not counted as a gap) - such a policy is PROVABLY unable to apply to the account
    regardless of its excludeUsers list, there is nothing to exclude FROM. The original
    version of this exemption looked at includeUsers alone and was NOT provably correct: a
    policy scoped via includeGroups or includeRoles can still reach the account through
    group or role membership even though includeUsers never names it directly, so a
    non-empty includeGroups/includeRoles now fails closed (treated as reachable, not
    exempted) instead. This function's Reason notes when an exemption applied.

    HONEST LIMITATION: exclusion matching is against conditions.users.excludeUsers only -
    a break-glass account excluded only via GROUP membership (excludeGroups) is not detected
    here and will show as a gap even if it is genuinely protected. This mirrors the read-only,
    no-group-expansion scope of Task 1.9; group-based exclusion resolution is future work.
#>

function Test-PulseBreakGlassExcluded {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $breakGlassAccounts = @($exclusionContext.BreakGlassAccounts)

    if ($breakGlassAccounts.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No break-glass accounts are declared in the assessment profile (BreakGlassAccounts) - emergency access cannot be verified to exist or to be protected from Conditional Access lockout.'
    }

    # Graph principal-id GUID shape, e.g. '11111111-2222-3333-4444-555555555555'.
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $malformedAccounts = @($breakGlassAccounts | Where-Object { $_ -notmatch $guidPattern })
    $resolvableAccounts = @($breakGlassAccounts | Where-Object { $_ -match $guidPattern })

    $enabledPolicies = @($Datasets.conditionalAccessPolicies | Where-Object { $_.state -eq 'enabled' })

    $formatEvidence = @($malformedAccounts | ForEach-Object {
        @{ Identity = $_; Detail = @{ issue = 'cannot resolve format - Conditional Access excludeUsers holds GUID principal ids and this declared value is not GUID-shaped' } }
    })

    $gapEvidence = @()
    $exemptionsApplied = $false
    foreach ($account in $resolvableAccounts) {
        $unexcludedPolicyNames = @()
        foreach ($policy in $enabledPolicies) {
            $includeUsers = @($policy.conditions.users.includeUsers)
            # @($null) is a ONE-element array in PowerShell (containing $null), not an
            # empty one - a policy fixture/live row with no includeGroups/includeRoles
            # member at all (property access on a PSCustomObject returns $null, not a
            # missing-member error) would otherwise wrongly count as "has 1 included
            # group/role" and always fail closed, even when the property is genuinely
            # absent rather than genuinely populated. $null is filtered out explicitly
            # before the @() wrap so only a REAL, non-null entry counts.
            $includeGroupsRaw = $policy.conditions.users.includeGroups
            $includeRolesRaw = $policy.conditions.users.includeRoles
            $includeGroups = if ($null -eq $includeGroupsRaw) { @() } else { @($includeGroupsRaw) }
            $includeRoles = if ($null -eq $includeRolesRaw) { @() } else { @($includeRolesRaw) }
            # Fail-closed fix (post-review): a policy is only PROVABLY unable to reach the
            # account when includeUsers is scoped away from it AND there is no OTHER path
            # (a group or role membership) that could still reach it. The original check
            # only ever looked at includeUsers - a policy scoped to includeGroups (the
            # account is a member of an included group) or includeRoles (the account holds
            # an included role) can still apply to the account even though its own object
            # id never appears in includeUsers, so exempting on includeUsers alone was
            # wrong: it could exempt an account that is genuinely still exposed. Neither
            # group nor role membership is resolved here (see this file's own HONEST
            # LIMITATION note - group-based exclusion resolution is future work), so any
            # non-empty includeGroups/includeRoles means this function cannot PROVE the
            # policy can't reach the account - it fails closed (treated as reachable, so a
            # missing excludeUsers entry still counts as a gap) rather than exempting.
            $policyCanReachAccount = ($includeUsers.Count -eq 0) -or ($includeUsers -contains 'All') -or ($includeUsers -contains $account) -or ($includeGroups.Count -gt 0) -or ($includeRoles.Count -gt 0)
            if (-not $policyCanReachAccount) {
                # Provably cannot cover this account - exempt, not a gap.
                $exemptionsApplied = $true
                continue
            }

            $excludeUsers = @($policy.conditions.users.excludeUsers)
            if ($excludeUsers -notcontains $account) {
                $unexcludedPolicyNames += [string] $policy.displayName
            }
        }

        if ($unexcludedPolicyNames.Count -gt 0) {
            $gapEvidence += @{
                Identity = $account
                Detail   = @{ notExcludedFromPolicies = $unexcludedPolicyNames }
            }
        }
    }

    $allEvidence = @($gapEvidence) + @($formatEvidence)

    if ($gapEvidence.Count -gt 0) {
        $exemptionNote = if ($exemptionsApplied) { ' (some enabled policies were exempted from this count because their own include scope provably cannot reach the account)' } else { '' }
        return New-PulseFinding -Status Fail -Reason "$($gapEvidence.Count) of $($resolvableAccounts.Count) resolvable declared break-glass account(s) are not excluded from at least one enabled Conditional Access policy that can reach them - they could be locked out during an incident.$exemptionNote" -Evidence $allEvidence
    }

    if ($malformedAccounts.Count -gt 0) {
        return New-PulseFinding -Status Warn -Reason "$($malformedAccounts.Count) of $($breakGlassAccounts.Count) declared break-glass account(s) are not GUID-shaped and cannot be resolved against Conditional Access excludeUsers - format cannot be verified. Declare break-glass accounts by their Entra object id (GUID), not UPN or display name." -Evidence $allEvidence
    }

    $exemptionNote = if ($exemptionsApplied) { ' (with some enabled policies exempted because their own include scope provably cannot reach the account)' } else { '' }
    return New-PulseFinding -Status Pass -Reason "$($resolvableAccounts.Count) declared break-glass account(s), all excluded from every enabled Conditional Access policy that can reach them ($($enabledPolicies.Count) checked)$exemptionNote."
}
