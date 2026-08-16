<#
    Private: TP.ENT.0005 rule function - MFA is required for admin roles by an ENFORCED
    Conditional Access policy.

    The 9-role minimum is Microsoft's own documented floor (how-to-policy-phish-resistant-
    admin-mfa - see this check's References.Authorities): Global Administrator, Application
    Administrator, Authentication Administrator, Billing Administrator, Cloud Application
    Administrator, Conditional Access Administrator, Exchange Administrator, Helpdesk
    Administrator, Password Administrator. Role coverage is checked by TEMPLATE ID (stable
    across every Entra tenant, documented by Microsoft), not by display name - a renamed or
    localized role name can never mask coverage.

    Coverage is computed as the UNION of includeRoles across every ENABLED policy whose
    grantControls require MFA - an organization commonly splits "MFA for admins" across more
    than one policy (e.g. one for cloud apps, one for Azure management), and this check does
    not penalize that split as long as every one of the 9 roles is covered by AT LEAST one
    of them. Report-only-only coverage (no enabled policy covers a role at all) is reported
    as a gap, same distinction TP.ENT.0004 makes for legacy auth.

    MFA-SATISFACTION (post-review, H1 adjudicated): a policy satisfies "requires MFA" when
    EITHER grantControls.builtInControls contains 'mfa' OR grantControls.authenticationStrength
    is bound (non-null) - Microsoft's own phishing-resistant admin MFA template (this check's
    own primary cited authority) configures authenticationStrength, not builtInControls
    'mfa'. The original builtInControls-only check meant a tenant that followed Microsoft's
    recommended template to the letter FAILED this check. Evidence records which mechanism
    satisfied each covering policy.

    HONEST LIMITATION: this checks includeRoles coverage only - conditions.users.excludeRoles
    or excludeUsers narrowing a policy back down for a specific admin is not reconciled here;
    a role "covered" by includeRoles that is then carved back out by an exclusion would still
    read as covered. Future work, same class of limitation as TP.ENT.0003's group-exclusion
    gap.
#>

function Test-PulseAdminMfaEnforced {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    # Microsoft's well-known, tenant-stable role template ids for the 9 named roles - see
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
    }

    $allPolicies = @($Datasets.conditionalAccessPolicies)

    # Which MFA mechanism (if any) a policy satisfies - $null when neither is present.
    $getMfaMechanism = {
        param($policy)
        $builtInControls = @($policy.grantControls.builtInControls)
        if ($builtInControls -contains 'mfa') {
            return 'builtInControls:mfa'
        }
        if ($null -ne $policy.grantControls.authenticationStrength) {
            return 'authenticationStrength'
        }
        return $null
    }

    # 'All' COVERS ADMINS BY DEFINITION (post-review fix): in Entra Conditional Access
    # policy semantics, conditions.users.includeUsers = @('All') means every user in the
    # tenant, admins included - there is no way to be an admin role member and NOT be
    # covered by an 'All' policy. The original shape check only ever looked at
    # includeRoles, so a tenant-wide MFA policy scoped via includeUsers='All' (a very
    # common, arguably STRONGER pattern than role-scoping) was not counted toward admin MFA
    # coverage at all - a false Fail against a tenant doing the right thing.
    $isMfaForRolesShape = {
        param($policy)
        $mechanism = & $getMfaMechanism $policy
        $includeRoles = @($policy.conditions.users.includeRoles)
        $includeUsers = @($policy.conditions.users.includeUsers)
        $coversAllUsers = $includeUsers -contains 'All'
        return ($null -ne $mechanism) -and (($includeRoles.Count -gt 0) -or $coversAllUsers)
    }

    $enabledMfaPolicies = @($allPolicies | Where-Object { $_.state -eq 'enabled' -and (& $isMfaForRolesShape $_) })

    $coveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $enabledMfaPolicies) {
        $includeUsers = @($policy.conditions.users.includeUsers)
        if ($includeUsers -contains 'All') {
            # Covers every one of the 9 required roles by definition - see the docstring
            # note above.
            foreach ($roleId in $requiredAdminRoles.Keys) {
                $coveredRoleIds.Add([string] $roleId) | Out-Null
            }
            continue
        }

        foreach ($roleId in @($policy.conditions.users.includeRoles)) {
            $coveredRoleIds.Add([string] $roleId) | Out-Null
        }
    }

    $missingRoles = @($requiredAdminRoles.GetEnumerator() | Where-Object { -not $coveredRoleIds.Contains($_.Key) })

    if ($missingRoles.Count -eq 0) {
        $evidence = @($enabledMfaPolicies | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName; mfaMechanism = (& $getMfaMechanism $_) } } })
        return New-PulseFinding -Status Pass -Reason "All 9 of Microsoft's minimum admin roles are covered by MFA-requiring, enabled Conditional Access polic$(if ($enabledMfaPolicies.Count -eq 1) { 'y' } else { 'ies' })." -Evidence $evidence
    }

    $evidence = @($missingRoles | ForEach-Object { @{ Identity = $_.Key; Detail = @{ roleDisplayName = $_.Value } } })
    return New-PulseFinding -Status Fail -Reason "$($missingRoles.Count) of Microsoft's 9 minimum admin roles are not covered by any enabled, MFA-requiring Conditional Access policy." -Evidence $evidence
}
