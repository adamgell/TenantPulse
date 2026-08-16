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

    $isMfaForRolesShape = {
        param($policy)
        $builtInControls = @($policy.grantControls.builtInControls)
        $includeRoles = @($policy.conditions.users.includeRoles)
        return ($builtInControls -contains 'mfa') -and ($includeRoles.Count -gt 0)
    }

    $enabledMfaPolicies = @($allPolicies | Where-Object { $_.state -eq 'enabled' -and (& $isMfaForRolesShape $_) })

    $coveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $enabledMfaPolicies) {
        foreach ($roleId in @($policy.conditions.users.includeRoles)) {
            $coveredRoleIds.Add([string] $roleId) | Out-Null
        }
    }

    $missingRoles = @($requiredAdminRoles.GetEnumerator() | Where-Object { -not $coveredRoleIds.Contains($_.Key) })

    if ($missingRoles.Count -eq 0) {
        $evidence = @($enabledMfaPolicies | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName } } })
        return New-PulseFinding -Status Pass -Reason "All 9 of Microsoft's minimum admin roles are covered by MFA-requiring, enabled Conditional Access polic$(if ($enabledMfaPolicies.Count -eq 1) { 'y' } else { 'ies' })." -Evidence $evidence
    }

    $evidence = @($missingRoles | ForEach-Object { @{ Identity = $_.Key; Detail = @{ roleDisplayName = $_.Value } } })
    return New-PulseFinding -Status Fail -Reason "$($missingRoles.Count) of Microsoft's 9 minimum admin roles are not covered by any enabled, MFA-requiring Conditional Access policy." -Evidence $evidence
}
