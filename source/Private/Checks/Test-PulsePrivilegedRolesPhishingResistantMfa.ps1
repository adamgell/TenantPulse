<#
    Private: TP.ENT.0018 rule function - a phishing-resistant authentication STRENGTH
    (not merely generic MFA) is required for Microsoft's documented minimum set of 9
    privileged admin roles by an ENFORCED Conditional Access policy (ScuBA MS.AAD.3.1v1 +
    MS.AAD.3.6v1, both SHALL). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0018.

    DELIBERATELY DISTINCT FROM TP.ENT.0005 (per that check's own research entry Notes - do
    not merge): TP.ENT.0005 accepts EITHER builtInControls 'mfa' OR any bound
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
    therefore NEVER counted toward role coverage - but it is not silently dropped either:
    every such policy is surfaced in evidence (Detail.classification =
    'custom-or-unrecognized-strength'), on both the Pass and Fail path, so an operator
    reviewing the finding sees it and can manually confirm whether it is actually
    phishing-resistant. A tenant relying exclusively on a correctly-built custom
    phishing-resistant strength still reads as a Fail here - a known, documented gap, not a
    silent one.

    ROLE COVERAGE SUBTRACTS EXCLUSIONS (post-review, Medium fix - was a false-Pass bug): an
    includeAll-or-includeRoles policy's own conditions.users.excludeRoles is subtracted
    from what that policy covers before computing the union - a policy that targets "All
    users" (or explicitly includes Global Administrator) but ALSO excludes the Global
    Administrator role template id does NOT cover Global Administrator; the earlier
    implementation ignored excludeRoles entirely and could read a role as covered when an
    enforced policy explicitly carved it back out, a false Pass on this Critical check.
    conditions.users.excludeUsers/excludeGroups are handled the same way TP.ENT.0017
    handles them: not subtracted from ROLE coverage (excluding a specific user does not
    un-cover the ROLE - a different, still-covered admin in that role keeps the role
    covered), but any excluded identifier on a covering policy that is not declared in the
    operator's break-glass/service-account context is surfaced as an informational note in
    Reason, not a Fail - matching TP.ENT.0017's own convention exactly.

    Reuses the same 9-role minimum and role-template-id join TP.ENT.0005 already
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
        [hashtable] $Context = @{}
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
    }

    $builtInPhishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'

    $views = @(@($Datasets.conditionalAccessPolicies) | ConvertTo-PulseCaPolicyView)

    # Classifies a view's bound authenticationStrength (if any): 'none' (no strength
    # bound), 'builtin' (the one documented built-in phishing-resistant strength id), or
    # 'custom' (any other bound id - never auto-trusted, see this file's own CUSTOM
    # STRENGTHS docstring section).
    $classifyStrength = {
        param($view)
        $strength = $view.grants.authenticationStrength
        if ($null -eq $strength -or [string]::IsNullOrEmpty([string] $strength.id)) { return 'none' }
        if ([string] $strength.id -eq $builtInPhishingResistantStrengthId) { return 'builtin' }
        return 'custom'
    }

    $candidatePolicies = @($views | Where-Object {
        $_.state -eq 'enforced' -and (($_.conditions.users.includeRoles.Count -gt 0) -or $_.conditions.users.includeAll)
    })

    $coveringPolicies = @()
    $customStrengthPolicies = @()
    foreach ($policy in $candidatePolicies) {
        $classification = & $classifyStrength $policy
        if ($classification -eq 'builtin') {
            $coveringPolicies += $policy
        } elseif ($classification -eq 'custom') {
            $customStrengthPolicies += $policy
        }
    }

    $coveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $coveringPolicies) {
        $excludeRoles = [System.Collections.Generic.HashSet[string]]::new([string[]] @($policy.conditions.users.excludeRoles), [System.StringComparer]::OrdinalIgnoreCase)

        $grantedRoleIds = if ($policy.conditions.users.includeAll) { @($requiredAdminRoles.Keys) } else { @($policy.conditions.users.includeRoles) }
        foreach ($roleId in $grantedRoleIds) {
            if ($excludeRoles.Contains([string] $roleId)) { continue }
            $coveredRoleIds.Add([string] $roleId) | Out-Null
        }
    }

    $missingRoles = @($requiredAdminRoles.GetEnumerator() | Where-Object { -not $coveredRoleIds.Contains($_.Key) })

    # Undocumented excludeUsers/excludeGroups note - same convention as TP.ENT.0017: never
    # fails the check, just surfaces identifiers excluded from a covering policy that are
    # not in the operator-declared break-glass/service-account context.
    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $documentedExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($exclusionContext.ExcludedIdentifiers)) { $documentedExclusions.Add([string] $id) | Out-Null }
    $undocumentedExclusionCount = 0
    foreach ($policy in $coveringPolicies) {
        foreach ($excludedId in @($policy.conditions.users.excludeUsers)) {
            if (-not $documentedExclusions.Contains([string] $excludedId)) { $undocumentedExclusionCount++ }
        }
    }

    $customEvidence = @($customStrengthPolicies | ForEach-Object {
        @{
            Identity = $_.id
            Detail   = @{
                displayName            = $_.displayName
                classification         = 'custom-or-unrecognized-strength'
                authenticationStrengthId = $_.grants.authenticationStrength.id
                note                   = 'Bound authenticationStrength id is not the documented built-in phishing-resistant strength - not automatically trusted as phishing-resistant; review manually against policies/authenticationStrengthPolicies.'
            }
        }
    })

    if ($missingRoles.Count -eq 0) {
        $evidence = @($coveringPolicies | ForEach-Object { @{ Identity = $_.id; Detail = @{ displayName = $_.displayName; authenticationStrengthId = $_.grants.authenticationStrength.id } } }) + $customEvidence
        $reason = "All 9 of Microsoft's minimum admin roles are covered by an enforced Conditional Access policy requiring the built-in phishing-resistant authentication strength."
        if ($undocumentedExclusionCount -gt 0) {
            $reason += " $undocumentedExclusionCount excluded identifier(s) on the covering policy/policies are not in the operator-declared break-glass/service-account list - confirm those exclusions are intentional."
        }
        if ($customStrengthPolicies.Count -gt 0) {
            $reason += " $($customStrengthPolicies.Count) additional polic$(if ($customStrengthPolicies.Count -eq 1) { 'y binds' } else { 'ies bind' }) a custom/unrecognized authentication strength - not counted toward coverage, see evidence."
        }
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
    }

    $missingEvidence = @($missingRoles | ForEach-Object { @{ Identity = $_.Key; Detail = @{ roleDisplayName = $_.Value } } })
    $reason = "$($missingRoles.Count) of Microsoft's 9 minimum admin roles are not covered by any enforced Conditional Access policy requiring the built-in phishing-resistant authentication strength (generic MFA - builtInControls 'mfa' alone - does not satisfy this check; see TP.ENT.0005 for that lower bar)."
    if ($customStrengthPolicies.Count -gt 0) {
        $reason += " $($customStrengthPolicies.Count) polic$(if ($customStrengthPolicies.Count -eq 1) { 'y binds' } else { 'ies bind' }) a custom/unrecognized authentication strength - not counted toward coverage without manual verification, see evidence."
    }
    return New-PulseFinding -Status Fail -Reason $reason -Evidence ($missingEvidence + $customEvidence)
}
