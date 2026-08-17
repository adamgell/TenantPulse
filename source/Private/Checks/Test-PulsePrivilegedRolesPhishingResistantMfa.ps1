<#
    Private: TP.ENT.0018 rule function - a phishing-resistant authentication STRENGTH
    (not merely generic MFA) is required for Microsoft's documented minimum set of 9
    privileged admin roles by an ENFORCED Conditional Access policy (ScuBA MS.AAD.3.1v1 +
    MS.AAD.3.6v1, both SHALL). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0018.

    DELIBERATELY DISTINCT FROM TP.ENT.0005 (per that check's own research entry Notes - do
    not merge): TP.ENT.0005 accepts EITHER builtInControls 'mfa' OR any bound
    authenticationStrength as satisfying "MFA required". THIS check accepts ONLY a bound
    authenticationStrength whose id is one of the built-in phishing-resistant-capable
    strengths - builtInControls 'mfa' alone (which still permits SMS/voice/TOTP as the
    second factor) never satisfies this, higher, bar. A tenant can pass TP.ENT.0005 while
    failing this check; that divergence is the whole point of keeping both checks.

    BUILT-IN STRENGTH IDS (Microsoft-documented, stable across every Entra tenant - see this
    check's own References.Authorities):
        '00000000-0000-0000-0000-000000000004' - "Phishing-resistant MFA" (FIDO2, Windows
                                                    Hello for Business, certificate-based
                                                    auth multifactor)
        '00000000-0000-0000-0000-000000000005' - "Phishing-resistant MFA strength" variant
                                                    some tenants see for certificate-based
                                                    auth (single-factor, still
                                                    phishing-resistant) - included as an
                                                    honest, documented allow-list entry
                                                    rather than silently narrowing to just
                                                    the first id.
    HONEST LIMITATION: a tenant-DEFINED custom authentication strength built from
    phishing-resistant combinations (FIDO2/certificate-based/Windows Hello) has its own,
    non-well-known id - this check cannot recognize a custom strength without resolving it
    against `v1.0/policies/authenticationStrengthPolicies` (the research entry's own
    Entra.AuthenticationStrengths.List candidate descriptor), which is not wired into this
    check's Data.Datasets. A tenant relying exclusively on a correctly-built custom
    phishing-resistant strength will read as a Fail here - a known, documented gap, not a
    silent one. Future work: resolve custom strength ids the same way
    ConvertTo-PulseCaPolicyView's own -Context.AuthenticationStrengthDisplayNames mechanism
    already anticipates for DISPLAY NAMES (it does not currently attempt to classify a
    custom strength's underlying allowedCombinations as phishing-resistant).

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
        [hashtable] $Datasets
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

    $phishingResistantStrengthIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000005')) {
        $phishingResistantStrengthIds.Add($id) | Out-Null
    }

    $views = @(@($Datasets.conditionalAccessPolicies) | ConvertTo-PulseCaPolicyView)

    $isPhishingResistant = {
        param($view)
        $strength = $view.grants.authenticationStrength
        if ($null -eq $strength -or [string]::IsNullOrEmpty([string] $strength.id)) { return $false }
        return $phishingResistantStrengthIds.Contains([string] $strength.id)
    }

    $coveringPolicies = @($views | Where-Object {
        $_.state -eq 'enforced' -and (& $isPhishingResistant $_) -and (($_.conditions.users.includeRoles.Count -gt 0) -or $_.conditions.users.includeAll)
    })

    $coveredRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $coveringPolicies) {
        if ($policy.conditions.users.includeAll) {
            foreach ($roleId in $requiredAdminRoles.Keys) { $coveredRoleIds.Add([string] $roleId) | Out-Null }
            continue
        }
        foreach ($roleId in @($policy.conditions.users.includeRoles)) {
            $coveredRoleIds.Add([string] $roleId) | Out-Null
        }
    }

    $missingRoles = @($requiredAdminRoles.GetEnumerator() | Where-Object { -not $coveredRoleIds.Contains($_.Key) })

    if ($missingRoles.Count -eq 0) {
        $evidence = @($coveringPolicies | ForEach-Object { @{ Identity = $_.id; Detail = @{ displayName = $_.displayName; authenticationStrengthId = $_.grants.authenticationStrength.id } } })
        return New-PulseFinding -Status Pass -Reason "All 9 of Microsoft's minimum admin roles are covered by an enforced Conditional Access policy requiring a phishing-resistant authentication strength." -Evidence $evidence
    }

    $evidence = @($missingRoles | ForEach-Object { @{ Identity = $_.Key; Detail = @{ roleDisplayName = $_.Value } } })
    return New-PulseFinding -Status Fail -Reason "$($missingRoles.Count) of Microsoft's 9 minimum admin roles are not covered by any enforced Conditional Access policy requiring a phishing-resistant authentication strength (generic MFA - builtInControls 'mfa' alone - does not satisfy this check; see TP.ENT.0005 for that lower bar)." -Evidence $evidence
}
