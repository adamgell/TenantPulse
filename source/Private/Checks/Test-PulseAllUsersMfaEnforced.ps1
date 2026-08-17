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

    ALL-USERS SHAPE: a policy counts as "targets all users" when
    conditions.users.includeAll is true (ConvertTo-PulseCaPolicyView's own normalized
    includeUsers -contains 'All' flag) - role-scoped or group-scoped policies (even a very
    broad group) do not satisfy this check; that is TP.ENT.0005's job, not this one's. A
    policy's own conditions.users.excludeUsers/excludeGroups is expected content for a
    genuinely all-users policy (break-glass/service-account exclusions), not disqualifying -
    the shared exclusion context (Get-PulseCaExclusionContext, Task 4.1) is consulted so a
    documented break-glass/service-account exclusion never registers as a coverage gap by
    itself; an UNDOCUMENTED excluded identifier is surfaced as a Warn-tier note in Reason,
    not a Fail, since this check's job is "does an enforced all-users MFA policy exist", not
    re-litigating TP.ENT.0003's own exclusion-hygiene job.

    MFA-SATISFACTION: identical mechanism union to TP.ENT.0005 - grants.builtInControls
    contains 'mfa' OR grants.authenticationStrength is bound (any authentication strength,
    not only phishing-resistant - the phishing-resistant BAR specifically is TP.ENT.0018's
    job, not this one's; do not merge, per that check's own research entry Notes).
#>

function Test-PulseAllUsersMfaEnforced {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $views = @(@($Datasets.conditionalAccessPolicies) | ConvertTo-PulseCaPolicyView)
    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $documentedExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($exclusionContext.ExcludedIdentifiers)) {
        $documentedExclusions.Add([string] $id) | Out-Null
    }

    $satisfiesMfa = {
        param($view)
        if (@($view.grants.builtInControls) -contains 'mfa') { return $true }
        if ($null -ne $view.grants.authenticationStrength -and -not [string]::IsNullOrEmpty([string] $view.grants.authenticationStrength.id)) { return $true }
        return $false
    }

    $coveringPolicies = @($views | Where-Object {
        $_.state -eq 'enforced' -and $_.conditions.users.includeAll -and (& $satisfiesMfa $_)
    })

    if ($coveringPolicies.Count -eq 0) {
        $reportOnlyCandidates = @($views | Where-Object {
            $_.state -eq 'reportOnly' -and $_.conditions.users.includeAll -and (& $satisfiesMfa $_)
        })
        if ($reportOnlyCandidates.Count -gt 0) {
            $evidence = @($reportOnlyCandidates | ForEach-Object { @{ Identity = $_.id; Detail = @{ displayName = $_.displayName; state = $_.state } } })
            return New-PulseFinding -Status Fail -Reason "$($reportOnlyCandidates.Count) all-users MFA-requiring Conditional Access policy/policies exist but are report-only, not enforced - report-only is functionally the same as not having the policy." -Evidence $evidence
        }
        return New-PulseFinding -Status Fail -Reason 'No enabled, enforced Conditional Access policy requires MFA (or a stronger authentication-strength grant) for all users.'
    }

    $undocumented = @()
    foreach ($policy in $coveringPolicies) {
        $excludeUsers = @($policy.conditions.users.excludeUsers)
        foreach ($excludedId in $excludeUsers) {
            if (-not $documentedExclusions.Contains([string] $excludedId)) {
                $undocumented += [pscustomobject]@{ PolicyId = $policy.id; ExcludedId = $excludedId }
            }
        }
    }

    $evidence = @($coveringPolicies | ForEach-Object {
        @{ Identity = $_.id; Detail = @{ displayName = $_.displayName; mfaMechanism = if (@($_.grants.builtInControls) -contains 'mfa') { 'builtInControls:mfa' } else { 'authenticationStrength' } } }
    })

    if ($undocumented.Count -gt 0) {
        return New-PulseFinding -Status Pass -Reason "An enabled, enforced Conditional Access policy requires MFA for all users; $($undocumented.Count) excluded identifier(s) on the covering policy/policies are not in the operator-declared break-glass/service-account list - confirm those exclusions are intentional." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'An enabled, enforced Conditional Access policy requires MFA (or a stronger authentication-strength grant) for all users.' -Evidence $evidence
}
