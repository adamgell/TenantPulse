<#
    Private: TP.ENT.0001 rule function - Security Defaults state is appropriate.

    Security Defaults (identitySecurityDefaultsEnforcementPolicy) is Microsoft's free,
    all-or-nothing baseline identity protection - the fallback for tenants without
    Conditional Access (which needs Entra ID P1). Once even one Conditional Access policy
    is enabled, Security Defaults stops being the tenant's meaningful control (Microsoft
    recommends turning it off once CA takes over the same ground).

    POST-REVIEW FIX (adjudicated): this used to report Pass-with-a-caveat-Reason when CA
    supersedes Security Defaults, because a Function rule could not return NotApplicable at
    all. Now that it can (see New-PulseFinding's own docstring), that case returns
    NotApplicable instead - Pass-with-Reason silently earned this check's full scoring
    weight for every CA tenant regardless of whether Security Defaults itself was even
    configured sanely, which inflated the score with credit nobody actually verified.
    NotApplicable is scored correctly by Add-PulseScores: excluded from both earned and
    possible, not quietly counted as a pass.

    FIELD-ABSENCE LENS (two places, both enforced, the second one closed by this same
    review pass - it had been missed originally):
      - securityDefaultsPolicy.isEnabled: an absent/null value throws (-> engine Error),
        never silently reads as Pass or Fail.
      - conditionalAccessPolicies[].state: an absent/null value ALSO throws now - a CA
        policy with no recorded state is not "not enabled" (which would silently undercount
        enabledCaPolicies and could tip a CA-protected tenant into a spurious Fail), it is
        data this check cannot honestly reason about at all.
    A genuinely empty conditionalAccessPolicies collection (no CA licensed/configured at
    all) is a normal, expected shape, not an absence bug - it participates in
    enabledCaCount = 0 like any other real "zero policies" tenant.
#>

function Test-PulseSecurityDefaultsAppropriate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $caPolicies = @($Datasets.conditionalAccessPolicies)

    foreach ($policy in $caPolicies) {
        if ($null -eq $policy.state -or [string]::IsNullOrEmpty([string] $policy.state)) {
            throw "conditionalAccessPolicies entry '$($policy.id)' has no state value - an absent state must never silently read as not-enabled."
        }
    }

    $enabledCaPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' })

    if ($enabledCaPolicies.Count -gt 0) {
        $noun = if ($enabledCaPolicies.Count -eq 1) { 'policy' } else { 'policies' }
        return New-PulseFinding -Status NotApplicable -Reason "Conditional Access is in use ($($enabledCaPolicies.Count) enabled $noun); Security Defaults is no longer the tenant's primary access-control layer and is not evaluated as a standalone control here."
    }

    $securityDefaultsRows = @($Datasets.securityDefaultsPolicy)
    if ($securityDefaultsRows.Count -eq 0) {
        throw 'securityDefaultsPolicy dataset returned no rows - the service returned no Security Defaults state to evaluate.'
    }

    $isEnabled = $securityDefaultsRows[0].isEnabled
    if ($null -eq $isEnabled) {
        throw "securityDefaultsPolicy returned no isEnabled value - check the operation's response shape survived collection."
    }

    if ([bool] $isEnabled) {
        return New-PulseFinding -Status Pass -Reason 'Security Defaults is enabled and no Conditional Access policies are in use - the tenant has a baseline identity-protection control.'
    }

    return New-PulseFinding -Status Fail -Reason 'Security Defaults is disabled and no Conditional Access policies are enabled - the tenant has no baseline identity protection at all (no MFA enforcement, no legacy-auth block).' -Evidence @(
        @{ Identity = 'tenant-security-defaults'; Detail = @{ isEnabled = $false; enabledConditionalAccessPolicyCount = 0 } }
    )
}
