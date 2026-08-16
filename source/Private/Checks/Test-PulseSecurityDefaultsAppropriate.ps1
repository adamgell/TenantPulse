<#
    Private: TP.ENT.0001 rule function - Security Defaults state is appropriate.

    Security Defaults (identitySecurityDefaultsEnforcementPolicy) is Microsoft's free,
    all-or-nothing baseline identity protection - the fallback for tenants without
    Conditional Access (which needs Entra ID P1). Once even one Conditional Access policy
    is enabled, Security Defaults stops being the tenant's meaningful control (Microsoft
    recommends turning it off once CA takes over the same ground) - this check reports Pass
    with an explanatory Reason in that case rather than judging the isEnabled flag at all,
    because it is no longer the control that matters. ENGINE CONSTRAINT: a Function rule can
    only return Pass/Warn/Fail (Invoke-PulseEvaluation), not NotApplicable - "CA supersedes
    Security Defaults" is therefore represented as Pass-with-Reason, the closest available
    status, not a true NA. This is a deliberate, documented approximation, not an oversight.

    FIELD-ABSENCE LENS: if no Conditional Access policy is enabled, securityDefaultsPolicy
    (SecurityDefaultsPolicy.Get, still Pending as of GraphKit's current release - see
    DatasetMap.psd1) must actually carry an isEnabled value to judge - an absent/null value
    throws (-> engine Error), never silently reads as Pass or Fail. A genuinely empty
    conditionalAccessPolicies collection (no CA licensed/configured at all) is a normal,
    expected shape, not an absence bug - it participates in enabledCaCount = 0 like any
    other real "zero policies" tenant.
#>

function Test-PulseSecurityDefaultsAppropriate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $caPolicies = @($Datasets.conditionalAccessPolicies)
    $enabledCaPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' })

    if ($enabledCaPolicies.Count -gt 0) {
        $noun = if ($enabledCaPolicies.Count -eq 1) { 'policy' } else { 'policies' }
        return New-PulseFinding -Status Pass -Reason "Conditional Access is in use ($($enabledCaPolicies.Count) enabled $noun); Security Defaults is no longer the tenant's primary access-control layer and is not evaluated as a standalone control here."
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
