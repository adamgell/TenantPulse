<#
    Private: TP.ENT.0003 rule function - break-glass accounts exist and are excluded from
    every enabled Conditional Access policy.

    Consumes the shared Get-PulseCaExclusionContext (Task 1.9 stub) for its
    BreakGlassAccounts list - this check is specifically about the OPERATOR-DECLARED
    emergency-access accounts (an -AssessmentProfile's BreakGlassAccounts, threaded through
    as $Context - see Invoke-PulseEvaluation's own -Context docstring for how a Function
    rule opts in by declaring -Context), not the broader permanent-Global-Administrator
    heuristic Get-PulseCaExclusionContext also computes (that heuristic is for TP.ENT.0004/
    0005 to reason about who else is exempt, not for THIS check's core assertion).

    Fails closed when no break-glass accounts are declared at all - Microsoft's own
    emergency-access guidance requires at least 2 dedicated, cloud-only accounts excluded
    from every Conditional Access policy; a tenant that has never told TenantPulse which
    accounts those are cannot have this verified, and "unverified" is reported as a finding
    (Fail), not silently skipped.

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

    $enabledPolicies = @($Datasets.conditionalAccessPolicies | Where-Object { $_.state -eq 'enabled' })

    $evidence = @()
    foreach ($account in $breakGlassAccounts) {
        $unexcludedPolicyNames = @()
        foreach ($policy in $enabledPolicies) {
            $excludeUsers = @($policy.conditions.users.excludeUsers)
            if ($excludeUsers -notcontains $account) {
                $unexcludedPolicyNames += [string] $policy.displayName
            }
        }

        if ($unexcludedPolicyNames.Count -gt 0) {
            $evidence += @{
                Identity = $account
                Detail   = @{ notExcludedFromPolicies = $unexcludedPolicyNames }
            }
        }
    }

    if ($evidence.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason "$($evidence.Count) of $($breakGlassAccounts.Count) declared break-glass account(s) are not excluded from at least one enabled Conditional Access policy - they could be locked out during an incident." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "$($breakGlassAccounts.Count) declared break-glass account(s), all excluded from every enabled Conditional Access policy ($($enabledPolicies.Count) checked)."
}
