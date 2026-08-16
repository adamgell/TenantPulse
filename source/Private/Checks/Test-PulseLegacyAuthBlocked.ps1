<#
    Private: TP.ENT.0004 rule function - legacy authentication is blocked by an ENFORCED
    Conditional Access policy.

    "Enforced" is the load-bearing word: Rule.State must be exactly 'enabled' - a policy in
    'enabledForReportingButNotEnforced' (report-only) proves nothing is actually blocked,
    only that Microsoft's own managed-policies feature (or an operator) staged it. This
    check distinguishes those two outcomes in its Reason so an operator sees "you have a
    policy, it just isn't turned on" rather than "you have nothing".

    Legacy-auth-blocking shape: conditions.clientAppTypes includes 'exchangeActiveSync' or
    'other' (the two client app types basic/legacy auth protocols present as), and
    grantControls.builtInControls includes 'block'.
#>

function Test-PulseLegacyAuthBlocked {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $allPolicies = @($Datasets.conditionalAccessPolicies)

    $isLegacyAuthBlockShape = {
        param($policy)
        $clientAppTypes = @($policy.conditions.clientAppTypes)
        $builtInControls = @($policy.grantControls.builtInControls)
        return (($clientAppTypes -contains 'exchangeActiveSync') -or ($clientAppTypes -contains 'other')) -and ($builtInControls -contains 'block')
    }

    $enforcedBlockPolicies = @($allPolicies | Where-Object { $_.state -eq 'enabled' -and (& $isLegacyAuthBlockShape $_) })

    if ($enforcedBlockPolicies.Count -gt 0) {
        $evidence = @($enforcedBlockPolicies | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName } } })
        return New-PulseFinding -Status Pass -Reason "$($enforcedBlockPolicies.Count) enabled Conditional Access polic$(if ($enforcedBlockPolicies.Count -eq 1) { 'y blocks' } else { 'ies block' }) legacy authentication." -Evidence $evidence
    }

    $reportOnlyBlockPolicies = @($allPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and (& $isLegacyAuthBlockShape $_) })

    if ($reportOnlyBlockPolicies.Count -gt 0) {
        $evidence = @($reportOnlyBlockPolicies | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName; state = 'enabledForReportingButNotEnforced' } } })
        return New-PulseFinding -Status Fail -Reason "$($reportOnlyBlockPolicies.Count) Conditional Access polic$(if ($reportOnlyBlockPolicies.Count -eq 1) { 'y' } else { 'ies' }) would block legacy authentication but $(if ($reportOnlyBlockPolicies.Count -eq 1) { 'is' } else { 'are' }) still in report-only mode - nothing is actually enforced." -Evidence $evidence
    }

    return New-PulseFinding -Status Fail -Reason 'No Conditional Access policy blocks legacy authentication protocols, enforced or report-only.'
}
