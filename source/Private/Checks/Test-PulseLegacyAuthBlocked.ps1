<#
    Private: TP.ENT.0004 rule function - legacy authentication is blocked by an ENFORCED
    Conditional Access policy.

    "Enforced" is the load-bearing word: Rule.State must be exactly 'enabled' - a policy in
    'enabledForReportingButNotEnforced' (report-only) proves nothing is actually blocked,
    only that Microsoft's own managed-policies feature (or an operator) staged it. This
    check distinguishes those two outcomes in its Reason so an operator sees "you have a
    policy, it just isn't turned on" rather than "you have nothing".

    Legacy-auth-blocking shape: conditions.clientAppTypes includes 'exchangeActiveSync',
    'other' (the two client app types basic/legacy auth protocols present as), or 'all'
    (post-review, L1 - a policy scoped to every client app type necessarily covers legacy
    protocols too; it should not be treated as silently missing that coverage just because
    it was not itemized), and grantControls.builtInControls includes 'block'.

    EXCLUSION-CONTEXT WIRING (Task 3.5): consumes Get-PulseCaExclusionContext for
    ExcludedIdentifiers (BreakGlassAccounts/ServiceAccounts declared in -Context, plus
    ActiveGlobalAdmins/ResolvedGroupExclusions when their backing datasets happen to be
    present - see that function's own docstring). This is EVIDENCE ONLY, never a Status
    input: an identity excluded from the legacy-auth block is not itself a finding here (a
    service account still legitimately using a legacy protocol is a common, deliberate
    reason to exclude it), so exclusion honoring never changes Pass/Fail. For every declared
    ExcludedIdentifier, evidence records which of the policies THIS check evaluated (the
    legacy-auth-block-shaped ones) actually name it in excludeUsers, split by
    excludedFromEnforcedBlockPolicies vs. excludedFromReportOnlyBlockPolicies - REPORT-ONLY
    EXCLUSION NEVER COUNTS AS HONORED PROTECTION (same enforced-vs-report-only binding this
    check already applies to the block itself), it is surfaced only so an operator can see
    declared intent that a report-only policy has not yet made real. Only
    'conditionalAccessPolicies' is declared in this check's own Data.Datasets (unchanged by
    this wiring) - -Datasets.directoryRoleAssignments is therefore never present here, so
    ActiveGlobalAdmins is always empty for this check; that absence is read defensively by
    Get-PulseCaExclusionContext itself (field-absence, not a failure) rather than by adding
    a new required dataset that would degrade this check to NotApplicable in any tenant
    collection that never gathered directoryRoleAssignments.
#>

function Test-PulseLegacyAuthBlocked {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $allPolicies = @($Datasets.conditionalAccessPolicies)

    $isLegacyAuthBlockShape = {
        param($policy)
        $clientAppTypes = @($policy.conditions.clientAppTypes)
        $builtInControls = @($policy.grantControls.builtInControls)
        return (($clientAppTypes -contains 'exchangeActiveSync') -or ($clientAppTypes -contains 'other') -or ($clientAppTypes -contains 'all')) -and ($builtInControls -contains 'block')
    }

    $enforcedBlockPolicies = @($allPolicies | Where-Object { $_.state -eq 'enabled' -and (& $isLegacyAuthBlockShape $_) })
    $reportOnlyBlockPolicies = @($allPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and (& $isLegacyAuthBlockShape $_) })

    # Honored-exclusion evidence (additive, never a Status input - see docstring above).
    # Built once and appended to whichever branch below returns, so the same evidence shape
    # is available on Pass, report-only-Fail, and no-policy-Fail alike.
    $exclusionEvidence = @()
    $exclusionContext = Get-PulseCaExclusionContext -Context $Context -Datasets $Datasets
    $excludedIdentifiers = @($exclusionContext.ExcludedIdentifiers)
    if ($excludedIdentifiers.Count -gt 0 -and ($enforcedBlockPolicies.Count -gt 0 -or $reportOnlyBlockPolicies.Count -gt 0)) {
        foreach ($identifier in $excludedIdentifiers) {
            $enforcedNames = @($enforcedBlockPolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            $reportOnlyNames = @($reportOnlyBlockPolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            if ($enforcedNames.Count -eq 0 -and $reportOnlyNames.Count -eq 0) { continue }
            $exclusionEvidence += @{
                Identity = $identifier
                SortKey  = "exclusion:$identifier"
                Detail   = @{
                    excludedFromEnforcedBlockPolicies   = $enforcedNames
                    excludedFromReportOnlyBlockPolicies = $reportOnlyNames
                }
            }
        }
    }

    if ($enforcedBlockPolicies.Count -gt 0) {
        $evidence = @($enforcedBlockPolicies | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName } } }) + $exclusionEvidence
        return New-PulseFinding -Status Pass -Reason "$($enforcedBlockPolicies.Count) enabled Conditional Access polic$(if ($enforcedBlockPolicies.Count -eq 1) { 'y blocks' } else { 'ies block' }) legacy authentication." -Evidence $evidence
    }

    if ($reportOnlyBlockPolicies.Count -gt 0) {
        $evidence = @($reportOnlyBlockPolicies | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName; state = 'enabledForReportingButNotEnforced' } } }) + $exclusionEvidence
        return New-PulseFinding -Status Fail -Reason "$($reportOnlyBlockPolicies.Count) Conditional Access polic$(if ($reportOnlyBlockPolicies.Count -eq 1) { 'y' } else { 'ies' }) would block legacy authentication but $(if ($reportOnlyBlockPolicies.Count -eq 1) { 'is' } else { 'are' }) still in report-only mode - nothing is actually enforced." -Evidence $evidence
    }

    return New-PulseFinding -Status Fail -Reason 'No Conditional Access policy blocks legacy authentication protocols, enforced or report-only.'
}
