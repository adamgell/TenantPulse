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

    COMPLETENESS FOLD-IN (dual review, fix round): the first cut of this wiring silently
    dropped two of Get-PulseCaExclusionContext's own "never silently dropped" fields -
    MalformedDeclaredAccounts (a declared identifier that can never match ANY policy's
    excludeUsers, GUID-shape mismatch) and GroupExclusionNote (set whenever
    GroupExclusionsResolved is $false) were never read, so a malformed declared account left
    zero evidence trace here even though the shared context function's own contract says it
    is always enumerated for a caller that cares. Fixed: every malformed declared account
    gets its own evidence entry UNCONDITIONALLY when the list is non-empty (independent of
    whether any legacy-auth-block-shaped policy exists at all - a malformed identifier can
    never match one regardless), and a single group-exclusion-resolution note entry is added
    whenever GroupExclusionsResolved is $false AND the operator declared some exclusion-
    relevant context at all (a resolvable ExcludedIdentifier or a malformed account) - gating
    on "declared something" keeps the zero-Context call shape (most existing tests, and any
    caller that never opts into -Context) producing byte-identical evidence to before this
    fix, since telling an operator who declared nothing that "group exclusions aren't
    resolved" has no action to attach to.

    MISREADING-RISK FOLD-IN (dual review, fix round): an identity excluded ONLY from a
    report-only-shaped policy (never from any enforced one) now carries an explicit
    reportOnlyProtectionWarning message on its evidence entry, mirroring
    Get-PulseCaExclusionContext's own ENFORCED VS. REPORT-ONLY docstring warning - a
    skimming operator who sees "excludedFromReportOnlyBlockPolicies: [...]" without reading
    the field name closely could otherwise misread "excluded" as "safe." The warning is
    omitted when the identity is ALSO excluded from at least one enforced policy (genuinely
    honored there already, nothing to warn about).
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
    $malformedAccounts = @($exclusionContext.MalformedDeclaredAccounts)
    # "Declared something" gate (fix-round addition): true when the operator's -Context
    # contributed EITHER a resolvable ExcludedIdentifier or a malformed one - used below to
    # decide whether the malformed-account and group-exclusion-note entries are worth
    # surfacing at all. See this file's own COMPLETENESS FOLD-IN docstring note.
    $hasDeclaredExclusionContext = ($excludedIdentifiers.Count -gt 0) -or ($malformedAccounts.Count -gt 0)

    if ($excludedIdentifiers.Count -gt 0 -and ($enforcedBlockPolicies.Count -gt 0 -or $reportOnlyBlockPolicies.Count -gt 0)) {
        foreach ($identifier in $excludedIdentifiers) {
            $enforcedNames = @($enforcedBlockPolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            $reportOnlyNames = @($reportOnlyBlockPolicies | Where-Object { @($_.conditions.users.excludeUsers) -contains $identifier } | ForEach-Object { [string] $_.displayName })
            if ($enforcedNames.Count -eq 0 -and $reportOnlyNames.Count -eq 0) { continue }
            $detail = @{
                excludedFromEnforcedBlockPolicies   = $enforcedNames
                excludedFromReportOnlyBlockPolicies = $reportOnlyNames
            }
            # MISREADING-RISK FOLD-IN: report-only-ONLY exclusion (never also excluded from
            # an enforced policy) gets an explicit warning - see this file's own docstring.
            if ($reportOnlyNames.Count -gt 0 -and $enforcedNames.Count -eq 0) {
                $detail.reportOnlyProtectionWarning = 'Report-only policies do not protect this account - nothing is actually enforced, so this identity is NOT locked out of legacy authentication by these polic' + $(if ($reportOnlyNames.Count -eq 1) { 'y' } else { 'ies' }) + ' today.'
            }
            $exclusionEvidence += @{
                Identity = $identifier
                SortKey  = "exclusion:$identifier"
                Detail   = $detail
            }
        }
    }

    # COMPLETENESS FOLD-IN: malformed declared accounts can never match ANY policy's
    # excludeUsers (not GUID-shaped), so they are surfaced unconditionally - independent of
    # whether any legacy-auth-block-shaped policy exists at all.
    foreach ($malformed in $malformedAccounts) {
        $exclusionEvidence += @{
            Identity = $malformed
            SortKey  = "malformed:$malformed"
            Detail   = @{
                issue = 'not GUID-shaped - Conditional Access excludeUsers holds GUID principal ids, so this declared exclusion can never match any policy and cannot be honored, enforced or report-only.'
            }
        }
    }

    # COMPLETENESS FOLD-IN: surfaces "group-based exclusion cannot be verified" whenever the
    # operator declared some exclusion-relevant context at all - see the "declared
    # something" gate comment above and this file's own docstring for why an empty -Context
    # call does not get this entry (nothing declared, nothing actionable to warn about).
    if ($hasDeclaredExclusionContext -and -not $exclusionContext.GroupExclusionsResolved) {
        $exclusionEvidence += @{
            Identity = 'group-exclusion-resolution'
            SortKey  = 'group-exclusion-resolution'
            Detail   = @{
                note = $exclusionContext.GroupExclusionNote
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
