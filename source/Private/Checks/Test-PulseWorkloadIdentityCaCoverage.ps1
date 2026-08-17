<#
    Private: TP.ENT.0024 rule function - workload-identity Conditional Access COVERAGE
    AWARENESS (practitioner note, not a scored pass/fail). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0024.

    INFO-SEVERITY / NON-SCORED, PER THE RESEARCH ENTRY'S OWN RECOMMENDATION: this check's
    own descriptor declares Severity 'Info', which Add-PulseScores' pinned Scoring Model 1.0
    already weights at 0 (see that function's own docstring) - a Pass or Fail from this rule
    contributes NOTHING to the tenant's overall score either way, by construction of the
    engine's existing severity-weight table, with no new engine mechanism needed. This rule
    therefore always returns Pass - it is genuinely awareness-only ("count found",
    never "you failed something") - and puts the substantive information in Reason/Evidence
    instead of Status, matching the research entry's own "0 workload-identity CA policies
    found, consider whether..." framing verbatim.

    WHAT THIS CAN AND CANNOT ASSERT (research entry's own honest limitation, carried
    forward): this can only report "N conditions.clientApplications-scoped, enforced CA
    policies exist" - it cannot assert "the RIGHT service principals are covered", since
    there is no general Graph signal in this check's own dataset for "this service principal
    is sensitive enough to need workload-identity CA". Consumes
    ConvertTo-PulseCaPolicyView's own clientApplications field (Task 4.4 addition to that
    shared view - see that function's own docstring) rather than reading conditions.
    clientApplications off a raw policy row directly, per the plan's own "CA checks all
    consume T4.1 views" convention.
#>

function Test-PulseWorkloadIdentityCaCoverage {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $views = @(@($Datasets.conditionalAccessPolicies) | ConvertTo-PulseCaPolicyView)

    $workloadIdentityPolicies = @($views | Where-Object {
        $_.state -eq 'enforced' -and (@($_.conditions.clientApplications.includeApplications).Count -gt 0)
    })

    if ($workloadIdentityPolicies.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason '0 enforced Conditional Access policies scope conditions.clientApplications (workload-identity targeting). This is a practitioner awareness note, not a scored finding - consider whether any of this tenant''s service principals with privileged Graph permissions warrant a workload-identity CA policy. Requires Entra ID Workload ID Premium to act on.'
    }

    $evidence = @($workloadIdentityPolicies | ForEach-Object { @{ Identity = $_.id; Detail = @{ displayName = $_.displayName; includedApplicationCount = @($_.conditions.clientApplications.includeApplications).Count } } })
    return New-PulseFinding -Status Pass -Reason "$($workloadIdentityPolicies.Count) enforced Conditional Access polic$(if ($workloadIdentityPolicies.Count -eq 1) { 'y scopes' } else { 'ies scope' }) conditions.clientApplications (workload-identity targeting). This is a practitioner awareness note, not a scored finding - it confirms coverage EXISTS, not that it targets the right service principals." -Evidence $evidence
}
