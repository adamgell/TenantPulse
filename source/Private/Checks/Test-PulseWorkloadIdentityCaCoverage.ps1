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

    $classifiedPolicies = @(for ($policyOrdinal = 0; $policyOrdinal -lt $views.Count; $policyOrdinal++) {
        $policy = $views[$policyOrdinal]
        if ($policy.state -eq 'enforced' -and $policy.conditions.clientApplications.present) {
            [pscustomobject]@{
                Policy            = $policy
                Scope             = Get-PulseCaWorkloadIdentityScope -ClientApplications $policy.conditions.clientApplications
                CollectionOrdinal = $policyOrdinal
            }
        }
    })

    $validPolicies = @($classifiedPolicies | Where-Object { $_.Scope.State -eq 'Valid' })
    $malformedPolicies = @($classifiedPolicies | Where-Object { $_.Scope.State -eq 'Malformed' })
    $evidence = @($classifiedPolicies | ForEach-Object {
        $policy = $_.Policy
        $scope = $_.Scope
        $policyIdentity = Get-PulseCaPolicyEvidenceIdentity -Policy $policy -CollectionOrdinal $_.CollectionOrdinal
        @{ Identity = $policyIdentity; Detail = @{
            displayName                            = $policy.displayName
            classification                         = $scope.State
            reasonCodes                            = @($scope.ReasonCodes)
            includedServicePrincipalCount          = $scope.IncludedServicePrincipalCount
            excludedServicePrincipalCount          = $scope.ExcludedServicePrincipalCount
            includesAllServicePrincipals           = $scope.IncludesAllServicePrincipals
            hasServicePrincipalFilter              = $scope.HasServicePrincipalFilter
            includedAgentIdServicePrincipalCount   = $scope.IncludedAgentIdServicePrincipalCount
            excludedAgentIdServicePrincipalCount   = $scope.ExcludedAgentIdServicePrincipalCount
            includesAllAgentIdServicePrincipals    = $scope.IncludesAllAgentIdServicePrincipals
            hasAgentIdServicePrincipalFilter       = $scope.HasAgentIdServicePrincipalFilter
        } }
    })

    $reason = "$($validPolicies.Count) valid enforced Conditional Access polic$(if ($validPolicies.Count -eq 1) { 'y scopes' } else { 'ies scope' }) conditions.clientApplications; $($malformedPolicies.Count) malformed enforced polic$(if ($malformedPolicies.Count -eq 1) { 'y requires' } else { 'ies require' }) review. This is a practitioner awareness note, not a scored finding - it reports selector validity, not whether the right identities are covered."
    if ($classifiedPolicies.Count -eq 0) {
        $reason += ' Consider whether privileged service principals or agent identities warrant workload-identity Conditional Access. Requires Entra ID Workload ID Premium to act on.'
    }

    if ($evidence.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason $reason
    }
    return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
}
