<#
    Private: TP.INT.0008 rule function - Intune Multi Admin Approval policy configured
    (Task 3.2, Maester port MT.1096 - Test-MtOperationApprovalPolicies, MIT).

    PENDING DATASET (honest NA, not invented): the operationApprovalPolicies dataset maps
    to `deviceManagement/operationApprovalPolicies` (beta), which has no released GraphKit
    0.1.1 descriptor as of this task - DatasetMap.psd1 marks it Pending=$true. On a live
    tenant this check therefore always resolves NotApplicable (the collector Skips the
    dataset with reason 'descriptor-pending: awaiting GraphKit release', which
    Invoke-PulseEvaluation's own dataset-status gate turns into this check's
    NotApplicable, quoting that reason) until GraphKit ships the descriptor - a G-batch
    request, not something this task can invent a Graph call for. The rule body below is
    real, tested against fixture data (Write-PulseDataset does not consult Pending - only
    the live collector does), and will start actually evaluating live tenants the moment
    the descriptor ships with no code change here.

    RULE (ported verbatim from Maester's own pass/fail split - live-verified against
    https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/multi-admin-approval,
    fetched for this check): Pass when at least one operationApprovalPolicies row exists
    (count > 0) - Fail when zero rows. Maester's own function does not evaluate WHICH
    resource types (Apps/Compliance/Configuration/Device actions/RBAC/Scripts/Tenant
    Configuration) a given policy actually protects, only that at least one exists; this
    port carries the exact same depth (a known gap, not a silent one - see Consulting
    text) rather than inventing a per-resource-type coverage check Maester itself does not
    perform.
#>

function Test-PulseMultiAdminApprovalConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $policies = @($Datasets.operationApprovalPolicies)

    if ($policies.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No Intune Multi Admin Approval (operation approval) policy is configured - any single admin account (including a compromised one) can deploy scripts, apps, configuration/compliance policies, or perform device wipe/retire/delete actions with no second-admin approval step.'
    }

    $evidence = ConvertTo-PulseMaesterEvidence -Rows $policies -IdentityProperty 'id' -SortKeyProperty 'displayName' -DetailProperties @('displayName', 'policyType')

    $reason = "$($policies.Count) Multi Admin Approval polic$(if ($policies.Count -eq 1) { 'y is' } else { 'ies are' }) configured, requiring a second admin to approve changes to the protected resource type(s) before they take effect."
    return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
}
