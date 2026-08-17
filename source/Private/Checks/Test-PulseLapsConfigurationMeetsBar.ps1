<#
    Private: TP.INT.0015 rule function - LAPS configuration policy meets minimum security
    bar (Task 3.2, Maester port MT.1177 - Test-MtIntuneLAPSConfiguration, MIT).

    PENDING COMPOSITE DATASET: same shape family as TP.INT.0014
    (endpointSecurityDiskEncryptionPolicies) - deviceManagement/configurationPolicies
    filtered to templateFamily eq 'endpointSecurityAccountProtection', further filtered
    client-side to the LAPS templateId (adc46e5a-f4aa-4ff6-aeff-4f27bc525796 per Maester's
    own hardcoded value - the research entry's own "template ID trap" note: this GUID
    could not be independently re-verified against a live tenant from inside this task, so
    it is carried through AS-IS from Maester's own source rather than invented or altered;
    whoever builds the composite descriptor should re-confirm it against Ivy24 before this
    check's Pending flag is dropped), then each matching policy's settings walked and
    resolved against the four LAPS CSP criteria below. DatasetMap.psd1 declares
    'endpointSecurityLapsPolicies' Pending=$true, holding the ALREADY-RESOLVED per-policy
    shape ({policyId, policyName, backsUpToEntra, hasSufficientComplexity,
    hasSufficientLength, hasPostAuthAction}) - this rule does not re-implement Maester's
    own opaque CSP choice-value suffix-matching itself, for the same reason
    Test-PulseBitLockerFullDiskEncryption.ps1 does not (schema-version-dependent,
    unverifiable without live tenant access from inside this task).

    RULE (ported verbatim, ALL FOUR criteria required on the SAME policy - Maester's own
    logic explicitly does not OR across separate policies, and this port mirrors that
    exactly, per the research entry's own Notes warning against a looser bar - live-verified
    against
    https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords,
    fetched for this check): a policy is COMPLIANT when backsUpToEntra AND
    hasSufficientComplexity AND hasSufficientLength AND hasPostAuthAction are ALL true.
    Pass when at least one policy is compliant. Fail when policies of this template exist
    but none are fully compliant (or zero such policies exist at all - mirrors
    TP.INT.0014/Maester's own zero-policies-is-Fail behavior, not a skip). Evidence lists
    every matching policy with its four resolved booleans, so a reader can see exactly
    which criterion each near-miss policy fails, not just that it failed.
#>

function Test-PulseLapsConfigurationMeetsBar {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $policies = @($Datasets.endpointSecurityLapsPolicies)

    $compliant = @($policies | Where-Object {
            ($_.backsUpToEntra -eq $true) -and
            ($_.hasSufficientComplexity -eq $true) -and
            ($_.hasSufficientLength -eq $true) -and
            ($_.hasPostAuthAction -eq $true)
        })

    if ($compliant.Count -gt 0) {
        $evidence = ConvertTo-PulseMaesterEvidence -Rows $policies -IdentityProperty 'policyId' -SortKeyProperty 'policyName' -DetailProperties @('policyName', 'backsUpToEntra', 'hasSufficientComplexity', 'hasSufficientLength', 'hasPostAuthAction')
        return New-PulseFinding -Status Pass -Reason "At least one Windows LAPS policy ($($compliant.Count) of $($policies.Count)) meets the full minimum security bar on a single policy: backs up to Entra ID, 4-class-or-higher password complexity, >= 14-character passwords, and a recognized post-authentication reset action." -Evidence $evidence
    }

    if ($policies.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No Windows LAPS Endpoint Security policy is configured (templateFamily endpointSecurityAccountProtection, LAPS template) - local administrator passwords are not centrally rotated or backed up by this mechanism, leaving them static or shared across the fleet.'
    }

    $evidence = ConvertTo-PulseMaesterEvidence -Rows $policies -IdentityProperty 'policyId' -SortKeyProperty 'policyName' -DetailProperties @('policyName', 'backsUpToEntra', 'hasSufficientComplexity', 'hasSufficientLength', 'hasPostAuthAction')
    $reason = "$($policies.Count) Windows LAPS polic$(if ($policies.Count -eq 1) { 'y exists' } else { 'ies exist' }), but none meet all four minimum-bar criteria ON THE SAME POLICY (see each policy's own evidence for which criterion falls short) - a policy missing even one criterion (e.g. backup destination correct but password length under 14) does not meet the bar; criteria are not OR'd across separate policies."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
