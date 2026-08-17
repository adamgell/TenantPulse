<#
    Private: TP.INT.0014 rule function - BitLocker full-disk encryption enforced via
    Endpoint Security policy (Task 3.2, Maester port MT.1123 -
    Test-MtBitLockerFullDiskEncryption, MIT).

    PENDING COMPOSITE DATASET: this check's real input is
    deviceManagement/configurationPolicies filtered to
    templateReference/templateFamily eq 'endpointSecurityDiskEncryption', THEN each
    matching policy's settings walked (.../configurationPolicies('{id}')/settings) and
    inspected for the BitLocker CSP's system-drive encryption-type setting
    (device_vendor_msft_bitlocker_systemdrivesencryptiontype and its child dropdown) -
    Maester's own function reads the resolved choice value's suffix (`_1` = Full
    encryption) directly off the raw setting row. No released GraphKit descriptor performs
    this templateFamily-filtered list + per-policy settings fan-out as a single composite
    operation. DatasetMap.psd1 declares 'endpointSecurityDiskEncryptionPolicies'
    Pending=$true, holding the ALREADY-RESOLVED per-policy shape ({policyId, policyName,
    isFullDiskEncryption:[bool]}) a future composite descriptor would need to produce -
    this rule deliberately does NOT re-implement Maester's own opaque suffix-matching
    (`_1`/`_2` on a choice value) itself, since that matching is schema-version-dependent
    and the research entry's own Notes explicitly call for verifying it against a live
    tenant's actual settings-catalog schema before shipping - something this task cannot
    do without Ivy24 access from inside a rule function. Whoever builds the composite
    descriptor resolves that suffix-matching once, centrally, and hands this rule a plain
    boolean.

    RULE (ported - live-verified against
    https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-disk-encryption-settings,
    fetched for this check, which confirms the BitLocker CSP settings this check keys on
    exist, though that specific page documents only the DEPRECATED pre-June-2023 profile
    format - the current Settings Catalog format Maester's own function reads is
    documented instead via the BitLocker CSP reference it links to): Pass when at least
    one endpointSecurityDiskEncryption-templateFamily policy has
    isFullDiskEncryption = $true. Fail when policies of this template family exist but
    none set full-disk encryption (or zero such policies exist at all - Maester's own
    function returns $false, not a skip, for zero policies). Evidence lists every matching
    policy with its resolved boolean, not just the offending ones, so a reader can see
    "used-space-only" policies explicitly rather than only their absence.

    DEDUPE NOTE (research entry's own "dedupe trap" - out of scope for this rule
    specifically, in scope for TP.INT.0031's future settings-expansion-based complement):
    this check only ever sees policies created through the Endpoint security > Disk
    encryption blade (the templateReference route) - it does not, and cannot, see BitLocker
    settings pushed through a generic Settings Catalog profile outside that blade. No
    double-counting risk exists WITHIN this check; the risk is a FUTURE check
    double-reporting the same policy this one already covers.
#>

function Test-PulseBitLockerFullDiskEncryption {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $policies = @($Datasets.endpointSecurityDiskEncryptionPolicies)

    $fullyEncrypted = @($policies | Where-Object { $_.isFullDiskEncryption -eq $true })

    if ($fullyEncrypted.Count -gt 0) {
        $evidence = ConvertTo-PulseMaesterEvidence -Rows $policies -IdentityProperty 'policyId' -SortKeyProperty 'policyName' -DetailProperties @('policyName', 'isFullDiskEncryption')
        return New-PulseFinding -Status Pass -Reason "At least one Endpoint Security Disk Encryption policy ($($fullyEncrypted.Count) of $($policies.Count)) enforces full-disk encryption (not used-space-only, not unconfigured) for the OS drive." -Evidence $evidence
    }

    if ($policies.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No Endpoint Security Disk Encryption policy is configured (templateFamily endpointSecurityDiskEncryption) - BitLocker enforcement through this policy surface does not exist for this tenant. Note this check only sees policies created via the Endpoint security > Disk encryption blade; a generic Settings Catalog profile could still push BitLocker CSP settings outside this check''s visibility.'
    }

    $evidence = ConvertTo-PulseMaesterEvidence -Rows $policies -IdentityProperty 'policyId' -SortKeyProperty 'policyName' -DetailProperties @('policyName', 'isFullDiskEncryption')
    $reason = "$($policies.Count) Endpoint Security Disk Encryption polic$(if ($policies.Count -eq 1) { 'y exists' } else { 'ies exist' }), but none enforce full-disk encryption for the OS drive (used-space-only or unconfigured) - a lost/stolen device''s data at rest is not protected by this policy surface."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
