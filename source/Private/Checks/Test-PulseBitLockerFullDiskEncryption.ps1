<#
    Private: TP.INT.0014 rule function - BitLocker full-disk encryption enforced via
    Endpoint Security policy (Task 3.2, Maester port MT.1123 -
    Test-MtBitLockerFullDiskEncryption, MIT).

    PENDING COMPOSITE DATASET: this check's real input is
    deviceManagement/configurationPolicies filtered to
    templateReference/templateFamily eq 'endpointSecurityDiskEncryption', THEN each
    matching policy's settings walked (.../configurationPolicies('{id}')/settings) and
    inspected for the BitLocker CSP's system-drive encryption-type setting. No released
    GraphKit descriptor performs this templateFamily-filtered list + per-policy settings
    fan-out as a single composite operation. DatasetMap.psd1 declares
    'endpointSecurityDiskEncryptionPolicies' Pending=$true, holding the ALREADY-RESOLVED
    per-policy shape ({policyId, policyName, isFullDiskEncryption:[bool]}) a future
    composite descriptor would need to produce - this rule deliberately does NOT
    re-implement the suffix-matching itself; whoever builds the composite descriptor
    resolves it once, centrally, and hands this rule a plain boolean.

    SETTING IDENTITY - CORRECTED (T3.4 whole-task dual review, fix round 1,
    CRITICAL-ADJUDICATION finding; corpus-verified against
    scratch/live-27/snapshot/reference/settingDefinitions.json, 18,227 real definitions,
    grep'd by line number): the earlier docstring here (and TP.INT.0031's own original
    authoring pass) both assumed `device_vendor_msft_bitlocker_systemdrivesencryptiontype`
    ITSELF carries the Full-vs-Used-space-only choice, with `_1` meaning "Full encryption."
    The corpus proves this wrong - TWO DISTINCT settings are involved, in a parent/child
    dependency relationship:
      - PARENT, `device_vendor_msft_bitlocker_systemdrivesencryptiontype`
        (displayName "Enforce drive encryption type on operating system drives",
        `uxBehavior: "toggle"`) is a plain ON/OFF ENABLEMENT TOGGLE, NOT the encryption
        type itself: options are `..._0` = "Disabled", `..._1` = "Enabled" - "Enabled"
        here means "this policy governs SOME encryption-type choice", nothing about
        Full-vs-Used-space-only. The corpus's own `options[]` entry for `..._1`:
        `"itemId": "device_vendor_msft_bitlocker_systemdrivesencryptiontype_1",
        "name": "Enabled", "optionValue": {"value": 1}` - `dependedOnBy` names the CHILD
        setting below as required once this option is selected.
      - CHILD, `device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name`
        (displayName "Select the encryption type:") is the setting that ACTUALLY carries
        Full-vs-Used-space-only, and only exists in a policy's configuration when the
        PARENT is set to "Enabled" (its own `dependentOn` names
        `device_vendor_msft_bitlocker_systemdrivesencryptiontype_1` as a required parent
        selection - a Settings Catalog structural constraint, not a convention this module
        invented: a dependent child setting cannot be present in a policy's configuration
        without its parent's enabling option also being selected on the SAME policy).
        Its own three options: `..._0` = "Allow user to choose (default)", `..._1` =
        "Full encryption", `..._2` = "Used Space Only encryption".
    CONCLUSION: "Full encryption enforced" means the CHILD resolves to
    `device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name_1`
    - checking the CHILD ALONE is both necessary and sufficient (not merely "likely
    requiring parent-enabled AND child-full", per the review's own initial framing): the
    corpus's own dependency graph proves a policy can never carry a value for the child
    settingDefinitionId without the parent already being "Enabled" on that identical
    policy, so a second, independent parent-side check adds no additional certainty this
    dependency does not already guarantee. Any future composite descriptor (or
    TP.INT.0031's own settings-expansion consumer) that resolves
    isFullDiskEncryption/matches this defId must target the CHILD's `_1` option, never the
    parent's.

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

    FIELD-ABSENCE LENS (POST-REVIEW FIX): an absent isFullDiskEncryption used to be read
    the same as present-and-$false (both failed the -eq $true test and silently fell into
    "not full-disk encryption"). Absent means the resolved suffix-matched boolean this
    check's own dataset docstring describes was never produced for that policy row - this
    rule cannot honestly reason about it, and now throws instead.
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

    foreach ($policy in $policies) {
        if ($null -eq $policy.isFullDiskEncryption) {
            throw "Test-PulseBitLockerFullDiskEncryption: Endpoint Security Disk Encryption policy '$($policy.policyName)' has no isFullDiskEncryption value - an absent value here is not decidable as 'not full-disk encryption', it means this rule cannot tell whether the resolved suffix-matched boolean was ever produced for this policy."
        }
    }

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
