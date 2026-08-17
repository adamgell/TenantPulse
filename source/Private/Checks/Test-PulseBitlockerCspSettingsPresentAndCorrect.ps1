<#
    Private: TP.INT.0031 rule function - BitLocker CSP `SystemDrivesEncryptionType`
    setting present and resolved to full-disk encryption, across EVERY expanded Settings
    Catalog policy regardless of creation path (Part A/T3.4's settingPresenceIndex, not a
    template-family-filtered Graph fetch) - the settings-expansion complement
    TP.INT.0014's own Consulting text and this task's research record both name explicitly
    ("a BitLocker CSP setting pushed via a generic Settings Catalog profile outside that
    blade is invisible to [TP.INT.0014] by design").

    ARTIFACT, NOT A DATASET: reads $Context.ArtifactReader.GetSettingPresenceIndex() via
    Data.Expansions = @('settingPresenceIndex') - never a raw Graph dataset, never streams
    the underlying expanded/settingsCatalog.jsonl this index was built from (checks NEVER
    stream jsonl - the standing rule Part A's whole index exists to satisfy).

    SETTING IDENTITY - CORRECTED (T3.4 whole-task dual review, fix round 1,
    CRITICAL-ADJUDICATION finding, corpus-verified against
    scratch/live-27/snapshot/reference/settingDefinitions.json, 18,227 real definitions):
    the original authoring pass matched `device_vendor_msft_bitlocker_systemdrivesencryptiontype`
    ITSELF against option `_1`, assuming that IS the Full-vs-Used-space-only choice. The
    corpus proves this wrong. Two DISTINCT settings are involved, parent/child:
      - PARENT, `device_vendor_msft_bitlocker_systemdrivesencryptiontype` (displayName
        "Enforce drive encryption type on operating system drives", `uxBehavior:
        "toggle"`) is a plain ON/OFF ENABLEMENT TOGGLE: `..._0` = "Disabled", `..._1` =
        "Enabled" - "Enabled" means only "this policy governs SOME encryption-type
        choice," nothing about Full-vs-Used-space-only.
      - CHILD, `device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name`
        (displayName "Select the encryption type:") carries the ACTUAL choice: `..._0` =
        "Allow user to choose (default)", `..._1` = "Full encryption", `..._2` = "Used
        Space Only encryption". The corpus's own dependency graph
        (`dependentOn`/`dependedOnBy`) proves this child setting can NEVER appear in a
        policy's configuration without the parent already being "Enabled" on that
        IDENTICAL policy - a Settings Catalog structural constraint, not a convention this
        module invented.
    This check therefore targets the CHILD definitionId's `_1` option
    (`device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name_1`)
    ALONE - checking the child alone is both necessary and sufficient, since its own
    corpus-proven dependency on the parent already guarantees "Enabled" on the same policy
    whenever the child has any value at all; a second, independent parent-side check would
    add no certainty this dependency does not already provide. See
    Test-PulseBitLockerFullDiskEncryption.ps1's own docstring (TP.INT.0014) for the
    identical corrected understanding, applied there too. HIGH CONFIDENCE now
    (corpus-verified) - the PENDING VERIFICATION hedge from the original authoring pass is
    RETIRED for this check.

    HONESTY STATES (this task's own brief, shared by every Part B check via
    Resolve-PulseSettingPresenceCriterion.ps1 - see that file's own docstring for the full
    accounting):
      - Artifact not 'Available' (index was never built this snapshot, or its own
        family(ies) were all unavailable) -> NotApplicable, quoting the artifact's Reason.
      - Setting present with the correct value on an ASSIGNED policy (regardless of
        family - settingsCatalog/compliance/deviceConfiguration all indexed under the
        same definitionId key) -> Pass.
      - Setting present with the correct value ONLY on policy(ies) this module could not
        confirm are assigned (NotAssigned or Unknown/deferred) -> Fail, disclosed as
        "present but not confirmed assigned" - an unassigned policy protects zero devices,
        the same practical outcome as no policy at all.
      - Setting present on an ASSIGNED policy but its value is REDACTED (Sensitive/secret-
        classified for some reason - not expected for a Choice-typed encryption-mode
        setting in practice, but the index cannot assume that, and this rule must not
        either) -> Warn, "presence confirmed, value unreadable" - NEVER Pass on a value
        this rule could not actually read.
      - Setting absent entirely from every expanded family -> Fail.
      - `anyUnknownAssignment` on the definitionId's own entry is disclosed in the Reason
        whenever true, REGARDLESS of which status above applies - dynamic-group/filter
        assignment ambiguity is a fact worth surfacing even alongside a confident Pass
        (a satisfying value was found on a DIFFERENT, confirmed-assigned policy, but some
        OTHER policy carrying this same setting has unresolvable assignment status too).

    EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding I4): every status path
    now attaches one evidence row per family (settingsCatalog/compliance/
    deviceConfiguration) carrying that family's own presence/assignment/redaction counts
    from Resolve-PulseSettingPresenceCriterion.ps1's Entry. The presence index is keyed by
    definitionId/family, never by policy - it has NO policy names to offer - so this
    evidence honestly surfaces counts only, never a policy identity or name.

    PARTIAL SCAN DISCLOSURE (TP.INT.0006 precedent, reused verbatim): whenever
    -Artifact.Gaps is non-empty, the Reason is prefixed with the same
    "PARTIAL SCAN - N family(ies) excluded (...)" text TP.INT.0006 already established,
    on EVERY status this rule can return, not just Pass - a reader must never mistake an
    incomplete scan for a clean one on any status.

    DEDUPE, NOT DOUBLE-COUNTED (research entry's own "dedupe trap" note): this check and
    TP.INT.0014 are DELIBERATELY independent, non-blocking signals over the same
    underlying risk, not merged into one finding - TenantPulse's finding schema has no
    cross-check suppression mechanism (same YAGNI-bounded-scope reasoning TP.INT.0006's own
    docstring already applies to severity escalation). A tenant whose ONLY qualifying
    BitLocker policy went through the Endpoint Security blade Passes TP.INT.0014 AND this
    check identically (both read the same underlying setting, from two different
    collection paths) - this is intentional corroboration, not disagreement; a reviewer
    reading both findings side by side sees two independent confirmations of the same
    fact, never two checks reporting DIFFERENT verdicts on the same real-world state
    (since both ultimately resolve the identical CSP setting).
#>

function Test-PulseBitlockerCspSettingsPresentAndCorrect {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    if (-not $Context -or -not $Context.ContainsKey('ArtifactReader') -or $null -eq $Context.ArtifactReader) {
        throw 'Test-PulseBitlockerCspSettingsPresentAndCorrect: no $Context.ArtifactReader was supplied - this rule cannot read the settingPresenceIndex expansion artifact without it.'
    }

    # CORPUS-VERIFIED (see this file's own docstring): the CHILD dropdown setting, not the
    # parent enablement toggle, carries the actual Full-vs-Used-space-only choice.
    $script:PulseBitlockerSystemDrivesEncryptionTypeDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
    $script:PulseBitlockerFullEncryptionOptionId = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name_1'

    $artifact = $Context.ArtifactReader.GetSettingPresenceIndex()

    if ($artifact.Status -ne 'Available') {
        return New-PulseFinding -Status NotApplicable -Reason $artifact.Reason
    }

    $gapFamilyNames = [System.Collections.Generic.List[string]]::new()
    foreach ($gap in @($artifact.Gaps)) {
        $gapReasonText = [string] $gap.reason
        $familyMatch = [regex]::Match($gapReasonText, 'family:([^;]+)')
        if ($familyMatch.Success) {
            $gapFamilyNames.Add($familyMatch.Groups[1].Value) | Out-Null
        } elseif (-not [string]::IsNullOrEmpty($gapReasonText)) {
            $gapFamilyNames.Add($gapReasonText) | Out-Null
        }
    }
    $gapDisclosure = if ($gapFamilyNames.Count -gt 0) {
        "PARTIAL SCAN - $($gapFamilyNames.Count) family(ies) excluded ($([string]::Join(', ', $gapFamilyNames))), so this result does not cover those families' policies. "
    } else { '' }

    $isFullEncryption = { param($value) $value -eq $script:PulseBitlockerFullEncryptionOptionId }

    $familyNames = @('settingsCatalog', 'compliance', 'deviceConfiguration')
    $combined = [pscustomobject]@{
        Present                        = $false
        SatisfiedAssignedPolicyCount   = 0
        SatisfiedUnassignedPolicyCount = 0
        RedactedAssignedPolicyCount    = 0
        AnyUnknownAssignment           = $false
        UnknownAssignmentPolicyCount   = 0
    }
    # PER-FAMILY EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding I4): the
    # presence-index Entry Resolve-PulseSettingPresenceCriterion.ps1 exposes never carries
    # POLICY NAMES (the index is keyed by definitionId/family, not by policy) - only
    # presence/assignment/redaction COUNTS per family. Evidence below honestly attaches
    # what the index actually offers; it does not (and cannot) name which policy carries
    # the setting.
    $evidence = [System.Collections.Generic.List[object]]::new()
    foreach ($family in $familyNames) {
        $criterion = Resolve-PulseSettingPresenceCriterion -Artifact $artifact -Family $family `
            -DefinitionId $script:PulseBitlockerSystemDrivesEncryptionTypeDefinitionId -IsSatisfyingValue $isFullEncryption
        if ($criterion.Present) { $combined.Present = $true }
        $combined.SatisfiedAssignedPolicyCount += $criterion.SatisfiedAssignedPolicyCount
        $combined.SatisfiedUnassignedPolicyCount += $criterion.SatisfiedUnassignedPolicyCount
        $combined.RedactedAssignedPolicyCount += $criterion.RedactedAssignedPolicyCount
        if ($criterion.AnyUnknownAssignment) { $combined.AnyUnknownAssignment = $true }
        $combined.UnknownAssignmentPolicyCount += $criterion.UnknownAssignmentPolicyCount

        $evidence.Add(@{
            Identity = $family
            Detail   = @{
                family                          = $family
                settingDefinitionId             = $script:PulseBitlockerSystemDrivesEncryptionTypeDefinitionId
                present                         = $criterion.Present
                satisfiedAssignedPolicyCount    = $criterion.SatisfiedAssignedPolicyCount
                satisfiedUnassignedPolicyCount  = $criterion.SatisfiedUnassignedPolicyCount
                redactedAssignedPolicyCount     = $criterion.RedactedAssignedPolicyCount
                anyUnknownAssignment            = $criterion.AnyUnknownAssignment
                unknownAssignmentPolicyCount    = $criterion.UnknownAssignmentPolicyCount
            }
            SortKey  = $family
        })
    }

    $unknownDisclosure = if ($combined.AnyUnknownAssignment) {
        " $($combined.UnknownAssignmentPolicyCount) polic(ies) carrying this setting have a deferred/unknown assignment status (dynamic-group or filter membership could not be resolved) - this was NOT counted as assigned either way."
    } else { '' }

    if ($combined.SatisfiedAssignedPolicyCount -gt 0) {
        $reason = "${gapDisclosure}The BitLocker CSP system-drive encryption type resolves to Full encryption on at least one assigned Settings Catalog policy ($($combined.SatisfiedAssignedPolicyCount) polic(ies)).${unknownDisclosure}"
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence.ToArray()
    }

    if ($combined.RedactedAssignedPolicyCount -gt 0) {
        $reason = "${gapDisclosure}The BitLocker CSP system-drive encryption type is configured on $($combined.RedactedAssignedPolicyCount) assigned policy(ies), but its value is redacted (Sensitive/secret-classified) and could not be read - presence is confirmed, correctness is not.${unknownDisclosure}"
        return New-PulseFinding -Status Warn -Reason $reason -Evidence $evidence.ToArray()
    }

    if ($combined.SatisfiedUnassignedPolicyCount -gt 0) {
        $reason = "${gapDisclosure}The BitLocker CSP system-drive encryption type resolves to Full encryption on $($combined.SatisfiedUnassignedPolicyCount) polic(ies), but none of them could be confirmed as assigned to any device or user - an unassigned policy protects nothing.${unknownDisclosure}"
        return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
    }

    if (-not $combined.Present) {
        $reason = "${gapDisclosure}The BitLocker CSP system-drive encryption type setting was not found in any expanded Settings Catalog, compliance, or device configuration policy for this snapshot.${unknownDisclosure}"
        return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
    }

    $reason = "${gapDisclosure}The BitLocker CSP system-drive encryption type is configured somewhere, but never resolves to Full encryption on any policy this module could evaluate.${unknownDisclosure}"
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
}
