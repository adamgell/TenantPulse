<#
    Private: TP.INT.0016 rule function - Microsoft's three "Standard protection" Attack
    Surface Reduction (ASR) rules configured to Block or Audit (not Warn/Disabled/
    unconfigured), evaluated as a UNION across every expanded policy in the tenant (Part
    A/T3.4's settingPresenceIndex, not a template-family-filtered Graph fetch) - a rule
    set entirely by policy A and another entirely by policy B still counts as a combined
    Pass, per this check's own research entry.

    Maester MT.1178 port (`Test-MtIntuneASRRules`, MIT) - upgraded at authoring time to
    consume the settings-expansion index rather than the `configurationPolicies`
    template-family fetch the original research entry proposed, per this task's own
    scope: the settings-expansion layer already answers "is this rule configured
    ANYWHERE in the tenant, on an assigned policy" without a second Graph round-trip, and
    without the template-family blind spot TP.INT.0031's own docstring explains for
    BitLocker (an ASR rule pushed through a generic Settings Catalog profile, not the
    Endpoint Security > ASR blade, is invisible to a templateFamily-filtered fetch but
    fully visible here).

    ARTIFACT, NOT A DATASET: reads $Context.ArtifactReader.GetSettingPresenceIndex() via
    Data.Expansions = @('settingPresenceIndex') - never streams the underlying
    expanded/settingsCatalog.jsonl this index was built from.

    RULE IDENTITY (live-fetched 2026-08-17, confirmed live -
    https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference):
    the three "Standard protection rules", by GUID:
      - `56a863a9-875e-4185-98a7-b882c64b5ce5` - Block abuse of exploited vulnerable
        signed drivers (Device)
      - `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` - Block credential stealing from the
        Windows local security authority subsystem (LSASS)
      - `e6db77e5-3df2-4cf1-b95a-636979351e5b` - Block persistence through WMI event
        subscription
    These three GUIDs are Microsoft's own stable, documented rule identifiers (not
    schema-version-dependent the way a Settings Catalog optionId suffix is) - HIGH
    confidence, no hedge needed.

    SETTING IDENTITY (PENDING VERIFICATION against a live tenant, same class of hedge
    TP.INT.0014/TP.INT.0031 already carry for BitLocker): the Policy CSP path
    `./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules`
    (live-fetched 2026-08-17, confirmed live -
    https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender)
    is a single GroupSettingCollection keyed per rule GUID in Settings Catalog, from
    which this rule derives one settingDefinitionId per rule GUID following this module's
    own established `device_vendor_msft_<csp path>` naming convention:
    `device_vendor_msft_policy_config_defender_attacksurfacereductionrules_<guid>`. This
    exact string has NOT been independently confirmed against a live tenant's actual
    Settings Catalog schema from inside this task - whoever next re-baselines this check
    against a real Ivy24 (or successor) snapshot should confirm it and drop this hedge.
    VALUE MATCHING IS DELIBERATELY TOLERANT of two plausible representations given that
    same uncertainty: Microsoft's own documented ASR rule state values are the bare
    integers 0=Disabled/NotConfigured, 1=Block, 2=Audit, 6=Warn (stable, well-documented,
    high confidence) - this rule accepts EITHER a bare `'1'`/`'2'` canonicalValue OR a
    Settings-Catalog-choice-style suffixed value ending in `_1`/`_2` (matching the
    `_<suffix>` optionId pattern TP.INT.0031's own BitLocker check already established),
    so a schema surprise in EITHER direction does not silently misclassify a correctly
    configured rule as absent.

    UNION LOGIC (this check's own defining trait, from its research entry): each of the
    three rule GUIDs is resolved INDEPENDENTLY via Resolve-PulseSettingPresenceCriterion
    (no per-policy correlation needed or attempted - unlike TP.INT.0032's own
    same-policy caveat, a tenant-wide union across POLICIES is explicitly the correct bar
    here, not a same-policy AND). Pass requires ALL THREE rules individually satisfied by
    an assigned policy (each may be a DIFFERENT policy).

    HONESTY STATES (shared machinery, see Resolve-PulseSettingPresenceCriterion.ps1's own
    docstring for the full accounting): Warn on a redacted rule value (never Pass on a
    value that could not be read); a rule satisfied only on unassigned/unknown-assignment
    policies does not count toward the union; `anyUnknownAssignment` is disclosed
    per-rule whenever true, regardless of overall status; the PARTIAL SCAN gap-disclosure
    prefix (TP.INT.0006 precedent) applies whenever -Artifact.Gaps is non-empty.

    ONLY 3 OF ~19 ASR RULES (this check's own research entry, carried through
    unconditionally): this is intentionally a floor, not full ASR coverage - Consulting
    text says so explicitly, matching the research entry's own Notes.
#>

function Test-PulseAsrStandardProtectionRulesConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    if (-not $Context -or -not $Context.ContainsKey('ArtifactReader') -or $null -eq $Context.ArtifactReader) {
        throw 'Test-PulseAsrStandardProtectionRulesConfigured: no $Context.ArtifactReader was supplied - this rule cannot read the settingPresenceIndex expansion artifact without it.'
    }

    $standardProtectionRules = [ordered]@{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem (LSASS)'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    }

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

    $isBlockOrAudit = {
        param($value)
        $text = [string] $value
        if ($text -eq '1' -or $text -eq '2') { return $true }
        if ($text -like '*_1' -or $text -like '*_2') { return $true }
        return $false
    }

    $familyNames = @('settingsCatalog', 'compliance', 'deviceConfiguration')
    $unsatisfiedRules = [System.Collections.Generic.List[string]]::new()
    $satisfiedRuleNames = [System.Collections.Generic.List[string]]::new()
    $anyUnknownAssignment = $false
    $totalUnknownAssignmentPolicyCount = 0
    $anyRedactedAssignedOnUnsatisfied = $false
    $anySatisfiedButUnassigned = $false

    foreach ($guid in $standardProtectionRules.Keys) {
        $definitionId = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_$guid"
        $ruleSatisfiedByAssigned = $false
        $ruleSatisfiedButUnassigned = $false
        $ruleRedactedAssigned = $false

        foreach ($family in $familyNames) {
            $criterion = Resolve-PulseSettingPresenceCriterion -Artifact $artifact -Family $family -DefinitionId $definitionId -IsSatisfyingValue $isBlockOrAudit
            if ($criterion.SatisfiedAssignedPolicyCount -gt 0) { $ruleSatisfiedByAssigned = $true }
            if ($criterion.SatisfiedUnassignedPolicyCount -gt 0) { $ruleSatisfiedButUnassigned = $true }
            if ($criterion.RedactedAssignedPolicyCount -gt 0) { $ruleRedactedAssigned = $true }
            if ($criterion.AnyUnknownAssignment) {
                $anyUnknownAssignment = $true
                $totalUnknownAssignmentPolicyCount += $criterion.UnknownAssignmentPolicyCount
            }
        }

        if ($ruleSatisfiedByAssigned) {
            $satisfiedRuleNames.Add($standardProtectionRules[$guid]) | Out-Null
        } else {
            $unsatisfiedRules.Add($standardProtectionRules[$guid]) | Out-Null
            if ($ruleRedactedAssigned) { $anyRedactedAssignedOnUnsatisfied = $true }
            if ($ruleSatisfiedButUnassigned) { $anySatisfiedButUnassigned = $true }
        }
    }

    $unknownDisclosure = if ($anyUnknownAssignment) {
        " $totalUnknownAssignmentPolicyCount polic(ies) carrying one of these rules have a deferred/unknown assignment status (dynamic-group or filter membership could not be resolved) - this was NOT counted as assigned either way."
    } else { '' }

    if ($unsatisfiedRules.Count -eq 0) {
        $reason = "${gapDisclosure}All 3 Standard Protection ASR rules (Block abuse of exploited vulnerable signed drivers, Block credential stealing from LSASS, Block persistence through WMI event subscription) are configured to Block or Audit on at least one assigned policy each (union across policies).${unknownDisclosure}"
        return New-PulseFinding -Status Pass -Reason $reason
    }

    if ($anyRedactedAssignedOnUnsatisfied -and $satisfiedRuleNames.Count -gt 0) {
        $reason = "${gapDisclosure}$($unsatisfiedRules.Count) of 3 Standard Protection ASR rule(s) ($([string]::Join('; ', $unsatisfiedRules))) could not be confirmed - at least one is present on an assigned policy but its value is redacted and could not be read.${unknownDisclosure}"
        return New-PulseFinding -Status Warn -Reason $reason
    }

    $reason = "${gapDisclosure}$($unsatisfiedRules.Count) of 3 Standard Protection ASR rule(s) are not configured to Block or Audit on any confirmed-assigned policy: $([string]::Join('; ', $unsatisfiedRules)).$(if ($anySatisfiedButUnassigned) { ' At least one of these has a correct value on a policy that could not be confirmed as assigned - an unassigned policy protects nothing.' } else { '' })${unknownDisclosure}"
    return New-PulseFinding -Status Fail -Reason $reason
}
