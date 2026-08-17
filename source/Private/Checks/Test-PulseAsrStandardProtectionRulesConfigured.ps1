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

    RULE IDENTITY - CORRECTED (T3.4 whole-task dual review, fix round 1, CRITICAL/
    convergent finding): the original authoring pass derived a GUID-suffixed
    settingDefinitionId (`..._<rule-guid>`) by analogy with the Policy CSP node path,
    marked PENDING VERIFICATION, and got it wrong - the review's own ground truth,
    `scratch/live-27/snapshot/reference/settingDefinitions.json` (the Phase 2 captured
    corpus, 18,227 real Settings Catalog definitions, available all along and not
    consulted at original authoring time), shows the REAL definitionId is a lowercase
    NAME-SLUG of the rule's own `displayName`, and the REAL option identifiers are FULL
    itemId strings ending `_off`/`_block`/`_audit`/`_warn` - never a bare GUID suffix,
    never a bare `_1`/`_2`. Exact corpus entries (grep'd by line number in that file,
    quoted verbatim in this task's own report):
      - `device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers`
        (displayName "Block abuse of exploited vulnerable signed drivers (Device)") -
        options include itemId
        `..._blockabuseofexploitedvulnerablesigneddrivers_block` and `..._audit`. Each
        option's own internal wire-format encoding (a SEPARATE JSON field inside the
        catalog entry, describing the raw CSP payload the OMA-URI actually sends - not
        what a policy row's resolved value carries) embeds the rule GUID
        `56a863a9-875e-4185-98a7-b882c64b5ce5` in a `"<guid>=<state>"` string - confirming
        Microsoft's own published GUID is still the correct rule identity, just not usable
        as a settingDefinitionId/itemId suffix the way the original authoring pass
        assumed; see this task's own report for the exact corpus JSON quoted verbatim.
      - `device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem`
        - options include `..._block`, `..._audit`, `..._warn`; wire-format GUID
        `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`.
      - `device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription`
        - options include `..._block`; wire-format GUID
        `e6db77e5-3df2-4cf1-b95a-636979351e5b`.
    A real Settings Catalog policy row's own resolved choice-setting value is the FULL
    itemId string (e.g. `..._blockabuseofexploitedvulnerablesigneddrivers_block`),
    matching this module's own established row-schema convention (T2.2's
    ConvertTo-PulseSettingRows reads a choice setting's raw resolved value verbatim) -
    never the option's own internal wire-format encoding described above, which is
    catalog metadata, not what a policy row's own value carries. HIGH CONFIDENCE now
    (corpus-verified, not carried-through guesswork) - the PENDING VERIFICATION hedge from
    the original authoring pass is RETIRED for this check.

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
    REDACTION WARN IS UNCONDITIONAL (Phase 3 whole-phase review fix, catalog-coherence
    finding I1): the redacted-assigned-on-unsatisfied Warn gate previously also required
    `$satisfiedRuleNames.Count -gt 0`, an undocumented extra condition that caused a
    0-of-3-satisfied tenant carrying a present-but-redacted-assigned rule to Fail claiming
    "not configured" for a value this check never actually managed to read - dishonest.
    Aligned with sibling TP.INT.0031's (Test-PulseBitlockerCspSettingsPresentAndCorrect.ps1)
    unconditional redaction-Warn: ANY redacted-assigned value on an unsatisfied rule Warns,
    regardless of how many other rules are satisfied.

    ONLY 3 OF ~19 ASR RULES (this check's own research entry, carried through
    unconditionally): this is intentionally a floor, not full ASR coverage - Consulting
    text says so explicitly, matching the research entry's own Notes.

    EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding I4): every status
    path (Pass/Warn/Fail) now attaches one evidence row per rule, Identity =
    settingDefinitionId (unique per rule, no collision risk), carrying that rule's own
    presence/assignment/redaction counts summed across families from
    Resolve-PulseSettingPresenceCriterion.ps1's Entry. The presence index has NO policy
    names to offer - this evidence honestly surfaces counts only.
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

    # CORPUS-VERIFIED definitionIds (T3.4 dual-review fix round 1) - name-slugs of the
    # rule's own displayName, exactly as found in
    # scratch/live-27/snapshot/reference/settingDefinitions.json - never a GUID suffix.
    $standardProtectionRules = [ordered]@{
        'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers'                       = 'Block abuse of exploited vulnerable signed drivers'
        'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem' = 'Block credential stealing from the Windows local security authority subsystem (LSASS)'
        'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription'                        = 'Block persistence through WMI event subscription'
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

    $familyNames = @('settingsCatalog', 'compliance', 'deviceConfiguration')
    $unsatisfiedRules = [System.Collections.Generic.List[string]]::new()
    $satisfiedRuleNames = [System.Collections.Generic.List[string]]::new()
    $anyUnknownAssignment = $false
    $totalUnknownAssignmentPolicyCount = 0
    $anyRedactedAssignedOnUnsatisfied = $false
    $anySatisfiedButUnassigned = $false
    # PER-RULE EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding I4): the
    # presence-index Entry never carries POLICY NAMES (keyed by definitionId/family, not
    # by policy) - only presence/assignment/redaction COUNTS, summed across families here.
    # Identity is the rule's own definitionId, unique per rule by construction (no
    # collision risk).
    $evidence = [System.Collections.Generic.List[object]]::new()

    foreach ($definitionId in $standardProtectionRules.Keys) {
        # CORPUS-VERIFIED (see this file's own docstring): the satisfying values are the
        # FULL itemId strings "<definitionId>_block"/"<definitionId>_audit" - never a bare
        # integer, never a GUID suffix.
        $blockOptionId = "${definitionId}_block"
        $auditOptionId = "${definitionId}_audit"
        $isBlockOrAudit = {
            param($value)
            $text = [string] $value
            return $text -eq $blockOptionId -or $text -eq $auditOptionId
        }.GetNewClosure()

        $ruleSatisfiedByAssigned = $false
        $ruleSatisfiedButUnassigned = $false
        $ruleRedactedAssigned = $false
        $ruleSatisfiedAssignedCount = 0
        $ruleSatisfiedUnassignedCount = 0
        $ruleRedactedAssignedCount = 0
        $rulePresent = $false
        $ruleAnyUnknownAssignment = $false
        $ruleUnknownAssignmentCount = 0

        foreach ($family in $familyNames) {
            $criterion = Resolve-PulseSettingPresenceCriterion -Artifact $artifact -Family $family -DefinitionId $definitionId -IsSatisfyingValue $isBlockOrAudit
            if ($criterion.Present) { $rulePresent = $true }
            if ($criterion.SatisfiedAssignedPolicyCount -gt 0) { $ruleSatisfiedByAssigned = $true }
            if ($criterion.SatisfiedUnassignedPolicyCount -gt 0) { $ruleSatisfiedButUnassigned = $true }
            if ($criterion.RedactedAssignedPolicyCount -gt 0) { $ruleRedactedAssigned = $true }
            $ruleSatisfiedAssignedCount += $criterion.SatisfiedAssignedPolicyCount
            $ruleSatisfiedUnassignedCount += $criterion.SatisfiedUnassignedPolicyCount
            $ruleRedactedAssignedCount += $criterion.RedactedAssignedPolicyCount
            if ($criterion.AnyUnknownAssignment) {
                $anyUnknownAssignment = $true
                $ruleAnyUnknownAssignment = $true
                $totalUnknownAssignmentPolicyCount += $criterion.UnknownAssignmentPolicyCount
                $ruleUnknownAssignmentCount += $criterion.UnknownAssignmentPolicyCount
            }
        }

        if ($ruleSatisfiedByAssigned) {
            $satisfiedRuleNames.Add($standardProtectionRules[$definitionId]) | Out-Null
        } else {
            $unsatisfiedRules.Add($standardProtectionRules[$definitionId]) | Out-Null
            if ($ruleRedactedAssigned) { $anyRedactedAssignedOnUnsatisfied = $true }
            if ($ruleSatisfiedButUnassigned) { $anySatisfiedButUnassigned = $true }
        }

        $evidence.Add(@{
            Identity = $definitionId
            Detail   = @{
                settingDefinitionId             = $definitionId
                ruleName                         = $standardProtectionRules[$definitionId]
                present                          = $rulePresent
                satisfiedAssignedPolicyCount    = $ruleSatisfiedAssignedCount
                satisfiedUnassignedPolicyCount  = $ruleSatisfiedUnassignedCount
                redactedAssignedPolicyCount     = $ruleRedactedAssignedCount
                anyUnknownAssignment            = $ruleAnyUnknownAssignment
                unknownAssignmentPolicyCount    = $ruleUnknownAssignmentCount
            }
            SortKey  = $definitionId
        })
    }

    $unknownDisclosure = if ($anyUnknownAssignment) {
        " $totalUnknownAssignmentPolicyCount polic(ies) carrying one of these rules have a deferred/unknown assignment status (dynamic-group or filter membership could not be resolved) - this was NOT counted as assigned either way."
    } else { '' }

    if ($unsatisfiedRules.Count -eq 0) {
        $reason = "${gapDisclosure}All 3 Standard Protection ASR rules (Block abuse of exploited vulnerable signed drivers, Block credential stealing from LSASS, Block persistence through WMI event subscription) are configured to Block or Audit on at least one assigned policy each (union across policies).${unknownDisclosure}"
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence.ToArray()
    }

    if ($anyRedactedAssignedOnUnsatisfied) {
        $reason = "${gapDisclosure}$($unsatisfiedRules.Count) of 3 Standard Protection ASR rule(s) ($([string]::Join('; ', $unsatisfiedRules))) could not be confirmed - at least one is present on an assigned policy but its value is redacted and could not be read.${unknownDisclosure}"
        return New-PulseFinding -Status Warn -Reason $reason -Evidence $evidence.ToArray()
    }

    $reason = "${gapDisclosure}$($unsatisfiedRules.Count) of 3 Standard Protection ASR rule(s) are not configured to Block or Audit on any confirmed-assigned policy: $([string]::Join('; ', $unsatisfiedRules)).$(if ($anySatisfiedButUnassigned) { ' At least one of these has a correct value on a policy that could not be confirmed as assigned - an unassigned policy protects nothing.' } else { '' })${unknownDisclosure}"
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
}
