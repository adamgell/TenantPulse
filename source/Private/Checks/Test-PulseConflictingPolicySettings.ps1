<#
    Private: TP.INT.0006 rule function - conflicting security-setting values across two or
    more Settings Catalog / configuration policies (Task 3.1).

    ARTIFACT, NOT A DATASET (see this task's own standing-constraint note): this check's
    real input is Task 2.6's expanded/conflicts.json artifact, read via
    $Context.ArtifactReader.GetConflictArtifact() (Invoke-PulseEvaluation's own opt-in
    $Context wiring - see that function's own docstring, and New-PulseArtifactReader's own
    docstring for why a rule receives this narrow, read-only accessor rather than a raw
    $Store handle) - never a raw Graph dataset streamed row by row. Data.Datasets still
    declares 'configurationPolicies' (a real, already-DatasetMap-registered, Read/Safe
    dataset) purely to satisfy the descriptor schema's non-empty-Datasets requirement and
    to give the engine SOME signal that Intune Settings Catalog data was collected for this
    tenant at all - this check's OWN NotApplicable-vs-Pass/Warn/Fail decision is made
    entirely from the conflicts artifact, not from that dataset's rows (which this rule
    never reads). ACCEPTED WART, one-off until T3.2 (per the phase-3 plan amendment): a
    proper Data.Expansions declaration shape belongs in the descriptor schema instead of
    reusing Data.Datasets for a dataset the rule does not actually read - out of scope for
    this task.

    FOUR-STATE DEGRADE (this task's own brief): when the conflicts artifact is not
    'Available' (no manifest.expansions.conflicts entry at all, or a recorded
    NotExpanded/Failed status - i.e. -ExpandSettings was never run for this snapshot, or
    it ran and failed), this check returns NotApplicable, quoting
    Get-PulseConflictArtifact's own Reason (itself either "no entry" text this rule
    supplies, or the expansions entry's OWN recorded reason, verbatim) - never a silent
    Pass. A hash-mismatch on a supposedly-'Expanded' artifact is NOT caught here - it
    propagates as a thrown exception, which Invoke-PulseCheckEvaluation turns into this
    check's Error status (see Get-PulseConflictArtifact's own docstring for why that
    distinction matters: "expansion wasn't run" is a normal NotApplicable, "the file no
    longer matches what the manifest recorded" is a data-integrity failure that must never
    be reported as a confident finding of any kind).

    RULE SEMANTICS (verbatim from this task's brief, never collapsing 'possible'/'unknown'
    into a false positive or a false negative):
      - Pass: the artifact is Available and holds ZERO conflicts.
      - Fail: at least one conflict has assignmentOverlap 'proven' or 'possible'.
      - Warn: at least one conflict exists, but NONE has assignmentOverlap 'proven' or
        'possible' (this covers both the literal "all conflicts are 'unknown'" case the
        brief names explicitly - the deferred-assignments state, T2.6's own
        ASSIGNMENTS-DEFERRED clause - AND the narrower case of a conflict set that mixes
        'unknown' with 'none' but never rises to 'possible'/'proven'. The brief is
        explicit that a 'none' conflict "does not drive Fail on its own" but says nothing
        about it driving a silent Pass either - real setting-value divergence exists in
        both cases, so BOTH degrade to Warn, never a false-confident Pass. See Ivy24's own
        live-gate breakdown recorded in docs/STATUS.md's "Phase 2 (Settings expansion,
        core slice T2.1-T2.7)" section, "Conflicts: real conflicts surfaced" bullet: 165
        total conflicts, assignmentOverlap none=8/possible=34/unknown=123 -> Fail, driven
        purely by the 34 possible - the 8 'none' conflicts are exactly the "worth
        evidence, does not drive Fail on its own" case this rule's Warn/Fail split is
        built to keep honest).

    PRODUCT BEHAVIOR, LIVE-VERIFIED (Task 3.1 review-fix round - an earlier draft of this
    check's own Consulting text asserted the OPPOSITE and was corrected): Microsoft's own
    guidance (learn.microsoft.com/en-us/intune/solutions/education/tutorial-school-deployment/policy-conflicts,
    fetched and verified live for this fix) states plainly: "When conflicts occur, Intune
    generates an error and doesn't apply either setting." This is NOT a last-writer-wins /
    silent-success outcome - it is an ENFORCEMENT GAP: neither policy's value reaches the
    device for the conflicting setting, and the failure is only visible by proactively
    checking Devices > Monitor > Configuration policy assignment failure. Every
    product-behavior claim in this file and its descriptor is written to match that
    verified behavior, not the plausible-sounding-but-wrong last-writer-wins assumption an
    earlier draft made.

    SEVERITY ESCALATION IS OUT OF SCOPE (deliberate, documented, not a gap): the research
    entry names a per-conflict severity escalation (Medium -> High for BitLocker/ASR/LAPS
    CSP definitionIds) as a design intention, but TenantPulse's finding schema has no
    per-instance severity override today - Invoke-PulseEvaluation always stamps a
    finding's severity from its check descriptor's own static Severity field, for every
    check in the catalog, with no mechanism for a rule to override it per-conflict. Adding
    that mechanism is out of this task's YAGNI-bounded scope (it would be an engine change
    touching every check, not a TP.INT.0006-specific one) - the descriptor's Severity
    stays a static 'Medium', and the escalation stays a REVIEWER judgment call surfaced in
    this check's own Consulting text (definitionId is present in every conflict's evidence
    Identity, so a reviewer can still make that call by eye) rather than an automated one.

    EVIDENCE: one entry per conflict, Identity = settingDefinitionId (T2.6's own
    conflict-record identity, unique per definitionId within one conflicts.json), built via
    the Maester shim's ConvertTo-PulseMaesterEvidence (Convert-PulseMaesterAdapter.ps1,
    this same task) rather than hand-rolling the same {Identity;Detail;SortKey} mapping a
    ported Maester check body will need too. Detail carries settingName, nameVariants,
    values (policy names + concrete/redacted values per T2.6's own conflict-record shape),
    assignmentOverlap and assignmentOverlapReason - a reader gets the full four-state
    picture per conflict, never a collapsed true/false.
#>

function Test-PulseConflictingPolicySettings {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    if (-not $Context -or -not $Context.ContainsKey('ArtifactReader') -or $null -eq $Context.ArtifactReader) {
        throw 'Test-PulseConflictingPolicySettings: no $Context.ArtifactReader was supplied - this rule cannot read the conflicts expansion artifact without it (see Invoke-PulseEvaluation''s own ArtifactReader wiring note).'
    }

    $artifact = $Context.ArtifactReader.GetConflictArtifact()

    if ($artifact.Status -ne 'Available') {
        return New-PulseFinding -Status NotApplicable -Reason $artifact.Reason
    }

    $conflicts = @($artifact.Conflicts)

    if ($conflicts.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason 'No conflicting security-setting values were detected across the expanded Settings Catalog / configuration policy index for this snapshot.'
    }

    $evidence = ConvertTo-PulseMaesterEvidence -Rows $conflicts -IdentityProperty 'settingDefinitionId' -DetailProperties @('settingName', 'nameVariants', 'values', 'assignmentOverlap', 'assignmentOverlapReason')

    $provenCount = @($conflicts | Where-Object { $_.assignmentOverlap -eq 'proven' }).Count
    $possibleCount = @($conflicts | Where-Object { $_.assignmentOverlap -eq 'possible' }).Count
    $unknownCount = @($conflicts | Where-Object { $_.assignmentOverlap -eq 'unknown' }).Count
    $noneCount = @($conflicts | Where-Object { $_.assignmentOverlap -eq 'none' }).Count

    if ($provenCount -gt 0 -or $possibleCount -gt 0) {
        $reason = "$($conflicts.Count) conflicting setting(s) found across policies, and assignment-scope overlap is confirmed or cannot be ruled out for $($provenCount + $possibleCount) of them ($provenCount proven, $possibleCount possible, $unknownCount unknown, $noneCount none) - per Microsoft's own guidance, Intune generates an error and applies NEITHER setting for a proven/possible conflict, so the intended configuration is not enforced on the affected devices until this is resolved (see Devices > Monitor > Configuration policy assignment failure)."
        return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
    }

    $reason = "$($conflicts.Count) conflicting setting(s) found across policies, but assignment-scope overlap could not be determined for any of them ($unknownCount unknown, $noneCount none) - see each conflict's own assignmentOverlapReason (typically assignments-deferred pending a GraphKit release) before treating this as safe; an overlap that later resolves to proven/possible means Intune will generate an error and enforce neither policy's value on the affected devices."
    return New-PulseFinding -Status Warn -Reason $reason -Evidence $evidence
}
