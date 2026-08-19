<#
    Private: TP.INT.0017 rule function - at least one App Control for Business
    (WDAC) policy is in Enforce mode with an active control (built-in controls
    selected, or a non-empty uploaded XML payload). Maester MT.1179 port
    (`Test-MtIntuneAppControl`, MIT).

    ARTIFACT, NOT A DATASET: reads $Context.ArtifactReader.GetSettingPresenceIndex()
    via Data.Expansions = @('settingPresenceIndex') - never streams jsonl.

    SAME-POLICY AND: Pass requires enforce + active control on ONE policy.
    A tenant that audits on policy A and uploads empty XML on policy B Fails.
    Classification is Get-PulseAppControlPolicyStates (corpus-verified live
    ids; Maester's dead `..._policy` / `*upload_policy_selected` strings are
    NOT used - see that helper's docstring).

    ASSIGNMENT: Settings Catalog assignments are still deferred (G-gate).
    Matching Maester, policy existence is enough - not confirmed-assigned.

    HONESTY:
      - Artifact not Available -> NotApplicable, quoting the artifact Reason.
      - PARTIAL SCAN prefix when -Artifact.Gaps is non-empty (TP.INT.0006).
      - Redacted build-options / audit-mode / XML-on-upload on a policy that
        would otherwise be the only candidate -> Warn, never Pass.
      - Unknown-assignment disclosure is appended whenever true; it does not
        change Pass/Fail (assignments are not part of this check's bar).
#>

function Test-PulseAppControlPolicyEnforcing {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    if (-not $Context -or -not $Context.ContainsKey('ArtifactReader') -or $null -eq $Context.ArtifactReader) {
        throw 'Test-PulseAppControlPolicyEnforcing: no $Context.ArtifactReader was supplied - this rule cannot read the settingPresenceIndex expansion artifact without it.'
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

    $classified = Get-PulseAppControlPolicyStates -Artifact $artifact
    $policies = @($classified.Policies)
    $unknownDisclosure = if ($classified.AnyUnknownAssignment) {
        ' One or more App Control settings sit on a policy whose assignment status is deferred/unknown (Settings Catalog assignments are not collected in this slice) - assignment is not part of this check''s bar.'
    } else { '' }

    $evidence = @(
        $policies | ForEach-Object {
            @{
                Identity = $_.PolicyId
                Detail   = @{
                    policyId         = $_.PolicyId
                    buildOptions     = $_.BuildOptions
                    auditMode        = $_.AuditMode
                    hasActiveControl = $_.HasActiveControl
                    enforcing        = $_.Enforcing
                }
                SortKey  = $_.PolicyId
            }
        }
    )

    $passing = @($policies | Where-Object { $_.Enforcing -and $_.HasActiveControl })
    if ($passing.Count -gt 0) {
        $reason = "${gapDisclosure}$($passing.Count) of $($policies.Count) App Control for Business polic$(if ($policies.Count -eq 1) { 'y is' } else { 'ies are' }) in Enforce mode with an active control (built-in controls, or a non-empty uploaded XML payload).${unknownDisclosure}"
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
    }

    $undecidable = @($policies | Where-Object {
            ($_.AuditRedacted -or $_.ActiveControlUnknown) -and -not ($_.Enforcing -and $_.HasActiveControl)
        })
    if ($undecidable.Count -gt 0) {
        $reason = "${gapDisclosure}$($undecidable.Count) App Control for Business polic$(if ($undecidable.Count -eq 1) { 'y has' } else { 'ies have' }) a redacted enforce-mode or active-control value, so this check cannot confirm an enforcing policy with an active control.${unknownDisclosure}"
        return New-PulseFinding -Status Warn -Reason $reason -Evidence $evidence
    }

    if ($policies.Count -eq 0) {
        $reason = "${gapDisclosure}No App Control for Business policy is configured (no applicationcontrolv2 build-options / audit-mode / XML-upload setting present in the settings-catalog expansion).${unknownDisclosure}"
        return New-PulseFinding -Status Fail -Reason $reason
    }

    $reason = "${gapDisclosure}None of $($policies.Count) App Control for Business polic$(if ($policies.Count -eq 1) { 'y is' } else { 'ies are' }) in Enforce mode with an active control (built-in controls, or a non-empty uploaded XML payload). Audit-only policies and upload-mode policies with an empty XML payload do not block untrusted executables.${unknownDisclosure}"
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
