<#
    Private: TP.INT.0018 rule function - a Managed Installer configuration is
    enabled AND backed by an App Control policy that is itself in Enforce mode
    with an active control. Maester MT.1180 port
    (`Test-MtIntuneManagedInstallerRules`, MIT).

    ARTIFACT, NOT A DATASET: reads $Context.ArtifactReader.GetSettingPresenceIndex()
    via Data.Expansions = @('settingPresenceIndex') - never streams jsonl.

    SAME-POLICY AND / DEPENDENCY TRAP: Pass requires Managed Installer enabled
    on a policy that ALSO satisfies TP.INT.0017's own bar (enforce + active
    control). Managed Installer on an audit-only policy, or on an enforce-mode
    upload with empty XML, is a false sense of protection and Fails.

    Classification is Get-PulseAppControlPolicyStates (corpus-verified live
    ids; see that helper's docstring for the Maester-dead-id correction).

    ASSIGNMENT: Settings Catalog assignments are still deferred (G-gate).
    Matching Maester, policy existence is enough.

    HONESTY: same NotApplicable / PARTIAL SCAN / redaction-Warn / unknown-
    assignment disclosure contract as TP.INT.0017.
#>

function Test-PulseManagedInstallerPairedWithEnforcingAppControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    if (-not $Context -or -not $Context.ContainsKey('ArtifactReader') -or $null -eq $Context.ArtifactReader) {
        throw 'Test-PulseManagedInstallerPairedWithEnforcingAppControl: no $Context.ArtifactReader was supplied - this rule cannot read the settingPresenceIndex expansion artifact without it.'
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
                    policyId          = $_.PolicyId
                    buildOptions      = $_.BuildOptions
                    auditMode         = $_.AuditMode
                    managedInstaller  = $_.ManagedInstaller
                    hasActiveControl  = $_.HasActiveControl
                    enforcing         = $_.Enforcing
                }
                SortKey  = $_.PolicyId
            }
        }
    )

    $passing = @($policies | Where-Object {
            $_.Enforcing -and $_.HasActiveControl -and $_.ManagedInstaller -eq 'enabled'
        })
    if ($passing.Count -gt 0) {
        $reason = "${gapDisclosure}$($passing.Count) of $($policies.Count) App Control for Business polic$(if ($policies.Count -eq 1) { 'y is' } else { 'ies are' }) in Enforce mode with an active control AND Managed Installer enabled.${unknownDisclosure}"
        return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
    }

    $undecidable = @($policies | Where-Object {
            ($_.AuditRedacted -or $_.ActiveControlUnknown -or $_.ManagedInstallerRedacted) -and -not (
                $_.Enforcing -and $_.HasActiveControl -and $_.ManagedInstaller -eq 'enabled'
            )
        })
    if ($undecidable.Count -gt 0) {
        $reason = "${gapDisclosure}$($undecidable.Count) App Control for Business polic$(if ($undecidable.Count -eq 1) { 'y has' } else { 'ies have' }) a redacted enforce-mode, active-control, or Managed Installer value, so this check cannot confirm Managed Installer on an enforcing policy with an active control.${unknownDisclosure}"
        return New-PulseFinding -Status Warn -Reason $reason -Evidence $evidence
    }

    if ($policies.Count -eq 0) {
        $reason = "${gapDisclosure}No App Control for Business policy is configured, so Managed Installer cannot be paired with an enforcing App Control policy.${unknownDisclosure}"
        return New-PulseFinding -Status Fail -Reason $reason
    }

    $auditMi = @($policies | Where-Object { $_.ManagedInstaller -eq 'enabled' -and -not $_.Enforcing }).Count
    $emptyXmlMi = @($policies | Where-Object { $_.ManagedInstaller -eq 'enabled' -and $_.Enforcing -and -not $_.HasActiveControl }).Count
    $suffix = ''
    if ($auditMi -gt 0) {
        $suffix += " $auditMi polic$(if ($auditMi -eq 1) { 'y has' } else { 'ies have' }) Managed Installer enabled on an audit-only (or unenforced) App Control policy, which does not actively trust deployed apps."
    }
    if ($emptyXmlMi -gt 0) {
        $suffix += " $emptyXmlMi polic$(if ($emptyXmlMi -eq 1) { 'y is' } else { 'ies are' }) in Enforce mode with Managed Installer enabled but no active control (empty XML upload)."
    }

    $reason = "${gapDisclosure}None of $($policies.Count) App Control for Business polic$(if ($policies.Count -eq 1) { 'y has' } else { 'ies have' }) Managed Installer enabled on an Enforce-mode policy with an active control.${suffix}${unknownDisclosure}"
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
