<#
    Private: TP.INT.0012 rule function - Windows Feature Update policy avoids
    end-of-support builds (Task 3.2, Maester port MT.1102 - Test-MtFeatureUpdatePolicy,
    MIT).

    DATASET (live): GraphKit 0.2.2 shipped the official descriptor and DatasetMap now treats
    this dataset as live. Type `WindowsFeatureUpdateProfile`, Operation `List`,
    ApiVersion `beta`; this check evaluates live tenant data.

    DETERMINISM: "is endOfSupportDate in the past" needs an "as of when" reference.
    Maester's own function compares against Get-Date (wall-clock, live-evaluation time) -
    TenantPulse's own evaluation model forbids that (re-evaluating the SAME snapshot must
    be byte-identical every time; see Invoke-PulseEvaluation's own docstring). This rule
    instead compares against $Context.EvaluationCutoffBase (falling back to
    SnapshotCreatedUtc), exactly like Test-PulseStaleDevices.ps1's own established
    pattern - "as of the moment this snapshot was collected", not "as of right now".

    RULE (ported from Maester's own filter, adapted for determinism as above -
    live-verified against
    https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education,
    fetched for this check, which confirms real historical endOfSupportDate values exist
    per Windows 11 feature-update version, e.g. version 22H2 -> 2025-10-15): Fail when any
    profile's endOfSupportDate is on/before the cutoff. Pass when every profile's
    endOfSupportDate is after the cutoff (or absent - see below). NotApplicable
    (skip-if-none-configured, MIRRORING Maester's own ItemNotFoundException ->
    SkippedBecause Custom behavior - the research entry's own Notes call this out
    explicitly) when zero profiles are configured at all, which is a legitimately empty
    List result, distinct from an unparseable/absent endOfSupportDate on an EXISTING
    profile (which this rule treats as "cannot prove this profile is a problem" and
    excludes from the offending set, rather than guessing either way - field-absence
    lens).
#>

function Test-PulseFeatureUpdatePolicyAvoidsEos {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $profiles = @($Datasets.windowsFeatureUpdateProfiles)

    if ($profiles.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Windows Feature Update deployment profiles are configured for this tenant - there is nothing for this check to evaluate (mirrors Maester''s own skip-if-none-configured behavior for this check, not a Pass).'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }

    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseFeatureUpdatePolicyAvoidsEos: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied - this rule cannot determine "as of when" to compare endOfSupportDate without it.'
    }

    $cutoff = [datetime]::Parse($cutoffBaseText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)

    $offending = [System.Collections.Generic.List[object]]::new()
    foreach ($profile in $profiles) {
        $eosText = [string] $profile.endOfSupportDate
        if ([string]::IsNullOrWhiteSpace($eosText)) { continue }

        $eosDate = $null
        try {
            $eosDate = [datetime]::Parse($eosText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        } catch {
            continue
        }

        if ($eosDate -le $cutoff) {
            $offending.Add($profile)
        }
    }

    if ($offending.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "None of the $($profiles.Count) Windows Feature Update profile(s) target a Windows version/build whose end-of-support date has already passed."
    }

    $evidence = ConvertTo-PulseMaesterEvidence -Rows $offending.ToArray() -IdentityProperty 'id' -SortKeyProperty 'displayName' -DetailProperties @('displayName', 'featureUpdateVersion', 'endOfSupportDate')

    $reason = "$($offending.Count) of $($profiles.Count) Windows Feature Update profile(s) target a Windows version/build whose end-of-support date has already passed - devices targeted by these profiles receive no further security updates for that OS version until the profile is updated to a currently-supported feature update version."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
