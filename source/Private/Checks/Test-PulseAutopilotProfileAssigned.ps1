<#
    Private: TP.INT.0026 rule function - Windows Autopilot deployment profile exists and
    is assigned (Task 3.3, research-matrix - no Maester origin, practitioner judgment).

    DATASET (live): GraphKit 0.2.2 shipped the official descriptor and DatasetMap now treats
    this dataset as live. Type `WindowsAutopilotDeploymentProfile`, Operation `List`,
    ApiVersion `beta`; this check evaluates live tenant data.

    CLAIM (live-verified against https://learn.microsoft.com/en-us/autopilot/, fetched for
    this check - the page is a valid, current landing page linking Windows Autopilot
    overview/requirements/device-registration/ESP/manual-registration articles): confirms
    Windows Autopilot and its device-preparation successor are both live, current Microsoft
    products, not deprecated.

    DEVICE-PREPARATION CAVEAT (per the research entry's own Notes): Microsoft is actively
    transitioning tenants toward "device preparation" policies as a classic-Autopilot
    alternative. This rule evaluates CLASSIC deployment profiles only (the resource this
    dataset represents) - a tenant fully migrated to device preparation could legitimately
    show zero classic profiles and still have a working zero-touch story. That alternate
    pass path is intentionally NOT implemented in this v1 (device-preparation policies are
    a different, not-yet-covered Graph resource) - the Consulting text says so explicitly
    so a NotApplicable/Fail here is read with that caveat, rather than this rule silently
    guessing device-preparation coverage it cannot see.

    FIELD-ABSENCE LENS: `assignments` absent entirely on a profile row is treated the same
    as an empty array (Graph consistently omits an empty relationship in some response
    shapes) - NOT thrown, since "no assignments" is a decidable, common, and expected shape
    for this specific relationship (unlike an expiry date, absence here is not ambiguous:
    Maester itself, and Microsoft's own $expand=assignments contract, return either an
    empty array or an absent property for "no assignments", never $null-meaning-something-
    else). This is a deliberate, documented exception to the field-absence-throws default,
    scoped narrowly to this one relationship-shaped property.

    RULE: zero profiles configured = NotApplicable (mirrors the sibling checks'
    skip-if-none-configured framing - Autopilot may genuinely not be in use, or the tenant
    may be fully on device preparation, see above). Otherwise Pass if at least one profile
    has a non-empty `assignments` array; Fail if every profile has zero assignments.
#>

function Test-PulseAutopilotProfileAssigned {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $profiles = @($Datasets.windowsAutopilotDeploymentProfiles)
    if ($profiles.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Windows Autopilot deployment profiles are configured for this tenant - classic Windows Autopilot zero-touch provisioning is not in use (or the tenant may be fully migrated to Windows Autopilot device preparation, a separate resource this check does not evaluate), so there is nothing for this check to evaluate.'
    }

    $assignedCount = 0
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $profiles.Count; $index++) {
        $profile = $profiles[$index]

        $assignments = @()
        if ((Test-PulseRowPropertyPresent -Row $profile -PropertyName 'assignments') -and $null -ne $profile.assignments) {
            $assignments = @($profile.assignments)
        }
        $hasAssignment = $assignments.Count -gt 0
        if ($hasAssignment) { $assignedCount++ }

        # ORDINAL FALLBACK (Phase 3 whole-phase review, catalog-coherence finding I2): the
        # id-less fallback used to be displayName itself - two id-less profiles sharing a
        # displayName would collide on the same evidence Identity/SortKey pair and degrade
        # the whole evaluation to Error via Assert-PulseEvidenceNoDuplicates. Per-row
        # ordinal ('autopilot-profile-<index>', 0-based) is guaranteed unique within one
        # evaluation.
        $identity = if (Test-PulseRowPropertyPresent -Row $profile -PropertyName 'id') { [string] $profile.id } else { "autopilot-profile-$index" }
        $rows.Add(@{
            Identity = $identity
            Detail   = @{ displayName = $profile.displayName; assignmentCount = $assignments.Count }
            SortKey  = $identity
        })
    }

    if ($assignedCount -gt 0) {
        return New-PulseFinding -Status Pass -Reason "$assignedCount of $($profiles.Count) Windows Autopilot deployment profile(s) have at least one assignment - registered Autopilot devices covered by an assigned profile receive the intended out-of-box provisioning experience." -Evidence $rows.ToArray()
    }

    return New-PulseFinding -Status Fail -Reason "None of the $($profiles.Count) Windows Autopilot deployment profile(s) configured for this tenant have any assignment - registered Autopilot devices fall through to standard Azure AD Join/manual setup instead of the intended zero-touch provisioning experience until at least one profile is assigned to a group." -Evidence $rows.ToArray()
}
