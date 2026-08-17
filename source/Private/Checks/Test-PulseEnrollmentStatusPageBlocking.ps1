<#
    Private: TP.INT.0028 rule function - Enrollment Status Page configured with blocking
    failure behavior (Task 3.3, research-matrix - no Maester origin, practitioner
    judgment).

    LIVE DATASET: shares `deviceEnrollmentConfigurations` (GraphKit 0.1.1 released
    `DeviceEnrollmentConfiguration`/`List`, v1.0) with TP.INT.0025 - the SAME mixed
    collection, filtered here to `#microsoft.graph.windows10EnrollmentCompletionPageConfiguration`
    rows instead. NOT Pending, a deliberate deviation from the research entry's own Notes
    (which assumed ESP needed a beta-only descriptor with "no v1.0 equivalent") - the ESP
    resource type itself, and its `allowDeviceUseOnInstallFailure` property, are both
    present on the already-released v1.0 DeviceEnrollmentConfiguration/List descriptor;
    only some DEEPER ESP sub-settings are beta-only, none of which this check reads.

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-enrollment/windows/setup-status-page,
    fetched for this check - the original research entry's own Authority URL
    (autopilot/enrollment-status) is a valid but thinner overview page; this is the fuller,
    setup-focused canonical URL): the ESP "Block device use until all apps and profiles are
    installed" toggle is documented exactly as No = "Users can leave the ESP before Intune
    is finished setting up the device" / Yes = "Users can't leave the ESP until Intune is
    done" - live-confirmed this is the Graph `allowDeviceUseOnInstallFailure` property
    (No -> blocking enabled -> property is `$false`; live-verified against the
    windows10EnrollmentCompletionPageConfiguration resource's own documented property set).

    FIELD-ABSENCE LENS: `assignments` absent is treated as zero assignments, same
    documented narrow exception as TP.INT.0026 (a relationship-shaped property, not an
    ambiguous scalar). `allowDeviceUseOnInstallFailure` absent is handled by the
    RESOLVED-LIVE rule immediately below - a scalar the rule needs a concrete boolean for,
    but its absence has a known, benign live cause that gets its own explicit outcome
    rather than a bare throw.

    RESOLVED-LIVE (2026-08-17): live-verified against a real tenant's
    DeviceEnrollmentConfiguration/List response - the endpoint returns TRIMMED
    windows10EnrollmentCompletionPageConfiguration rows on the LIST shape: 9 properties
    total, with `allowDeviceUseOnInstallFailure` (and `showInstallationProgress`) simply
    not projected onto it at all. This is a property of the LIST endpoint's projection,
    not a per-tenant configuration difference, so it is either absent from every ESP row
    in a collection or present on every one - never a real mix. Rule: `allowDeviceUseOnInstallFailure`
    absent from EVERY ESP row = NotApplicable, Reason naming the projection limitation and
    the fix it implies (a per-object GET descriptor returning the FULL
    windows10EnrollmentCompletionPageConfiguration shape - not available yet, tracked as a
    future G-batch item, not solved here). Absent from SOME but not all ESP rows in the
    SAME evaluation remains the genuine anomaly the pre-fix code already treated it as (if
    the projection limitation explained the absence it would be absent from every row
    uniformly, never some-but-not-others) - that mixed case still throws.

    RULE: zero ESP profiles = NotApplicable (skip - no ESP configured at all, a real and
    not-uncommon tenant state). Otherwise Pass if at least one ASSIGNED ESP profile has
    `allowDeviceUseOnInstallFailure = $false` (blocking enabled); Fail if every ESP profile
    is either unassigned or has blocking disabled. This check asserts only the top-level
    blocking toggle, deliberately not the fuller ESP sub-timeout/app-blocklist depth (per
    the research entry's own scoping note).

    PASS EVIDENCE (Phase 3 whole-phase review, catalog-coherence finding M1): the Pass
    path now attaches a corroborating per-row evidence summary too, matching
    Test-PulseStaleDevices.ps1's own precedent of never leaving a Pass evidence-empty when
    real per-row data already exists to corroborate it with.
#>

function Test-PulseEnrollmentStatusPageBlocking {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $allRows = @($Datasets.deviceEnrollmentConfigurations)
    $espRows = @($allRows | Where-Object {
        (Test-PulseRowPropertyPresent -Row $_ -PropertyName '@odata.type') -and
        ([string] $_.'@odata.type') -eq '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'
    })

    if ($espRows.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Enrollment Status Page (ESP) profile is configured for this tenant - there is nothing for this check to evaluate.'
    }

    # RESOLVED-LIVE (2026-08-17): count rows where allowDeviceUseOnInstallFailure is
    # present vs absent BEFORE deciding anything - absent from every row is the known,
    # benign List-endpoint projection limitation (NotApplicable); absent from some but not
    # all is a genuine anomaly (still throws). See this file's own docstring.
    $presentCount = 0
    foreach ($esp in $espRows) {
        if ((Test-PulseRowPropertyPresent -Row $esp -PropertyName 'allowDeviceUseOnInstallFailure') -and $null -ne $esp.allowDeviceUseOnInstallFailure) {
            $presentCount++
        }
    }

    if ($presentCount -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason "The live DeviceEnrollmentConfiguration/List endpoint returned $($espRows.Count) Enrollment Status Page (ESP) profile(s), none carrying allowDeviceUseOnInstallFailure - a known projection limitation of that LIST endpoint (it returns a trimmed windows10EnrollmentCompletionPageConfiguration shape), not a tenant configuration gap. Evaluating the blocking toggle requires a per-object GET of each ESP profile, which this check does not yet perform."
    }

    if ($presentCount -ne $espRows.Count) {
        throw "Test-PulseEnrollmentStatusPageBlocking: $($espRows.Count - $presentCount) of $($espRows.Count) windows10EnrollmentCompletionPageConfiguration row(s) are missing allowDeviceUseOnInstallFailure while the rest carry it - a mixed shape the known List-endpoint projection limitation does not explain (it is either absent from every row or present on every row, never a genuine mix)."
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $hasBlockingAssigned = $false

    for ($index = 0; $index -lt $espRows.Count; $index++) {
        $esp = $espRows[$index]

        $assignments = @()
        if ((Test-PulseRowPropertyPresent -Row $esp -PropertyName 'assignments') -and $null -ne $esp.assignments) {
            $assignments = @($esp.assignments)
        }
        $isAssigned = $assignments.Count -gt 0
        $isBlocking = -not [bool] $esp.allowDeviceUseOnInstallFailure

        if ($isAssigned -and $isBlocking) { $hasBlockingAssigned = $true }

        # ORDINAL FALLBACK (Phase 3 whole-phase review, catalog-coherence finding I2): the
        # id-less fallback used to be displayName itself - two id-less ESP profiles sharing
        # a displayName would collide on the same evidence Identity/SortKey pair and
        # degrade the whole evaluation to Error via Assert-PulseEvidenceNoDuplicates.
        # Per-row ordinal ('esp-profile-<index>', 0-based) is guaranteed unique within one
        # evaluation.
        $identity = if (Test-PulseRowPropertyPresent -Row $esp -PropertyName 'id') { [string] $esp.id } else { "esp-profile-$index" }
        $rows.Add(@{
            Identity = $identity
            Detail   = @{
                displayName                    = $esp.displayName
                assignmentCount                = $assignments.Count
                allowDeviceUseOnInstallFailure = [bool] $esp.allowDeviceUseOnInstallFailure
            }
            SortKey  = $identity
        })
    }

    if ($hasBlockingAssigned) {
        # M1 (Phase 3 whole-phase review): Pass now carries a corroborating per-profile
        # evidence row too, consistent with Test-PulseStaleDevices.ps1's own precedent of
        # never leaving a Pass evidence-empty when real per-row data already exists to
        # corroborate it with.
        return New-PulseFinding -Status Pass -Reason "At least one assigned Enrollment Status Page (ESP) profile blocks device use until all required apps and profiles are installed." -Evidence $rows.ToArray()
    }

    $reason = "None of the $($espRows.Count) Enrollment Status Page (ESP) profile(s) configured for this tenant are BOTH assigned AND set to block device use on install failure - users can bypass an incomplete or failed provisioning run and start working on an under-configured, potentially noncompliant device."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $rows.ToArray()
}
