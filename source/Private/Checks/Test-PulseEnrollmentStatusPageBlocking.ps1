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
    ambiguous scalar). `allowDeviceUseOnInstallFailure` absent on an existing ESP row is
    undecidable and throws - unlike `assignments`, this is a scalar the rule needs a
    concrete boolean for.

    RULE: zero ESP profiles = NotApplicable (skip - no ESP configured at all, a real and
    not-uncommon tenant state). Otherwise Pass if at least one ASSIGNED ESP profile has
    `allowDeviceUseOnInstallFailure = $false` (blocking enabled); Fail if every ESP profile
    is either unassigned or has blocking disabled. This check asserts only the top-level
    blocking toggle, deliberately not the fuller ESP sub-timeout/app-blocklist depth (per
    the research entry's own scoping note).
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

    $rows = [System.Collections.Generic.List[object]]::new()
    $hasBlockingAssigned = $false

    for ($index = 0; $index -lt $espRows.Count; $index++) {
        $esp = $espRows[$index]

        if (-not (Test-PulseRowPropertyPresent -Row $esp -PropertyName 'allowDeviceUseOnInstallFailure') -or $null -eq $esp.allowDeviceUseOnInstallFailure) {
            throw 'Test-PulseEnrollmentStatusPageBlocking: a windows10EnrollmentCompletionPageConfiguration row is missing allowDeviceUseOnInstallFailure.'
        }

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
        return New-PulseFinding -Status Pass -Reason "At least one assigned Enrollment Status Page (ESP) profile blocks device use until all required apps and profiles are installed."
    }

    $reason = "None of the $($espRows.Count) Enrollment Status Page (ESP) profile(s) configured for this tenant are BOTH assigned AND set to block device use on install failure - users can bypass an incomplete or failed provisioning run and start working on an under-configured, potentially noncompliant device."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $rows.ToArray()
}
