<#
    Private: TP.INT.0025 rule function - Personally-owned Windows device enrollment
    blocked (Task 3.3, research-matrix - no Maester origin, practitioner judgment from
    Microsoft's own enrollment-restrictions guidance).

    LIVE DATASET: `deviceEnrollmentConfigurations` maps to GraphKit 0.1.1's released
    `DeviceEnrollmentConfiguration`/`List` (v1.0) descriptor, PathTemplate
    `/deviceManagement/deviceEnrollmentConfigurations` - confirmed via a live
    Get-GraphOperation -List enumeration, NOT Pending. Shared with TP.INT.0028 (ESP), which
    reads the SAME raw dataset filtered to a different derived type.

    MIXED-COLLECTION FILTER: deviceEnrollmentConfigurations returns every enrollment
    restriction/limit/ESP/etc. configuration in one flat collection, distinguished per row
    by `@odata.type`. This rule filters to
    `#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration` rows only, then
    reads `windowsRestriction.personalDeviceEnrollmentBlocked` (live-verified property path
    against the deviceEnrollmentPlatformRestriction sub-resource's own documented shape,
    Graph v1.0/beta).

    CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/device-enrollment/restrictions, fetched for
    this check): personal-Windows-device blocking is real and works by AUTHORIZING specific
    corporate enrollment paths (Windows Autopilot, GPO/co-management auto-enrollment, bulk
    provisioning package, device enrollment manager) rather than by device-attribute
    inspection - "Intune checks to make sure that each new Windows enrollment request has
    been authorized for corporate enrollment. Unauthorized enrollments are blocked." The
    same page is EXPLICIT that this restriction "applies to enrollments that are user-driven"
    only - Autopilot self-deploying/pre-provisioned, bulk enrollment, co-managed
    enrollments, and several other scenarios always use the DEFAULT policy regardless of
    any custom restriction. This rule therefore only evaluates the tenant's DEFAULT
    platform-restrictions policy (priority defines which one is default; Maester-equivalent
    behavior does not exist here, so "default" is read directly from the row's own
    priority/id shape rather than assumed positionally - see below).

    DEFAULT-POLICY SELECTION: Intune always applies exactly one platform-restrictions
    policy as the tenant default, identified by the LOWEST `priority` value among rows of
    this type (the documented "one default policy... applies... until you assign a
    higher-priority policy" behavior) - ties are impossible in a real tenant (Intune
    enforces unique priorities), but a defensive ordinal-stable pick (lowest priority, then
    lowest id) is used rather than assuming array order.

    FIELD-ABSENCE LENS: `@odata.type` absent on a row is skipped (cannot classify it, not
    treated as a platform-restrictions row); `windowsRestriction` or its own
    `personalDeviceEnrollmentBlocked` absent on the selected default row is undecidable and
    throws.

    RULE: zero deviceEnrollmentConfigurations rows, or zero rows of the platform-
    restrictions type, is NotApplicable (no restriction policy exists at all - an
    unexpected but not-impossible tenant state, not silently treated as "blocked"). Pass
    when the default policy's `windowsRestriction.personalDeviceEnrollmentBlocked` is
    `$true`; Fail otherwise. Per the research entry's own Notes, a Fail here is a
    LOW-CONFIDENCE finding when the tenant enrolls exclusively via Autopilot (see
    TP.INT.0026) - the Consulting text softens accordingly rather than this rule
    cross-referencing that check directly (keeping this check single-dataset and simple).
#>

function Test-PulsePersonalWindowsEnrollmentBlocked {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $allRows = @($Datasets.deviceEnrollmentConfigurations)
    $restrictionRows = @($allRows | Where-Object {
        (Test-PulseRowPropertyPresent -Row $_ -PropertyName '@odata.type') -and
        ([string] $_.'@odata.type') -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
    })

    if ($restrictionRows.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No device platform enrollment restriction policy was found for this tenant - there is nothing for this check to evaluate.'
    }

    foreach ($row in $restrictionRows) {
        if (-not (Test-PulseRowPropertyPresent -Row $row -PropertyName 'priority') -or $null -eq $row.priority) {
            throw 'Test-PulsePersonalWindowsEnrollmentBlocked: a deviceEnrollmentPlatformRestrictionsConfiguration row is missing priority - cannot identify the tenant default policy.'
        }
    }

    $sorted = @($restrictionRows | Sort-Object -Property @{ Expression = { [int] $_.priority } }, @{ Expression = { [string] $_.id } })
    $default = $sorted[0]

    if (-not (Test-PulseRowPropertyPresent -Row $default -PropertyName 'windowsRestriction') -or $null -eq $default.windowsRestriction) {
        throw 'Test-PulsePersonalWindowsEnrollmentBlocked: the default platform restrictions policy is missing windowsRestriction.'
    }

    $windowsRestriction = $default.windowsRestriction
    if (-not (Test-PulseRowPropertyPresent -Row $windowsRestriction -PropertyName 'personalDeviceEnrollmentBlocked') -or $null -eq $windowsRestriction.personalDeviceEnrollmentBlocked) {
        throw 'Test-PulsePersonalWindowsEnrollmentBlocked: the default policy''s windowsRestriction is missing personalDeviceEnrollmentBlocked.'
    }

    $blocked = [bool] $windowsRestriction.personalDeviceEnrollmentBlocked

    $evidence = @(
        @{
            Identity = [string] $default.id
            Detail   = @{ displayName = $default.displayName; priority = $default.priority; personalDeviceEnrollmentBlocked = $blocked }
            SortKey  = [string] $default.id
        }
    )

    if ($blocked) {
        return New-PulseFinding -Status Pass -Reason 'The tenant''s default Windows device platform restriction policy blocks personally-owned Windows device enrollment - Windows enrollment is limited to corporate-authorized paths (Autopilot, GPO/co-management, bulk provisioning, device enrollment manager).' -Evidence $evidence
    }

    return New-PulseFinding -Status Fail -Reason 'The tenant''s default Windows device platform restriction policy does NOT block personally-owned Windows device enrollment - any Windows device can enroll via user-driven methods (Company Portal, Add Work Account, MDM-only), expanding the unmanaged-endpoint attack surface. This restriction only governs user-driven enrollment; a fleet enrolled exclusively via Windows Autopilot may not need this control - cross-check TP.INT.0026 before treating this as urgent.' -Evidence $evidence
}
