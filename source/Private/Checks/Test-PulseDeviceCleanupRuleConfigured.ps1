<#
    Private: TP.INT.0007 rule function - Intune managed-device clean-up rule configured
    (Task 3.2, Maester port MT.1053 - Test-MtManagedDeviceCleanupSettings, MIT).

    ADAPTED, NOT A LINE-FOR-LINE PORT (live-verified divergence): Maester's own function
    queries the newer per-platform RULES collection, `deviceManagement/managedDeviceCleanupRules`
    (plural - each row a distinct rule with displayName/deviceCleanupRulePlatformType/
    deviceInactivityBeforeRetirementInDays). The GraphKit descriptor actually released
    (0.1.1, Type 'DeviceCleanupRule', Operation 'Get') instead resolves to the OLDER,
    simpler SINGLETON resource `deviceManagement/managedDeviceCleanupSettings` - one
    tenant-wide deviceInactivityBeforeRetirementInDays value, no per-platform rows, no
    displayName/platform to report per-rule (live-confirmed via Microsoft Graph's own
    managedDeviceCleanupSettings resource doc, which shows exactly one property on this
    resource: https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevicecleanupsettings).
    This check is ported against the descriptor that actually exists, not the one
    Maester's own implementation happens to call - same field-absence/zero-as-fail
    semantics, but Evidence carries the one tenant-wide value TenantPulse can actually
    read, not a per-rule table.

    CORRECTED CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules, fetched
    for this check - an earlier research-entry draft said cleanup rules "delete
    managed-device records"; the live doc says otherwise): device clean-up rules only
    HIDE stale device records from the admin center/reports - "Don't trigger any actions
    on the device (no wipe or retire)", and a hidden device reappears automatically if it
    checks back in before its device certificate expires. This check's Consulting text
    reflects that corrected behavior throughout, never "deletes".

    RULE: Fail when deviceInactivityBeforeRetirementInDays is absent, $null, blank, or
    resolves to 0 (Maester's own "falsy or zero" condition, ported verbatim) - Pass
    otherwise. The property is documented as a String type on the Graph resource (a known
    Graph-doc quirk - see this file's own inline note) but always carries a numeric day
    count in practice; parsed defensively rather than assumed to be a native [int].
#>

function Test-PulseDeviceCleanupRuleConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $rows = @($Datasets.managedDeviceCleanupSettings)
    if ($rows.Count -eq 0) {
        throw 'Test-PulseDeviceCleanupRuleConfigured: managedDeviceCleanupSettings dataset returned no rows - the service returned nothing to evaluate for this tenant-wide singleton.'
    }

    $rawValue = $rows[0].deviceInactivityBeforeRetirementInDays
    $days = 0
    $hasValue = $false
    if ($null -ne $rawValue -and [string]$rawValue -ne '') {
        $parsed = 0
        if ([int]::TryParse([string] $rawValue, [ref] $parsed)) {
            $days = $parsed
            $hasValue = $true
        }
    }

    $evidence = @(
        @{
            Identity = 'managedDeviceCleanupSettings'
            Detail   = @{ deviceInactivityBeforeRetirementInDays = $rawValue }
            SortKey  = 'managedDeviceCleanupSettings'
        }
    )

    if (-not $hasValue -or $days -eq 0) {
        $reason = 'No Intune device clean-up rule is configured: deviceInactivityBeforeRetirementInDays is absent or 0, so Intune never automatically hides stale managed-device records from the admin center - the device count/compliance-rate view can drift indefinitely stale without anyone noticing.'
        return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
    }

    $reason = "A device clean-up rule is configured: devices that have not checked in for $days day(s) are automatically hidden from the Intune admin center and reports (the device is not wiped or retired - it simply stops appearing until it checks in again or its certificate expires)."
    return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence
}
