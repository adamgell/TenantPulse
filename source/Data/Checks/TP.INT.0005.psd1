@{
    Id         = 'TP.INT.0005'
    Title      = 'Devices inactive for more than 90 days'
    Category   = 'Intune.DeviceLifecycle'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('managedDevices', 'entraDevices')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseStaleDevices'
    }
    Consulting = @{
        WhatItMeans  = 'Reports devices with no recorded check-in activity in over 90 days, from TWO genuinely different populations: Intune-managed devices (managedDevices.lastSyncDateTime) and Entra-registered devices (entraDevices.approximateLastSignInDateTime). These are not the same device count in most tenants - a device can be Entra-registered (has an identity, can authenticate) without ever being Intune-enrolled, and this check also surfaces that population gap directly, because an Entra-registered-but-unmanaged device is itself a coverage finding.'
        WhyItMatters = 'A stale device is an unpatched, unmonitored, un-reviewed endpoint sitting in inventory - it still counts against license totals, can still authenticate if its credentials are valid, and its compliance state is stale data an admin might mistakenly trust. Microsoft''s own device-lifecycle guidance (Intune cleanup rules, Entra stale-device management) exists specifically because this backlog accumulates silently otherwise.'
        Remediation  = @(
            'Configure an Intune device cleanup rule (Devices > Device clean-up rules) to automatically hide devices inactive beyond a defined threshold - this hides, it does not delete or wipe, and never touches the underlying Entra device object.'
            'For Entra-registered devices, follow Microsoft''s stale-device management guidance: disable first (with a grace period), monitor for any owner objection, then delete - never delete a system-managed (Autopilot) device.'
            'Investigate the population gap this check reports (Entra-registered but not Intune-managed) separately - it may indicate BYOD registrations that were never enrolled, or an incomplete migration.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DevicesMenu', 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#6-intune-operational-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules'
            'https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices'
        )
    }
    Origin     = $null
}
