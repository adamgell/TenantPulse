@{
    Id         = 'TP.INT.0027'
    Title      = 'No orphaned Windows Autopilot device identities'
    Category   = 'Intune.Enrollment'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('windowsAutopilotDeviceIdentities')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseNoOrphanedAutopilotIdentities'
    }
    Consulting = @{
        WhatItMeans  = 'Registering a device''s hardware hash with Windows Autopilot is only half of the zero-touch provisioning story - the device identity also needs to be covered by a deployment profile assignment before it will actually receive the intended out-of-box experience. This check Fails when a registered Autopilot device identity''s own `deploymentProfileAssignmentStatus` is `notAssigned` - never targeted by any deployment profile at all - listing every such device by serial number and model.'
        WhyItMatters = 'An orphaned Autopilot identity is a logistics gap that only becomes visible when someone unboxes the device: instead of the expected zero-touch setup, it falls through to a generic OOBE, forcing manual configuration on-site or a return trip through IT. This is not a security control gap - it is a deployment-readiness signal that matters most right before a hardware rollout, when discovering it late is expensive.'
        Remediation  = @(
            'Intune admin center > Devices > Windows > Windows enrollment > Devices - filter or sort by Profile status to find devices showing "Assigned - not synced" or unassigned, then confirm each is covered by a Deployment Profile assignment.'
            'If a batch of devices consistently shows notAssigned, check whether the group used to target the deployment profile(s) actually includes those device or user objects - a common cause is a dynamic group rule that does not match newly-registered hardware hashes.'
            'Run this check again shortly before a planned hardware rollout, not just periodically, so newly-registered-but-unassigned devices are caught before they reach end users.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/AutopilotDevicesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0027--no-orphaned-windows-autopilot-device-identities'
        Authorities = @(
            'https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotdeviceidentity?view=graph-rest-beta'
        )
    }
}
