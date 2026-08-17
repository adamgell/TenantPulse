@{
    Id         = 'TP.INT.0025'
    Title      = 'Personally-owned Windows device enrollment blocked'
    Category   = 'Intune.Enrollment'
    Severity   = 'Medium'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('deviceEnrollmentConfigurations')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulsePersonalWindowsEnrollmentBlocked'
    }
    Consulting = @{
        WhatItMeans  = 'The tenant''s default device platform restriction policy can block personally-owned Windows devices from enrolling. Rather than inspecting a device attribute, Intune enforces this by requiring the enrollment request itself to be AUTHORIZED for corporate enrollment - via Windows Autopilot, GPO or co-management auto-enrollment, a bulk provisioning package, or a device enrollment manager account. This check Fails when the tenant''s default policy leaves `personalDeviceEnrollmentBlocked` unset for Windows, meaning any Windows device can enroll through ordinary user-driven methods (Company Portal, Add Work Account, MDM-only enrollment).'
        WhyItMatters = 'Without this restriction, an employee''s personal Windows PC can be enrolled into full MDM management the same way a corporate laptop would be - expanding the unmanaged-endpoint attack surface and complicating every compliance-policy assumption built around a corporate-owned fleet. Because the restriction only governs USER-DRIVEN enrollment - Autopilot, bulk, and co-managed enrollments always use the default policy regardless - a tenant that enrolls exclusively via Autopilot may be intentionally relying on that separate control rather than this one; treat a Fail here as a lower-confidence finding until Windows Autopilot coverage (TP.INT.0026) is also reviewed.'
        Remediation  = @(
            'Intune admin center > Devices > Device onboarding > Enrollment > Device platform restriction - open the default restriction policy (or create/edit a higher-priority one) and set Windows > Personally owned devices to Block.'
            'Before blocking, confirm every legitimate Windows enrollment path in use (Autopilot, GPO, bulk provisioning, DEM accounts) is actually authorized in your environment - this restriction blocks any Windows enrollment that does not go through one of those paths, including some automatic MDM enrollment scenarios Microsoft explicitly classifies as personal even when the user intended otherwise.'
            'If the tenant deliberately allows BYOD Windows devices, treat this Fail as an accepted risk rather than a gap - document the decision so it is not repeatedly re-flagged as an open finding.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DeviceEnrollmentRestrictionsMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0025--personally-owned-windows-device-enrollment-blocked'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-enrollment/restrictions'
        )
    }
}
