@{
    Id         = 'TP.INT.0028'
    Title      = 'Enrollment Status Page configured with blocking failure behavior'
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
        Function = 'Test-PulseEnrollmentStatusPageBlocking'
    }
    Consulting = @{
        WhatItMeans  = 'The Windows Autopilot Enrollment Status Page (ESP) can be configured to block a user from reaching the desktop until every required app and policy has finished installing ("Block device use until all apps and profiles are installed" = Yes). This check Fails when no ESP profile is BOTH assigned to a group AND set to block on failure; zero ESP profiles configured at all is treated as a legitimate skip. Note: this check evaluates explicitly-assigned ESP profiles only - it does not separately account for the tenant''s implicit default ESP profile, which Intune applies automatically when no other profile targets a device, a known depth gap.'
        WhyItMatters = 'Without blocking enabled, a user can exit the ESP and start using a device before required apps, certificates, network profiles, or security policies have finished applying - the device looks provisioned but is actually incomplete, and may be noncompliant or missing critical software the moment the user starts working with it.'
        Remediation  = @(
            'Intune admin center > Devices > Device onboarding > Enrollment > Windows > Enrollment Status Page - open the profile that should be blocking, set "Show app and profile installation progress" to Yes, then "Block device use until all apps and profiles are installed" to Yes.'
            'Confirm the profile is actually assigned to the group(s) covering the intended Autopilot device population - a correctly-configured but unassigned ESP profile provides zero coverage.'
            'Review the default ESP profile separately (Intune admin center > same pane > Default profile > Properties) since it is not returned as an "assigned" profile in the Graph collection this check reads, but still applies automatically to any device/user with no other ESP profile targeted at them.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/EnrollmentStatusPageMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0028--enrollment-status-page-configured-with-blocking-failure-behavior'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-enrollment/windows/setup-status-page'
        )
    }
}
