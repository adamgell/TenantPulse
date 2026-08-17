@{
    Id         = 'TP.INT.0020'
    Title      = 'Apple Automated Device Enrollment tokens valid and syncing'
    Category   = 'Intune.Connectors'
    Severity   = 'Critical'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('depOnboardingSettings')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAppleAdeTokensValid'
    }
    Consulting = @{
        WhatItMeans  = 'An Apple ADE (Automated Device Enrollment, formerly Device Enrollment Program/DEP) token creates the trust relationship that lets Intune sync device information and enrollment policies from Apple Business/School Manager, and enables zero-touch enrollment for corporate-owned Apple devices. Each token is renewed roughly annually. This check Fails a token that is already expired or whose most recent successful sync did not happen today (the same calendar day as the snapshot), Warns a token within 30 days of expiry, and treats zero configured tokens as a legitimate skip rather than a failure.'
        WhyItMatters = 'An expired or non-syncing ADE token stops NEW Apple devices from auto-enrolling via zero-touch provisioning - a purchasing team can buy devices that appear correctly in Apple Business Manager and still never show up for Intune to manage, because the sync that would surface them is broken. Because ADE token renewal changing the Apple ID does not force existing enrolled devices to re-enroll (unlike the APNs certificate), this failure mode is easy to miss until someone notices new hardware silently isn''t enrolling.'
        Remediation  = @(
            'Intune admin center > Devices > Device onboarding > Enrollment > Apple mobile > Bulk Enrollment Methods > Enrollment program tokens - select the offending token and choose Renew token, using the same Apple ID that created it.'
            'Also renew the token if the Apple ID''s password changed, or if the person who originally set it up has left the organization - both situations can silently break sync even before the token''s own expiration date arrives.'
            'If sync has stalled but the token is not expired, trigger a manual sync from the same admin center pane first and confirm the Last Sync timestamp updates before assuming a renewal is required.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/AppleEnrollment')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0020--apple-automated-device-enrollment-tokens-valid-and-syncing'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-enrollment/apple/setup-apple-token'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1093'; License = 'MIT' }
}
