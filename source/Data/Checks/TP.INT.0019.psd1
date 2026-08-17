@{
    Id         = 'TP.INT.0019'
    Title      = 'Apple MDM Push (APNs) certificate valid for more than 30 days'
    Category   = 'Intune.Connectors'
    Severity   = 'Critical'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('applePushNotificationCertificate')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseApplePushCertificateValid'
    }
    Consulting = @{
        WhatItMeans  = 'The Apple Push Notification service (APNs) certificate is required for Microsoft Intune to manage ANY iOS/iPadOS or macOS device - it is the trust relationship that lets Intune send management commands to Apple devices at all. Apple issues the certificate for 365 days; Microsoft gives a 30-day grace period after it expires before management is fully cut off. This check Fails once the certificate has actually expired and Warns once fewer than 30 days remain, matching Intune''s own renewal reminder window.'
        WhyItMatters = 'An expired APNs certificate makes every Apple device in the tenant unmanageable instantly - no policy pushes, no compliance checks, no remote actions - until the certificate is renewed. The certificate MUST be renewed (not recreated) using the exact same Apple ID that originally created it; renewing with a different Apple ID, or letting the lapse run past Apple''s own grace window, forces every enrolled Apple device through a full unenroll-and-re-enroll cycle. This is one of the highest-blast-radius single points of failure in an Apple device management program.'
        Remediation  = @(
            'Intune admin center > Devices > Device onboarding > Enrollment > Apple > Apple MDM Push Certificate - renew the certificate using the SAME Apple ID shown in the "Apple ID" field (never create a brand-new certificate unless the tenant has no Apple devices enrolled yet).'
            'Confirm the Apple ID''s mailbox is monitored by more than one person (a shared distribution list, not a single admin''s personal inbox) so the annual renewal reminder from Apple/Microsoft is never missed by one person leaving the organization.'
            'If the certificate has already expired, renew immediately - Apple gives only a limited grace period before requiring full device re-enrollment, and every day of delay extends the outage window for the whole Apple fleet.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/AppleEnrollment')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0019--apple-mdm-push-apns-certificate-valid-for-more-than-30-days'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-enrollment/apple/create-mdm-push-certificate'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1092'; License = 'MIT' }
}
