@{
    Id         = 'TP.INT.0022'
    Title      = 'Android Enterprise connection bound, validated, and syncing'
    Category   = 'Intune.Connectors'
    Severity   = 'Critical'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('androidManagedStoreAccountEnterpriseSettings')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAndroidEnterpriseConnectionHealthy'
    }
    Consulting = @{
        WhatItMeans  = 'Connecting Microsoft Intune to a managed Google Play account is a tenant-wide prerequisite for every Android Enterprise management option - personally-owned work profile (BYOD), corporate-owned work profile, fully managed, and dedicated devices all depend on this single connection. This check Fails when the connection is bound but not fully validated, or is validated but its app catalog sync is failing or stale (more than a day since the last success); a tenant that has never bound the connection at all is treated as a legitimate skip, not a failure.'
        WhyItMatters = 'Because every Android Enterprise enrollment path shares this one connection, a broken bind or a stalled app sync degrades Android device management tenant-wide rather than for a single policy or device group - new devices may fail to enroll and managed app deployment/updates can silently stop reaching the entire Android fleet, often noticed only when a rollout or a new enrollment unexpectedly fails.'
        Remediation  = @(
            'Intune admin center > Devices > Android > Enrollment (or Tenant administration > Connectors and tokens > Managed Google Play) - check the connection status and, if broken, follow the reconnect/re-authenticate flow with the same Microsoft Entra (or Gmail) account originally used to create it.'
            'If the connection shows bound but not validated, confirm the Microsoft Entra account used to manage it still has an active mailbox and has not been disabled or had MFA/Conditional Access changes block the validation handshake.'
            'If bound and validated but sync is stale, trigger a manual sync from the same admin center pane and confirm the Last Sync timestamp updates; persistent sync failures usually trace back to a Google Admin console-side issue rather than an Intune-side one.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/AndroidEnrollmentMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0022--android-enterprise-connection-bound-validated-and-syncing'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-enrollment/android/connect-managed-google-play'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1095'; License = 'MIT' }
}
