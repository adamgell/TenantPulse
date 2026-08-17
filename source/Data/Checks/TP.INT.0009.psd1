@{
    Id         = 'TP.INT.0009'
    Title      = 'Windows diagnostic data processor configuration enabled'
    Category   = 'Intune.Governance'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('dataProcessorServiceForWindowsFeaturesOnboarding')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseWindowsDataProcessorEnabled'
    }
    Consulting = @{
        WhatItMeans  = 'Windows diagnostic data processor configuration lets an organization act as the GDPR-defined CONTROLLER (rather than Microsoft as controller) for Windows diagnostic data collected from Microsoft Entra-joined devices, and is a prerequisite several Intune Windows-update features depend on (compatibility reports for Windows updates, reports for expedite policies, and driver/expedited-update failure alerts). Enabling it requires BOTH a qualifying Windows license attestation (Enterprise/Education/VDA E3 or E5, or the equivalent Microsoft 365 bundle) AND explicitly turning the feature on - Tenant administration > Connectors and tokens > Windows data, both toggles default to Off.'
        WhyItMatters = 'This is a data-governance/compliance posture item, not an attack-surface control - leaving it off does not expose anything, but it silently disables several update-visibility features admins may already believe are working (compatibility reports, expedited/driver update failure alerts), and it is the specific mechanism by which the organization - rather than Microsoft by default - controls Windows diagnostic data under GDPR/EU Data Boundary terms for enrolled devices.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Connectors and tokens > Windows data > toggle "I confirm that my tenant owns one of these licenses" On (only if the tenant genuinely holds a qualifying license - Windows Enterprise/Education/VDA E3 or E5, or the equivalent Microsoft 365 bundle; this is a licensing attestation, not a technical validation Intune performs for you).'
            'On the same page, toggle "Enable features that require Windows diagnostic data in processor configuration" On - this is a separate switch from the license attestation and both must be set for this check to Pass.'
            'If diagnostic-data-dependent features (update compatibility reports, expedited/driver update failure alerts) already appear broken or empty, this configuration is the first thing to verify - re-run this check after changing either toggle to confirm both booleans now read true.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/TenantAdminMenu/~/connectorsAndTokens')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0009--windows-diagnostic-data-processor-configuration-enabled'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/privacy/enable-windows-diagnostic-data'
            'https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-dataprocessorserviceforwindowsfeaturesonboarding?view=graph-rest-beta'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1099'; License = 'MIT' }
}
