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
        WhatItMeans  = 'Tenant administration > Connectors and tokens > Windows data has TWO INDEPENDENT toggles, both default Off, that gate overlapping-but-not-identical Intune feature sets: (1) "Enable features that require Windows diagnostic data in processor configuration" gates compatibility reports for Windows updates, reports for expedite policies, and driver/expedited/feature update failure alerts; (2) "I confirm that my tenant owns one of these licenses" (a licensing attestation, not a technical validation Intune performs for you - Windows Enterprise/Education/VDA E3 or E5, or the equivalent Microsoft 365 bundle) gates compatibility/expedite reports AND Remediations. The two toggles are not one unified AND-gate over an identical feature list - each independently governs its own set, with compatibility/expedite reporting the shared overlap between them.'
        WhyItMatters = 'This is a data-governance/feature-enablement posture item, not an attack-surface control - leaving either toggle off does not expose anything, but it silently disables update-visibility and Remediations features admins may already believe are working (compatibility reports, expedited/driver/feature update failure alerts, and Remediations specifically depend on the license-verification toggle). Author''s note, not a claim from the cited page: enabling Windows diagnostic data processing is also the general mechanism (documented separately in Microsoft''s Windows privacy docs, not this Intune page) by which an organization rather than Microsoft becomes the data processor for that diagnostic data - this check does not evaluate any GDPR/EU Data Boundary-specific setting, only whether both Intune toggles are on.'
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
