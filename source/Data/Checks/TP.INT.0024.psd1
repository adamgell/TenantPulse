@{
    Id         = 'TP.INT.0024'
    Title      = 'Mobile Threat Defense connectors enabled and syncing'
    Category   = 'Intune.Connectors'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('mobileThreatDefenseConnectors')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseMobileThreatDefenseConnectorsHealthy'
    }
    Consulting = @{
        WhatItMeans  = 'A Mobile Threat Defense (MTD) connector (Microsoft Defender for Endpoint or a third-party MTD partner) feeds device risk-level signal into Intune device compliance policies and Conditional Access rules. This check Fails a connector that is not enabled, or has not reported a heartbeat within the last day (a practitioner-judgment freshness window, not an officially published Microsoft SLA); zero configured connectors is treated as a legitimate skip, common for tenants that rely on a different signal source or none at all.'
        WhyItMatters = 'Compliance policies using the Device Threat Level rule only work as strong as the connector feeding them - once a connector goes disabled or its heartbeat goes stale, Intune keeps evaluating compliance against the LAST risk level it received, so a device that has since become compromised or noncompliant per the MTD partner can keep passing compliance and Conditional Access checks with no visible error until someone notices the connector itself is unhealthy.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Connectors and tokens > Mobile Threat Defense - select the affected connector and confirm its Connection status and Last synchronized time, then re-enable or re-authenticate per the partner''s own reconnection steps if it shows disconnected.'
            'For Microsoft Defender for Endpoint specifically, also verify the integration status from the Microsoft Defender XDR portal side (Settings > Endpoints > Advanced features > Microsoft Intune connection) since either side disabling the link breaks the connector.'
            'Confirm the account used to configure the connector still holds the Endpoint Security Manager role (or an equivalent custom role with Mobile Threat Defense Read/Modify rights) - a permissions change on that account is a common silent cause of connector drift.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/MTDMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0024--mobile-threat-defense-connectors-enabled-and-syncing'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-security/mobile-threat-defense/enable-connector'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1098'; License = 'MIT' }
}
