@{
    Id         = 'TP.INT.0030'
    Title      = 'Fleet compliance rate below acceptable threshold'
    Category   = 'Intune.Compliance'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('managedDevices')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseFleetComplianceRateAcceptable'
    }
    Consulting = @{
        WhatItMeans  = 'This check measures the proportion of the whole managed-device fleet currently in a noncompliant state. It is a telemetry/trend signal rather than a single binary control gap: Pass below 5% noncompliant, Warn between 5% and 10%, Fail above 10%. Those percentages are this check''s own practitioner-judgment default (informed by common staged-rollout practice), not a specific published Microsoft SHALL/SHOULD threshold - no such official numeric target could be located during this check''s own research.'
        WhyItMatters = 'A high fleet-wide noncompliance rate is usually either a policy-configuration problem (a rule the fleet cannot realistically meet, e.g. a minimum OS version rolled out too aggressively) or a genuine fleet-health problem (a real population of devices that are actually out of policy) - either way, it is the signal that tells you whether it is safe to layer Conditional Access device-compliance enforcement on top without locking out a meaningful share of your own users.'
        Remediation  = @(
            'Intune admin center > Devices > Monitor > Noncompliant devices - review the top noncompliance reasons across the fleet before assuming a single fix will resolve the rate; different device populations often fail for different rules.'
            'If a specific rule (e.g. minimum OS version, encryption requirement) accounts for most of the noncompliance, consider whether the rule''s threshold is realistic for the CURRENT fleet, or whether it needs a longer grace period/staged rollout rather than an immediate hard requirement.'
            'Treat this as a trend to watch over time, not a one-time gate - re-run this check after each policy change to confirm the noncompliance rate is moving in the intended direction before tightening enforcement further.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0030--fleet-compliance-rate-below-acceptable-threshold'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-security/compliance/overview'
        )
    }
}
