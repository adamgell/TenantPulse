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
        WhatItMeans  = 'This check classifies every managed device into one of three buckets - verified COMPLIANT (`complianceState == compliant`), verified NONCOMPLIANT (`complianceState == noncompliant`), or UNVERIFIED-OR-UNHEALTHY (`conflict`, `error`, `inGracePeriod`, `configManager`, `unknown`, or any other state) - and measures both rates. It is a telemetry/trend signal rather than a single binary control gap: Pass when verified-noncompliant is below 5% AND the unverified-or-unhealthy share is below 5%; Warn when verified-noncompliant is 5-10%, OR when it is under 5% but the unverified-or-unhealthy share is 5% or more (a fleet cannot bare-Pass on the strength of a bucket this check cannot actually confirm); Fail above 10% verified-noncompliant. Those percentages are this check''s own practitioner-judgment default (informed by common staged-rollout practice), not a specific published Microsoft SHALL/SHOULD threshold - no such official numeric target could be located during this check''s own research.'
        WhyItMatters = 'A high fleet-wide noncompliance rate is usually either a policy-configuration problem (a rule the fleet cannot realistically meet, e.g. a minimum OS version rolled out too aggressively) or a genuine fleet-health problem (a real population of devices that are actually out of policy) - either way, it is the signal that tells you whether it is safe to layer Conditional Access device-compliance enforcement on top without locking out a meaningful share of your own users. A material unverified-or-unhealthy share is its own distinct risk: those devices are not confirmed compliant either - `conflict`/`error` mean Intune could not even finish evaluating them, `inGracePeriod` means a remediation clock is already running, and `configManager` means Intune''s own compliance state is not authoritative for that device at all - so ignoring that bucket and looking only at the noncompliant percentage can make a fleet look healthier than it actually is.'
        Remediation  = @(
            'Intune admin center > Devices > Monitor > Noncompliant devices - review the top noncompliance reasons across the fleet before assuming a single fix will resolve the rate; different device populations often fail for different rules.'
            'If a specific rule (e.g. minimum OS version, encryption requirement) accounts for most of the noncompliance, consider whether the rule''s threshold is realistic for the CURRENT fleet, or whether it needs a longer grace period/staged rollout rather than an immediate hard requirement.'
            'If this finding escalated on the unverified-or-unhealthy share rather than the noncompliant rate, check the breakdown in this finding''s own evidence - a large `conflict`/`error` count usually points at a policy-evaluation problem, while a large `configManager` count means those devices'' real compliance state lives in Configuration Manager, not Intune, and should be reviewed there.'
            'Treat this as a trend to watch over time, not a one-time gate - re-run this check after each policy change to confirm both rates are moving in the intended direction before tightening enforcement further.'
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
