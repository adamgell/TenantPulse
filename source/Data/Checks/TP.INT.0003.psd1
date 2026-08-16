@{
    Id         = 'TP.INT.0003'
    Title      = 'Devices without an assigned compliance policy are marked noncompliant'
    Category   = 'Intune.Compliance'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('deviceManagementSettings')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type       = 'Expression'
        Expression = @'
$settingsRows = @($Datasets.deviceManagementSettings)
if ($settingsRows.Count -eq 0) {
    throw 'deviceManagementSettings dataset returned no rows - the service returned nothing to evaluate.'
}
$secureByDefault = $settingsRows[0].secureByDefault
if ($null -eq $secureByDefault) {
    throw 'deviceManagementSettings returned no secureByDefault value - an absent value must never read as pass or fail.'
}
$secureByDefault -eq $true
'@
    }
    Consulting = @{
        WhatItMeans  = 'deviceManagement/settings carries a single tenant-wide default, secureByDefault, that decides what happens to a device that enrolls but is never targeted by ANY compliance policy. secureByDefault = true means an unassigned device is marked NOT compliant (the secure default); false means it is treated as compliant by default - silently passing every "require compliant device" Conditional Access check with zero posture verification. This check asserts the secure ($true) state.'
        WhyItMatters = 'A gap in compliance policy assignment - a new device platform, a group that missed a policy assignment, an onboarding delay - is inevitable in every real tenant. Whether that gap is fail-safe (unassigned = noncompliant, caught immediately) or fail-open (unassigned = compliant, invisible until an incident) is decided entirely by this one setting. Fail-open silently defeats every device-compliance-gated Conditional Access policy in the tenant for exactly the devices most likely to be unmanaged.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Connectors and tokens > device compliance defaults (or Devices > Compliance policies > Compliance policy settings) - set "Mark devices with no compliance policy assigned as" to Not compliant.'
            'After changing this, audit for any device population that is enrolled but intentionally has no compliance policy assigned (e.g. kiosk/shared devices) - they will immediately start reading as noncompliant and may need an explicit compliance policy of their own rather than relying on the old fail-open default.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#6-intune-operational-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-security/compliance/overview'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1054'; License = 'MIT' }
}
