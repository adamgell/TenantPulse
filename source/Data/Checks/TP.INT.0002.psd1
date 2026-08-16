@{
    Id         = 'TP.INT.0002'
    Title      = 'A compliance policy exists for every enrolled platform'
    Category   = 'Intune.Compliance'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('deviceCompliancePolicies', 'managedDevices')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseCompliancePolicyPerPlatform'
    }
    Consulting = @{
        WhatItMeans  = 'Compares the set of platforms actually enrolled in the tenant (from managedDevices) against the set of platforms with at least one compliance policy defined (discriminated by each policy''s own @odata.type - windows10CompliancePolicy, iosCompliancePolicy, an androidXCompliancePolicy variant, or macOSCompliancePolicy). Every enrolled platform should have at least one.'
        WhyItMatters = 'Device compliance is the input every "require compliant device" Conditional Access policy depends on - a platform with no compliance policy at all can never be marked compliant, which either silently blocks every user on that platform once such a CA policy exists, or (worse, if TP.INT.0003''s "no policy = compliant" default is misconfigured) silently lets every device on that platform through with zero posture checks.'
        Remediation  = @(
            'Intune admin center > Devices > Compliance policies > Create policy, choose the missing platform, and configure at minimum: minimum OS version, encryption required, and (where the platform supports it) a threat-level requirement tied to Defender for Endpoint.'
            'Assign the new policy to a group covering the enrolled devices on that platform - policy existence alone is necessary but not sufficient; TP.INT.0002 checks existence only (see the check function''s own documented limitation on assignment verification).'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#6-intune-operational-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-security/compliance/overview'
        )
    }
    Origin     = $null
}
