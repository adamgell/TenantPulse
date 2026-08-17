@{
    Id         = 'TP.INT.0012'
    Title      = 'Windows Feature Update policy avoids end-of-support builds'
    Category   = 'Intune.Updates'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('windowsFeatureUpdateProfiles')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseFeatureUpdatePolicyAvoidsEos'
    }
    Consulting = @{
        WhatItMeans  = 'Windows Feature Update deployment profiles (a distinct beta resource from the update-ring/deferral profiles TP.INT.0004 already checks) pin a device population to a specific Windows feature update VERSION - e.g. "Windows 11, version 22H2". Each Windows version has a published end-of-support date after which Microsoft stops shipping security updates for it. This check Fails when any configured Feature Update profile targets a version whose end-of-support date has already passed as of when the snapshot was collected.'
        WhyItMatters = 'Devices pinned to a Feature Update profile targeting an already-unsupported Windows version receive no further security patches for that OS version at all - not a delayed patch, a PERMANENT gap that only closes when the profile itself is updated to target a currently-supported version. This is distinct from TP.INT.0004 (deferral/deadline cadence for updates the device WILL eventually get) - this check is about whether the target version itself is still receiving updates in the first place.'
        Remediation  = @(
            'Intune admin center > Devices > Windows > Feature updates for Windows 10 and later - open each offending profile and update its target Feature update to a currently-supported version (see this check''s own evidence for exactly which profile(s) and version(s) are affected).'
            'Before changing the target version, confirm device/app compatibility for the newer feature update in a pilot ring - a jump across several feature update versions can surface driver or app-compatibility issues that a single-version-at-a-time deferral cadence would have caught earlier.'
            'Cross-reference the Microsoft Lifecycle page for the specific Windows edition in use (Enterprise/Education/Pro) to confirm the CURRENT end-of-support date for whichever version you retarget to - support windows differ by edition and version, and this check only evaluates what is already configured, not what to pick next.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceUpdates/WindowsFeatureUpdateProfilesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0012--windows-feature-update-policy-avoids-end-of-support-builds'
        Authorities = @(
            'https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1102'; License = 'MIT' }
}
