@{
    Id         = 'TP.INT.0007'
    Title      = 'Intune device clean-up rule configured'
    Category   = 'Intune.Governance'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('managedDeviceCleanupSettings')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseDeviceCleanupRuleConfigured'
    }
    Consulting = @{
        WhatItMeans  = 'Intune device clean-up rules automatically HIDE managed-device records that have not checked in for a configured number of days (30-270) from the admin center and reports - they do not wipe, retire, or otherwise act on the physical device (Microsoft''s own guidance is explicit: "Don''t trigger any actions on the device (no wipe or retire)"). A hidden device reappears automatically if it checks in again before its device certificate expires; after that it needs to re-enroll. deviceInactivityBeforeRetirementInDays absent or 0 means no such rule is configured for this tenant.'
        WhyItMatters = 'Without a clean-up rule, every device that is ever enrolled - decommissioned hardware, factory-reset test devices, devices lost to attrition without a formal offboarding step - stays visible in Intune''s device count and reports indefinitely. That inflates the apparent managed-device population, makes compliance-rate percentages look worse (or artificially better) than the actively-used fleet actually is, and makes "how many devices do we really manage" a question nobody can answer confidently from the admin center alone. This is a reporting-hygiene control, not an attack-surface control - it never changes what happens to any individual device.'
        Remediation  = @(
            'Intune admin center > Devices > Device clean-up rules > Create - pick a platform (or "All platforms"), and set "Remove devices that haven''t checked in for this many days" to a value between 30 and 270 (start with 90 unless your fleet''s realistic check-in cadence argues for a different number).'
            'Use the "Preview affected devices" option before creating the rule to see which devices would be hidden immediately, so a longer-than-expected offline population (seasonal/field devices) does not get hidden by surprise.'
            'Remember this only hides devices from the Intune admin center/reports, not from Microsoft Entra ID - a stale device''s Entra ID object needs its own clean-up process (see Manage stale devices in Microsoft Entra ID) if the goal is removing it everywhere, not just from Intune''s own views.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/deviceCleanUp')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0007--intune-device-clean-up-rule-configured'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules'
            'https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevicecleanupsettings?view=graph-rest-beta'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1053'; License = 'MIT' }
}
