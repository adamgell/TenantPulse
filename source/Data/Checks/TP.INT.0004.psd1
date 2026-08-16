@{
    Id         = 'TP.INT.0004'
    Title      = 'At least 2 Windows Update rings have deadlines configured'
    Category   = 'Intune.Updates'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('deviceConfigurations')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseUpdateRingDeadlines'
    }
    Consulting = @{
        WhatItMeans  = 'Windows Update for Business ring profiles (deviceConfigurations with @odata.type windowsUpdateForBusinessConfiguration) control how feature and quality updates roll out to Windows devices. This check confirms at least 2 rings exist AND each has an actual deadline configured (deadlineForFeatureUpdatesInDays or deadlineForQualityUpdatesInDays greater than zero) - Microsoft ships deadlines unset by default, so this is checking for deliberate authoring, not a default that happened to look fine.'
        WhyItMatters = 'Without at least a pilot ring and a broad ring, every device updates on the same schedule - a bad update breaks the whole fleet at once instead of surfacing in a small pilot group first. Without deadlines, users can defer updates indefinitely, leaving devices unpatched against known vulnerabilities for months.'
        Remediation  = @(
            'Intune admin center > Devices > Windows > Update rings > Create profile - build at minimum a Pilot ring (small test group, 0-day feature deferral) and a Broad ring (wider rollout, several days'' feature deferral for staged safety).'
            'On each ring, set Deadline for feature updates and Deadline for quality updates (Update settings > Deadline for updates) - a deadline forces installation after the grace period even if the user keeps deferring.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsUpdateForBusinessMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#6-intune-operational-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-updates/windows/manage-update-rings'
            'https://learn.microsoft.com/en-us/intune/device-updates/windows/ref-update-ring-settings'
        )
    }
    Origin     = $null
}
