@{
    Id         = 'TP.INT.0031'
    Title      = 'BitLocker CSP settings present and correct across all Settings Catalog policies'
    Category   = 'Intune.SettingsCatalog'
    Severity   = 'Critical'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Expansions = @('settingPresenceIndex')
        Gates      = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseBitlockerCspSettingsPresentAndCorrect'
    }
    Consulting = @{
        WhatItMeans  = 'The BitLocker CSP system-drive encryption-type setting can be pushed to Windows devices through ANY Settings Catalog-backed policy - not only the dedicated "Endpoint security > Disk encryption" blade TP.INT.0014 already checks. This check reads Part A''s per-family setting-presence index (built from every expanded settingsCatalog/compliance/deviceConfiguration policy, regardless of which Intune blade created it) and Passes only when the setting resolves to Full encryption (not Used space only, not unconfigured) on a policy this module could confirm is actually assigned to a device or user - a correct value sitting on an unassigned policy protects nothing, so it does not count as a Pass here.'
        WhyItMatters = 'A tenant that authors BitLocker settings through a generic Settings Catalog profile - rather than through the purpose-built Disk Encryption blade - is invisible to TP.INT.0014 by design (that check only ever reads policies carrying a templateReference to the Disk Encryption template). This check closes that specific blind spot using data already collected during settings expansion, at no extra Graph cost. Used-space-only encryption only protects data written after encryption was enabled; on a lost or stolen device, only full encryption guarantees data at rest is unreadable without the recovery key - the same underlying risk TP.INT.0014''s own Consulting text already explains, now covered from a second collection path.'
        Remediation  = @(
            'This finding''s Reason and evidence report presence/assignment COUNTS only, not policy names - the settings-presence index this check reads is keyed by setting and family, not by policy. In the Intune admin center, search Devices > Configuration for policies containing the "Select the encryption type" BitLocker CSP setting, and confirm the one(s) resolving to Full encryption are assigned to the intended device population.'
            'If the correct value exists only on an unassigned policy, assign it to a device group, or move the setting into an existing assigned policy - an unassigned policy is functionally identical to no policy at all.'
            'If BitLocker is intentionally managed exclusively through the Endpoint security > Disk encryption blade, no action is needed here beyond TP.INT.0014 - this check exists to catch the OTHER path, not to prescribe which path to use.'
            'A Warn status (value redacted/unreadable) means this module could confirm the setting is present and assigned but could not verify its actual value - review the policy directly in the Intune admin center to confirm it resolves to Full encryption.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/PoliciesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0031--bitlocker-csp-settings-present-and-correct-across-all-settings-catalog-policies'
        Authorities = @(
            'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp'
        )
    }
    Origin     = $null
}
