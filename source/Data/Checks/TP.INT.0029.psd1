@{
    Id         = 'TP.INT.0029'
    Title      = 'Security baselines assigned and not on a deprecated version'
    Category   = 'Intune.SecurityBaselines'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('securityBaselinesAssignedAndCurrent')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseSecurityBaselinesAssignedAndCurrent'
    }
    Consulting = @{
        WhatItMeans  = 'For each Intune security baseline family in use (Windows, Microsoft Defender for Endpoint, Microsoft Edge, Windows 365), an instance of that baseline needs BOTH an active assignment and a current (non-deprecated) template version to do its job. Once a newer baseline version is released, profiles built on an older version become read-only for their settings - they keep enforcing what they already enforce, but never pick up newer hardening additions, and eventually the version itself loses support. This check Fails a baseline instance that is unassigned (zero enforcement) or built on a deprecated template version.'
        WhyItMatters = 'An unassigned baseline instance provides no protection at all despite looking configured in the admin center - a common "we deployed baselines" false sense of security. A baseline stuck on an old version silently misses newer settings Microsoft added specifically in response to new threats or new OS capabilities, a slow-motion drift away from current best practice that nobody notices without deliberately checking baseline versions.'
        Remediation  = @(
            'Intune admin center > Endpoint security > Security baselines - select the baseline type, open Profiles, and confirm every instance you rely on has an assignment (not "Not assigned").'
            'From the same baseline type''s Profiles > Versions view, identify any profile still on an older version and use "Update version" to migrate it forward, reviewing the settings diff before applying so new defaults do not silently override deliberate customizations.'
            'Before assuming a Fail here is urgent, confirm which baseline family it belongs to - an older-but-still-enforcing baseline is a lower-urgency drift issue than a completely unassigned one, which enforces nothing at all.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityBaselinesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0029--security-baselines-assigned-and-not-on-a-deprecated-version'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview'
        )
    }
}
