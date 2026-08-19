@{
    Id         = 'TP.INT.0017'
    Title      = 'App Control for Business policy enforcing (not audit-only)'
    Category   = 'Intune.SettingsCatalog'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Expansions = @('settingPresenceIndex')
        Gates      = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAppControlPolicyEnforcing'
    }
    Consulting = @{
        WhatItMeans  = 'App Control for Business (formerly WDAC) restricts which applications and drivers are allowed to run. This check reads Part A''s setting-presence index and Passes only when at least one App Control policy is in Enforce mode (audit mode disabled) AND has an active control - built-in controls selected, or a custom XML upload whose payload is non-empty. Evaluated as a SAME-POLICY AND, not a tenant-wide union: a tenant that audits on policy A and uploads empty XML on policy B still Fails, because neither policy actually blocks untrusted executables. Settings Catalog assignments are still deferred in this slice, so this check matches Maester and treats policy existence as enough - it does not require a confirmed assignment.'
        WhyItMatters = 'Application allowlisting is one of the strongest single controls against unknown/novel malware, but only when enforced. An audit-only policy logs untrusted executables and does not block them. An upload-mode policy with an empty XML payload is the same class of silent failure - the tenant looks like it has App Control and does not. Because this check reads the settings-expansion index rather than a template-family-filtered Graph fetch, it also sees App Control settings that landed through the Endpoint Security Application Control template surface (visibility:"template" in the live setting-definitions capture - unpublished in Microsoft''s Graph schema docs, live-confirmed in-repo).'
        Remediation  = @(
            'Intune admin center > Endpoint security > App Control for Business > Create Policy - set Policy creation type to Built-in controls (or XML upload with a real code-integrity policy), set Audit mode to Disabled (Enforce), and assign the policy.'
            'If this finding names a policy as XML-upload with no payload, edit that policy and upload a non-empty App Control XML - an empty upload is not an active control.'
            'A Warn status means at least one candidate policy has a redacted enforce-mode or active-control value - review the policy directly in the Intune admin center to confirm its actual state.'
            'Start newly-enabled App Control policies in Audit mode against a representative device population before moving to Enforce, per Microsoft''s own App Control rollout guidance, then flip Audit mode off once false positives are cleared.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/appcontrol')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0017--app-control-for-business-policy-enforcing-not-audit-only'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-app-control-policy'
            'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1179'; License = 'MIT' }
}
