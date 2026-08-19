@{
    Id         = 'TP.INT.0018'
    Title      = 'Managed Installer rules paired with an enforcing App Control policy'
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
        Function = 'Test-PulseManagedInstallerPairedWithEnforcingAppControl'
    }
    Consulting = @{
        WhatItMeans  = 'Managed Installer automatically trusts applications deployed through Intune (or ConfigMgr) so they are not blocked by App Control. This check reads Part A''s setting-presence index and Passes only when "Trust apps from managed installer" is enabled on a policy that is itself in Enforce mode with an active control - the same bar TP.INT.0017 uses. Evaluated as a SAME-POLICY AND: Managed Installer on an audit-only policy, or on an enforce-mode upload with an empty XML payload, Fails, because the underlying App Control policy is not actually blocking (or trusting) anything. Settings Catalog assignments are still deferred in this slice, so this check matches Maester and treats policy existence as enough.'
        WhyItMatters = 'Managed Installer without an enforcing App Control policy is a false sense of protection - the toggle is on, but nothing is being enforced for it to trust against. The inverse is also a real operational risk: an enforcing App Control policy without Managed Installer will block Intune-deployed LOB apps that have no explicit allow rule, which is the usual source of false-positive help-desk tickets during an App Control rollout.'
        Remediation  = @(
            'Intune admin center > Endpoint security > App Control for Business - on an existing Enforce-mode policy with built-in controls (or a non-empty XML upload), enable Trust apps from managed installer.'
            'If TP.INT.0017 is also Failing, fix that first: Managed Installer can only meaningfully pass on a policy that is itself enforcing with an active control.'
            'A Warn status means at least one candidate policy has a redacted enforce-mode, active-control, or Managed Installer value - review the policy directly in the Intune admin center.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/appcontrol')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0018--managed-installer-rules-paired-with-an-enforcing-app-control-policy'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-app-control-policy#managed-installer'
            'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-deploy-managed-installer'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1180'; License = 'MIT' }
}
