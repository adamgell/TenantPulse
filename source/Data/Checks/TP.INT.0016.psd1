@{
    Id         = 'TP.INT.0016'
    Title      = 'Attack Surface Reduction "Standard Protection" baseline rules configured'
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
        Function = 'Test-PulseAsrStandardProtectionRulesConfigured'
    }
    Consulting = @{
        WhatItMeans  = 'Microsoft Defender for Endpoint''s Attack Surface Reduction (ASR) rules can each be set to Block, Audit, Warn, or left Disabled/unconfigured. This check reads Part A''s per-family setting-presence index and Passes only when all three of Microsoft''s "Standard protection rules" - block abuse of exploited vulnerable signed drivers, block credential stealing from LSASS, block persistence through WMI event subscription - resolve to Block or Audit on at least one policy this module could confirm is assigned. Evaluated as a UNION across every expanded policy in the tenant, not per-policy: a tenant where policy A sets rule 1 and policy B sets rules 2 and 3 still Passes, because the combined effective configuration on a device receiving both policies covers all three. Only these 3 of Defender''s roughly 19 ASR rules are checked - this is intentionally Microsoft''s own documented minimum floor, not full ASR coverage.'
        WhyItMatters = 'These three rules target the ASR techniques Microsoft''s own documentation and top ransomware playbooks treat as the highest-value, lowest-friction wins: vulnerable-driver abuse (a common EDR-bypass/privilege-escalation precursor), LSASS credential theft (the same class of attack Mimikatz and similar tools exploit), and WMI-event-subscription persistence (a common fileless-malware technique). Because this check reads the settings-expansion index rather than a template-family-filtered fetch, it also catches ASR rules configured through a generic Settings Catalog profile outside the Endpoint Security > Attack Surface Reduction blade - a coverage path Maester''s own MT.1178 (the check this ports) does not see.'
        Remediation  = @(
            'Intune admin center > Endpoint security > Attack surface reduction > Create Policy (Windows, Attack surface reduction rules profile) - set the three Standard protection rules to Block (or Audit while validating for false positives), and assign the policy.'
            'If this finding names a rule as present but only on an unassigned policy, assign that policy to the intended device population - an unassigned policy has zero real-world effect.'
            'A Warn status means at least one of the three rules is present on an assigned policy but its recorded value is redacted/unreadable - review the policy directly in the Intune admin center to confirm its actual state.'
            'Start any newly-enabled rule in Audit mode against a representative device population before moving to Block, per Microsoft''s own ASR rollout guidance, to catch false positives before they impact users.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/EndpointSecurityAttackSurfaceReduction')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0016--attack-surface-reduction-standard-protection-baseline-rules-configured'
        Authorities = @(
            'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference'
            'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1178'; License = 'MIT' }
}
