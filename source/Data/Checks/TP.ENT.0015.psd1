@{
    Id         = 'TP.ENT.0015'
    Title      = 'Password Protection mode, on-prem enforcement, and Smart Lockout thresholds'
    Category   = 'Entra.PasswordProtection'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('directorySettings')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulsePasswordProtectionEnforced'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms five Password Rule Settings directorySettings: mode is Enforce, not Audit (BannedPasswordCheckOnPremisesMode, EIDSCA.PR01); the on-premises AD password-protection proxy/agent is enabled where hybrid (EnableBannedPasswordCheckOnPremises, EIDSCA.PR02); a custom banned-password list is active (EnableBannedPasswordCheck, EIDSCA.PR03); and Smart Lockout duration is at least 60 seconds (LockoutDurationInSeconds, EIDSCA.PR05) with a lockout threshold of at most 10 failed attempts (LockoutThreshold, EIDSCA.PR06). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'Audit mode looks like Password Protection is configured - the banned-password list and Smart Lockout exist, log entries even get written when someone tries a weak/banned password - but it blocks nothing. A tenant left in the default Audit mode is exactly as exposed to credential-guessing/spray attacks (NIST/MITRE TA0006 Credential Access, T1110 Brute Force) as one with no Password Protection at all. PR02 closes the same gap for on-premises/hybrid identities. PR03 stops org-specific weak passwords (company name, product names) that Microsoft''s global list cannot know about. PR05/PR06 bound how long and how many guesses an attacker gets before Smart Lockout engages - defaults that were never reviewed are not the same as a deliberately-tuned posture.'
        Remediation  = @(
            'In Entra ID > Security > Authentication methods > Password protection, set "Mode" to Enforce.'
            'If the tenant is hybrid, confirm the on-premises Password Protection proxy/agent is also enabled and healthy before flipping to Enforce, or the on-prem side keeps allowing banned passwords unaffected by this cloud-side setting.'
            'Enable "Enforce custom list" and populate it with organization-specific banned terms (company name, product names, local sports teams).'
            'Review Smart Lockout''s lockout duration (>=60s) and lockout threshold (<=10 attempts) and set them deliberately rather than leaving Microsoft''s defaults unreviewed.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordProtection')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0015--password-protection-mode-and-smart-lockout-settings-eidscapr01pr03-pr05-pr06'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.PR01'
            'https://maester.dev/docs/tests/EIDSCA.PR02'
            'https://maester.dev/docs/tests/EIDSCA.PR03'
            'https://maester.dev/docs/tests/EIDSCA.PR05'
            'https://maester.dev/docs/tests/EIDSCA.PR06'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'PR01,PR02,PR03,PR05,PR06'; License = 'MIT' }
}
