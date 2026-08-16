@{
    Id         = 'TP.ENT.0015'
    Title      = 'Password Protection is set to Enforce mode'
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
        WhatItMeans  = 'Confirms the Password Rule Settings directorySetting''s BannedPasswordCheckOnPremisesMode value is Enforce, not Audit (EIDSCA.PR01). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'Audit mode looks like Password Protection is configured - the banned-password list and Smart Lockout exist, log entries even get written when someone tries a weak/banned password - but it blocks nothing. A tenant left in the default Audit mode is exactly as exposed to credential-guessing/spray attacks (NIST/MITRE TA0006 Credential Access, T1110 Brute Force) as one with no Password Protection at all; it just looks better on a checklist.'
        Remediation  = @(
            'In Entra ID > Security > Authentication methods > Password protection, set "Mode" to Enforce.'
            'If the tenant is hybrid, confirm the on-premises Password Protection proxy/agent is also enabled and healthy before flipping to Enforce, or the on-prem side keeps allowing banned passwords unaffected by this cloud-side setting.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordProtection')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0015--password-protection-mode-and-smart-lockout-settings-eidscapr01pr03-pr05-pr06'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.PR01'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'PR01'; License = 'MIT' }
}
