@{
    Id         = 'TP.ENT.0006'
    Title      = 'FIDO2 security key authentication method is enabled with attestation and key restrictions enforced'
    Category   = 'Entra.AuthenticationMethods'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('authenticationMethodsPolicy')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseFido2MethodConfigured'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms FIDO2 security keys are enabled as an authentication method (EIDSCA.AF01), with attestation enforced so only enterprise-attested keys can register (AF03), and key-restriction policy turned on (AF04). Self-service registration (AF02) and the specific allow/block key-restriction shape (AF05/AF06) are reported alongside as context, not as pass/fail gates on their own.'
        WhyItMatters = 'FIDO2 is one of only two Microsoft-recognized phishing-resistant authentication methods (with certificate-based auth). Enabling FIDO2 without attestation lets any FIDO2-compliant key - including a cheap, unmanaged one an attacker could supply - register for a user, quietly undermining the entire phishing-resistant-MFA control area this check''s sibling, TP.ENT.0018, depends on.'
        Remediation  = @(
            'In Entra ID > Authentication methods > Policies, enable the FIDO2 Security Key method if it is currently disabled.'
            'Under FIDO2 security key settings, set "Enforce attestation" to Yes so only enterprise-attested keys can be registered.'
            'Set "Enforce key restrictions" to Yes and configure an explicit allow-list (or block-list) of AAGUIDs matching your procured hardware, rather than leaving key restriction off.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0006--fido2-security-key-authentication-method-configuration-eidscaaf01af06'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AF01'
            'https://maester.dev/docs/tests/EIDSCA.AF03'
            'https://maester.dev/docs/tests/EIDSCA.AF04'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AF01,AF02,AF03,AF04,AF05,AF06'; License = 'MIT' }
}
