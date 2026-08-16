@{
    Id         = 'TP.ENT.0009'
    Title      = 'SMS is not usable as an authentication sign-in factor'
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
        Function = 'Test-PulseSmsSignInMethodDisabled'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms no target group in the Sms authentication method configuration is usable for sign-in (authenticationMethodConfigurations(''Sms'').includeTargets[].isUsableForSignIn == false for every target, EIDSCA.AS04). SMS may still be configured for other purposes, but must not be a viable primary or MFA sign-in path for any target scope.'
        WhyItMatters = 'SMS (and voice call, TP.ENT.0011''s sibling control) one-time-passcode authentication is vulnerable to SIM-swap attacks and SS7 protocol interception - an attacker who compromises a phone number, not the device or account, can complete sign-in or MFA. CISA''s SCuBA baseline (MS.AAD.3.5v2) rates disabling SMS/voice/email OTP SHALL - the strongest, federally-mandatory criticality tier under BOD 25-01. This is per-target-group, not a single tenant-wide toggle: a tenant can disable SMS for most users but leave a forgotten pilot or exception group still exposed, and that gap will not show up in a simple "is SMS enabled" summary.'
        Remediation  = @(
            'In Entra ID > Authentication methods > Policies > SMS, review every target group listed and disable "Usable for sign-in" for each one still marked enabled.'
            'If a target group must temporarily allow SMS for a migration/exception scenario, document the business justification and set a review date rather than leaving it open-ended.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0009--sms-sign-in-authentication-method-disabled-eidscaas04'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AS04'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AS04'; License = 'MIT' }
}
