@{
    Id         = 'TP.ENT.0011'
    Title      = 'Voice call is not enabled as an authentication method'
    Category   = 'Entra.AuthenticationMethods'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('authenticationMethodsPolicy')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseVoiceCallMethodDisabled'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms Voice call is not enabled as an authentication method (authenticationMethodConfigurations(''Voice'').state == disabled, EIDSCA.AV01) - a single tenant-wide toggle, unlike TP.ENT.0009''s SMS sibling which is evaluated per target group.'
        WhyItMatters = 'Voice call one-time-passcode authentication shares SMS''s exposure to SIM-swap attacks and SS7 protocol interception - an attacker who compromises a phone number, not the device or account, can complete sign-in or MFA. CISA''s SCuBA baseline (MS.AAD.3.5v2) rates disabling SMS/voice/email OTP SHALL - the strongest, federally-mandatory criticality tier under BOD 25-01, the same authority as TP.ENT.0009.'
        Remediation  = @(
            'In Entra ID > Authentication methods > Policies > Voice calls, set the method to Disabled.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0011--voice-call-authentication-method-disabled-eidscaav01'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AV01'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AV01'; License = 'MIT' }
}
