@{
    Id         = 'TP.ENT.0010'
    Title      = 'Temporary Access Pass is enabled and configured for one-time use'
    Category   = 'Entra.AuthenticationMethods'
    Severity   = 'Medium'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('authenticationMethodsPolicy')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseTemporaryAccessPassConfigured'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms Temporary Access Pass is enabled (authenticationMethodConfigurations(''TemporaryAccessPass'').state == enabled, EIDSCA.AT01) and, where used, is deliberately configured for one-time use rather than left reusable (isUsableOnce, EIDSCA.AT02) - reported as its own evidence row since it is only meaningful once AT01 is enabled.'
        WhyItMatters = 'Temporary Access Pass supports secure onboarding and recovery flows that avoid emailing or verbally sharing initial passwords - a common weak-onboarding pattern that hands an attacker a durable, phishable credential before the user ever sets their own password. Without TAP enabled, organizations tend to fall back to those weaker methods by default, not because they made a deliberate choice. A reusable (not one-time) pass is a smaller but related gap: it stays valid for repeated use within its lifetime window rather than expiring after first use.'
        Remediation  = @(
            'In Entra ID > Authentication methods > Policies > Temporary Access Pass, set the method to Enabled if not already.'
            'For general onboarding scenarios, configure passes as one-time use; reserve reusable passes for specific, time-boxed operational needs (e.g. bulk device provisioning) with a documented justification.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0010--temporary-access-pass-method-configuration-eidscaat01at02'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AT01'
            'https://maester.dev/docs/tests/EIDSCA.AT02'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AT01,AT02'; License = 'MIT' }
}
