@{
    Id         = 'TP.ENT.0007'
    Title      = 'Authentication methods policy general settings (migration state, suspicious-activity reporting)'
    Category   = 'Entra.AuthenticationMethods'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('authenticationMethodsPolicy')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAuthMethodsPolicyGeneralSettings'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms three general settings on the tenant''s single authenticationMethodsPolicy object: the legacy per-user MFA/SSPR-to-unified-policy migration is complete or was never started fresh (policyMigrationState, EIDSCA.AG01); suspicious sign-in-attempt reporting from the Authenticator app/voice calls is enabled (reportSuspiciousActivitySettings.state, EIDSCA.AG02); and that reporting is scoped to all users, not silently narrowed (reportSuspiciousActivitySettings.includeTarget.id, EIDSCA.AG03).'
        WhyItMatters = 'An incomplete migration (AG01) means legacy per-user MFA/SSPR policy can still silently override the unified policy''s settings - undermining every other authentication-method check in this catalog (TP.ENT.0006/0008/0009/0010/0011) even when those checks themselves report Pass, because the legacy policy may be the one actually in effect. AG02/AG03 close the MFA-fatigue/push-bombing detection loop: without suspicious-activity reporting scoped to all users, a user targeted by a push-bombing attack has no way to signal it, and their risk score never rises for Conditional Access to act on.'
        Remediation  = @(
            'In Entra ID > Authentication methods > Policies, complete the migration from the legacy per-user MFA/SSPR policies to the unified authentication methods policy if not already done.'
            'Under Authentication methods > Settings, enable "Report suspicious activity" and scope it to all users (not a narrow pilot group left over from testing).'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthMethodsSettings')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0007--authentication-methods-policy-general-settings-eidscaag01ag03'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AG01'
            'https://maester.dev/docs/tests/EIDSCA.AG02'
            'https://maester.dev/docs/tests/EIDSCA.AG03'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AG01,AG02,AG03'; License = 'MIT' }
}
