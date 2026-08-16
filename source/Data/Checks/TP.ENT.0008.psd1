@{
    Id         = 'TP.ENT.0008'
    Title      = 'Microsoft Authenticator is enabled with number matching and app-name display required tenant-wide'
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
        Function = 'Test-PulseAuthenticatorMethodConfigured'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms Microsoft Authenticator is enabled (EIDSCA.AM01), its OTP fallback is turned off (AM02), and number matching for push approvals (AM03/AM04) plus application-name display in notifications (AM06/AM07) are both required and scoped to all users, not just a pilot group. Geographic-location display (AM09/AM10) is reported alongside as a fraud-detection-assistive setting.'
        WhyItMatters = 'Authenticator push is the most widely deployed MFA method in most Entra tenants, which makes it the most attractive target for MFA-fatigue/push-bombing attacks - an attacker who has a stolen password simply spams push approvals until an exhausted user taps Approve. Number matching (a code the user must retype from the sign-in screen) is the specific control that closes that gap; scoping it to less than "all users" leaves exactly the gap it was meant to close for whoever falls outside the scope.'
        Remediation  = @(
            'In Entra ID > Authentication methods > Microsoft Authenticator, confirm the method is enabled and its Include target covers All users (or a group covering every real user).'
            'Under Configure, set "Require number matching for push notifications" to Enabled, scoped to All users.'
            'Set "Show application name in push and passwordless notifications" to Enabled, scoped to All users, and disable the OTP fallback ("Allow use of Microsoft Authenticator OTP") unless a documented business need requires it.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0008--microsoft-authenticator-method-configuration-eidscaam01-am04-am06-am07-am09-am10'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AM01'
            'https://maester.dev/docs/tests/EIDSCA.AM03'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AM01,AM02,AM03,AM04,AM06,AM07,AM09,AM10'; License = 'MIT' }
}
