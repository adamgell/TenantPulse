@{
    Id         = 'TP.ENT.0018'
    Title      = 'Phishing-resistant authentication strength is required for privileged roles'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Critical'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @('EntraP1')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulsePrivilegedRolesPhishingResistantMfa'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms an enforced Conditional Access policy requires the built-in "Phishing-resistant MFA" authentication strength (FIDO2, Windows Hello for Business, or certificate-based authentication) - not merely generic MFA - for Microsoft''s documented minimum set of 9 privileged admin roles. A policy binding a CUSTOM authentication strength is reported in evidence but never counted toward coverage: this check cannot verify from Conditional Access data alone whether a custom strength''s underlying allowed-combinations are actually phishing-resistant, so it is surfaced for manual review rather than auto-trusted.'
        WhyItMatters = 'ScuBA rates both the all-users (MS.AAD.3.1v1) and privileged-role (MS.AAD.3.6v1) phishing-resistant requirements SHALL. A tenant can pass "MFA required for admins" (TP.ENT.0005) while still allowing SMS or voice-call OTP as the second factor - both are vulnerable to SIM-swap/SS7 interception and real-world MFA-bypass attacks that phishing-resistant methods close off entirely.'
        Remediation  = @(
            'Create a Conditional Access policy from Microsoft''s phishing-resistant admin MFA template, scoped to at least the 9 minimum admin roles.'
            'Grant control: require authentication strength, set to the built-in "Phishing-resistant MFA" strength.'
            'Ensure FIDO2 security keys or Windows Hello for Business are actually provisioned for privileged accounts (TP.ENT.0006) before enforcing - the policy alone does not provision credentials.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0018--phishing-resistant-authentication-strength-required-for-privileged-roles'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-phish-resistant-admin-mfa'
            'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths'
        )
    }
    Origin     = $null
}
