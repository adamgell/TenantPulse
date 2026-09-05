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
        WhatItMeans  = 'Confirms one or more enforced Conditional Access policies require the built-in "Phishing-resistant MFA" authentication strength for Microsoft''s documented minimum set of 14 privileged admin roles across universal resource and sign-in scope. Role exclusions are subtracted per policy and Graph grant AND/OR semantics are enforced, so an OR alternative does not require phishing resistance. Narrowed conditions cannot establish universal protection. A custom strength remains indeterminate until its allowed combinations can be evaluated from authentication-strength policy data.'
        WhyItMatters = 'ScuBA rates both the all-users (MS.AAD.3.1v1) and privileged-role (MS.AAD.3.6v1) phishing-resistant requirements SHALL. A tenant can pass "MFA required for admins" (TP.ENT.0005) while still allowing SMS or voice-call OTP as the second factor - both are vulnerable to SIM-swap/SS7 interception and real-world MFA-bypass attacks that phishing-resistant methods close off entirely.'
        Remediation  = @(
            'Create a Conditional Access policy from Microsoft''s phishing-resistant admin MFA template, scoped to all 14 currently documented admin roles and all resources.'
            'Grant control: require authentication strength, set to the built-in "Phishing-resistant MFA" strength.'
            'Ensure FIDO2 security keys or Windows Hello for Business are actually provisioned for privileged accounts (TP.ENT.0006) before enforcing - the policy alone does not provision credentials.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0018--phishing-resistant-authentication-strength-required-for-privileged-roles'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
            'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
        )
    }
    Origin     = $null
}
