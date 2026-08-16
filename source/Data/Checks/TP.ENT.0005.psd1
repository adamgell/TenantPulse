@{
    Id         = 'TP.ENT.0005'
    Title      = 'MFA is required for admin roles by an enforced Conditional Access policy'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @('EntraP1')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAdminMfaEnforced'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms an enabled (not report-only) Conditional Access policy requires MFA for Microsoft''s documented minimum set of 9 admin roles - Global Administrator, Application Administrator, Authentication Administrator, Billing Administrator, Cloud Application Administrator, Conditional Access Administrator, Exchange Administrator, Helpdesk Administrator, and Password Administrator. Coverage can be split across more than one enabled policy; each role just needs to be covered by at least one of them.'
        WhyItMatters = 'Admin roles are the highest-value credential-theft target in the tenant - a compromised admin account without MFA is a compromised tenant. Microsoft auto-deploys a report-only "MFA for admins" managed policy specifically because this gap is so common and so consequential; leaving it in report-only is functionally the same as not having it.'
        Remediation  = @(
            'If Microsoft''s managed "Require multifactor authentication for admins" policy exists in report-only, confirm break-glass exclusions (TP.ENT.0003) and switch it to On.'
            'Otherwise create a policy from the phishing-resistant admin MFA template: target the 9+ admin roles, grant control require authentication strength (phishing-resistant preferred, MFA as a floor).'
            'Re-run this check after any role restructuring - a renamed custom role built on top of a built-in admin role does not change the underlying role template id this check keys on, but a role assignment moved to a genuinely different role definition can.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#2-conditional-access-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-phish-resistant-admin-mfa'
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies'
        )
    }
    Origin     = $null
}
