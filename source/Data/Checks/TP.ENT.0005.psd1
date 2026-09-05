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
        WhatItMeans  = 'Confirms one or more enabled (not report-only) Conditional Access policies require MFA for Microsoft''s documented minimum set of 14 admin roles across universal resource and sign-in scope. Coverage can be split across policies, but role exclusions are subtracted per policy. Graph grant AND/OR semantics are enforced: an OR alternative does not require MFA. Microsoft''s built-in MFA-satisfying strengths count; custom strengths remain indeterminate until requirementsSatisfied is collected. Narrowed conditions cannot establish universal protection, and missing evidence is indeterminate only when unresolved policies could cover every remaining role.'
        WhyItMatters = 'Admin roles are the highest-value credential-theft target in the tenant - a compromised admin account without MFA is a compromised tenant. Microsoft auto-deploys a report-only "MFA for admins" managed policy specifically because this gap is so common and so consequential; leaving it in report-only is functionally the same as not having it.'
        Remediation  = @(
            'If Microsoft''s managed "Require multifactor authentication for admins" policy exists in report-only, confirm break-glass exclusions (TP.ENT.0003) and switch it to On.'
            'Otherwise create a policy from the phishing-resistant admin MFA template: target all 14 currently documented admin roles and all resources, grant control require authentication strength (phishing-resistant preferred, MFA as a floor).'
            'Re-run this check after any role restructuring - a renamed custom role built on top of a built-in admin role does not change the underlying role template id this check keys on, but a role assignment moved to a genuinely different role definition can.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#2-conditional-access-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
        )
    }
    Origin     = $null
}
