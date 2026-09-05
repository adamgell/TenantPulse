@{
    Id         = 'TP.ENT.0017'
    Title      = 'MFA is required for all users by an enforced Conditional Access policy'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Critical'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @('EntraP1')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAllUsersMfaEnforced'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms an enabled (not report-only) Conditional Access policy requires MFA for all intended users across universal resource and sign-in scope. Direct account exclusions count only when they match the operator-declared exception set; all other user, resource, platform, location, risk, device-filter, authentication-flow, or client-app narrowing prevents a universal Pass. Graph grant AND/OR semantics are enforced, and custom authentication strengths remain indeterminate until requirementsSatisfied is available.'
        WhyItMatters = 'ScuBA rates this control SHALL (CISA BOD 25-01 mandatory tier) - it is the single highest-leverage Conditional Access control in the whole catalog. Microsoft auto-deploys several "Require MFA for all users" managed policies in report-only by default specifically because this gap is so common; leaving it in report-only is functionally the same as not having it.'
        Remediation  = @(
            'If Microsoft''s managed "Require multifactor authentication for all users" policy exists in report-only, confirm break-glass/service-account exclusions (TP.ENT.0003) and switch it to On.'
            'Otherwise create a policy targeting All users, All cloud apps, grant control require MFA (or a stronger authentication strength).'
            'Document any exclusion in the assessment profile''s BreakGlassAccounts/ServiceAccounts so it is recognized as intentional rather than surfaced as an undocumented gap.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0017--mfa-required-for-all-users-by-an-enforced-conditional-access-policy'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
        )
    }
    Origin     = $null
}
