@{
    Id         = 'TP.ENT.0004'
    Title      = 'Legacy authentication is blocked by an enforced Conditional Access policy'
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
        Function = 'Test-PulseLegacyAuthBlocked'
    }
    Consulting = @{
        WhatItMeans  = 'Legacy authentication protocols (POP, IMAP, older Exchange ActiveSync clients, legacy SMTP) cannot present an MFA challenge at all. This check requires enforced Conditional Access coverage for BOTH legacy client buckets - Exchange ActiveSync and Other clients - across all intended users, resources, platforms, locations, risk states, devices, and authentication flows. Coverage may be split across complete policies and the All client-app sentinel covers both buckets. Narrowed conditions do not establish tenant-wide protection; missing scope evidence is never promoted to Pass.'
        WhyItMatters = 'Legacy authentication is one of the most heavily abused vectors in password-spray and credential-stuffing attacks precisely because it has no MFA challenge to defeat. Microsoft has been telling customers to block it for years; a report-only policy that never got turned on gives a false sense of protection while leaving the door open.'
        Remediation  = @(
            'If a legacy-auth-block policy already exists in report-only mode (Microsoft auto-deploys one via managed policies), confirm break-glass accounts are excluded (see TP.ENT.0003), then switch its state to On.'
            'If no such policy exists, create one from Microsoft''s own template: Conditional Access > Policies > New policy > Templates > "Block legacy authentication" - target all users and all resources, client apps Exchange ActiveSync + Other clients, grant control Block.'
            'Confirm legacy auth is not actually in use first (sign-in logs, clientAppUsed) so the new block does not unexpectedly cut off a still-dependent line-of-business app - migrate it to modern auth before enforcing.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#2-conditional-access-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication'
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0'
            'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
        )
    }
    Origin     = $null
}
