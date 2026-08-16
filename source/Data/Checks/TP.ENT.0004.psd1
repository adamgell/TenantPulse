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
        WhatItMeans  = 'Legacy authentication protocols (POP, IMAP, older Exchange ActiveSync clients, legacy SMTP) cannot present an MFA challenge at all - if a Conditional Access policy does not explicitly block them, MFA requirements everywhere else in the tenant can simply be bypassed by using a legacy protocol instead. This check requires the block to be ENFORCED (state ''enabled''), not merely staged in report-only mode.'
        WhyItMatters = 'Legacy authentication is one of the most heavily abused vectors in password-spray and credential-stuffing attacks precisely because it has no MFA challenge to defeat. Microsoft has been telling customers to block it for years; a report-only policy that never got turned on gives a false sense of protection while leaving the door open.'
        Remediation  = @(
            'If a legacy-auth-block policy already exists in report-only mode (Microsoft auto-deploys one via managed policies), confirm break-glass accounts are excluded (see TP.ENT.0003), then switch its state to On.'
            'If no such policy exists, create one from Microsoft''s own template: Conditional Access > Policies > New policy > Templates > "Block legacy authentication" - target all users, client apps Exchange ActiveSync + Other clients, grant control Block.'
            'Confirm legacy auth is not actually in use first (sign-in logs, clientAppUsed) so the new block does not unexpectedly cut off a still-dependent line-of-business app - migrate it to modern auth before enforcing.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#2-conditional-access-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication'
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies'
        )
    }
    Origin     = $null
}
