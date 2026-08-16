@{
    Id         = 'TP.ENT.0001'
    Title      = 'Legacy authentication is blocked by Conditional Access'
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
        Function = 'Test-PulseFixtureRule'
    }
    Consulting = @{
        WhatItMeans  = 'Legacy authentication protocols bypass modern Conditional Access controls.'
        WhyItMatters = 'Attackers commonly use legacy protocols to bypass MFA enforcement.'
        Remediation  = @('Create a Conditional Access policy blocking legacy authentication.')
        PortalLinks  = @('https://entra.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/legacy-auth.md#blocking'
        Authorities = @(
            'https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication'
            'MS.AAD.1.1v1'
        )
    }
    Origin     = $null
}
