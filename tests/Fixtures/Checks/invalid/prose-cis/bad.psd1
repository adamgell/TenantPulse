@{
    Id         = 'TP.ENT.0027'
    Title      = 'Free-prose References.Cis instead of the ID-only format'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseFixtureRule'
    }
    Consulting = @{
        WhatItMeans  = 'Placeholder.'
        WhyItMatters = 'Placeholder.'
        Remediation  = @('Placeholder.')
        PortalLinks  = @('https://entra.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/prose-cis.md#a'
        Authorities = @('https://learn.microsoft.com/')
        Cis         = @('Ensure administrative accounts are cloud-only and phishing-resistant')
    }
    Origin     = $null
}
