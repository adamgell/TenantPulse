@{
    Id         = 'TP.ENT.0025'
    Title      = 'Bad Impact value'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Extreme'
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
        Research    = 'docs/research/iha-v2/bad-impact.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
