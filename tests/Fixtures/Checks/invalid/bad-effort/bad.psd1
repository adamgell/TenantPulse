@{
    Id         = 'TP.ENT.0024'
    Title      = 'Bad Effort value'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Low'
    Effort     = 'Extreme'
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
        Research    = 'docs/research/iha-v2/bad-effort.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
