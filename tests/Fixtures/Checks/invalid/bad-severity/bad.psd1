@{
    Id         = 'TP.ENT.0011'
    Title      = 'Bad severity value'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Extreme'
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
        Research    = 'docs/research/iha-v2/bad-severity.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
