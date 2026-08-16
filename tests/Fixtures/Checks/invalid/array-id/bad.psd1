@{
    Id         = @('TP.ENT.0001')
    Title      = 'Array-typed Id'
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
        Research    = 'docs/research/iha-v2/array-id.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
