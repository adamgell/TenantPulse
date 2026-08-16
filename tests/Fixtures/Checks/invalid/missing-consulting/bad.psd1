@{
    Id         = 'TP.ENT.0016'
    Title      = 'Missing Consulting.WhyItMatters'
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
        WhatItMeans = 'Placeholder.'
        Remediation = @('Placeholder.')
        PortalLinks = @('https://entra.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/missing-consulting.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
