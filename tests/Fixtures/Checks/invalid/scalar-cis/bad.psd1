@{
    Id         = 'TP.ENT.0025'
    Title      = 'Scalar References.Cis instead of an array'
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
        Research    = 'docs/research/iha-v2/scalar-cis.md#a'
        Authorities = @('https://learn.microsoft.com/')
        Cis         = 'CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)'
    }
    Origin     = $null
}
