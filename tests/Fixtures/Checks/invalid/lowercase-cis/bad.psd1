@{
    Id         = 'TP.ENT.0028'
    Title      = 'Lowercase CIS-shaped References.Cis (case-sensitivity bypass)'
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
        Research    = 'docs/research/iha-v2/lowercase-cis.md#a'
        Authorities = @('https://learn.microsoft.com/')
        Cis         = @('cis microsoft 365 foundations benchmark v7.0.0, rec. 5.2.2.1 (e3 level 1)')
    }
    Origin     = $null
}
