@{
    Id         = 'TP.ENT.0023'
    Title      = 'Rule.Type is Expression but Rule.Expression is missing'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @()
    }
    Rule       = @{
        Type = 'Expression'
    }
    Consulting = @{
        WhatItMeans  = 'Placeholder.'
        WhyItMatters = 'Placeholder.'
        Remediation  = @('Placeholder.')
        PortalLinks  = @('https://entra.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/missing-expression.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
