@{
    Id         = 'TP.ENT.0020'
    Title      = 'Rule.Expression does not parse as PowerShell'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @()
    }
    Rule       = @{
        Type       = 'Expression'
        Expression = '$Datasets.foo -gt ('
    }
    Consulting = @{
        WhatItMeans  = 'Placeholder.'
        WhyItMatters = 'Placeholder.'
        Remediation  = @('Placeholder.')
        PortalLinks  = @('https://entra.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/bad-expression-syntax.md#a'
        Authorities = @('https://learn.microsoft.com/')
    }
    Origin     = $null
}
