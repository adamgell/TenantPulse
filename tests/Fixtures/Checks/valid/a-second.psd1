@{
    Id         = 'TP.INT.9999'
    Title      = 'Device compliance policies exist'
    Category   = 'Intune.Compliance'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('deviceCompliancePolicies')
        Gates    = @()
    }
    Rule       = @{
        Type       = 'Expression'
        Expression = '$Datasets.deviceCompliancePolicies.Count -gt 0'
    }
    Consulting = @{
        WhatItMeans  = 'No device compliance policies were found for this tenant.'
        WhyItMatters = 'Compliance policies are a prerequisite for Conditional Access compliance gates.'
        Remediation  = @('Create at least one device compliance policy per platform.')
        PortalLinks  = @('https://intune.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/compliance.md#baseline-count'
        Authorities = @('https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started')
    }
    Origin     = @{
        Project = 'Maester'
        Id      = 'MT.1105'
        License = 'MIT'
    }
}
