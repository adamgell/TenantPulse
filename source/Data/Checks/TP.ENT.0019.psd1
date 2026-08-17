@{
    Id         = 'TP.ENT.0019'
    Title      = 'Service principal credential hygiene (password/certificate lifetime)'
    Category   = 'Entra.Identity'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('servicePrincipals')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAppCredentialHygiene'
    }
    Consulting = @{
        WhatItMeans  = 'Flags service principal password credentials (client secrets) older than 180 days and certificate credentials older than 365 days - ScuBA''s recommended lifetime ceilings. Evidence is capped to the 50 worst offenders (by degree over threshold); the total offending and total evaluated counts always appear in the finding reason even when evidence itself is capped. SCOPE NOTE: this check evaluates service principal credentials only - app-registration (application object) credential hygiene is not yet collectible pending a future GraphKit descriptor release; a tenant''s app registrations with long-lived secrets are not visible to this check yet.'
        WhyItMatters = 'Long-lived app-only secrets are a durable, easily-forgotten credential class - a leaked long-lived secret grants standing access with none of the rotation hygiene interactive user credentials get, and app-only compromises are a common real-world breach vector distinct from user-account compromise.'
        Remediation  = @(
            'Rotate any flagged password credential to a certificate credential where the integration supports it, or to a shorter-lived secret.'
            'Set a rotation reminder or automated rotation for any credential approaching the 180-day (password) / 365-day (certificate) threshold.'
            'Prefer Managed Identity over a client secret/certificate wherever the workload runs on Azure infrastructure that supports it - eliminates the credential entirely.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AppAppsPreview')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0019--application-and-service-principal-credential-hygiene'
        Authorities = @(
            'https://learn.microsoft.com/en-us/graph/api/resources/application'
        )
    }
    Origin     = $null
}
